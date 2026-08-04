"""Adapter-specific composition roots.

Each root binds one storage backend to the core services and exposes
FastAPI dependencies so the host application never wires services by hand:

    session_factory = create_session_factory(settings.database_url)
    auth = SQLAlchemyAuth(settings=settings, session_factory=session_factory)
    app.include_router(make_auth_router(auth))  # routes use Depends(auth.get_*)

The dependency callables are plain closures assigned in ``__init__``, so the
same methods work outside HTTP: ``await auth.get_authentication_service(session)``
(in a worker, CLI script, or test) and inside FastAPI via ``Depends``.

Plugin composition happens in ``__init__``: the ordered ``plugins`` are
resolved, their table/read/create/update mixins are folded into the user model
and schemas, the contract check runs, and every plugin's ``router_factory``
is available through :meth:`build_plugin_routers`. ``overrides`` lets a
consumer replace a base mixin (keyed by its ``__name__``).

Storage backends are optional: this module imports **neither** SQLAlchemy nor
Beanie at module load (only under ``TYPE_CHECKING`` for the type checker), so
``import blenx_auth.fastapi`` works with no storage backend installed. Each
backend's SDK is imported lazily inside the matching root's ``__init__`` and
errors if the host did not install it.

NOTE: this module intentionally omits ``from __future__ import annotations``.
FastAPI evaluates dependency signatures with ``inspect.signature(..., eval_str=True)``,
which cannot resolve the closures referenced inside ``Depends(...)`` if they are
deferred to strings; eager annotations keep the sub-dependencies concrete. Only the
``__init__`` *parameter* annotations that name storage types are written as strings,
so they are not evaluated at class-definition time.
"""

from blenx_auth.fastapi.composition import _merge_plugin_hooks
from blenx_auth.fastapi.composition import _collect_fn
from collections.abc import  Awaitable, Callable, Mapping, Sequence
from functools import reduce
from typing import TYPE_CHECKING, Any

from blenx_auth.core.contracts import run_contract_check
from blenx_auth.core.email import NullEmailSender
from blenx_auth.core.impl_protocols import AuthBackend
from blenx_auth.core.jwt import TokenService
from blenx_auth.core.plugins import AuthPlugin, resolve_plugin_order
from blenx_auth.core.plugins.hooks import AuthHooks, merge_hooks
from blenx_auth.core.ports import EmailSender
from blenx_auth.core.schemas import RegisterRequest, UserAdminUpdate, UserRead, UserUpdate
from blenx_auth.core.services import (
    AuthenticationService,
    EmailVerificationService,
    PasswordResetService,
    UserService,
)
from blenx_auth.core.settings import AuthSettings
from blenx_auth.fastapi.class_builder_pydantic import build_pydantic_model
from blenx_auth.fastapi.class_builder_sqla import build_sqla_models
from blenx_auth.fastapi.current_user import make_current_user_dependencies
from blenx_auth.fastapi.routers._provider import PluginRouterConfig
from fastapi import APIRouter, Depends

if TYPE_CHECKING:
    from beanie import PydanticObjectId
    from blenx_auth.beanie.repositories import (
        BeanieOAuthAccountRepository,
        BeanieRefreshTokenRepository,
        BeanieUserRepository,
    )
class BeanieAuth(AuthBackend[Any]):
    """Composition root: Beanie/MongoDB backend wired to core services.

    Beanie binds its ``Document`` classes to one database globally (via
    :func:`blenx_auth.beanie.init_beanie_db` at startup), so repositories are
    shared instance state and the service dependencies take no session. With
    ``plugins`` the root builds a ``User`` document subclass carrying the
    plugin/consumer table mixins' fields.
    """

    def __init__(
        self,
        *,
        settings: AuthSettings,
        email_sender: EmailSender | None = None,
        parse_subject: "Callable[[str], PydanticObjectId] | None" = None,
        plugins: Sequence[AuthPlugin] = (),
        consumer_table_mixin: type | None = None,
        consumer_read_mixin: type | None = None,
        consumer_create_mixin: type | None = None,
        consumer_update_mixin: type | None = None,
        consumer_admin_update_mixin: type | None = None,
        overrides: Mapping[str, type] | None = None,
        base_hooks: AuthHooks | None = None,
    ) -> None:
        from beanie import PydanticObjectId
        from blenx_auth.beanie.models import User as BeanieUser
        from blenx_auth.beanie.repositories import (
            BeanieOAuthAccountRepository,
            BeanieRefreshTokenRepository,
            BeanieUserRepository,
        )
        from blenx_auth.fastapi.class_builder_beanie import build_beanie_model

        if parse_subject is None:
            parse_subject = PydanticObjectId

        ordered_plugins = resolve_plugin_order(plugins)
        overrides = overrides or {}
        collect = _collect_fn(ordered_plugins, overrides)

        table_mixins = collect("table_mixin", consumer_table_mixin)
        read_mixins = collect("read_mixin", consumer_read_mixin)
        create_mixins = collect("create_mixin", consumer_create_mixin)
        update_mixins = collect("update_mixin", consumer_update_mixin)

        if table_mixins:
            user_model = build_beanie_model("User", BeanieUser, table_mixins)
        else:
            user_model = BeanieUser

        register_schema = build_pydantic_model(
            "UserCreate", base=RegisterRequest,  kind="create",mixins=create_mixins
        )

        # Beanie's identity is a Mongo ObjectId, not a UUID: the composed read
        # schema must serialize it as-is or every HTTP response fails
        # response-model validation (uuid.UUID rejects ObjectId input).
        user_read_schema = build_pydantic_model(
            "UserRead",
            base=UserRead,
            kind="read",
            mixins=read_mixins,
            field_overrides={"id": (PydanticObjectId, ...)},
        )
        user_update_schema = build_pydantic_model(
            "UserUpdate", base=UserUpdate, kind="update",mixins=update_mixins
        )
        user_admin_update_schema = build_pydantic_model(
            "UserAdminUpdate",
            base=UserAdminUpdate,
            kind="update",
            mixins=[]
        )

        run_contract_check(
            user_model, user_read_schema, register_schema, user_update_schema
        )

        self._settings = settings
        self._email_sender: EmailSender = email_sender or NullEmailSender()
        self._parse_subject = parse_subject
        self._tokens = TokenService(settings)
        self._user_model = user_model
        self._plugins = ordered_plugins
        self._base_hooks = base_hooks or AuthHooks()
        self._hooks = _merge_plugin_hooks(ordered_plugins, self._base_hooks)
        self._users = BeanieUserRepository(model=user_model)
        self._refresh_tokens = BeanieRefreshTokenRepository()
        self._oauth_accounts = BeanieOAuthAccountRepository()

        self.User = user_model
        self.UserRead = user_read_schema
        self.UserCreate = register_schema
        self.UserUpdate = user_update_schema
        self.UserAdminUpdate = user_admin_update_schema
        self.hooks = self._hooks
        self.register_schema = register_schema
        self.user_read_schema = user_read_schema
        self.user_update_schema = user_update_schema
        self.user_admin_update_schema = user_admin_update_schema

        async def get_authentication_service() -> AuthenticationService[PydanticObjectId]:
            verification = EmailVerificationService(
                users=self._users,
                tokens=self._tokens,
                email_sender=self._email_sender,
                settings=self._settings,
                parse_subject=self._parse_subject,
            )
            return AuthenticationService(
                users=self._users,
                refresh_tokens=self._refresh_tokens,
                oauth_accounts=self._oauth_accounts,
                tokens=self._tokens,
                email_sender=self._email_sender,
                verification=verification,
                settings=self._settings,
                parse_subject=self._parse_subject,
                hooks=self._hooks,
            )

        async def get_verification_service() -> EmailVerificationService[PydanticObjectId]:
            return EmailVerificationService(
                users=self._users,
                tokens=self._tokens,
                email_sender=self._email_sender,
                settings=self._settings,
                parse_subject=self._parse_subject,
            )

        async def get_password_reset_service() -> PasswordResetService[PydanticObjectId]:
            return PasswordResetService(
                users=self._users,
                refresh_tokens=self._refresh_tokens,
                tokens=self._tokens,
                email_sender=self._email_sender,
                settings=self._settings,
                parse_subject=self._parse_subject,
            )

        async def get_user_service() -> UserService[PydanticObjectId]:
            return UserService(
                repo=self._users,
                hooks=self._hooks,
                model=user_model,
            )

        self.get_authentication_service: Callable[
            ..., Awaitable[AuthenticationService[PydanticObjectId]]
        ] = get_authentication_service
        self.get_verification_service: Callable[
            ..., Awaitable[EmailVerificationService[PydanticObjectId]]
        ] = get_verification_service
        self.get_password_reset_service: Callable[
            ..., Awaitable[PasswordResetService[PydanticObjectId]]
        ] = get_password_reset_service
        self.get_user_service: Callable[..., Awaitable[UserService[PydanticObjectId]]] = (
            get_user_service
        )

        current_user = make_current_user_dependencies(self.get_authentication_service)
        self.get_current_user = current_user.get_current_user
        self.get_current_active_user = current_user.get_current_active_user
        self.get_current_verified_user = current_user.get_current_verified_user
        self.get_current_superuser = current_user.get_current_superuser
        self.CurrentUser = current_user.CurrentUser
        self.CurrentActiveUser = current_user.CurrentActiveUser
        self.CurrentVerifiedUser = current_user.CurrentVerifiedUser
        self.CurrentSuperUser = current_user.CurrentSuperUser

        from blenx_auth.fastapi.routers import make_auth_router, make_users_router

        self.routers: list[APIRouter] = [
            make_auth_router(self),
            make_users_router(self),
            *self.build_plugin_routers(),
        ]

    @property
    def token_service(self) -> TokenService:
        """The configured token service (e.g. for OAuth state minting)."""
        return self._tokens

    @property
    def settings(self) -> AuthSettings:
        """The configured settings."""
        return self._settings

    @property
    def user_model(self) -> type:
        """The composed (or static) user document this root bound services to."""
        return self._user_model

    def _plugin_router_config(self, plugin: AuthPlugin) -> PluginRouterConfig:
        return PluginRouterConfig(
            session_factory=None,
            token_service=self._tokens,
            User=self._user_model,
            UserRead=self.user_read_schema,
        )

    def build_plugin_routers(self) -> list[APIRouter]:
        """Build every registered plugin's router (host app includes these)."""
        routers: list[APIRouter] = []
        for plugin in self._plugins:
            if plugin.router_factory is None:
                continue
            routers.append(plugin.router_factory(self._plugin_router_config(plugin)))
        return routers

    def plugin_router_config(self, name: str) -> PluginRouterConfig | None:
        """The router config for one plugin by name, else ``None``."""
        for plugin in self._plugins:
            if plugin.name == name:
                return self._plugin_router_config(plugin)
        return None

    def get_user_repository(self) -> "BeanieUserRepository":
        """User repository (direct/off-HTTP use)."""
        return self._users

    def get_refresh_token_repository(self) -> "BeanieRefreshTokenRepository":
        """Refresh-token repository (direct/off-HTTP use)."""
        return self._refresh_tokens

    def get_oauth_account_repository(self) -> "BeanieOAuthAccountRepository":
        """OAuth-account repository (direct/off-HTTP use)."""
        return self._oauth_accounts
