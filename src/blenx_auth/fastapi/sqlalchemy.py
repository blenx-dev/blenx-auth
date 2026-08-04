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

import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping, Sequence
from functools import reduce
from typing import TYPE_CHECKING, Annotated, Any

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
from blenx_auth.fastapi.composition import collect_fn, merge_plugin_hooks
from blenx_auth.fastapi.current_user import make_current_user_dependencies
from blenx_auth.fastapi.routers._provider import PluginRouterConfig
from fastapi import APIRouter, Depends

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from blenx_auth.sqlalchemy.base import UserId
    from blenx_auth.sqlalchemy.repositories import (
        SQLAlchemyOAuthAccountRepository,
        SQLAlchemyRefreshTokenRepository,
        SQLAlchemyUserRepository,
    )


class SQLAlchemyAuth(AuthBackend[Any]):
    """Composition root: SQLAlchemy/PostgreSQL backend wired to core services.

    Holds the single configured ``TokenService``, email sender, and settings;
    builds fresh per-request repositories from the session yielded by
    :attr:`get_db_session`. With ``plugins`` / ``overrides`` the root tears down
    the shared registry and re-maps ``User`` (plus ``RefreshToken`` and
    ``OAuthAccount``) so plugin/consumer table mixins become real columns.
    """

    def __init__(
        self,
        *,
        settings: AuthSettings,
        session_factory: "async_sessionmaker[AsyncSession]",
        email_sender: EmailSender | None = None,
        parse_subject: "Callable[[str], UserId] | None" = None,
        plugins: Sequence[AuthPlugin] = (),
        overrides: Mapping[str, type] | None = None,
        base_hooks: AuthHooks | None = None,
        tablename: str = "user",
    ) -> None:
        from sqlalchemy.ext.asyncio import AsyncSession

        from blenx_auth.sqlalchemy.base import AuthBase, UserId
        from blenx_auth.sqlalchemy.models import (
            BaseUserTableMixin,
            make_oauth_account_model,
            make_refresh_token_model,
        )
        from blenx_auth.sqlalchemy.repositories import (
            SQLAlchemyOAuthAccountRepository,
            SQLAlchemyRefreshTokenRepository,
            SQLAlchemyUserRepository,
        )

        if parse_subject is None:
            parse_subject = uuid.UUID

        ordered_plugins = resolve_plugin_order(plugins)
        overrides = overrides or {}
        collect = collect_fn(ordered_plugins, overrides)

        table_mixins = collect("table_mixin", None)
        print("table_mixins", table_mixins)
        read_mixins = collect("read_mixin", None)
        create_mixins = collect("create_mixin", None)
        update_mixins = collect("update_mixin", None)
        user_model, refresh_model, oauth_model = build_sqla_models(
            auth_base=AuthBase,
            core_mixin=BaseUserTableMixin,
            tablename=tablename,
            table_mixins=table_mixins,
            refresh_token_factory=make_refresh_token_model,
            oauth_account_factory=make_oauth_account_model,
        )

        register_schema = build_pydantic_model(
            "UserCreate", base=RegisterRequest, kind="create", mixins=create_mixins
        )
        user_read_schema = build_pydantic_model(
            "UserRead", base=UserRead, kind="read", mixins=read_mixins
        )
        user_update_schema = build_pydantic_model(
            "UserUpdate", base=UserUpdate, kind="update", mixins=update_mixins
        )
        user_admin_update_schema = build_pydantic_model(
            "UserAdminUpdate",
            base=UserAdminUpdate,
            kind="update",
            mixins=collect("update_mixin", None),
        )

        run_contract_check(user_model, user_read_schema, register_schema, user_update_schema)

        self._settings = settings
        self._session_factory = session_factory
        self._email_sender: EmailSender = email_sender or NullEmailSender()
        self._parse_subject = parse_subject
        self._tokens = TokenService(settings)
        self._user_model = user_model
        self._refresh_model = refresh_model
        self._oauth_model = oauth_model
        self._plugins = ordered_plugins
        self._base_hooks = base_hooks or AuthHooks()
        self._hooks = merge_plugin_hooks(ordered_plugins, self._base_hooks)

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

        async def get_db_session() -> AsyncIterator[AsyncSession]:
            """Yield a request-scoped session (closes it when the request ends)."""
            async with self._session_factory() as session:
                yield session

        async def get_authentication_service(
            session: Annotated[AsyncSession, Depends(get_db_session)],
        ) -> AuthenticationService[UserId]:
            users = SQLAlchemyUserRepository(session, model=user_model)
            refresh_tokens = SQLAlchemyRefreshTokenRepository(session, model=refresh_model)
            oauth_accounts = SQLAlchemyOAuthAccountRepository(session, model=oauth_model)
            verification = EmailVerificationService(
                users=users,
                tokens=self._tokens,
                email_sender=self._email_sender,
                settings=self._settings,
                parse_subject=self._parse_subject,
            )
            return AuthenticationService(
                users=users,
                refresh_tokens=refresh_tokens,
                oauth_accounts=oauth_accounts,
                tokens=self._tokens,
                email_sender=self._email_sender,
                verification=verification,
                settings=self._settings,
                parse_subject=self._parse_subject,
                hooks=self._hooks,
            )

        async def get_verification_service(
            session: Annotated[AsyncSession, Depends(get_db_session)],
        ) -> EmailVerificationService[UserId]:
            return EmailVerificationService(
                users=SQLAlchemyUserRepository(session, model=user_model),
                tokens=self._tokens,
                email_sender=self._email_sender,
                settings=self._settings,
                parse_subject=self._parse_subject,
            )

        async def get_password_reset_service(
            session: Annotated[AsyncSession, Depends(get_db_session)],
        ) -> PasswordResetService[UserId]:
            return PasswordResetService(
                users=SQLAlchemyUserRepository(session, model=user_model),
                refresh_tokens=SQLAlchemyRefreshTokenRepository(session, model=refresh_model),
                tokens=self._tokens,
                email_sender=self._email_sender,
                settings=self._settings,
                parse_subject=self._parse_subject,
            )

        async def get_user_service(
            session: Annotated[AsyncSession, Depends(get_db_session)],
        ) -> UserService[UserId]:
            return UserService(
                repo=SQLAlchemyUserRepository(session, model=user_model),
                hooks=self._hooks,
                model=user_model,
            )

        self.get_db_session: Callable[..., AsyncIterator[AsyncSession]] = get_db_session
        self.get_authentication_service: Callable[..., Awaitable[AuthenticationService[UserId]]] = (
            get_authentication_service
        )
        self.get_verification_service: Callable[
            ..., Awaitable[EmailVerificationService[UserId]]
        ] = get_verification_service
        self.get_password_reset_service: Callable[..., Awaitable[PasswordResetService[UserId]]] = (
            get_password_reset_service
        )
        self.get_user_service: Callable[..., Awaitable[UserService[UserId]]] = get_user_service

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
        """The composed (or static) user model this root bound its services to."""
        return self._user_model

    def _plugin_router_config(self, plugin: AuthPlugin) -> PluginRouterConfig:
        return PluginRouterConfig(
            session_factory=self._session_factory,
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

    def get_user_repository(self, session: "AsyncSession") -> "SQLAlchemyUserRepository":
        """User repository bound to ``session`` (for direct/off-HTTP use)."""
        from blenx_auth.sqlalchemy.repositories import SQLAlchemyUserRepository

        return SQLAlchemyUserRepository(session, model=self._user_model)

    def get_refresh_token_repository(
        self, session: "AsyncSession"
    ) -> "SQLAlchemyRefreshTokenRepository":
        """Refresh-token repository bound to ``session`` (for direct/off-HTTP use)."""
        from blenx_auth.sqlalchemy.repositories import SQLAlchemyRefreshTokenRepository

        return SQLAlchemyRefreshTokenRepository(session, model=self._refresh_model)

    def get_oauth_account_repository(
        self, session: "AsyncSession"
    ) -> "SQLAlchemyOAuthAccountRepository":
        """OAuth-account repository bound to ``session`` (for direct/off-HTTP use)."""
        from blenx_auth.sqlalchemy.repositories import SQLAlchemyOAuthAccountRepository

        return SQLAlchemyOAuthAccountRepository(session, model=self._oauth_model)
