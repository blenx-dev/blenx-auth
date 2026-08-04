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
    from blenx_auth.sqlalchemy.base import UserId
    from blenx_auth.sqlalchemy.repositories import (
        SQLAlchemyOAuthAccountRepository,
        SQLAlchemyRefreshTokenRepository,
        SQLAlchemyUserRepository,
    )
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker


def _collect_fn(
    ordered_plugins: Sequence[AuthPlugin], overrides: Mapping[str, type]
) -> Callable[[str, type | None], list[type]]:
    """Return a ``collect(attr, consumer_mixin)`` closure for one composition.

    ``overrides`` replaces any plugin/consumer mixin with a consumer class
    keyed by the mixin's ``__name__`` (locked decision #7).
    """

    def collect(attr: str, consumer_mixin: type | None) -> list[type]:
        mixins = [
            getattr(p, attr) for p in ordered_plugins if getattr(p, attr) is not None
        ]
        if consumer_mixin is not None:
            mixins.append(consumer_mixin)
        resolved = [overrides.get(m.__name__, m) for m in mixins]
        return list(dict.fromkeys(resolved))

    return collect


def _merge_plugin_hooks(plugins: Sequence[AuthPlugin], base: AuthHooks) -> AuthHooks:
    return reduce(merge_hooks, (p.hooks for p in plugins), base)



