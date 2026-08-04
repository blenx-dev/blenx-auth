"""Shared typing for router factories (not part of the public API)."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol, TypedDict

from pydantic import BaseModel

from blenx_auth.core.ports import UserAccount
from blenx_auth.core.services import (
    AuthenticationService,
    EmailVerificationService,
    PasswordResetService,
    UserService,
)


class AuthProvider(Protocol):
    """The service/current-user surface every composition root exposes."""

    get_authentication_service: Callable[..., Awaitable[AuthenticationService[Any]]]
    get_verification_service: Callable[..., Awaitable[EmailVerificationService[Any]]]
    get_password_reset_service: Callable[..., Awaitable[PasswordResetService[Any]]]
    get_user_service: Callable[..., Awaitable[UserService[Any]]]
    get_current_user: Callable[..., Awaitable[UserAccount[Any]]]
    get_current_active_user: Callable[..., Awaitable[UserAccount[Any]]]
    get_current_verified_user: Callable[..., Awaitable[UserAccount[Any]]]
    get_current_superuser: Callable[..., Awaitable[UserAccount[Any]]]
    CurrentUser: Any
    CurrentActiveUser: Any
    CurrentVerifiedUser: Any
    CurrentSuperUser: Any


def _default_tags() -> list[str | Enum]:
    return ["auth"]


@dataclass
class AuthRouterConfig:
    prefix: str = "/auth"
    tags: list[str | Enum] = field(default_factory=_default_tags)
    register_schema: type[BaseModel] | None = None
    user_read_schema: type[BaseModel] | None = None
    user_update_schema: type[BaseModel] | None = None
    user_admin_update_schema: type[BaseModel] | None = None


class AuthRouterConfigOverrides(TypedDict, total=False):
    """Mirror of AuthRouterConfig's fields, all optional for override purposes."""

    prefix: str
    tags: list[str | Enum]
    register_schema: type[BaseModel]
    user_read_schema: type[BaseModel]
    user_update_schema: type[BaseModel]
    user_admin_update_schema: type[BaseModel]


@dataclass
class PluginRouterConfig:
    """What a plugin's ``router_factory`` receives from the composition root.

    Carries the storage/schema context a plugin router may need; plugin-specific
    services (e.g. a bound ``TwoFactorService``) are supplied by the plugin's
    own closure rather than re-derived here.
    """

    session_factory: Any
    token_service: Any
    User: type
    UserRead: type


def merge_router_config(
    auth: AuthProvider,
    options: AuthRouterConfigOverrides,
    *,
    prefix: str,
) -> AuthRouterConfig:
    """Build a router config from the root's composed schemas plus explicit options.

    A composition root exposes its dynamically-composed schemas as plain
    attributes (``register_schema``, ``user_read_schema``, ``user_update_schema``,
    ``user_admin_update_schema``) so ``make_auth_router`` / ``make_users_router``
    bind them by default; explicit ``**options`` always win.
    """
    defaults: dict[str, Any] = {
        name: getattr(auth, name, None)
        for name in (
            "register_schema",
            "user_read_schema",
            "user_update_schema",
            "user_admin_update_schema",
        )
    }
    defaults["prefix"] = prefix
    return AuthRouterConfig(**{**defaults, **options})


__all__ = ["AuthProvider", "PluginRouterConfig"]
