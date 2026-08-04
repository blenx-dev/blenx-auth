"""Shared typing for router factories (not part of the public API)."""

from __future__ import annotations
from typing import TypedDict
from dataclasses import field
from enum import Enum

from collections.abc import Awaitable, Callable
from typing import Any, Protocol
from dataclasses import dataclass
from blenx_auth.core.ports import UserAccount
from blenx_auth.core.services import (
    AuthenticationService,
    EmailVerificationService,
    PasswordResetService,
)


class AuthProvider(Protocol):
    """The service/current-user surface every composition root exposes."""

    get_authentication_service: Callable[..., Awaitable[AuthenticationService[Any]]]
    get_verification_service: Callable[..., Awaitable[EmailVerificationService[Any]]]
    get_password_reset_service: Callable[..., Awaitable[PasswordResetService[Any]]]
    get_current_user: Callable[..., Awaitable[UserAccount[Any]]]
    get_current_active_user: Callable[..., Awaitable[UserAccount[Any]]]
    get_current_verified_user: Callable[..., Awaitable[UserAccount[Any]]]


def _default_tags():
    return ["auth"]


@dataclass
class AuthRouterConfig:
    prefix: str = "/auth"
    tags: list[str | Enum] = field(default_factory=_default_tags)


class AuthRouterConfigOverrides(TypedDict, total=False):
    """Mirror of AuthRouterConfig's fields, all optional for override purposes."""

    prefix: str
    tags: list[str | Enum]


__all__ = ["AuthProvider"]
