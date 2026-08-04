"""Current-user dependencies (bound to a composition root).

:func:`make_current_user_dependencies` turns a composition root's
``get_authentication_service`` into the current-user dependency family:

- ``get_current_user`` resolves a Bearer access token to an active user. All
  *policy* — token validation, lockout, account state — lives in the services;
  these functions only decide "who is making this request".
- ``get_current_active_user`` / ``get_current_verified_user`` belt-and-suspenders
  guards for endpoints that must never run for inactive/unverified accounts.
- ``CurrentUser`` / ``CurrentActiveUser`` / ``CurrentVerifiedUser`` are the
  ``Annotated`` aliases for route signatures (``user: auth.CurrentUser``).

NOTE: this module intentionally omits ``from __future__ import annotations``.
FastAPI evaluates dependency signatures with ``inspect.signature(..., eval_str=True)``,
which cannot resolve the closures referenced inside ``Depends(...)`` if they are
deferred to strings; eager annotations keep the sub-dependencies concrete.
"""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Annotated, Any

from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from blenx_auth.core.exceptions import (
    InactiveAccountError,
    InvalidCredentialsError,
    UnverifiedAccountError,
)
from blenx_auth.core.ports import UserAccount
from blenx_auth.core.services import AuthenticationService
from fastapi import Depends, Security

bearer_scheme = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class CurrentUserDeps:
    """The current-user dependency family for one composition root."""

    get_current_user: Callable[..., Awaitable[UserAccount[Any]]]
    get_current_active_user: Callable[..., Awaitable[UserAccount[Any]]]
    get_current_verified_user: Callable[..., Awaitable[UserAccount[Any]]]
    CurrentUser: Any
    CurrentActiveUser: Any
    CurrentVerifiedUser: Any


def make_current_user_dependencies(
    get_authentication_service: Callable[..., Awaitable[AuthenticationService[Any]]],
) -> CurrentUserDeps:
    """Bind the current-user dependencies to a composition root's auth service."""

    async def get_current_user(
        credentials: Annotated[HTTPAuthorizationCredentials | None, Security(bearer_scheme)],
        auth_service: Annotated[AuthenticationService[Any], Depends(get_authentication_service)],
    ) -> UserAccount[Any]:
        """Resolve the Bearer access token to an active user.

        A missing or malformed header, an invalid/expired token, an unknown
        subject, and a deactivated account each raise the appropriate
        :class:`AuthError` (all rendered as 401/403 by the app-level handler).
        """
        if credentials is None:
            raise InvalidCredentialsError()
        return await auth_service.authenticate_access_token(credentials.credentials)

    async def get_current_active_user(
        user: Annotated[UserAccount[Any], Depends(get_current_user)],
    ) -> UserAccount[Any]:
        """Belt-and-suspenders: ``authenticate_access_token`` already rejects
        inactive accounts, but endpoints that must *never* run for them can
        depend on this and stay correct even if that guarantee shifts."""
        if not user.is_active:
            raise InactiveAccountError()
        return user

    async def get_current_verified_user(
        user: Annotated[UserAccount[Any], Depends(get_current_user)],
    ) -> UserAccount[Any]:
        """A user who completed email verification (e.g. privileged actions)."""
        if not user.is_verified:
            raise UnverifiedAccountError()
        return user

    return CurrentUserDeps(
        get_current_user=get_current_user,
        get_current_active_user=get_current_active_user,
        get_current_verified_user=get_current_verified_user,
        CurrentUser=Annotated[UserAccount[Any], Depends(get_current_user)],
        CurrentActiveUser=Annotated[UserAccount[Any], Depends(get_current_active_user)],
        CurrentVerifiedUser=Annotated[UserAccount[Any], Depends(get_current_verified_user)],
    )


__all__ = ["CurrentUserDeps", "bearer_scheme", "make_current_user_dependencies"]
