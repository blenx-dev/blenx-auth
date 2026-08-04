"""The ``/users`` router (bound to a composition root).

Owns the ``/users/me`` profile endpoint alongside the ``/auth`` flow routes;
both carry the same exception handler so every guard failure renders
consistently.

NOTE: this module intentionally omits ``from __future__ import annotations``
for the same reason as :mod:`blenx_auth.fastapi.routers.auth`.
"""

from blenx_auth.fastapi.routers._provider import AuthRouterConfig
from blenx_auth.fastapi.routers._provider import AuthRouterConfigOverrides
from typing import Unpack
from blenx_auth.core.impl_protocols import AuthBackend

from typing import Annotated, Any

from blenx_auth.core.ports import UserAccount
from blenx_auth.core.schemas import UserRead
from fastapi import APIRouter, Depends


def make_users_router(
    auth: AuthBackend,
    **options: Unpack[AuthRouterConfigOverrides],
) -> APIRouter:
    """Build the ``/users`` router bound to ``auth`` (a composition root)."""

    """Build the ``/auth`` router bound to ``auth`` (a composition root)."""
    config = AuthRouterConfig(**options)
    router = APIRouter(prefix=config.prefix, tags=config.tags)

    @router.get("/me", response_model=UserRead, summary="Current user profile")
    async def current_user(
        user: Annotated[UserAccount[Any], Depends(auth.get_current_user)],
    ) -> UserAccount[Any]:
        """The authenticated user's public profile."""
        return user

    return router


__all__ = ["make_users_router"]
