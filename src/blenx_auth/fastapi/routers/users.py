"""The ``/users`` router (bound to a composition root).

Owns the ``/users/me`` profile endpoint alongside the ``/auth`` flow routes;
both carry the same exception handler so every guard failure renders
consistently.

The ``PATCH`` routes use :class:`blenx_auth.core.services.UserService.update`,
whose ``exclude_unset=True`` semantics mean a ``{}`` body is a no-op rather
than a wipe, and declared-but-``None`` fields are explicit clears.

NOTE: this module intentionally omits ``from __future__ import annotations``
for the same reason as :mod:`blenx_auth.fastapi.routers.auth`.
"""

from typing import Annotated, Any, Unpack

from blenx_auth.core.impl_protocols import AuthBackend
from blenx_auth.core.ports import UserAccount
from blenx_auth.core.schemas import UserAdminUpdate, UserRead, UserUpdate
from blenx_auth.core.services import UserService
from blenx_auth.fastapi.routers._provider import (
    AuthRouterConfigOverrides,
    merge_router_config,
)
from fastapi import APIRouter, Depends


def make_users_router(
    auth: AuthBackend[Any],
    **options: Unpack[AuthRouterConfigOverrides],
) -> APIRouter:
    """Build the ``/users`` router bound to ``auth`` (a composition root)."""
    config = merge_router_config(auth, options, prefix="/users")
    router = APIRouter(prefix=config.prefix, tags=config.tags)
    user_read_schema = config.user_read_schema or UserRead
    user_update_schema = config.user_update_schema or UserUpdate
    user_admin_update_schema = config.user_admin_update_schema or UserAdminUpdate

    @router.get("/me", response_model=user_read_schema, summary="Current user profile")
    async def current_user(
        user: Annotated[UserAccount[Any], Depends(auth.get_current_user)],
    ) -> UserAccount[Any]:
        """The authenticated user's public profile."""
        return user

    print(user_update_schema.model_fields)

    @router.patch("/me", response_model=user_read_schema, summary="Update current user profile")
    async def update_me(
        payload: user_update_schema,  # type: ignore[valid-type]
        user: Annotated[UserAccount[Any], Depends(auth.get_current_user)],
        user_service: Annotated[UserService[Any], Depends(auth.get_user_service)],
    ) -> UserAccount[Any]:
        """Patch the current user's self-serviceable fields (e.g. display_name)."""
        return await user_service.update(user_id=user.id, payload=payload)

    @router.get("/{user_id}", response_model=user_read_schema, summary="Admin: get user")
    async def get_user(
        user_id: str,
        _superuser: Annotated[UserAccount[Any], Depends(auth.get_current_superuser)],
        user_service: Annotated[UserService[Any], Depends(auth.get_user_service)],
    ) -> UserAccount[Any]:
        """Admin-only user lookup."""
        return await user_service.get(user_id)

    @router.patch(
        "/{user_id}",
        response_model=user_read_schema,
        summary="Admin: update user",
    )
    async def admin_update_user(
        user_id: str,
        payload: user_admin_update_schema,  # type: ignore[valid-type]
        _superuser: Annotated[UserAccount[Any], Depends(auth.get_current_superuser)],
        user_service: Annotated[UserService[Any], Depends(auth.get_user_service)],
    ) -> UserAccount[Any]:
        """Admin-only user update (flags, verification state, display_name)."""
        return await user_service.update(user_id=user_id, payload=payload)

    return router


__all__ = ["make_users_router"]
