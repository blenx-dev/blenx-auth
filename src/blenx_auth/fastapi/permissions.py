"""Role and permission guards for the auth module.

The user table ships only the legacy ``is_superuser`` flag today, but the
guards are written against a forward-compatible capability model:

- :class:`Permission` enumerates known capabilities. Extend the enum as the
  product grows; every new permission needs its own string so audit logs and
  dependency checks stay greppable.
- :func:`roles_for` and :func:`permissions_for` are the *seams*: today they
  derive everything from ``is_superuser``, but when a real roles table lands,
  only these two functions change — every endpoint guard stays put.
- :func:`make_permission_guards` binds the guard *factories* to a composition
  root's current-user dependency. The returned
  ``require_permission``/``require_role``/``require_admin`` are dependency
  factories (``Depends(guards.require_admin())``) so a guard can carry
  arguments and still be reused as a FastAPI dependency.

Guards raise :class:`blenx_auth.core.exceptions.PermissionDeniedError`, which
``auth_error_handler`` renders as a 403.

NOTE: this module intentionally omits ``from __future__ import annotations``.
``make_permission_guards`` builds guards whose ``Depends(...)`` references a
closure variable; FastAPI resolves dependency signatures with
``inspect.signature(..., eval_str=True)``, which cannot resolve deferred string
annotations, so they are evaluated eagerly instead.
"""

import enum
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Annotated, Any

from blenx_auth.core.exceptions import PermissionDeniedError
from blenx_auth.core.ports import UserAccount
from fastapi import Depends


class Permission(enum.StrEnum):
    """Registry of capabilities. Prefixing keeps related ones grouped."""

    MANAGE_USERS = "users:manage"
    MANAGE_STYLISTS = "stylists:manage"
    MANAGE_SERVICES = "services:manage"
    MANAGE_AVAILABILITY = "availability:manage"
    MANAGE_BOOKINGS = "bookings:manage"


ROLE_PERMISSIONS: dict[str, frozenset[Permission]] = {
    "admin": frozenset(Permission),
    "stylist": frozenset(
        {
            Permission.MANAGE_AVAILABILITY,
        }
    ),
    "customer": frozenset(),
}


def roles_for(user: UserAccount[Any]) -> frozenset[str]:
    """Resolve the user's role names.

    Seam: swap this for a roles-table lookup when one exists. Today the only
    distinguished role is ``admin``, backed by the legacy ``is_superuser``
    flag.
    """
    if user.is_superuser:
        return frozenset(("admin",))
    return frozenset()


def permissions_for(user: UserAccount[Any]) -> frozenset[Permission]:
    """Resolve the user's effective permission set from their roles."""
    granted: set[Permission] = set()
    for role in roles_for(user):
        granted |= ROLE_PERMISSIONS[role]
    return frozenset(granted)


async def _ensure_permissions(
    user: UserAccount[Any], required: frozenset[Permission]
) -> UserAccount[Any]:
    granted = permissions_for(user)
    missing = required - granted
    if missing:
        first = sorted(missing)[0]
        raise PermissionDeniedError(detail=f"Missing permission: {first.value}.")
    return user


async def _ensure_role(user: UserAccount[Any], role: str) -> UserAccount[Any]:
    if role not in roles_for(user):
        raise PermissionDeniedError(detail=f"Role required: {role}.")
    return user


async def _ensure_admin(user: UserAccount[Any]) -> UserAccount[Any]:
    if "admin" not in roles_for(user):
        raise PermissionDeniedError(detail="Administrator access required.")
    return user


@dataclass(frozen=True)
class PermissionGuards:
    """Permission-guard factories bound to one composition root's current user."""

    require_permission: Callable[..., Callable[..., Awaitable[UserAccount[Any]]]]
    require_role: Callable[..., Callable[..., Awaitable[UserAccount[Any]]]]
    require_admin: Callable[[], Callable[..., Awaitable[UserAccount[Any]]]]


def make_permission_guards(
    current_active_user: Callable[..., Awaitable[UserAccount[Any]]],
) -> PermissionGuards:
    """Bind the guard factories to a composition root's active-current-user dep.

    Usage::

        guards = make_permission_guards(auth.get_current_active_user)
        @router.get("/admin", dependencies=[Depends(guards.require_admin())])
    """

    def require_permission(*required: Permission) -> Callable[..., Awaitable[UserAccount[Any]]]:
        async def _guard(
            user: Annotated[UserAccount[Any], Depends(current_active_user)],
        ) -> UserAccount[Any]:
            return await _ensure_permissions(user, frozenset(required))

        return _guard

    def require_role(role: str) -> Callable[..., Awaitable[UserAccount[Any]]]:
        async def _guard(
            user: Annotated[UserAccount[Any], Depends(current_active_user)],
        ) -> UserAccount[Any]:
            return await _ensure_role(user, role)

        return _guard

    def require_admin() -> Callable[..., Awaitable[UserAccount[Any]]]:
        async def _guard(
            user: Annotated[UserAccount[Any], Depends(current_active_user)],
        ) -> UserAccount[Any]:
            return await _ensure_admin(user)

        return _guard

    return PermissionGuards(
        require_permission=require_permission,
        require_role=require_role,
        require_admin=require_admin,
    )


__all__ = [
    "Permission",
    "PermissionGuards",
    "ROLE_PERMISSIONS",
    "make_permission_guards",
    "permissions_for",
    "roles_for",
]
