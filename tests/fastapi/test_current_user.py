"""Unit tests for the current-user dependency guards.

The HTTP routes already prove the happy paths; these cover the belt-and-
suspenders branches directly: inactive -> ``InactiveAccountError``,
unverified -> ``UnverifiedAccountError``, non-superuser ->
``PermissionDeniedError``, plus the missing-credentials and resolve paths.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from blenx_auth.core.exceptions import (
    InactiveAccountError,
    InvalidCredentialsError,
    PermissionDeniedError,
    UnverifiedAccountError,
)
from blenx_auth.fastapi.current_user import make_current_user_dependencies
from tests.fakes import FakeUser


async def _auth_service():
    return None


async def _resolve(user: FakeUser | None):
    async def authenticate_access_token(token: str) -> FakeUser | None:
        return user

    return SimpleNamespace(authenticate_access_token=authenticate_access_token)


async def test_missing_credentials_raises() -> None:
    deps = make_current_user_dependencies(_auth_service)
    auth = await _resolve(FakeUser(email="a@example.com", hashed_password="h"))
    with pytest.raises(InvalidCredentialsError):
        await deps.get_current_user(credentials=None, auth_service=auth)


async def test_get_current_user_resolves_bearer_token() -> None:
    deps = make_current_user_dependencies(_auth_service)
    expected = FakeUser(email="a@example.com", hashed_password="h")
    auth = await _resolve(expected)
    user = await deps.get_current_user(
        credentials=SimpleNamespace(credentials="some-token"),
        auth_service=auth,
    )
    assert user is expected


async def test_inactive_user_raises_inactive_account() -> None:
    deps = make_current_user_dependencies(_auth_service)
    inactive = FakeUser(email="a@example.com", hashed_password="h", is_active=False)
    with pytest.raises(InactiveAccountError):
        await deps.get_current_active_user(user=inactive)


async def test_active_user_passes_active_guard() -> None:
    deps = make_current_user_dependencies(_auth_service)
    active = FakeUser(email="a@example.com", hashed_password="h")
    assert await deps.get_current_active_user(user=active) is active


async def test_unverified_user_raises_unverified_account() -> None:
    deps = make_current_user_dependencies(_auth_service)
    unverified = FakeUser(email="a@example.com", hashed_password="h", is_verified=False)
    with pytest.raises(UnverifiedAccountError):
        await deps.get_current_verified_user(user=unverified)


async def test_verified_user_passes_verified_guard() -> None:
    deps = make_current_user_dependencies(_auth_service)
    verified = FakeUser(email="a@example.com", hashed_password="h", is_verified=True)
    assert await deps.get_current_verified_user(user=verified) is verified


async def test_non_superuser_raises_permission_denied() -> None:
    deps = make_current_user_dependencies(_auth_service)
    customer = FakeUser(email="a@example.com", hashed_password="h", is_superuser=False)
    with pytest.raises(PermissionDeniedError):
        await deps.get_current_superuser(user=customer)


async def test_superuser_passes_superuser_guard() -> None:
    deps = make_current_user_dependencies(_auth_service)
    admin = FakeUser(email="a@example.com", hashed_password="h", is_superuser=True)
    assert await deps.get_current_superuser(user=admin) is admin
