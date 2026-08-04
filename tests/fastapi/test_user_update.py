"""HTTP tests for the user-update routes (Task 7).

The update routes bind ``UserService.update`` (``exclude_unset=True``) to the
composed ``UserUpdate`` / ``UserAdminUpdate`` schemas, so these tests prove:
partial payloads don't wipe untouched fields, undeclared fields are rejected
(``extra="forbid"``), the admin path is superuser-gated, and a missing user
surfaces as 404.

The composition root is built with consumer table/read/update mixins declaring
``nickname`` and ``phone``; ``get_current_user`` / ``get_current_superuser`` /
``get_user_service`` are overridden with in-memory fakes.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from blenx_auth.core.exceptions import AuthError
from blenx_auth.core.plugins.hooks import AuthHooks
from blenx_auth.core.services import UserService
from blenx_auth.core.settings import AuthSettings
from blenx_auth.fastapi.composition import SQLAlchemyAuth
from blenx_auth.fastapi.exception_handlers import auth_error_handler
from blenx_auth.fastapi.routers import make_auth_router, make_users_router
from pydantic import BaseModel
from tests.fakes import FakeUser, FakeUsers

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import String
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import Mapped, mapped_column


class Settings(AuthSettings):
    secret_key = "x" * 32
    jwt_algorithm = "HS256"
    access_token_expire_minutes = 30
    refresh_token_expire_days = 30
    email_verification_token_expire_minutes = 1440
    password_reset_token_expire_minutes = 60
    max_failed_login_attempts = 3
    account_lockout_minutes = 15
    login_rate_limit_per_minute = 0
    frontend_url = "http://localhost:5173"
    backend_url = "http://localhost:8000"
    google_client_id = ""
    google_client_secret = ""


class ParsingFakeUsers(FakeUsers):
    """Like ``FakeUsers`` but converts URL-path string ids to UUIDs.

    The real repository converts path ids through ``parse_subject``; the
    plain fake compares ``uuid == str`` and misses every match.
    """

    async def get_by_id(self, user_id: Any) -> FakeUser | None:
        if isinstance(user_id, str):
            user_id = uuid.UUID(user_id)
        return await super().get_by_id(user_id)


class ProfileTableMixin:
    nickname: Mapped[str | None] = mapped_column(String(80), nullable=True)
    phone: Mapped[str | None] = mapped_column(String(30), nullable=True)


class ProfileReadMixin(BaseModel):
    nickname: str | None = None
    phone: str | None = None


class ProfileUpdateMixin(BaseModel):
    nickname: str | None = None


@pytest.fixture
def app() -> tuple[FastAPI, FakeUsers]:
    auth = SQLAlchemyAuth(
        settings=Settings(),
        session_factory=async_sessionmaker(class_=AsyncSession),  # unused here
        consumer_table_mixin=ProfileTableMixin,
        consumer_read_mixin=ProfileReadMixin,
        consumer_update_mixin=ProfileUpdateMixin,
    )
    users = ParsingFakeUsers()

    async def get_user_service() -> UserService[uuid.UUID]:
        return UserService(repo=users, hooks=AuthHooks(), model=auth.User)

    async def current_user() -> FakeUser:
        return users.rows["me@example.com"]

    async def current_superuser() -> FakeUser:
        user = users.rows["me@example.com"]
        if not user.is_superuser:
            from blenx_auth.core.exceptions import PermissionDeniedError

            raise PermissionDeniedError()
        return user

    app = FastAPI()
    app.add_exception_handler(AuthError, auth_error_handler)
    app.include_router(make_auth_router(auth))
    app.include_router(make_users_router(auth))

    app.dependency_overrides[auth.get_user_service] = get_user_service
    app.dependency_overrides[auth.get_current_user] = current_user
    app.dependency_overrides[auth.get_current_superuser] = current_superuser
    return app, users


def _seed(users: FakeUsers, **overrides: Any) -> FakeUser:
    user = FakeUser(
        email="me@example.com",
        hashed_password="hash",
        **overrides,
    )
    user.phone = "555-0100"
    users.rows["me@example.com"] = user
    return user


def test_patch_me_leaves_untouched_fields_alone(app: tuple[FastAPI, FakeUsers]) -> None:
    fastapi_app, users = app
    _seed(users)
    client = TestClient(fastapi_app)

    r = client.patch("/users/me", json={"nickname": "bob"})
    assert r.status_code == 200
    assert r.json()["nickname"] == "bob"
    assert users.rows["me@example.com"].phone == "555-0100"  # untouched by exclude_unset


def test_patch_me_rejects_undeclared_field(app: tuple[FastAPI, FakeUsers]) -> None:
    fastapi_app, users = app
    _seed(users)
    client = TestClient(fastapi_app)

    r = client.patch("/users/me", json={"is_active": False})
    assert r.status_code == 422


def test_admin_patch_requires_superuser(app: tuple[FastAPI, FakeUsers]) -> None:
    fastapi_app, users = app
    _seed(users, is_superuser=False)
    client = TestClient(fastapi_app)

    r = client.patch("/users/11111111-1111-1111-1111-111111111111", json={"is_active": False})
    assert r.status_code == 403


def test_admin_patch_as_superuser_updates_field(app: tuple[FastAPI, FakeUsers]) -> None:
    fastapi_app, users = app
    user = _seed(users, is_superuser=True)
    client = TestClient(fastapi_app)

    r = client.patch(f"/users/{user.id}", json={"is_active": False})
    assert r.status_code == 200
    assert users.rows["me@example.com"].is_active is False


def test_admin_get_user(app: tuple[FastAPI, FakeUsers]) -> None:
    fastapi_app, users = app
    user = _seed(users, is_superuser=True)
    client = TestClient(fastapi_app)

    r = client.get(f"/users/{user.id}")
    assert r.status_code == 200
    assert r.json()["email"] == "me@example.com"
    assert r.json()["phone"] == "555-0100"


def test_admin_patch_unknown_user_404(app: tuple[FastAPI, FakeUsers]) -> None:
    fastapi_app, users = app
    _seed(users, is_superuser=True)
    client = TestClient(fastapi_app)

    r = client.patch("/users/22222222-2222-2222-2222-222222222222", json={"is_active": False})
    assert r.status_code == 404
