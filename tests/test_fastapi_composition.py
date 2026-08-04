"""HTTP-level tests for the composition-root fastapi layer.

These build a real ``FastAPI`` app from :func:`make_auth_router` /
:func:`make_users_router` bound to a ``SQLAlchemyAuth`` composition root, and
override the root's service dependencies with in-memory fakes, so every route,
the ``AuthError`` handler, and the response models are exercised over the ASGI
transport without touching a database.

The overrides target ``auth.get_*`` (plain callables on the root), which is the
documented seam for swapping storage: FastAPI's ``dependency_overrides`` match
sub-dependencies too, so ``get_current_user`` keeps resolving the overridden
auth service.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from blenx_auth.core.exceptions import AuthError
from blenx_auth.core.jwt import TokenService
from blenx_auth.core.services import (
    AuthenticationService,
    EmailVerificationService,
    PasswordResetService,
)
from blenx_auth.core.settings import AuthSettings
from blenx_auth.fastapi.composition import SQLAlchemyAuth
from blenx_auth.fastapi.exception_handlers import auth_error_handler
from blenx_auth.fastapi.routers import make_auth_router, make_users_router
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from fastapi import FastAPI
from tests.fakes import FakeEmailSender, FakeOAuthAccounts, FakeRefreshTokens, FakeUsers


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


@pytest.fixture
def api() -> tuple[TestClient, FakeUsers, FakeRefreshTokens, FakeEmailSender]:
    settings = Settings()
    auth = SQLAlchemyAuth(
        settings=settings,
        session_factory=async_sessionmaker(class_=AsyncSession),  # unused here
    )

    users = FakeUsers()
    refresh_tokens = FakeRefreshTokens()
    oauth_accounts = FakeOAuthAccounts()
    mail = FakeEmailSender()
    tokens = TokenService(settings)

    def build_authentication() -> AuthenticationService[uuid.UUID]:
        verification = EmailVerificationService(
            users=users, tokens=tokens, email_sender=mail, settings=settings
        )
        return AuthenticationService(
            users=users,
            refresh_tokens=refresh_tokens,
            oauth_accounts=oauth_accounts,
            tokens=tokens,
            email_sender=mail,
            verification=verification,
            settings=settings,
        )

    def build_verification() -> EmailVerificationService[uuid.UUID]:
        return EmailVerificationService(
            users=users, tokens=tokens, email_sender=mail, settings=settings
        )

    def build_password_reset() -> PasswordResetService[uuid.UUID]:
        return PasswordResetService(
            users=users,
            refresh_tokens=refresh_tokens,
            tokens=tokens,
            email_sender=mail,
            settings=settings,
        )

    app = FastAPI()
    app.add_exception_handler(AuthError, auth_error_handler)
    app.include_router(make_auth_router(auth))
    app.include_router(make_users_router(auth))

    app.dependency_overrides[auth.get_authentication_service] = build_authentication
    app.dependency_overrides[auth.get_verification_service] = build_verification
    app.dependency_overrides[auth.get_password_reset_service] = build_password_reset

    return TestClient(app), users, refresh_tokens, mail


def test_register_login_me_flow(
    api: tuple[TestClient, FakeUsers, FakeRefreshTokens, FakeEmailSender],
) -> None:
    client, _, _, mail = api
    r = client.post("/auth/register", json={"email": "Ann@Example.com", "password": "password-123"})
    assert r.status_code == 201
    assert r.json()["email"] == "ann@example.com"
    assert r.json()["is_verified"] is False
    assert any("verify-email" in m.body for m in mail.sent)

    r = client.post("/auth/register", json={"email": "ann@example.com", "password": "password-123"})
    assert r.status_code == 409
    r = client.post("/auth/register", json={"email": "x@y.z", "password": "short"})
    assert r.status_code == 422

    r = client.post("/auth/login", json={"email": "ann@example.com", "password": "password-123"})
    assert r.status_code == 200
    body = r.json()
    assert body["token_type"] == "bearer"
    assert body["expires_in"] == 1800
    access = body["access_token"]

    r = client.get("/users/me", headers={"Authorization": f"Bearer {access}"})
    assert r.status_code == 200
    assert r.json()["email"] == "ann@example.com"

    r = client.get("/users/me")
    assert r.status_code == 401
    assert r.headers.get("www-authenticate") == "Bearer"
    r = client.get("/users/me", headers={"Authorization": "Bearer garbage"})
    assert r.status_code == 401


def test_verify_refresh_logout_flow(
    api: tuple[TestClient, FakeUsers, FakeRefreshTokens, FakeEmailSender],
) -> None:
    client, _, refresh_tokens, mail = api
    client.post("/auth/register", json={"email": "a@example.com", "password": "password-123"})
    r = client.post("/auth/login", json={"email": "a@example.com", "password": "password-123"})
    refresh = r.json()["refresh_token"]

    verify_token = next(m.body.split("token=")[1] for m in mail.sent if "verify-email" in m.body)
    r = client.post("/auth/verify", json={"token": verify_token})
    assert r.status_code == 204
    r = client.post("/auth/verify", json={"token": verify_token})
    assert r.status_code == 204

    r = client.post("/auth/refresh", json={"refresh_token": refresh})
    assert r.status_code == 200
    new_refresh = r.json()["refresh_token"]
    r = client.post("/auth/refresh", json={"refresh_token": refresh})
    assert r.status_code == 401

    r = client.post("/auth/logout", json={"refresh_token": new_refresh})
    assert r.status_code == 204
    r = client.post("/auth/logout", json={"refresh_token": new_refresh})
    assert r.status_code == 204
    assert all(row.revoked_at is not None for row in refresh_tokens.rows.values())


def test_logout_all_and_resend_verification(
    api: tuple[TestClient, FakeUsers, FakeRefreshTokens, FakeEmailSender],
) -> None:
    client, _, refresh_tokens, mail = api
    client.post("/auth/register", json={"email": "a@example.com", "password": "password-123"})
    r = client.post("/auth/login", json={"email": "a@example.com", "password": "password-123"})
    access = r.json()["access_token"]
    headers = {"Authorization": f"Bearer {access}"}

    r = client.post("/auth/resend-verification", headers=headers)
    assert r.status_code == 204
    assert any("verify-email" in m.body for m in mail.sent)

    r = client.post("/auth/logout-all", headers=headers)
    assert r.status_code == 204
    assert all(row.revoked_at is not None for row in refresh_tokens.rows.values())


def test_password_reset_flow(
    api: tuple[TestClient, FakeUsers, FakeRefreshTokens, FakeEmailSender],
) -> None:
    client, _, _, mail = api
    client.post("/auth/register", json={"email": "a@example.com", "password": "password-123"})
    r = client.post("/auth/forgot-password", json={"email": "ghost@example.com"})
    assert r.status_code == 204
    r = client.post("/auth/forgot-password", json={"email": "a@example.com"})
    assert r.status_code == 204
    reset_token = next(m.body.split("token=")[1] for m in mail.sent if "reset-password" in m.body)
    r = client.post(
        "/auth/reset-password", json={"token": reset_token, "new_password": "brand-new-99"}
    )
    assert r.status_code == 204
    r = client.post("/auth/login", json={"email": "a@example.com", "password": "password-123"})
    assert r.status_code == 401
    r = client.post("/auth/login", json={"email": "a@example.com", "password": "brand-new-99"})
    assert r.status_code == 200


def test_lockout_over_http(
    api: tuple[TestClient, FakeUsers, FakeRefreshTokens, FakeEmailSender],
) -> None:
    client, _, _, _ = api
    client.post("/auth/register", json={"email": "a@example.com", "password": "password-123"})
    for _ in range(2):
        r = client.post("/auth/login", json={"email": "a@example.com", "password": "wrong"})
        assert r.status_code == 401
    r = client.post("/auth/login", json={"email": "a@example.com", "password": "wrong"})
    assert r.status_code == 403
    assert r.headers.get("retry-after") == "900"
    r = client.post("/auth/login", json={"email": "a@example.com", "password": "password-123"})
    assert r.status_code == 403


class FakeOAuthClient:
    name = "google"
    base_scopes: list[str] | None = ["openid"]

    async def get_authorization_url(
        self,
        redirect_uri: str,
        state: str | None = None,
        scope: list[str] | None = None,
        **kwargs: Any,
    ) -> str:
        self.state = state
        return "https://provider.example/consent"

    async def get_access_token(self, code: str, redirect_uri: str, **kwargs: Any) -> dict[str, Any]:
        return {"access_token": "provider-at", "expires_at": 1_600_000_000, "refresh_token": "prt"}


def test_oauth_router_round_trip(
    api: tuple[TestClient, FakeUsers, FakeRefreshTokens, FakeEmailSender],
) -> None:
    from blenx_auth.core.services import AuthenticationService
    from blenx_auth.fastapi.routers.oauth import make_oauth_router

    settings = Settings()
    users = FakeUsers()
    refresh_tokens = FakeRefreshTokens()
    oauth_accounts = FakeOAuthAccounts()
    mail = FakeEmailSender()
    tokens = TokenService(settings)

    async def build_authentication() -> AuthenticationService[uuid.UUID]:
        verification = EmailVerificationService(
            users=users, tokens=tokens, email_sender=mail, settings=settings
        )
        return AuthenticationService(
            users=users,
            refresh_tokens=refresh_tokens,
            oauth_accounts=oauth_accounts,
            tokens=tokens,
            email_sender=mail,
            verification=verification,
            settings=settings,
        )

    async def get_id_email(access_token: str) -> tuple[str, str | None]:
        return "sub-1", "o@example.com"

    auth = SQLAlchemyAuth(
        settings=settings,
        session_factory=async_sessionmaker(class_=AsyncSession),  # unused here
    )
    app = FastAPI()
    app.add_exception_handler(AuthError, auth_error_handler)
    client = FakeOAuthClient()
    app.include_router(
        make_oauth_router(
            auth,
            client=client,
            get_id_email=get_id_email,
            prefix="/auth/google",
            backend_url=settings.backend_url,
            frontend_url=settings.frontend_url,
        )
    )
    app.dependency_overrides[auth.get_authentication_service] = build_authentication

    test_client = TestClient(app, follow_redirects=False)
    r = test_client.get("/auth/google/authorize")
    assert r.status_code == 307
    assert r.headers["location"].startswith("https://provider.example/consent")

    r = test_client.get("/auth/google/callback?code=abc")
    assert r.status_code == 401  # missing state is rejected before any exchange

    r = test_client.get(f"/auth/google/callback?code=abc&state={client.state}")
    assert r.status_code == 307
    assert "oauth-callback?access_token=" in r.headers["location"]
