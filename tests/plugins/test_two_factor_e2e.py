"""End-to-end test: two-factor plugin on a real SQLite engine over HTTP.

This is the final proof that Tasks 1–9 compose: the plugin's table/read/create
mixins land on ``User`` and the schemas, the contract check passes at root
construction, ``/auth/login`` downgrades to a challenge for 2FA users, and
``/2fa/verify`` completes the login — plus a non-enrolled user logs in with a
plain token.
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from blenx_auth.core.exceptions import AuthError, InvalidChallengeError
from blenx_auth.core.settings import AuthSettings
from blenx_auth.fastapi.composition import SQLAlchemyAuth
from blenx_auth.fastapi.exception_handlers import auth_error_handler
from blenx_auth.plugins.two_factor import make_two_factor_plugin
from blenx_auth.sqlalchemy.base import AuthBase
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from fastapi import FastAPI


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


class FakeOtpRepo:
    """A code is "correct" iff it equals ``123456`` (any user)."""

    async def verify_code(self, user_id: str, code: str) -> None:
        if code != "123456":
            raise InvalidChallengeError()


def test_two_factor_end_to_end() -> None:
    engine = create_async_engine(
        "sqlite+aiosqlite://",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    factory = async_sessionmaker(
        bind=engine, class_=AsyncSession, expire_on_commit=False, autoflush=False
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        async with engine.begin() as conn:
            await conn.run_sync(AuthBase.metadata.create_all)
        yield
        await engine.dispose()

    auth = SQLAlchemyAuth(
        settings=Settings(),
        session_factory=factory,
        plugins=[make_two_factor_plugin(otp_repo=FakeOtpRepo())],
    )

    # (7) composed columns exist and the app booted without contract errors
    assert "is_2fa_enabled" in auth.User.__table__.columns
    assert "two_factor_type" in auth.User.__table__.columns

    app = FastAPI(lifespan=lifespan)
    app.add_exception_handler(AuthError, auth_error_handler)
    for router in auth.routers:
        app.include_router(router)

    with TestClient(app) as client:
        # (2) register a 2FA-enabled user (the create mixin makes it a typed field)
        r = client.post(
            "/auth/register",
            json={"email": "ann@example.com", "password": "password-123", "is_2fa_enabled": True},
        )
        assert r.status_code == 201
        assert r.json()["is_2fa_enabled"] is True

        # (3) correct credentials -> challenge, not tokens
        r = client.post(
            "/auth/login",
            json={"email": "ann@example.com", "password": "password-123"},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["kind"] == "challenge"
        assert body["flow"] == "otp"
        challenge_token = body["challenge_token"]

        # (4) correct code -> tokens; the access token is a real access token
        r = client.post("/2fa/verify", json={"challenge_token": challenge_token, "code": "123456"})
        assert r.status_code == 200
        assert r.json()["kind"] == "token"
        access = r.json()["access_token"]
        r = client.get("/users/me", headers={"Authorization": f"Bearer {access}"})
        assert r.status_code == 200
        assert r.json()["email"] == "ann@example.com"

        # (5) wrong code -> error
        r = client.post(
            "/auth/login",
            json={"email": "ann@example.com", "password": "password-123"},
        )
        challenge_token = r.json()["challenge_token"]
        r = client.post("/2fa/verify", json={"challenge_token": challenge_token, "code": "000000"})
        assert r.status_code == 401

        # (6) a user without 2FA logs straight through with a token
        r = client.post(
            "/auth/register",
            json={"email": "bob@example.com", "password": "password-123"},
        )
        assert r.status_code == 201
        assert r.json()["is_2fa_enabled"] is False
        r = client.post(
            "/auth/login",
            json={"email": "bob@example.com", "password": "password-123"},
        )
        assert r.status_code == 200
        assert r.json()["kind"] == "token"
        assert r.json()["access_token"]
