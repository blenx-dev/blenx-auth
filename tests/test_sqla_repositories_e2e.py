"""E2E coverage for the SQLAlchemy repository flows on a real SQLite engine.

The auth-service tests run against in-memory fakes and the composition tests
override the repositories, so the *storage* paths of the SQLAlchemy repositories
(rebuilt for the plugin work with injectable models) are only partially
exercised elsewhere. This drives them over HTTP (refresh/logout-all/OAuth
callbacks) and directly (duplicate-create race -> domain error).
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import Any

import pytest
from blenx_auth.core.dto import NewUser
from blenx_auth.core.exceptions import AuthError, EmailAlreadyExistsError
from blenx_auth.core.settings import AuthSettings
from blenx_auth.fastapi.composition import SQLAlchemyAuth
from blenx_auth.fastapi.exception_handlers import auth_error_handler
from blenx_auth.fastapi.routers.oauth import make_oauth_router
from blenx_auth.sqlalchemy.base import AuthBase
from blenx_auth.sqlalchemy.repositories import SQLAlchemyUserRepository

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool


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


def _make_app() -> tuple[TestClient, Any, async_sessionmaker[AsyncSession]]:
    engine = create_async_engine(
        "sqlite+aiosqlite://",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    factory = async_sessionmaker(
        bind=engine, class_=AsyncSession, expire_on_commit=False, autoflush=False
    )

    async def _create_tables() -> None:
        async with engine.begin() as conn:
            await conn.run_sync(AuthBase.metadata.create_all)

    asyncio.run(_create_tables())

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        yield
        await engine.dispose()

    auth = SQLAlchemyAuth(settings=Settings(), session_factory=factory)
    oauth_client = FakeOAuthClient()

    async def get_id_email(access_token: str) -> tuple[str, str | None]:
        return "sub-1", "o@example.com"

    app = FastAPI(lifespan=lifespan)
    app.add_exception_handler(AuthError, auth_error_handler)
    for router in auth.routers:
        app.include_router(router)
    app.include_router(
        make_oauth_router(
            auth,
            client=oauth_client,
            get_id_email=get_id_email,
            prefix="/auth/google",
            backend_url=Settings().backend_url,
            frontend_url=Settings().frontend_url,
        )
    )
    return TestClient(app), oauth_client, factory


def test_refresh_logout_oauth_flows() -> None:
    client, oauth_client, _ = _make_app()

    with client:
        r = client.post(
            "/auth/register", json={"email": "a@example.com", "password": "password-123"}
        )
        assert r.status_code == 201
        r = client.post("/auth/login", json={"email": "a@example.com", "password": "password-123"})
        refresh = r.json()["refresh_token"]
        access = r.json()["access_token"]

        # refresh -> get_by_hash + revoke on the SQLAlchemy refresh repo
        r = client.post("/auth/refresh", json={"refresh_token": refresh})
        assert r.status_code == 200

        # logout-all -> revoke_all_for_user
        r = client.post("/auth/logout-all", headers={"Authorization": f"Bearer {access}"})
        assert r.status_code == 204

        # first OAuth callback links (insert); second reuses (get_by_provider_account)
        r = client.get("/auth/google/authorize", follow_redirects=False)
        assert r.status_code == 307
        state = oauth_client.state
        r = client.get(f"/auth/google/callback?code=abc&state={state}", follow_redirects=False)
        assert r.status_code == 307
        r = client.get(f"/auth/google/callback?code=abc&state={state}", follow_redirects=False)
        assert r.status_code == 307


def test_duplicate_create_raises_domain_error() -> None:
    _, _, factory = _make_app()
    auth = SQLAlchemyAuth(settings=Settings(), session_factory=factory)

    async def _run() -> None:
        async with factory() as session:
            repo = SQLAlchemyUserRepository(session, model=auth.User)
            await repo.create(NewUser(email="dup@example.com", hashed_password="h"))
            with pytest.raises(EmailAlreadyExistsError):
                await repo.create(NewUser(email="dup@example.com", hashed_password="h"))

    asyncio.run(_run())
