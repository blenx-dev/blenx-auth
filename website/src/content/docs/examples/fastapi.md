---
title: FastAPI example
description: Wire blenx-auth into a FastAPI app with the SQLAlchemy composition root.
---

FastAPI example — a complete, self-contained app wired to the `SQLAlchemyAuth`
composition root. It runs against an in-memory SQLite database so it works out
of the box; swap the engine for Postgres to use it in real deployments.

```bash
python -m pip install -e ".[fastapi]"
python examples/fastapi_example.py
```

The composition root wires the SQLAlchemy repositories to the core services and
exposes every FastAPI dependency — the service getters plus the current-user
guards — bound to your session factory. The routers are already built for you:

```python
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI

from blenx_auth.core.exceptions import AuthError
from blenx_auth.core.ports import UserAccount
from blenx_auth.core.settings import AuthSettings
from blenx_auth.fastapi import SQLAlchemyAuth, auth_error_handler
from blenx_auth.sqlalchemy.base import AuthBase
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import StaticPool


class Settings(AuthSettings):
    secret_key = "dev-only-secret-key-change-me-1234567890"
    jwt_algorithm = "HS256"
    access_token_expire_minutes = 30
    refresh_token_expire_days = 30
    email_verification_token_expire_minutes = 1440
    password_reset_token_expire_minutes = 60
    max_failed_login_attempts = 5
    account_lockout_minutes = 15
    login_rate_limit_per_minute = 0
    frontend_url = "http://localhost:5173"
    backend_url = "http://localhost:8000"
    google_client_id = ""
    google_client_secret = ""


def create_app() -> FastAPI:
    """Build the app: one composition root bound to an in-memory SQLite DB."""
    engine = create_async_engine(
        "sqlite+aiosqlite://",
        poolclass=StaticPool,  # share the one in-memory database across sessions
        connect_args={"check_same_thread": False},
    )
    session_factory = async_sessionmaker(
        bind=engine, class_=AsyncSession, expire_on_commit=False
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        async with engine.begin() as conn:
            await conn.run_sync(AuthBase.metadata.create_all)
        yield
        await engine.dispose()

    # The composition root wires the SQLAlchemy repositories to the core
    # services and exposes every FastAPI dependency (service getters plus the
    # current-user guards) bound to its session factory.
    auth = SQLAlchemyAuth(settings=Settings(), session_factory=session_factory)

    app = FastAPI(lifespan=lifespan)
    app.add_exception_handler(AuthError, auth_error_handler)
    for router in auth.routers:
        app.include_router(router)

    @app.get("/me", response_model=auth.UserRead, summary="Current user (protected)")
    async def current_user(
        user: Annotated[UserAccount, Depends(auth.get_current_active_user)],
    ) -> UserAccount:
        """A custom protected endpoint using the root's user guard."""
        return user

    return app


app = create_app()
```

## What you get for free

`auth.routers` already contains the `/auth` and `/users` routers:

| Method | Path | Notes |
| --- | --- | --- |
| `POST` | `/auth/register` | Creates an account and mails a verification link |
| `POST` | `/auth/login` | Returns an access + refresh pair (or a `challenge`) |
| `POST` | `/auth/refresh` | Rotates a refresh token into a fresh pair |
| `POST` | `/auth/logout` | Revokes a refresh token |
| `POST` | `/auth/logout-all` | Revokes every session for the current user |
| `POST` | `/auth/verify` | Consumes an email-verification token |
| `POST` | `/auth/resend-verification` | Mails a fresh verification link |
| `POST` | `/auth/forgot-password` | Mails a password-reset link |
| `POST` | `/auth/reset-password` | Sets a new password |
| `GET` | `/users/me` | Current user's public profile |
| `PATCH` | `/users/me` | Updates self-serviceable fields |
| `GET` | `/users/{id}` | Admin-only user lookup |
| `PATCH` | `/users/{id}` | Admin-only user update |

Custom routes reuse the root's dependency guards — the current-user family
`get_current_user`, `get_current_active_user`, `get_current_verified_user`,
`get_current_superuser` — as in the `/me` endpoint above.

## Gotchas

- **No `from __future__ import annotations` in your module.** FastAPI resolves
  dependency signatures with `inspect.signature(..., eval_str=True)`. A string
  annotation that references the `auth` closure (`Depends(auth...)`) cannot be
  resolved and the guard silently degrades to a query parameter (422). The
  library's own routers omit the future import for the same reason.
- **Use `auth.UserRead` as the response model** for custom endpoints; the
  composed schema serializes the backend's identity type (UUID, ObjectId, ...).
- **Postgres:** replace the in-memory engine with
  `create_async_engine("postgresql+asyncpg://user:pass@host/db")` and drop the
  `StaticPool`/`check_same_thread` kwargs.
- **MongoDB instead?** Use `BeanieAuth` with `init_beanie_db` — same routers,
  same dependencies, no session factory.
