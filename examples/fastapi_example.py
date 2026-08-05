"""FastAPI auth example — SQLAlchemy + Beanie backends.

Two self-contained composition roots are demonstrated side by side:

- ``create_app`` — ``SQLAlchemyAuth`` on an in-memory SQLite database, ready to
  run out of the box; swap the engine for Postgres for real deployments.
- ``create_beanie_app`` — ``BeanieAuth`` on MongoDB; requires a running MongoDB
  (start one with ``docker run -p 27017:27017 mongo`` or ``podman run ...``).

    pip install -e ".[fastapi,beanie]"
    python examples/fastapi_example.py
"""

# NOTE: no ``from __future__ import annotations`` here. FastAPI evaluates
# dependency signatures with inspect.signature(..., eval_str=True); a string
# annotation that references the ``auth`` closure (Depends(auth...)) cannot be
# resolved and the guard silently degrades to a query parameter. The library's
# own routers omit it for the same reason.

from blenx_auth.plugins.two_factor import OtpRepository
from blenx_auth.plugins.two_factor import make_two_factor_plugin
from contextlib import asynccontextmanager
from typing import Annotated

from blenx_auth.core.exceptions import AuthError
from blenx_auth.core.ports import UserAccount
from blenx_auth.core.settings import AuthSettings
from blenx_auth.fastapi import auth_error_handler
from blenx_auth.fastapi.sqlalchemy import SQLAlchemyAuth
from blenx_auth.sqlalchemy.base import AuthBase
from blenx_auth.plugins.birthday import make_birthday_plugin
from fastapi import Depends, FastAPI
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool


class PyOtpRepository(OtpRepository):
    """Code verification for one user; raises on a bad/missing code."""

    async def verify_code(self, user_id: str, code: str) -> None:
        raise AuthError()


def create_app() -> FastAPI:
    """Build the app: one composition root bound to an in-memory SQLite DB."""
    engine = create_async_engine(
        "postgresql+asyncpg://postgres:postgres@localhost:5432/app",
        poolclass=StaticPool,  # share the one in-memory database across sessions
        connect_args={"check_same_thread": False},
    )
    session_factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        async with engine.begin() as conn:
            await conn.run_sync(AuthBase.metadata.create_all)
        yield
        await engine.dispose()

    # The composition root wires the SQLAlchemy repositories to the core
    # services and exposes every FastAPI dependency (service getters plus the
    # current-user guards) bound to its session factory.
    auth = SQLAlchemyAuth(settings=AuthSettings(
        secret_key="dev-secret-key-0123456789abcdef0123456789abcdef",
        frontend_url="http://localhost:5173",
        backend_url="http://localhost:8000",
    ), session_factory=session_factory,
    plugins=[make_two_factor_plugin(otp_repo=PyOtpRepository()),make_birthday_plugin()])

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


def demo() -> None:
    """Exercise register/login/me over HTTP against the app."""
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        r = client.post(
            "/auth/register",
            json={
                "email": "ann@example.com",
                "password": "password-123",
                "display_name": "user 123",
            },
        )
        print(r)
        print(r.json())
        print(f"register: {r.status_code} {r.json()['email']}")

        r = client.post(
            "/auth/login",
            json={"email": "ann@example.com", "password": "password-123"},
        )
        access_token = r.json()["access_token"]
        print(f"login:    {r.status_code}")

        r = client.get("/me", headers={"Authorization": f"Bearer {access_token}"})
        print(f"me:       {r.status_code} {r.json()['email']}")


if __name__ == "__main__":
    demo()
    import uvicorn

    uvicorn.run(app, port=8001)
