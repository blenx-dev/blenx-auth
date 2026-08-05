"""SQLAlchemy-backed auth example.

Wires the ``blenx_auth`` SQLAlchemy repositories to a real database session.
Requires a running Postgres database; set ``DATABASE_URL`` accordingly.
"""

from __future__ import annotations

from blenx_auth.core.email import NullEmailSender
from blenx_auth.core.jwt import TokenService
from blenx_auth.core.services import AuthenticationService, EmailVerificationService
from blenx_auth.core.settings import AuthSettings
from blenx_auth.sqlalchemy import (
    AuthBase,
    SQLAlchemyOAuthAccountRepository,
    SQLAlchemyRefreshTokenRepository,
    SQLAlchemyUserRepository,
    create_session_factory,
)

DATABASE_URL = "postgresql+asyncpg://postgres:postgres@localhost:5432/styleos"


async def main() -> None:
    settings = AuthSettings(
        secret_key="dev-secret-key-0123456789abcdef0123456789abcdef",
        frontend_url="http://localhost:5173",
        backend_url="http://localhost:8000",
    )
    session_factory = create_session_factory(DATABASE_URL)

    async with session_factory() as session:  # type: ignore[attr-defined]
        # Create tables for demo purposes
        engine = session.bind
        async with engine.begin() as conn:
            await conn.run_sync(AuthBase.metadata.create_all)

        tokens = TokenService(settings)
        auth = AuthenticationService(
            users=SQLAlchemyUserRepository(session),
            refresh_tokens=SQLAlchemyRefreshTokenRepository(session),
            oauth_accounts=SQLAlchemyOAuthAccountRepository(session),
            tokens=tokens,
            email_sender=NullEmailSender(),
            verification=EmailVerificationService(
                users=SQLAlchemyUserRepository(session),
                tokens=tokens,
                email_sender=NullEmailSender(),
                settings=settings,
            ),
            settings=settings,
        )

        user = await auth.register(email="ann@example.com", password="password-123")
        print(f"Registered {user.email}")


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())
