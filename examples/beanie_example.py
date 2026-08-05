"""Beanie (MongoDB) example — same auth services on MongoDB.

Run with the ``beanie`` extra installed and a running MongoDB:

    python -m pip install -e "libs/blenx-auth[beanie]"
    python examples/beanie_example.py

This wires the Beanie repositories (instead of the SQLAlchemy ones) behind the
same services and settings, demonstrating that the core is storage-agnostic.
"""

from __future__ import annotations
from blenx_auth.core import AuthSettings

import asyncio
from blenx_auth.beanie import (
    BeanieOAuthAccountRepository,
    BeanieRefreshTokenRepository,
    BeanieUserRepository,
    init_beanie_db,
)
from blenx_auth.core.email import NullEmailSender
from blenx_auth.core.jwt import TokenService
from blenx_auth.core.services import (
    AuthenticationService,
    EmailVerificationService,
)
from motor.motor_asyncio import AsyncIOMotorClient

DB_URL = "mongodb://localhost:27017"


def _settings() -> AuthSettings:
    return AuthSettings(
        secret_key="dev-secret-key-0123456789abcdef0123456789abcdef",
        frontend_url="http://localhost:5173",
        backend_url="http://localhost:8000",
    )


async def main() -> None:
    client = AsyncIOMotorClient(DB_URL)
    await init_beanie_db(database=client.auth_example)

    settings = _settings()
    tokens = TokenService(settings)
    users = BeanieUserRepository()
    refresh_tokens = BeanieRefreshTokenRepository()
    oauth_accounts = BeanieOAuthAccountRepository()
    email_sender = NullEmailSender()

    verification = EmailVerificationService(
        users=users, tokens=tokens, email_sender=email_sender, settings=settings
    )
    auth = AuthenticationService(
        users=users,
        refresh_tokens=refresh_tokens,
        oauth_accounts=oauth_accounts,
        tokens=tokens,
        email_sender=email_sender,
        verification=verification,
        settings=settings,
    )

    await auth.register(email="ann@example.com", password="password-123")
    result = await auth.login(email="ann@example.com", password="password-123")
    if result.kind == "challenge":
        print("login ok, challenge required:", result.flow)
    else:
        print("login ok, access token:", result.access_token[:20], "...")


if __name__ == "__main__":
    asyncio.run(main())
