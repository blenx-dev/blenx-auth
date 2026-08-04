---
title: Standalone example
description: Wire up blenx-auth core services to in-memory fakes (no database, no web framework).
---

Minimal standalone auth example (no database, no web framework). Wires the core services
to in-memory fakes so the full auth lifecycle can be exercised from a plain Python script.
This demonstrates that `blenx_auth` services work without FastAPI installed.

```python
"""Minimal standalone auth example (no database, no web framework).

Wires the core services to in-memory fakes so the full auth lifecycle can be
exercised from a plain Python script. This demonstrates that ``blenx_auth``
services work without FastAPI installed.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace

from blenx_auth.core.jwt import TokenService
from blenx_auth.core.services import (
    AuthenticationService,
    EmailVerificationService,
)
from blenx_auth.core.settings import AuthSettings

# --- in-memory fakes (mirror tests/fakes.py) ------------------------------


class FakeUser:
    def __init__(self, email: str, hashed_password: str) -> None:
        self.email = email
        self.hashed_password = hashed_password
        self.is_verified = False
        self.is_active = True
        self.id = id(self)
        self.is_superuser = False


class FakeUsers:
    def __init__(self) -> None:
        self.rows: dict[str, FakeUser] = {}

    async def get_by_email(self, email: str):
        return self.rows.get(email.lower())

    async def get_by_id(self, user_id):
        return next((u for u in self.rows.values() if u.id == user_id), None)

    async def create(self, data):
        user = FakeUser(data.email, data.hashed_password)
        self.rows[user.email] = user
        return user

    async def save(self, user) -> None:
        self.rows[user.email] = user


class FakeRefreshTokens:
    def __init__(self) -> None:
        self.rows: dict[str, SimpleNamespace] = {}

    async def create(self, *, user_id, token_hash, expires_at, **kwargs):
        row = SimpleNamespace(
            id=uuid.uuid4(),
            user_id=user_id,
            token_hash=token_hash,
            expires_at=expires_at,
            revoked_at=None,
        )
        self.rows[token_hash] = row
        return row

    async def get_by_hash(self, token_hash):
        return self.rows.get(token_hash)

    async def revoke(self, token_id) -> None:
        for row in self.rows.values():
            if row.id == token_id and row.revoked_at is None:
                row.revoked_at = True

    async def revoke_all_for_user(self, user_id) -> None:
        for row in self.rows.values():
            if row.user_id == user_id and row.revoked_at is None:
                row.revoked_at = True


class FakeOAuthAccounts:
    def __init__(self) -> None:
        self.rows: list[SimpleNamespace] = []

    async def get_by_provider_account(self, provider, account_id):
        return next(
            (r for r in self.rows if r.oauth_name == provider and r.account_id == account_id),
            None,
        )

    async def link(self, data):
        row = SimpleNamespace(
            id=id(data),
            user_id=data.user_id,
            oauth_name=data.provider,
            account_id=data.account_id,
            account_email=data.account_email,
        )
        self.rows.append(row)
        return row

    async def refresh_token(self, *args, **kwargs) -> None:
        return None


class FakeEmailSender:
    def __init__(self) -> None:
        self.sent: list[str] = []

    async def send(self, message) -> None:
        self.sent.append(message.body)


# --- settings stub -------------------------------------------------------


def make_settings() -> AuthSettings:
    return SimpleNamespace(
        secret_key="t" * 32,
        jwt_algorithm="HS256",
        access_token_expire_minutes=30,
        refresh_token_expire_days=30,
        email_verification_token_expire_minutes=1440,
        password_reset_token_expire_minutes=60,
        max_failed_login_attempts=5,
        account_lockout_minutes=15,
        login_rate_limit_per_minute=0,
        frontend_url="http://localhost:5173",
        backend_url="http://localhost:8000",
        google_client_id="",
        google_client_secret=SimpleNamespace(get_secret_value=lambda: ""),
    )


async def main() -> None:
    settings = make_settings()
    tokens = TokenService(settings)
    users = FakeUsers()
    refresh_tokens = FakeRefreshTokens()
    oauth_accounts = FakeOAuthAccounts()
    mail = FakeEmailSender()

    auth = AuthenticationService(
        users=users,
        refresh_tokens=refresh_tokens,
        oauth_accounts=oauth_accounts,
        tokens=tokens,
        email_sender=mail,
        verification=EmailVerificationService(
            users=users,
            tokens=tokens,
            email_sender=mail,
            settings=settings,
        ),
        settings=settings,
    )

    print("Registering ann@example.com ...")
    user = await auth.register(email="ann@example.com", password="password-123")
    print(f"  created {user.email}")

    print("Logging in ...")
    pair = await auth.login(email="ann@example.com", password="password-123")
    print(f"  access_token={pair.access_token[:16]}...")

    print("Refreshing ...")
    rotated = await auth.refresh(pair.refresh_token)
    print(f"  new access_token={rotated.access_token[:16]}...")


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())
```
