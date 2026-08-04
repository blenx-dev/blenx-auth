"""In-memory fakes for auth tests (no database required).

Each fake satisfies the corresponding ``Protocol`` from ``blenx_auth.core.ports``, so
services and the HTTP layer can be exercised end-to-end without Postgres. State
persists for the lifetime of the fake instance, mimicking a request-scoped
session that lives for the duration of a test.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from types import SimpleNamespace

from blenx_auth.core.dto import EmailMessage, NewOAuthLink, NewUser
from blenx_auth.core.exceptions import EmailAlreadyExistsError


@dataclass
class FakeUser:
    email: str
    hashed_password: str
    is_verified: bool = False
    is_active: bool = True
    id: uuid.UUID = field(default_factory=uuid.uuid4)
    is_superuser: bool = False
    display_name: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    email_verified_at: datetime | None = None
    failed_login_attempts: int = 0
    locked_until: datetime | None = None
    password_reset_token_hash: str | None = None
    password_reset_token_expires_at: datetime | None = None


class FakeUsers:
    def __init__(self) -> None:
        self.rows: dict[str, FakeUser] = {}

    async def get_by_email(self, email: str) -> FakeUser | None:
        return self.rows.get(email.lower())

    async def get_by_id(self, user_id: uuid.UUID) -> FakeUser | None:
        return next((u for u in self.rows.values() if u.id == user_id), None)

    async def create(self, data: NewUser) -> FakeUser:
        user = FakeUser(
            email=data.email,
            hashed_password=data.hashed_password,
            is_verified=data.is_verified,
            display_name=data.display_name,
        )
        for name, value in data.extra_fields.items():
            setattr(user, name, value)
        if user.email in self.rows:
            raise EmailAlreadyExistsError()
        self.rows[user.email] = user
        return user

    async def save(self, user: FakeUser) -> None:
        self.rows[user.email] = user


class FakeRefreshTokens:
    def __init__(self) -> None:
        self.rows: dict[str, SimpleNamespace] = {}

    async def create(
        self,
        *,
        user_id: uuid.UUID,
        token_hash: str,
        expires_at: datetime,
        device_name: str | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> SimpleNamespace:
        row = SimpleNamespace(
            id=uuid.uuid4(),
            user_id=user_id,
            token_hash=token_hash,
            expires_at=expires_at,
            revoked_at=None,
        )
        self.rows[token_hash] = row
        return row

    async def get_by_hash(self, token_hash: str) -> SimpleNamespace | None:
        return self.rows.get(token_hash)

    async def revoke(self, token_id: uuid.UUID) -> None:
        for row in self.rows.values():
            if row.id == token_id and row.revoked_at is None:
                row.revoked_at = datetime.now(UTC)

    async def revoke_all_for_user(self, user_id: uuid.UUID) -> None:
        for row in self.rows.values():
            if row.user_id == user_id and row.revoked_at is None:
                row.revoked_at = datetime.now(UTC)


class FakeOAuthAccounts:
    def __init__(self) -> None:
        self.rows: list[SimpleNamespace] = []

    async def get_by_provider_account(
        self, provider: str, account_id: str
    ) -> SimpleNamespace | None:
        return next(
            (
                row
                for row in self.rows
                if row.oauth_name == provider and row.account_id == account_id
            ),
            None,
        )

    async def link(self, data: NewOAuthLink) -> SimpleNamespace:
        row = SimpleNamespace(
            id=uuid.uuid4(),
            user_id=data.user_id,
            oauth_name=data.provider,
            access_token=data.access_token,
            expires_at=data.expires_at,
            refresh_token=data.refresh_token,
            account_id=data.account_id,
            account_email=data.account_email,
        )
        self.rows.append(row)
        return row

    async def refresh_token(
        self, account_id: uuid.UUID, *, access_token: str, expires_at: int | None
    ) -> None:
        return None


class FakeEmailSender:
    def __init__(self) -> None:
        self.sent: list[EmailMessage] = []

    async def send(self, message: EmailMessage) -> None:
        self.sent.append(message)
