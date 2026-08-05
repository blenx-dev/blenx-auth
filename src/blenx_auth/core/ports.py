"""Ports (driven-interface contracts) for the auth module.

Services depend on these interfaces rather than on concrete SQLAlchemy models
or repository classes. Consequences:

- ``AuthenticationService`` and friends are unit-testable with plain dataclass
  fakes.
- Replacing the persistence layer never touches business logic.
- mypy enforces that the real models/repositories actually satisfy the
  contracts, so "structural" does not mean "unchecked".

Row contracts (``UserAccount``, ``RefreshTokenRow``, ``OAuthAccountRow``)
describe a row as the auth module sees it: every attribute maps 1:1 to a
column/field on the storage model. ``Mapped[...]`` declarations on the ORM
model satisfy these plain-type members because SQLAlchemy unwraps ``Mapped``
at type-check time.

Attributes are declared mutable because services persist changes by mutating
the user row they fetched and then calling ``UserRepository.save``; policy
(what to change) lives in the service, mechanics (how to persist) in the repo.

Repositories are parameterized by ``IdT`` only; the row shapes are the
structural ``UserAccount``/``RefreshTokenRow``/``OAuthAccountRow`` contracts.
"""

from __future__ import annotations

from datetime import  datetime
from typing import Protocol, TypeVar, runtime_checkable

from blenx_auth.core.dto import EmailMessage, IdT, NewOAuthLink, NewUser


class UserAccount(Protocol[IdT]):
    """A user row as the auth module sees it."""

    id: IdT
    email: str
    display_name: str
    hashed_password: str
    is_active: bool
    is_superuser: bool
    is_verified: bool
    created_at: datetime
    email_verified_at: datetime | None
    failed_login_attempts: int
    locked_until: datetime | None
    password_reset_token_hash: str | None
    password_reset_token_expires_at: datetime | None


class RefreshTokenRow(Protocol[IdT]):
    """A row in the ``refresh_tokens`` table."""

    id: IdT
    user_id: IdT
    token_hash: str
    expires_at: datetime
    revoked_at: datetime | None
    created_at: datetime
    device_name: str | None
    ip_address: str | None
    user_agent: str | None


class OAuthAccountRow(Protocol[IdT]):
    """A row in the ``oauth_account`` table."""

    id: IdT
    user_id: IdT
    oauth_name: str
    access_token: str
    expires_at: int | None
    refresh_token: str | None
    account_id: str
    account_email: str


@runtime_checkable
class UserRepository(Protocol[IdT]):
    """Persistence contract for user rows (CRUD only — no policy)."""

    async def get_by_email(self, email: str) -> UserAccount[IdT] | None: ...

    async def get_by_id(self, user_id: IdT) -> UserAccount[IdT] | None: ...

    async def create(self, data: NewUser) -> UserAccount[IdT]: ...

    async def save(self, user: UserAccount[IdT]) -> None: ...


@runtime_checkable
class RefreshTokenRepository(Protocol[IdT]):
    """Persistence contract for refresh-token rows."""

    async def create(
        self,
        *,
        user_id: IdT,
        token_hash: str,
        expires_at: datetime,
        device_name: str | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> RefreshTokenRow[IdT]: ...

    async def get_by_hash(self, token_hash: str) -> RefreshTokenRow[IdT] | None: ...

    async def revoke(self, token_id: IdT) -> None: ...

    async def revoke_all_for_user(self, user_id: IdT) -> None: ...


@runtime_checkable
class OAuthAccountRepository(Protocol[IdT]):
    """Persistence contract for OAuth-linked accounts."""

    async def get_by_provider_account(
        self, provider: str, account_id: str
    ) -> OAuthAccountRow[IdT] | None: ...

    async def link(self, data: NewOAuthLink[IdT]) -> OAuthAccountRow[IdT]: ...

    async def refresh_token(
        self, account_id: IdT, *, access_token: str, expires_at: int | None
    ) -> None: ...


@runtime_checkable
class EmailSender(Protocol):
    """Structural contract every mailer must satisfy."""

    async def send(self, message: EmailMessage) -> None: ...


UserIdT = TypeVar("UserIdT")
