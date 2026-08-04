"""Data-transfer objects for the auth module.

Plain frozen dataclasses that cross the port boundaries between services and
repositories (and, for ``TokenPair``, back out to the HTTP layer). They carry
no logic and no framework dependencies.

``IdT`` is the primary-key type of the storage adapter — ``uuid.UUID`` for the
SQLAlchemy adapter, ``bson.ObjectId`` for the Beanie adapter.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from typing import Generic, TypeVar, Any

from blenx_auth.core.constants import TOKEN_TYPE_BEARER

IdT = TypeVar("IdT")


@dataclass(slots=True, frozen=True)
class NewUser:
    """The subset of a user record required to create an account.

    ``extra_data`` carries consumer-defined fields (e.g. ``phone_number``)
    straight through to the repository, which persists them onto its model.
    """

    email: str
    hashed_password: str
    is_verified: bool = False
    is_superuser: bool = False
    birthdate: date | None = None
    extra_data: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class TokenPair:
    """What the login/refresh endpoints hand to the client."""

    access_token: str
    refresh_token: str
    expires_in: int
    token_type: str = TOKEN_TYPE_BEARER


@dataclass(slots=True, frozen=True)
class NewOAuthLink(Generic[IdT]):
    """Everything needed to persist a new provider identity."""

    provider: str
    account_id: str
    account_email: str
    user_id: IdT
    access_token: str
    expires_at: int | None = None
    refresh_token: str | None = None


@dataclass(frozen=True, slots=True)
class EmailMessage:
    """A plain-text email ready for delivery."""

    to: str
    subject: str
    body: str
