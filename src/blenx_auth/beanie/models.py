"""Beanie (MongoDB) ``Document`` models for the auth adapter.

These documents mirror the fields of the SQLAlchemy models in
:mod:`blenx_auth.sqlalchemy.models` so they satisfy the structural protocols in
:mod:`blenx_auth.core.ports`. Identity is a Mongo
:class:`~beanie.PydanticObjectId` stored as the MongoDB primary key (``_id``) —
the MongoDB-native key type, fixed by Beanie at class definition.

Unique constraints are declared as Mongo unique indexes (``email`` on user,
``token_hash`` on refresh token, ``(oauth_name, account_id)`` on oauth
account). A duplicate insert surfaces a ``pymongo.errors.DuplicateKeyError``,
the MongoDB analogue of SQLAlchemy's ``IntegrityError``; the repositories
translate it into the domain :class:`EmailAlreadyExistsError`.
"""

from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Annotated

from pydantic import AfterValidator, Field
from pymongo import IndexModel

from beanie import Document, Indexed, PydanticObjectId


def _now() -> datetime:
    return datetime.now(UTC)


def _to_utc(value: datetime) -> datetime:
    """Normalize a datetime to tz-aware UTC (Mongo returns naive UTC)."""
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _to_utc_or_none(value: datetime | None) -> datetime | None:
    return None if value is None else _to_utc(value)


# Required / optional tz-aware UTC datetimes. Without these, datetimes read
# back from MongoDB are offset-naive, which would break the services' comparisons
# against ``datetime.now(UTC)``.
UTCDateTime = Annotated[datetime, AfterValidator(_to_utc)]
OptUTCDateTime = Annotated[datetime | None, AfterValidator(_to_utc_or_none)]


class User(Document):
    """A user account document with a Mongo ``ObjectId`` primary key."""

    email: Annotated[str, Indexed(unique=True)]
    hashed_password: str
    is_active: bool = True
    is_superuser: bool = False
    is_verified: bool = False
    birthdate: date | None = None
    created_at: UTCDateTime = Field(default_factory=_now)
    email_verified_at: OptUTCDateTime = None
    failed_login_attempts: int = 0
    locked_until: OptUTCDateTime = None
    password_reset_token_hash: str | None = None
    password_reset_token_expires_at: OptUTCDateTime = None

    class Settings:
        name = "user"


class RefreshToken(Document):
    """A refresh-token document with a Mongo ``ObjectId`` primary key.

    Only the SHA-256 hash of a refresh token is stored (``token_hash``).
    """

    token_hash: Annotated[str, Indexed(unique=True)]
    expires_at: UTCDateTime
    revoked_at: OptUTCDateTime = None
    created_at: UTCDateTime = Field(default_factory=_now)
    device_name: str | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    user_id: PydanticObjectId

    class Settings:
        name = "refresh_tokens"


class OAuthAccount(Document):
    """A provider identity with a Mongo ``ObjectId`` primary key.

    Natural key ``(oauth_name, account_id)``; ``account_id`` is the provider's
    opaque subject id (Google's ``sub``), never the display email.
    """

    oauth_name: str
    access_token: str
    expires_at: int | None = None
    refresh_token: str | None = None
    account_id: str
    account_email: str
    user_id: PydanticObjectId

    class Settings:
        name = "oauth_account"
        indexes = [
            IndexModel([("oauth_name", 1), ("account_id", 1)], unique=True),
        ]


__all__ = ["OAuthAccount", "RefreshToken", "User"]
