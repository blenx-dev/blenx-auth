"""SQLAlchemy ORM models for the auth adapter.

The models map the existing ``user``, ``refresh_tokens``, and ``oauth_account``
tables so current rows survive a migration unchanged; only new columns are
added (with Python-side defaults where the tables have no server defaults).
"""

from __future__ import annotations

import datetime
import uuid

from sqlalchemy.orm import Mapped, mapped_column, relationship

from blenx_auth.core.constants import OAUTH_ACCOUNT_IDENTITY_COLUMNS
from blenx_auth.sqlalchemy.base import AuthBase
from sqlalchemy import (
    Boolean,
    Date,
    DateTime,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
    Uuid,
    func,
)


class OAuthAccount(AuthBase):
    """OAuth-linked account ORM model (maps the ``oauth_account`` table).

    The natural key is ``(oauth_name, account_id)`` — one row per provider per
    external id — enforced by a unique constraint so linking
    Google/GitHub/Microsoft cannot duplicate an identity. ``account_id`` is the
    provider's opaque subject id (Google's ``sub``), never the display email,
    because emails can change.
    """

    __tablename__ = "oauth_account"

    __table_args__ = (
        UniqueConstraint(*OAUTH_ACCOUNT_IDENTITY_COLUMNS, name="uq_oauth_account_identity"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("user.id", ondelete="CASCADE"), index=True
    )
    oauth_name: Mapped[str] = mapped_column(String(100), index=True)
    access_token: Mapped[str] = mapped_column(String(1024))
    expires_at: Mapped[int | None] = mapped_column(Integer)
    refresh_token: Mapped[str | None] = mapped_column(String(1024))
    account_id: Mapped[str] = mapped_column(String(320), index=True)
    account_email: Mapped[str] = mapped_column(String(320))

    user: Mapped[User] = relationship(back_populates="oauth_accounts")


class RefreshToken(AuthBase):
    """Refresh-token ORM model.

    Only the **SHA-256 hash** of a refresh token is stored (``token_hash``),
    never the token itself. ``user_id`` carries ``ondelete="CASCADE"`` so
    deleting a user cleans up every session family without application code.
    """

    __tablename__ = "refresh_tokens"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("user.id", ondelete="CASCADE"), index=True
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    expires_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime.datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    device_name: Mapped[str | None] = mapped_column(String(120))
    ip_address: Mapped[str | None] = mapped_column(String(45))
    user_agent: Mapped[str | None] = mapped_column(String(255))

    user: Mapped[User] = relationship(back_populates="refresh_tokens")


class User(AuthBase):
    """User account ORM model.

    Column names and types are unchanged for everything already in production;
    only new columns are added. New columns carry Python-side defaults because
    the table has no server defaults for booleans.
    """

    __tablename__ = "user"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)

    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(String(1024))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_superuser: Mapped[bool] = mapped_column(Boolean, default=False)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    birthdate: Mapped[datetime.date | None] = mapped_column(Date, nullable=True)

    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    email_verified_at: Mapped[datetime.datetime | None] = mapped_column(DateTime(timezone=True))
    failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime.datetime | None] = mapped_column(DateTime(timezone=True))
    password_reset_token_hash: Mapped[str | None] = mapped_column(String(64))
    password_reset_token_expires_at: Mapped[datetime.datetime | None] = mapped_column(
        DateTime(timezone=True)
    )

    refresh_tokens: Mapped[list[RefreshToken]] = relationship(
        "RefreshToken", back_populates="user", cascade="all, delete-orphan"
    )
    oauth_accounts: Mapped[list[OAuthAccount]] = relationship(
        "OAuthAccount", back_populates="user", cascade="all, delete-orphan"
    )
