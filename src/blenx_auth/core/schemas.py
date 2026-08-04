"""Pydantic v2 schemas for the auth HTTP boundary.

These models are the only place where request/response wire formats are
declared. They validate early (FastAPI turns ``ValidationError`` into a 422
before any service code runs) while the services in
:mod:`blenx_auth.core.services` remain the single source of truth for *policy*
(password strength, token lifetimes, lockout). Where a bound exists in both
layers it is kept in sync with :class:`blenx_auth.core.constants.PasswordPolicy`.

The ``Base*`` classes are the empty-plugin bases: a composition root rebuilds
each one with plugin/consumer mixins attached, so the base classes themselves
are never used directly at runtime (they exist so the request/response shapes
are declared here, in one place, and to keep the module importable standalone).
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from blenx_auth.core.constants import TOKEN_TYPE_BEARER, PasswordPolicy
from blenx_auth.core.dto import TokenPair


class BaseUserRead(BaseModel):
    """Base schema for user data. Extend this to add custom fields."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: EmailStr
    is_active: bool
    is_superuser: bool
    is_verified: bool
    birthdate: dt.date | None = None
    email_verified_at: dt.datetime | None = None
    created_at: dt.datetime = Field(default_factory=dt.datetime.now)


class UserRead(BaseUserRead):
    """Default UserRead schema with all standard fields."""


class BaseUserCreate(BaseModel):
    """Base payload for registration. Extend this to add custom fields.

    ``email``/``password`` are the core registration fields; plugin/consumer
    create mixins must never declare them (enforced by
    :func:`blenx_auth.core.plugins.collisions.check_no_field_collisions`).
    """

    model_config = ConfigDict(extra="forbid")

    email: EmailStr
    password: Annotated[
        str,
        Field(min_length=PasswordPolicy.MIN_LENGTH, max_length=PasswordPolicy.MAX_LENGTH),
    ]
    birthdate: dt.date | None = None


class RegisterRequest(BaseUserCreate):
    """Default registration payload schema."""


class BaseUserUpdate(BaseModel):
    """Base payload for self-service profile updates.

    Only profile fields belong here: email/password changes go through the
    dedicated email-change/password-reset flows and account-state flags are
    admin-only (see :class:`BaseUserAdminUpdate`). ``extra="forbid"`` makes
    the typed create/update guarantee airtight — a consumer sending an
    undeclared field gets a 422, never a silently-ignored one.
    """

    model_config = ConfigDict(extra="forbid")

    birthdate: dt.date | None = None


class UserUpdate(BaseUserUpdate):
    """Default user update payload schema."""


class BaseUserAdminUpdate(BaseModel):
    """Base payload for superuser-driven account updates.

    Carries the account-state flags (which self-service must not touch) plus
    the same profile fields as :class:`BaseUserUpdate`.
    """

    model_config = ConfigDict(extra="forbid")

    is_active: bool | None = None
    is_superuser: bool | None = None
    is_verified: bool | None = None
    birthdate: dt.date | None = None


class UserAdminUpdate(BaseUserAdminUpdate):
    """Default superuser account-update payload schema."""


class LoginRequest(BaseModel):
    """Payload for ``POST /auth/login``."""

    email: EmailStr
    password: str


class LoginSuccess(BaseModel):
    """A completed login (or a completed 2FA verification).

    Carries the same token pair fields the pre-union ``TokenResponse`` did so
    existing consumers keep working; ``kind == "token"`` discriminates it from
    :class:`LoginChallenge` in :data:`LoginResponse`.
    """

    kind: Literal["token"] = "token"
    access_token: str
    refresh_token: str | None = None
    expires_in: int | None = None
    token_type: str = TOKEN_TYPE_BEARER


class LoginChallenge(BaseModel):
    """A login that requires a second factor before tokens are issued.

    ``challenge_token`` is a short-lived, signed proof that step 1
    (credentials) succeeded; the client presents it (with a second factor)
    to the challenge's ``flow`` endpoint to complete the login.
    """

    kind: Literal["challenge"] = "challenge"
    flow: str
    challenge_token: str


#: Discriminated union for ``POST /auth/login`` responses (locked decision #9).
LoginResponse = Annotated[LoginSuccess | LoginChallenge, Field(discriminator="kind")]


class RefreshRequest(BaseModel):
    """Payload for ``POST /auth/refresh``."""

    refresh_token: Annotated[str, Field(min_length=16)]


class LogoutRequest(BaseModel):
    """Payload for ``POST /auth/logout``."""

    refresh_token: Annotated[str, Field(min_length=16)]


class VerifyEmailRequest(BaseModel):
    """Payload for ``POST /auth/verify-email``."""

    token: Annotated[str, Field(min_length=16)]


class ForgotPasswordRequest(BaseModel):
    """Payload for ``POST /auth/forgot-password``.

    Succeeds silently for unknown addresses (no account enumeration); the
    response shape is deliberately identical either way.
    """

    email: EmailStr


class ResetPasswordRequest(BaseModel):
    """Payload for ``POST /auth/reset-password``."""

    token: Annotated[str, Field(min_length=16)]
    new_password: Annotated[
        str,
        Field(min_length=PasswordPolicy.MIN_LENGTH, max_length=PasswordPolicy.MAX_LENGTH),
    ]


class TokenResponse(BaseModel):
    """Response for ``POST /auth/refresh`` (and legacy login consumers).

    ``POST /auth/login`` now returns the :data:`LoginResponse` union instead;
    this model is kept for the refresh route and for backward compatibility.
    """

    access_token: str
    refresh_token: str
    token_type: str = TOKEN_TYPE_BEARER
    expires_in: int

    @classmethod
    def from_pair(cls, pair: TokenPair) -> TokenResponse:
        return cls(
            access_token=pair.access_token,
            refresh_token=pair.refresh_token,
            expires_in=pair.expires_in,
        )
