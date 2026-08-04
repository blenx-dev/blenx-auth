"""Pydantic v2 schemas for the auth HTTP boundary.

These models are the only place where request/response wire formats are
declared. They validate early (FastAPI turns ``ValidationError`` into a 422
before any service code runs) while the services in
:mod:`blenx_auth.core.services` remain the single source of truth for *policy*
(password strength, token lifetimes, lockout). Where a bound exists in both
layers it is kept in sync with :class:`blenx_auth.core.constants.PasswordPolicy`.
"""

from __future__ import annotations

import datetime as dt
import uuid
from dataclasses import field
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from blenx_auth.core.constants import TOKEN_TYPE_BEARER, PasswordPolicy
from blenx_auth.core.dto import TokenPair


class BaseUserRead(BaseModel):
    """Base schema for user data. Extend this to add custom fields."""

    model_config = ConfigDict(from_attributes=True, extra="allow")

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


class BaseRegisterRequest(BaseModel):
    """Base payload for user registration. Extend this to add custom fields."""

    email: EmailStr
    password: Annotated[
        str,
        Field(min_length=PasswordPolicy.MIN_LENGTH, max_length=PasswordPolicy.MAX_LENGTH),
    ]
    birthdate: dt.date | None = None
    extra_data: dict[str, Any] = field(default_factory=dict)


class RegisterRequest(BaseRegisterRequest):
    """Default registration payload schema."""


class LoginRequest(BaseModel):
    """Payload for ``POST /auth/login``."""

    email: EmailStr
    password: str


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


class BaseUserUpdate(BaseModel):
    """Base payload for partial user updates. Extend to add custom fields."""

    email: EmailStr | None = None
    password: str | None = None
    is_active: bool | None = None
    is_verified: bool | None = None
    extra_data: dict[str, Any] = field(default_factory=dict)


class UserUpdate(BaseUserUpdate):
    """Default user update payload schema."""


class TokenResponse(BaseModel):
    """Response for ``POST /auth/login`` and ``POST /auth/refresh``."""

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
