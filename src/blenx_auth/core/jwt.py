"""JWT minting, decoding, and verification, plus the module's TokenService.

Tokens
------
Four token families exist, distinguished by the ``typ`` claim
(:class:`blenx_auth.core.constants.TokenType`):

- ``access`` — short-lived, presented as the bearer credential.
- ``refresh`` — long-lived, presented to ``TokenService.decode_refresh_token``.
- ``email_verify`` — single-purpose proof of address ownership.
- ``password_reset`` — single-purpose proof of account ownership.

Every token carries ``sub`` (the user id), ``iat``, ``exp``, and a fresh
``jti``. ``exp``/``iat`` are numeric (Unix) timestamps, keeping the module
timezone-agnostic.

Refresh tokens are JWTs like any other, but their raw value is **hashed
(SHA-256) before storage** (see :func:`hash_token`). The database therefore
never holds a usable refresh token: a leak of ``refresh_tokens.hashed_token``
yields nothing replayable. The ``jti`` links a JWT to its database row for
revocation bookkeeping.

One secret signs all families; :func:`verify_token` rejects any token whose
``typ`` does not match the caller's expectation, which is what stops an access
token being replayed where a verification token is required.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt as pyjwt

from blenx_auth.core.constants import (
    JWT_CLAIM_EXPIRES_AT,
    JWT_CLAIM_ISSUED_AT,
    JWT_CLAIM_JTI,
    JWT_CLAIM_SUBJECT,
    JWT_CLAIM_TYPE,
    OAUTH_STATE_LIFETIME_MINUTES,
    REFRESH_TOKEN_HASH_ALGORITHM,
    TokenType,
)
from blenx_auth.core.exceptions import ExpiredTokenError, InvalidTokenError
from blenx_auth.core.settings import AuthSettings

# The JWT payload is inherently heterogeneous JSON; ``Any`` is confined to the
# two functions that touch the wire format so the rest of the module stays
# fully typed.
_JWTPayload = dict[str, Any]


def _now() -> datetime:
    return datetime.now(UTC)


def _encode(
    subject: str, token_type: TokenType, expires_delta: timedelta, settings: AuthSettings
) -> str:
    """Encode a signed JWT with the module's standard claims."""
    now = _now()
    payload: _JWTPayload = {
        JWT_CLAIM_SUBJECT: subject,
        JWT_CLAIM_TYPE: token_type.value,
        JWT_CLAIM_JTI: str(uuid.uuid4()),
        JWT_CLAIM_ISSUED_AT: int(now.timestamp()),
        JWT_CLAIM_EXPIRES_AT: int((now + expires_delta).timestamp()),
    }
    return pyjwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm)


def _decode_raw(token: str, settings: AuthSettings) -> _JWTPayload:
    """Decode and validate the signature/expiry of ``token``.

    Raises :class:`ExpiredTokenError` or :class:`InvalidTokenError`; malformed,
    expired, and wrong-key tokens never surface as raw library exceptions.
    """
    try:
        return pyjwt.decode(token, settings.secret_key, algorithms=[settings.jwt_algorithm])
    except pyjwt.ExpiredSignatureError as exc:
        raise ExpiredTokenError() from exc
    except pyjwt.InvalidTokenError as exc:
        raise InvalidTokenError() from exc


def create_access_token(subject: str, settings: AuthSettings) -> str:
    """Create a short-lived access token for ``subject``."""
    return _encode(
        subject,
        TokenType.ACCESS,
        timedelta(minutes=settings.access_token_expire_minutes),
        settings,
    )


def create_refresh_token(subject: str, settings: AuthSettings) -> str:
    """Create a long-lived refresh token for ``subject``.

    The returned JWT is what the client stores; only its hash belongs in the
    database.
    """
    return _encode(
        subject,
        TokenType.REFRESH,
        timedelta(days=settings.refresh_token_expire_days),
        settings,
    )


def decode_token(token: str, settings: AuthSettings) -> str:
    """Return the ``sub`` claim of ``token`` without a ``typ`` check.

    Use this only when the token family is irrelevant; every other caller
    should use :func:`verify_token`.
    """
    payload = _decode_raw(token, settings)
    subject = payload.get(JWT_CLAIM_SUBJECT)
    if not isinstance(subject, str) or not subject:
        raise InvalidTokenError("Token is missing a subject.")
    return subject


def verify_token(token: str, expected_type: TokenType, settings: AuthSettings) -> str:
    """Return the ``sub`` claim only when ``token`` is valid **and** of
    ``expected_type``.

    This is the security-critical check: signature, expiry, subject presence,
    and token family must all pass. A mismatched ``typ`` is indistinguishable
    from a forged token.
    """
    payload = _decode_raw(token, settings)
    token_type = payload.get(JWT_CLAIM_TYPE)
    if token_type != expected_type.value:
        raise InvalidTokenError("Token type mismatch.")
    subject = payload.get(JWT_CLAIM_SUBJECT)
    if not isinstance(subject, str) or not subject:
        raise InvalidTokenError("Token is missing a subject.")
    return subject


def hash_token(raw: str) -> str:
    """Return the SHA-256 hex digest of ``raw``.

    SHA-256 is chosen because refresh/reset tokens are high-entropy random
    values — a fast, deterministic hash is correct here (unlike passwords,
    which need a slow, salted KDF because they are low-entropy).
    """
    return hashlib.new(REFRESH_TOKEN_HASH_ALGORITHM, raw.encode("utf-8")).hexdigest()


class TokenService:
    """Token minting and validation with settings bound.

    Services depend on this class (constructor-injected) rather than the
    module functions so time-to-live and secrets come from one configured
    instance and are trivially fakeable in tests.
    """

    def __init__(self, settings: AuthSettings) -> None:
        self._settings = settings

    def access_expires_delta(self) -> timedelta:
        return timedelta(minutes=self._settings.access_token_expire_minutes)

    def refresh_expires_delta(self) -> timedelta:
        return timedelta(days=self._settings.refresh_token_expire_days)

    def create_access_token(self, subject: str) -> str:
        return create_access_token(subject, self._settings)

    def create_refresh_token(self, subject: str) -> str:
        return create_refresh_token(subject, self._settings)

    def create_email_verification_token(self, subject: str) -> str:
        return _encode(
            subject,
            TokenType.EMAIL_VERIFY,
            timedelta(minutes=self._settings.email_verification_token_expire_minutes),
            self._settings,
        )

    def create_password_reset_token(self, subject: str) -> str:
        return _encode(
            subject,
            TokenType.PASSWORD_RESET,
            timedelta(minutes=self._settings.password_reset_token_expire_minutes),
            self._settings,
        )

    def decode_access_token(self, token: str) -> str:
        """Return the subject of a valid access token, else raise."""
        return verify_token(token, TokenType.ACCESS, self._settings)

    def decode_refresh_token(self, token: str) -> str:
        """Return the subject of a valid refresh token, else raise."""
        return verify_token(token, TokenType.REFRESH, self._settings)

    def verify_email_verification_token(self, token: str) -> str:
        """Return the subject of a valid email-verification token, else raise."""
        return verify_token(token, TokenType.EMAIL_VERIFY, self._settings)

    def verify_password_reset_token(self, token: str) -> str:
        """Return the subject of a valid password-reset token, else raise."""
        return verify_token(token, TokenType.PASSWORD_RESET, self._settings)

    def create_oauth_state(self) -> str:
        """Signed, short-lived state value for the OAuth authorize round-trip.

        The state is CSRF protection: only a state this server minted (and
        that is still unexpired) is accepted on the callback. It carries no
        subject; ``sub`` is a constant marker for the ``verify_token`` shape.
        """
        return _encode(
            "state",
            TokenType.OAUTH_STATE,
            timedelta(minutes=OAUTH_STATE_LIFETIME_MINUTES),
            self._settings,
        )

    def verify_oauth_state(self, token: str) -> None:
        """Raise unless ``token`` is a valid, unexpired OAuth state value."""
        verify_token(token, TokenType.OAUTH_STATE, self._settings)
