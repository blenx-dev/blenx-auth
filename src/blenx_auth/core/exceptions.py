"""Domain exceptions for the auth module.

Every failure a service can raise lives here as a plain exception (never a
FastAPI ``HTTPException``). That keeps ``blenx_auth.core.services`` free of
framework imports so it can be unit-tested with mocked repositories and reused
outside FastAPI (CLI scripts, workers, tests).

Each exception carries the HTTP metadata needed to map it to a response:
- ``status_code`` — the HTTP status the client should see.
- ``detail`` — a user-facing message (RFC 7807 ``detail``).
- ``headers`` — extra response headers (``WWW-Authenticate`` for 401s,
  ``Retry-After`` for lockout/rate-limit).

The FastAPI adapter registers a single exception handler for
:class:`AuthError` that renders this metadata, so endpoint code never maps
errors by hand.
"""

from __future__ import annotations

from typing import ClassVar


class AuthError(Exception):
    """Base class for every error raised by the auth module.

    Subclasses override ``status_code`` and ``default_detail``; the optional
    per-instance ``detail`` lets callers provide a more specific message
    without changing the error type.
    """

    status_code: ClassVar[int] = 500
    default_detail: ClassVar[str] = "Authentication error."
    headers: dict[str, str] = {}

    def __init__(self, detail: str | None = None) -> None:
        self.detail = detail or self.default_detail
        super().__init__(self.detail)


class InvalidCredentialsError(AuthError):
    """Login failed because the email/password pair did not match.

    Deliberately says nothing about *which* part was wrong so the endpoint
    cannot be used to enumerate registered addresses.
    """

    status_code = 401
    default_detail = "Invalid email or password."
    headers = {"WWW-Authenticate": "Bearer"}


class PasswordPolicyError(AuthError):
    """The supplied password violates the policy in :mod:`blenx_auth.core.constants`."""

    status_code = 422
    default_detail = "Password does not meet the required policy."


class EmailAlreadyExistsError(AuthError):
    """Registration collided with an existing account for the same email."""

    status_code = 409
    default_detail = "An account with this email already exists."


class AccountLockedError(AuthError):
    """Too many failed attempts triggered the lockout guard.

    ``retry_after`` carries the seconds until the lock expires so the HTTP
    mapping can emit ``Retry-After``.
    """

    status_code = 403
    default_detail = "Account temporarily locked due to too many failed attempts."

    def __init__(self, detail: str | None = None, *, retry_after: int | None = None) -> None:
        super().__init__(detail)
        self.retry_after = retry_after
        if retry_after is not None:
            self.headers = {"Retry-After": str(retry_after)}


class RateLimitExceededError(AuthError):
    """Extension point for external rate limiting (e.g. Redis leaky bucket).

    The module ships the error type and lets the caller supply ``Retry-After``;
    wiring an actual limiter is intentionally left to deployment.
    """

    status_code = 429
    default_detail = "Too many requests. Please try again later."

    def __init__(self, detail: str | None = None, *, retry_after: int | None = None) -> None:
        super().__init__(detail)
        self.retry_after = retry_after
        if retry_after is not None:
            self.headers = {"Retry-After": str(retry_after)}


class AccountStatusError(AuthError):
    """Base class for login/session failures caused by account state."""


class InactiveAccountError(AccountStatusError):
    """The account was explicitly deactivated."""

    status_code = 403
    default_detail = "This account has been deactivated."
    headers = {"WWW-Authenticate": "Bearer"}


class UnverifiedAccountError(AccountStatusError):
    """The account has not completed email verification."""

    status_code = 403
    default_detail = "Email verification required before continuing."
    headers = {"WWW-Authenticate": "Bearer"}


class TokenError(AuthError):
    """Base class for any failure while validating a signed token."""

    status_code = 401
    headers = {"WWW-Authenticate": "Bearer"}


class InvalidTokenError(TokenError):
    """Token is malformed, signed with the wrong key, or has the wrong type."""

    default_detail = "Invalid token."


class ExpiredTokenError(InvalidTokenError):
    """Token is well-formed but past its ``exp``."""

    default_detail = "Token has expired."


class RevokedTokenError(InvalidTokenError):
    """Token was explicitly revoked (logout, password change, rotation reuse)."""

    default_detail = "Token has been revoked."


class InvalidRefreshTokenError(TokenError):
    """Refresh token is unknown, revoked, or already rotated.

    Distinct from :class:`InvalidTokenError` because a refresh token is never
    a JWT — it is an opaque hashed value checked against the database, so its
    failure path (and the need to revoke the whole session family on reuse)
    differs from signed-token validation.
    """

    default_detail = "Invalid refresh token."


class PermissionDeniedError(AuthError):
    """Authenticated user lacks the required role or permission."""

    status_code = 403
    default_detail = "You do not have permission to perform this action."


class UserNotFoundError(AuthError):
    """No account exists for the requested user id."""

    status_code = 404
    default_detail = "User not found."

    def __init__(self, user_id: object | None = None) -> None:
        detail = self.default_detail if user_id is None else f"User '{user_id}' not found."
        super().__init__(detail)


class UserModelMappingError(AuthError):
    """A payload field has no corresponding attribute on the user model.

    Raised at the service layer when an update payload (or repository
    ``create`` call) names a field the storage model does not declare — the
    runtime analogue of the startup :class:`ContractMismatchError`.
    """

    status_code = 422
    default_detail = "Payload contains a field that is not present on the user model."

    def __init__(self, field_name: object | None = None) -> None:
        detail = (
            self.default_detail if field_name is None else f"Unknown user field '{field_name}'."
        )
        super().__init__(detail)


class InvalidChallengeError(AuthError):
    """A login challenge token is missing, expired, or on the wrong flow.

    Issued by the 2FA/step-up flows: the client presented a challenge token
    that is not pending (``scope != 2fa_pending``) or the wrong code.
    """

    status_code = 401
    default_detail = "Invalid or expired challenge."
    headers = {"WWW-Authenticate": "Bearer"}


class UnknownError(AuthError):
    status_code = 400
    default_detail = "Unknown Error. Please try again later."

    def __init__(self, field_name: object | None = None) -> None:
        detail = (
            self.default_detail if field_name is None else f"Unknown user field '{field_name}'."
        )
        super().__init__(detail)