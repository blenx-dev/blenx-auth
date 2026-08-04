"""Static security invariants and enum types for the auth module.

This module holds values that are **fixed by security policy** and must not
depend on environment configuration. Everything that can be tuned per
deployment (token time-to-live, secrets, lockout durations) belongs in the
host application's settings object that satisfies :class:`AuthSettings`.

Keep this module free of imports from the rest of the package so it can be
used by any layer (models, services, routes, tests) without introducing import
cycles.
"""

from __future__ import annotations

import enum


class TokenType(enum.StrEnum):
    """The ``typ`` claim discriminator for tokens minted by this module.

    A single JWT secret signs every token family, so the claim is the only
    thing that prevents, e.g., an access token being replayed as an email
    verification token. ``verify_token`` rejects any token whose type does not
    match the expected value.
    """

    ACCESS = "access"
    REFRESH = "refresh"
    EMAIL_VERIFY = "email_verify"
    PASSWORD_RESET = "password_reset"  # noqa: S105  (JWT type discriminator, not a secret)
    OAUTH_STATE = "oauth_state"  # noqa: S105  (JWT type discriminator, not a secret)


class PasswordPolicy(enum.IntEnum):
    """Bounds enforced by :func:`blenx_auth.core.password.validate_password`."""

    MIN_LENGTH = 8
    MAX_LENGTH = 128


class AccountStatus(enum.StrEnum):
    """Human-facing account statuses derived from the user record."""

    ACTIVE = "active"
    INACTIVE = "inactive"
    UNVERIFIED = "unverified"


# Number of random bytes backing single-use tokens (email verification and
# password reset). 32 bytes ~= 256 bits of entropy, which is unguessable over
# the lifetime of the token even with a fast local attacker.
TOKEN_BYTES = 32

# Lifetime of the signed OAuth ``state`` value carried through the authorize
# round-trip (CSRF protection for the login redirect). Kept short because the
# state is single-purpose and only needs to survive the browser bounce.
OAUTH_STATE_LIFETIME_MINUTES = 10

# Refresh tokens are stored hashed (SHA-256) in the database so a database
# leak never yields usable sessions.
REFRESH_TOKEN_HASH_ALGORITHM = "sha256"  # noqa: S105  (hash-algorithm name, not a secret)

# JWT claim names — kept central so every service names them identically.
JWT_CLAIM_SUBJECT = "sub"
JWT_CLAIM_TYPE = "typ"
JWT_CLAIM_JTI = "jti"
JWT_CLAIM_ISSUED_AT = "iat"
JWT_CLAIM_EXPIRES_AT = "exp"
JWT_CLAIM_NONCE = "nonce"

# Unique-constraint columns for OAuth identity: one account per provider per
# external id. Used to build the DB constraint and to look up existing accounts.
OAUTH_ACCOUNT_IDENTITY_COLUMNS = ("oauth_name", "account_id")

# Token-type string advertised on ``TokenResponse`` (RFC 6750 bearer scheme).
TOKEN_TYPE_BEARER = "bearer"  # noqa: S105  (RFC 6750 token-type, not a secret)
