"""Settings protocol for the auth package.

The core services depend on a structural ``AuthSettings`` protocol rather than
on a concrete settings class, so the package is reusable across projects — each
application provides its own settings object that satisfies the fields below.

The protocol is deliberately free of framework (pydantic-settings, env parsing)
concerns: it declares plain attribute *shapes* only. Host applications may back
it with pydantic-settings, dataclasses, or anything else.
"""

from __future__ import annotations

from typing import Protocol


class AuthSettings(Protocol):
    """Structural contract for the settings the auth package needs."""

    # JWT
    secret_key: str
    jwt_algorithm: str

    # Token lifetimes (minutes unless stated otherwise)
    access_token_expire_minutes: int
    refresh_token_expire_days: int
    email_verification_token_expire_minutes: int
    password_reset_token_expire_minutes: int

    # Login hardening
    max_failed_login_attempts: int
    account_lockout_minutes: int
    login_rate_limit_per_minute: int

    # URLs for email links and OAuth redirects
    frontend_url: str
    backend_url: str

    # Google OAuth
    google_client_id: str
    google_client_secret: str
