"""Settings protocol for the auth package.

The core services depend on a structural ``AuthSettings`` protocol rather than
on a concrete settings class, so the package is reusable across projects — each
application provides its own settings object that satisfies the fields below.

The protocol is deliberately free of framework (pydantic-settings, env parsing)
concerns: it declares plain attribute *shapes* only. Host applications may back
it with pydantic-settings, dataclasses, or anything else.
"""

from __future__ import annotations


from dataclasses import dataclass, replace

@dataclass(frozen=True, slots=True)
class AuthSettings:
    # JWT
    secret_key: str = "change-me"
    jwt_algorithm: str = "HS256"

    # Token lifetimes
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 10
    email_verification_token_expire_minutes: int = 30
    password_reset_token_expire_minutes: int = 30

    # Login hardening
    max_failed_login_attempts: int = 3
    account_lockout_minutes: int = 15
    login_rate_limit_per_minute: int = 5

    # URLs
    frontend_url: str = "http://localhost:3000"
    backend_url: str = "http://localhost:8000"

    # Google OAuth
    google_client_id: str = ""
    google_client_secret: str = ""

    def __post_init__(self) -> None:
        if self.secret_key == "change-me":
            raise ValueError(
                "AuthSettings.secret_key must be configured."
            )

        if len(self.secret_key) < 32:
            raise ValueError(
                "secret_key must be at least 32 characters."
            )