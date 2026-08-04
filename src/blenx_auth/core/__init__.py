"""Framework- and storage-free core of the auth module.

Contains policy (``constants``, ``exceptions``), primitives (``password``,
``jwt``), DTOs, structural ports, the three services, and the HTTP-boundary
schemas. Nothing here imports FastAPI, SQLAlchemy, Beanie, or Starlette.

Public modules:

- :mod:`blenx_auth.core.constants` — security invariants and enums.
- :mod:`blenx_auth.core.exceptions` — domain error types.
- :mod:`blenx_auth.core.settings` — the ``AuthSettings`` port.
- :mod:`blenx_auth.core.dto` — plain data objects crossing the ports.
- :mod:`blenx_auth.core.ports` — driven-interface contracts (repositories,
  email sender).
- :mod:`blenx_auth.core.services` — the three business services.
- :mod:`blenx_auth.core.schemas` — pydantic wire models for the FastAPI adapter.
"""

from blenx_auth.core.constants import (
    AccountStatus,
    PasswordPolicy,
    TokenType,
)
from blenx_auth.core.dto import NewOAuthLink, NewUser, TokenPair
from blenx_auth.core.exceptions import (
    AccountLockedError,
    AccountStatusError,
    AuthError,
    EmailAlreadyExistsError,
    ExpiredTokenError,
    InactiveAccountError,
    InvalidCredentialsError,
    InvalidRefreshTokenError,
    InvalidTokenError,
    PasswordPolicyError,
    PermissionDeniedError,
    RateLimitExceededError,
    RevokedTokenError,
    TokenError,
    UnverifiedAccountError,
)
from blenx_auth.core.password import hash_password, validate_password, verify_password
from blenx_auth.core.ports import (
    EmailSender,
    OAuthAccountRepository,
    RefreshTokenRepository,
    UserAccount,
    UserRepository,
)
from blenx_auth.core.schemas import (
    ForgotPasswordRequest,
    LoginRequest,
    LogoutRequest,
    RefreshRequest,
    RegisterRequest,
    ResetPasswordRequest,
    TokenResponse,
    UserRead,
    VerifyEmailRequest,
)
from blenx_auth.core.services import (
    AuthenticationService,
    EmailVerificationService,
    PasswordResetService,
)
from blenx_auth.core.settings import AuthSettings

__all__ = [
    "AccountLockedError",
    "AccountStatus",
    "AccountStatusError",
    "AuthError",
    "AuthSettings",
    "AuthenticationService",
    "EmailAlreadyExistsError",
    "EmailSender",
    "EmailVerificationService",
    "ExpiredTokenError",
    "ForgotPasswordRequest",
    "InactiveAccountError",
    "InvalidCredentialsError",
    "InvalidRefreshTokenError",
    "InvalidTokenError",
    "LoginRequest",
    "LogoutRequest",
    "NewOAuthLink",
    "NewUser",
    "OAuthAccountRepository",
    "PasswordPolicy",
    "PasswordPolicyError",
    "PasswordResetService",
    "PermissionDeniedError",
    "RateLimitExceededError",
    "RefreshRequest",
    "RefreshTokenRepository",
    "RegisterRequest",
    "ResetPasswordRequest",
    "RevokedTokenError",
    "TokenError",
    "TokenPair",
    "TokenResponse",
    "TokenType",
    "UnverifiedAccountError",
    "UserAccount",
    "UserRead",
    "UserRepository",
    "VerifyEmailRequest",
    "hash_password",
    "validate_password",
    "verify_password",
]
