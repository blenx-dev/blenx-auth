"""Core services: the framework- and storage-free business logic.

Each service is a plain class whose dependencies are structural ``Protocol``
types (repositories, ``TokenService``, ``EmailSender``, ``AuthSettings``) — no
FastAPI, no SQLAlchemy — so they are fully unit-testable with fakes and
framework-agnostic.

Policy ownership:
- **Repositories** persist; they know nothing about rules.
- **Services** decide (lockout thresholds, rotation, single-use semantics).
- **Routers/dependencies** (the FastAPI adapter) map decisions to HTTP.

Security notes implemented here:
- Lockout: ``failed_login_attempts`` climb to ``max_failed_login_attempts``;
  on the final failure the account is locked for ``account_lockout_minutes``
  and the counter resets (the lock, not the count, is the state).
- Refresh rotation: every successful refresh revokes the presented token and
  issues a new one. Presenting an already-revoked-but-valid token is treated
  as family compromise: every outstanding token for that user is revoked.
- Reset tokens are single-use: a JWT *plus* a DB-stored hash that is cleared on
  use, so replaying the same (still-valid) JWT fails.
"""

from blenx_auth.core.services.authentication import AuthenticationService
from blenx_auth.core.services.password_reset import PasswordResetService
from blenx_auth.core.services.user_service import UserService
from blenx_auth.core.services.verification import EmailVerificationService

__all__ = [
    "AuthenticationService",
    "EmailVerificationService",
    "PasswordResetService",
    "UserService",
]
