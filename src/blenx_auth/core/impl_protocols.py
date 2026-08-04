from typing import Any
from blenx_auth.core import PasswordResetService
from blenx_auth.core import EmailVerificationService
from blenx_auth.core import AuthenticationService
from collections.abc import Awaitable
from collections.abc import Callable
from blenx_auth.core import AuthSettings
from blenx_auth.core.jwt import TokenService
from blenx_auth.core.ports import UserIdT
from typing import Protocol
from typing import runtime_checkable


@runtime_checkable
class AuthBackend(Protocol[UserIdT]):
    """Structural contract every auth backend (SQLAlchemy, Beanie, ...) must satisfy.

    A backend is a composition root: it owns the ``TokenService``, the email
    sender, and ``settings``, and exposes FastAPI ``Depends``-compatible
    callables for the core services plus the "current user" dependencies.

    Backends are free to differ in *how* they build repositories (a fresh
    set per request from a session, vs. shared global instances) — that
    plumbing (e.g. ``get_db_session``, ``get_user_repository``) is
    intentionally left out of this protocol since its signature isn't
    consistent across backends. Only the resulting service/dependency
    surface is guaranteed.
    """

    # -- configuration -------------------------------------------------
    @property
    def token_service(self) -> TokenService:
        """The configured token service (e.g. for OAuth state minting)."""
        ...

    @property
    def settings(self) -> AuthSettings:
        """The configured settings."""
        ...

    # -- core service dependencies (FastAPI Depends-compatible) --------
    get_authentication_service: Callable[..., Awaitable[AuthenticationService[UserIdT]]]
    get_verification_service: Callable[..., Awaitable[EmailVerificationService[UserIdT]]]
    get_password_reset_service: Callable[..., Awaitable[PasswordResetService[UserIdT]]]

    # -- current-user dependencies --------------------------------------
    get_current_user: Callable[..., Awaitable[Any]]
    get_current_active_user: Callable[..., Awaitable[Any]]
    get_current_verified_user: Callable[..., Awaitable[Any]]

    CurrentUser: Any
    CurrentActiveUser: Any
    CurrentVerifiedUser: Any
