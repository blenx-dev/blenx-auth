"""Adapter-specific composition roots.

Each root binds one storage backend to the core services and exposes
FastAPI dependencies so the host application never wires services by hand:

    session_factory = create_session_factory(settings.database_url)
    auth = SQLAlchemyAuth(settings=settings, session_factory=session_factory)
    app.include_router(make_auth_router(auth))  # routes use Depends(auth.get_*)

The dependency callables are plain closures assigned in ``__init__``, so the
same methods work outside HTTP: ``await auth.get_authentication_service(session)``
(in a worker, CLI script, or test) and inside FastAPI via ``Depends``.

Storage backends are optional: this module imports **neither** SQLAlchemy nor
Beanie at module load (only under ``TYPE_CHECKING`` for the type checker), so
``import blenx_auth.fastapi`` works with no storage backend installed. Each
backend's SDK is imported lazily inside the matching root's ``__init__`` and
errors if the host did not install it.

NOTE: this module intentionally omits ``from __future__ import annotations``.
FastAPI evaluates dependency signatures with ``inspect.signature(..., eval_str=True)``,
which cannot resolve the closures referenced inside ``Depends(...)`` if they are
deferred to strings; eager annotations keep the sub-dependencies concrete. Only the
``__init__`` *parameter* annotations that name storage types are written as strings,
so they are not evaluated at class-definition time.
"""

from blenx_auth.core.impl_protocols import AuthBackend
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import TYPE_CHECKING, Annotated

from blenx_auth.core.email import NullEmailSender
from blenx_auth.core.jwt import TokenService
from blenx_auth.core.ports import EmailSender
from blenx_auth.core.services import (
    AuthenticationService,
    EmailVerificationService,
    PasswordResetService,
)
from blenx_auth.core.settings import AuthSettings
from blenx_auth.fastapi.current_user import make_current_user_dependencies
from fastapi import Depends

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from beanie import PydanticObjectId
    from blenx_auth.beanie.repositories import (
        BeanieOAuthAccountRepository,
        BeanieRefreshTokenRepository,
        BeanieUserRepository,
    )
    from blenx_auth.sqlalchemy.base import UserId
    from blenx_auth.sqlalchemy.repositories import (
        SQLAlchemyOAuthAccountRepository,
        SQLAlchemyRefreshTokenRepository,
        SQLAlchemyUserRepository,
    )


class SQLAlchemyAuth(AuthBackend):
    """Composition root: SQLAlchemy/PostgreSQL backend wired to core services.

    Holds the single configured ``TokenService``, email sender, and settings;
    builds fresh per-request repositories from the session yielded by
    :attr:`get_db_session`.
    """

    def __init__(
        self,
        *,
        settings: AuthSettings,
        session_factory: "async_sessionmaker[AsyncSession]",
        email_sender: EmailSender | None = None,
        parse_subject: "Callable[[str], UserId] | None" = None,
    ) -> None:
        from sqlalchemy.ext.asyncio import AsyncSession

        from blenx_auth.sqlalchemy.base import UserId
        from blenx_auth.sqlalchemy.repositories import (
            SQLAlchemyOAuthAccountRepository,
            SQLAlchemyRefreshTokenRepository,
            SQLAlchemyUserRepository,
        )

        if parse_subject is None:
            parse_subject = uuid.UUID

        self._settings = settings
        self._session_factory = session_factory
        self._email_sender: EmailSender = email_sender or NullEmailSender()
        self._parse_subject = parse_subject
        self._tokens = TokenService(settings)

        async def get_db_session() -> AsyncIterator[AsyncSession]:
            """Yield a request-scoped session (closes it when the request ends)."""
            async with self._session_factory() as session:
                yield session

        async def get_authentication_service(
            session: Annotated[AsyncSession, Depends(get_db_session)],
        ) -> AuthenticationService[UserId]:
            users = SQLAlchemyUserRepository(session)
            refresh_tokens = SQLAlchemyRefreshTokenRepository(session)
            oauth_accounts = SQLAlchemyOAuthAccountRepository(session)
            verification = EmailVerificationService(
                users=users,
                tokens=self._tokens,
                email_sender=self._email_sender,
                settings=self._settings,
                parse_subject=self._parse_subject,
            )
            return AuthenticationService(
                users=users,
                refresh_tokens=refresh_tokens,
                oauth_accounts=oauth_accounts,
                tokens=self._tokens,
                email_sender=self._email_sender,
                verification=verification,
                settings=self._settings,
                parse_subject=self._parse_subject,
            )

        async def get_verification_service(
            session: Annotated[AsyncSession, Depends(get_db_session)],
        ) -> EmailVerificationService[UserId]:
            return EmailVerificationService(
                users=SQLAlchemyUserRepository(session),
                tokens=self._tokens,
                email_sender=self._email_sender,
                settings=self._settings,
                parse_subject=self._parse_subject,
            )

        async def get_password_reset_service(
            session: Annotated[AsyncSession, Depends(get_db_session)],
        ) -> PasswordResetService[UserId]:
            return PasswordResetService(
                users=SQLAlchemyUserRepository(session),
                refresh_tokens=SQLAlchemyRefreshTokenRepository(session),
                tokens=self._tokens,
                email_sender=self._email_sender,
                settings=self._settings,
                parse_subject=self._parse_subject,
            )

        self.get_db_session: Callable[..., AsyncIterator[AsyncSession]] = get_db_session
        self.get_authentication_service: Callable[..., Awaitable[AuthenticationService[UserId]]] = (
            get_authentication_service
        )
        self.get_verification_service: Callable[
            ..., Awaitable[EmailVerificationService[UserId]]
        ] = get_verification_service
        self.get_password_reset_service: Callable[..., Awaitable[PasswordResetService[UserId]]] = (
            get_password_reset_service
        )

        current_user = make_current_user_dependencies(self.get_authentication_service)
        self.get_current_user = current_user.get_current_user
        self.get_current_active_user = current_user.get_current_active_user
        self.get_current_verified_user = current_user.get_current_verified_user
        self.CurrentUser = current_user.CurrentUser
        self.CurrentActiveUser = current_user.CurrentActiveUser
        self.CurrentVerifiedUser = current_user.CurrentVerifiedUser

    @property
    def token_service(self) -> TokenService:
        """The configured token service (e.g. for OAuth state minting)."""
        return self._tokens

    @property
    def settings(self) -> AuthSettings:
        """The configured settings."""
        return self._settings

    def get_user_repository(self, session: "AsyncSession") -> "SQLAlchemyUserRepository":
        """User repository bound to ``session`` (for direct/off-HTTP use)."""
        from blenx_auth.sqlalchemy.repositories import SQLAlchemyUserRepository

        return SQLAlchemyUserRepository(session)

    def get_refresh_token_repository(
        self, session: "AsyncSession"
    ) -> "SQLAlchemyRefreshTokenRepository":
        """Refresh-token repository bound to ``session`` (for direct/off-HTTP use)."""
        from blenx_auth.sqlalchemy.repositories import SQLAlchemyRefreshTokenRepository

        return SQLAlchemyRefreshTokenRepository(session)

    def get_oauth_account_repository(
        self, session: "AsyncSession"
    ) -> "SQLAlchemyOAuthAccountRepository":
        """OAuth-account repository bound to ``session`` (for direct/off-HTTP use)."""
        from blenx_auth.sqlalchemy.repositories import SQLAlchemyOAuthAccountRepository

        return SQLAlchemyOAuthAccountRepository(session)


class BeanieAuth(AuthBackend):
    """Composition root: Beanie/MongoDB backend wired to core services.

    Beanie binds its ``Document`` classes to one database globally (via
    :func:`blenx_auth.beanie.init_beanie_db` at startup), so repositories are
    shared instance state and the service dependencies take no session.
    """

    def __init__(
        self,
        *,
        settings: AuthSettings,
        email_sender: EmailSender | None = None,
        parse_subject: "Callable[[str], PydanticObjectId] | None" = None,
    ) -> None:
        from beanie import PydanticObjectId
        from blenx_auth.beanie.repositories import (
            BeanieOAuthAccountRepository,
            BeanieRefreshTokenRepository,
            BeanieUserRepository,
        )

        if parse_subject is None:
            parse_subject = PydanticObjectId

        self._settings = settings
        self._email_sender: EmailSender = email_sender or NullEmailSender()
        self._parse_subject = parse_subject
        self._tokens = TokenService(settings)
        self._users = BeanieUserRepository()
        self._refresh_tokens = BeanieRefreshTokenRepository()
        self._oauth_accounts = BeanieOAuthAccountRepository()

        async def get_authentication_service() -> AuthenticationService[PydanticObjectId]:
            verification = EmailVerificationService(
                users=self._users,
                tokens=self._tokens,
                email_sender=self._email_sender,
                settings=self._settings,
                parse_subject=self._parse_subject,
            )
            return AuthenticationService(
                users=self._users,
                refresh_tokens=self._refresh_tokens,
                oauth_accounts=self._oauth_accounts,
                tokens=self._tokens,
                email_sender=self._email_sender,
                verification=verification,
                settings=self._settings,
                parse_subject=self._parse_subject,
            )

        async def get_verification_service() -> EmailVerificationService[PydanticObjectId]:
            return EmailVerificationService(
                users=self._users,
                tokens=self._tokens,
                email_sender=self._email_sender,
                settings=self._settings,
                parse_subject=self._parse_subject,
            )

        async def get_password_reset_service() -> PasswordResetService[PydanticObjectId]:
            return PasswordResetService(
                users=self._users,
                refresh_tokens=self._refresh_tokens,
                tokens=self._tokens,
                email_sender=self._email_sender,
                settings=self._settings,
                parse_subject=self._parse_subject,
            )

        self.get_authentication_service: Callable[
            ..., Awaitable[AuthenticationService[PydanticObjectId]]
        ] = get_authentication_service
        self.get_verification_service: Callable[
            ..., Awaitable[EmailVerificationService[PydanticObjectId]]
        ] = get_verification_service
        self.get_password_reset_service: Callable[
            ..., Awaitable[PasswordResetService[PydanticObjectId]]
        ] = get_password_reset_service

        current_user = make_current_user_dependencies(self.get_authentication_service)
        self.get_current_user = current_user.get_current_user
        self.get_current_active_user = current_user.get_current_active_user
        self.get_current_verified_user = current_user.get_current_verified_user
        self.CurrentUser = current_user.CurrentUser
        self.CurrentActiveUser = current_user.CurrentActiveUser
        self.CurrentVerifiedUser = current_user.CurrentVerifiedUser

    @property
    def token_service(self) -> TokenService:
        """The configured token service (e.g. for OAuth state minting)."""
        return self._tokens

    @property
    def settings(self) -> AuthSettings:
        """The configured settings."""
        return self._settings

    def get_user_repository(self) -> "BeanieUserRepository":
        """User repository (direct/off-HTTP use)."""
        return self._users

    def get_refresh_token_repository(self) -> "BeanieRefreshTokenRepository":
        """Refresh-token repository (direct/off-HTTP use)."""
        return self._refresh_tokens

    def get_oauth_account_repository(self) -> "BeanieOAuthAccountRepository":
        """OAuth-account repository (direct/off-HTTP use)."""
        return self._oauth_accounts


__all__ = ["BeanieAuth", "SQLAlchemyAuth"]
