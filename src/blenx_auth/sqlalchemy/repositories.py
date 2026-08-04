"""SQLAlchemy-backed repositories implementing the core ports (CRUD only)."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from blenx_auth.core.dto import NewOAuthLink, NewUser
from blenx_auth.core.exceptions import EmailAlreadyExistsError
from blenx_auth.core.ports import (
    OAuthAccountRepository,
    RefreshTokenRepository,
    UserAccount,
    UserRepository,
)
from blenx_auth.sqlalchemy.base import UserId
from blenx_auth.sqlalchemy.models import OAuthAccount, RefreshToken, User
from sqlalchemy import select, update


class SQLAlchemyOAuthAccountRepository(OAuthAccountRepository[UserId]):
    """OAuth-account CRUD bound to a single request session."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_provider_account(self, provider: str, account_id: str) -> OAuthAccount | None:
        result = await self._session.scalars(
            select(OAuthAccount).where(
                OAuthAccount.oauth_name == provider,
                OAuthAccount.account_id == account_id,
            )
        )
        return result.one_or_none()

    async def link(self, data: NewOAuthLink[UserId]) -> OAuthAccount:
        account = OAuthAccount(
            oauth_name=data.provider,
            account_id=data.account_id,
            account_email=data.account_email,
            user_id=data.user_id,
            access_token=data.access_token,
            expires_at=data.expires_at,
            refresh_token=data.refresh_token,
        )
        self._session.add(account)
        await self._session.commit()
        await self._session.refresh(account)
        return account

    async def refresh_token(
        self, account_id: UserId, *, access_token: str, expires_at: int | None
    ) -> None:
        """Persist a refreshed provider access token on an existing link."""
        await self._session.execute(
            update(OAuthAccount)
            .where(OAuthAccount.id == account_id)
            .values(access_token=access_token, expires_at=expires_at)
        )
        await self._session.commit()


class SQLAlchemyRefreshTokenRepository(RefreshTokenRepository[UserId]):
    """Refresh-token CRUD bound to a single request session."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(
        self,
        *,
        user_id: UserId,
        token_hash: str,
        expires_at: datetime,
        device_name: str | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> RefreshToken:
        token = RefreshToken(
            user_id=user_id,
            token_hash=token_hash,
            expires_at=expires_at,
            device_name=device_name,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        self._session.add(token)
        await self._session.commit()
        await self._session.refresh(token)
        return token

    async def get_by_hash(self, token_hash: str) -> RefreshToken | None:
        result = await self._session.scalars(
            select(RefreshToken).where(RefreshToken.token_hash == token_hash)
        )
        return result.one_or_none()

    async def revoke(self, token_id: UserId) -> None:
        """Idempotently mark a single refresh token revoked."""
        await self._session.execute(
            update(RefreshToken)
            .where(RefreshToken.id == token_id, RefreshToken.revoked_at.is_(None))
            .values(revoked_at=datetime.now(UTC))
        )
        await self._session.commit()

    async def revoke_all_for_user(self, user_id: UserId) -> None:
        """Revoke every outstanding refresh token belonging to ``user_id``."""
        await self._session.execute(
            update(RefreshToken)
            .where(RefreshToken.user_id == user_id, RefreshToken.revoked_at.is_(None))
            .values(revoked_at=datetime.now(UTC))
        )
        await self._session.commit()


class SQLAlchemyUserRepository(UserRepository[UserId]):
    """User CRUD bound to a single request session.

    CRUD only — no authentication or lockout policy lives here. Policy
    decisions (``login``, lockouts, verification) are made by the services,
    which mutate the fetched ``User`` and call :meth:`save` to persist.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_email(self, email: str) -> User | None:
        result = await self._session.scalars(select(User).where(User.email == email))
        return result.one_or_none()

    async def get_by_id(self, user_id: UserId) -> User | None:
        return await self._session.get(User, user_id)

    async def create(self, data: NewUser) -> User:
        """Insert a new user.

        Email uniqueness is enforced by the unique index. A concurrent
        duplicate surfaces as ``sqlalchemy.exc.IntegrityError``, which is
        translated here into the domain :class:`EmailAlreadyExistsError` so the
        registration service and every backend behave identically under a race.
        """
        user = User(
            email=data.email,
            hashed_password=data.hashed_password,
            is_verified=data.is_verified,
            is_superuser=data.is_superuser,
            birthdate=data.birthdate,
        )
        try:
            self._session.add(user)
            await self._session.commit()
        except IntegrityError as exc:
            await self._session.rollback()
            raise EmailAlreadyExistsError() from exc
        await self._session.refresh(user)
        return user

    async def save(self, user: UserAccount[UserId]) -> None:
        """Persist any pending changes to ``user``.

        ``user`` is an ORM instance already tracked by this session (it was
        fetched via ``get_by_*`` or ``create``), so committing the session
        flushes its mutated mapped attributes.
        """
        self._session.add(user)
        await self._session.commit()
