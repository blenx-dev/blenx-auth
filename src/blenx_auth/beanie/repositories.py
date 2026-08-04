"""Beanie-backed repository implementations of the core ports (CRUD only).

CRUD only — no authentication or lockout policy lives here. Policy decisions
(``login``, lockouts, rotation, verification) are made by the services, which
mutate the fetched ``Document`` and call ``save`` to persist, exactly as they
do with the SQLAlchemy repositories.

Identity is ``PydanticObjectId`` (Mongo's native ``_id``); each repository
drives every query from the ``_model`` class attribute.

A duplicate ``create`` surfaces a ``pymongo.errors.DuplicateKeyError`` (the
MongoDB analogue of SQLAlchemy's ``IntegrityError``); it is translated here
into the domain :class:`EmailAlreadyExistsError` so every backend behaves
identically under a concurrent-insert race.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import cast

from pymongo.errors import DuplicateKeyError

from beanie import Document, PydanticObjectId
from blenx_auth.beanie.models import OAuthAccount, RefreshToken, User
from blenx_auth.core.dto import NewOAuthLink, NewUser
from blenx_auth.core.exceptions import EmailAlreadyExistsError, UserModelMappingError
from blenx_auth.core.ports import (
    OAuthAccountRepository,
    RefreshTokenRepository,
    UserAccount,
    UserRepository,
)


class BeanieUserRepository(UserRepository[PydanticObjectId]):
    """User CRUD bound to a ``User`` document.

    ``model`` is injectable so the composition root can point the repository at
    its composed document (base + plugin/consumer mixins).
    """

    _model: type[Document] = User

    def __init__(self, model: type[Document] | None = None) -> None:
        if model is not None:
            self._model = model

    async def get_by_email(self, email: str) -> User | None:
        return cast(User | None, await self._model.find_one({"email": email}))

    async def get_by_id(self, user_id: PydanticObjectId) -> User | None:
        return cast(User | None, await self._model.find_one({"_id": user_id}))

    async def create(self, data: NewUser) -> User:
        extra_fields = self._validated_extra_fields(data.extra_fields)
        user = self._model(
            email=data.email,
            hashed_password=data.hashed_password,
            is_verified=data.is_verified,
            is_superuser=data.is_superuser,
            birthdate=data.birthdate,
            **extra_fields,
        )
        try:
            await user.insert()
        except DuplicateKeyError as exc:
            raise EmailAlreadyExistsError() from exc
        return cast(User, user)

    async def save(self, user: UserAccount[PydanticObjectId]) -> None:
        """Persist mutations made by the service on a fetched document."""
        await cast(Document, user).save()

    def _validated_extra_fields(self, extra: dict[str, object]) -> dict[str, object]:
        model_fields = set(self._model.model_fields.keys())
        unknown = set(extra) - model_fields
        if unknown:
            raise UserModelMappingError(sorted(unknown)[0])
        return dict(extra)


class BeanieRefreshTokenRepository(RefreshTokenRepository[PydanticObjectId]):
    """Refresh-token CRUD bound to a ``RefreshToken`` document.

    ``model`` is injectable for the composition root's rebuilt document family.
    """

    _model: type[Document] = RefreshToken

    def __init__(self, model: type[Document] | None = None) -> None:
        if model is not None:
            self._model = model

    async def create(
        self,
        *,
        user_id: PydanticObjectId,
        token_hash: str,
        expires_at: datetime,
        device_name: str | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> RefreshToken:
        token = self._model(
            user_id=user_id,
            token_hash=token_hash,
            expires_at=expires_at,
            device_name=device_name,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        await token.insert()
        return cast(RefreshToken, token)

    async def get_by_hash(self, token_hash: str) -> RefreshToken | None:
        return cast(RefreshToken | None, await self._model.find_one({"token_hash": token_hash}))

    async def revoke(self, token_id: PydanticObjectId) -> None:
        """Idempotently mark a single refresh token revoked."""
        await self._model.find_one({"_id": token_id, "revoked_at": None}).update(
            {"$set": {"revoked_at": datetime.now(UTC)}}
        )

    async def revoke_all_for_user(self, user_id: PydanticObjectId) -> None:
        """Revoke every outstanding refresh token belonging to ``user_id``."""
        await self._model.find({"user_id": user_id, "revoked_at": None}).update(
            {"$set": {"revoked_at": datetime.now(UTC)}}
        )


class BeanieOAuthAccountRepository(OAuthAccountRepository[PydanticObjectId]):
    """OAuth-account CRUD bound to a ``OAuthAccount`` document.

    ``model`` is injectable for the composition root's rebuilt document family.
    """

    _model: type[Document] = OAuthAccount

    def __init__(self, model: type[Document] | None = None) -> None:
        if model is not None:
            self._model = model

    async def get_by_provider_account(self, provider: str, account_id: str) -> OAuthAccount | None:
        return cast(
            OAuthAccount | None,
            await self._model.find_one({"oauth_name": provider, "account_id": account_id}),
        )

    async def link(self, data: NewOAuthLink[PydanticObjectId]) -> OAuthAccount:
        account = self._model(
            oauth_name=data.provider,
            account_id=data.account_id,
            account_email=data.account_email,
            user_id=data.user_id,
            access_token=data.access_token,
            expires_at=data.expires_at,
            refresh_token=data.refresh_token,
        )
        await account.insert()
        return cast(OAuthAccount, account)

    async def refresh_token(
        self, account_id: PydanticObjectId, *, access_token: str, expires_at: int | None
    ) -> None:
        """Persist a refreshed provider access token on an existing link."""
        await self._model.find_one({"_id": account_id}).update(
            {"$set": {"access_token": access_token, "expires_at": expires_at}}
        )


__all__ = [
    "BeanieOAuthAccountRepository",
    "BeanieRefreshTokenRepository",
    "BeanieUserRepository",
]
