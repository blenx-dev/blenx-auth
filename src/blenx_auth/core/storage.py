"""Storage-context contract: the backend's only two responsibilities.

A storage context builds the composed User model **and** the core repositories
(User / RefreshToken / OAuthAccount). Everything else — services, routers,
hooks, schemas, composition — lives in ``build_auth`` (see
:mod:`blenx_auth.fastapi.composition`).

Plugin factories reach backend-specific persistence through this interface:

- :attr:`StorageContext.backend` tells a plugin which backend it is running on.
- :meth:`StorageContext.new_session` / :attr:`StorageContext.metadata` /
  :meth:`StorageContext.all_documents` let a plugin persist its own state (e.g.
  the two-factor OTP table/document) without importing a storage SDK itself.

The concrete implementations live in ``blenx_auth.sqlalchemy.context`` and
``blenx_auth.beanie.context``; this module is framework-free and imports no
storage SDK (SQLAlchemy/Beanie types appear only under ``TYPE_CHECKING``).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Literal, Protocol

from blenx_auth.core.ports import (
    OAuthAccountRepository,
    RefreshTokenRepository,
    UserRepository,
)

if TYPE_CHECKING:
    from sqlalchemy import MetaData
    from sqlalchemy.ext.asyncio import AsyncSession

StorageBackend = Literal["sqlalchemy", "beanie"]


class StorageContext(Protocol):
    """What every storage backend must provide to ``build_auth``.

    Exactly two responsibilities: model building and repository building.
    """

    backend: StorageBackend
    user_model: type

    def build_user_repository(self) -> UserRepository[Any]: ...

    def build_refresh_token_repository(self) -> RefreshTokenRepository[Any]: ...

    def build_oauth_account_repository(self) -> OAuthAccountRepository[Any]: ...

    # --- Backend-specific persistence hooks (symmetric surface) ------------

    def new_session(self) -> AsyncSession:
        """Open a session (SQLAlchemy only; the caller owns its lifetime)."""
        ...

    @property
    def metadata(self) -> MetaData | None:
        """The shared ``MetaData`` (SQLAlchemy) or ``None`` (Beanie)."""
        ...

    def all_documents(self) -> tuple[type, ...]:
        """Every Beanie ``Document`` class to register (Beanie only; ``()`` on
        SQLAlchemy)."""
        ...


__all__ = ["StorageBackend", "StorageContext"]
