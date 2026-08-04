"""SQLAlchemy (PostgreSQL) adapter for ``blenx_auth``.

This is the **default** backend. It provides the ORM models, the CRUD
repository classes, and the ``create_session_factory`` helper that implement the
ports in :mod:`blenx_auth.core.ports`, so the same core services (register,
login, refresh rotation, OAuth link, password reset) run on PostgreSQL.

Identity is fixed to ``uuid.UUID`` (``UserId``), the natural PostgreSQL key
type; Mongo-native ``ObjectId`` identity belongs to the Beanie adapter.
"""

from blenx_auth.sqlalchemy.base import AuthBase, UserId
from blenx_auth.sqlalchemy.models import OAuthAccount, RefreshToken, User
from blenx_auth.sqlalchemy.repositories import (
    SQLAlchemyOAuthAccountRepository,
    SQLAlchemyRefreshTokenRepository,
    SQLAlchemyUserRepository,
)
from blenx_auth.sqlalchemy.session import create_session_factory

__all__ = [
    "AuthBase",
    "OAuthAccount",
    "RefreshToken",
    "SQLAlchemyOAuthAccountRepository",
    "SQLAlchemyRefreshTokenRepository",
    "SQLAlchemyUserRepository",
    "User",
    "UserId",
    "create_session_factory",
]
