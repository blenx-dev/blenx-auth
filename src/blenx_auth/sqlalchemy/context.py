"""SQLAlchemy storage context: composed ``User`` table + core repositories.

A storage context has exactly two responsibilities (see
:mod:`blenx_auth.core.storage`):

1. **Model building** — compose the ``user`` ``Table`` on the shared
   ``AuthBase.metadata`` from :data:`CORE_USER_COLUMNS` plus every plugin's
   ``sqla_columns`` and the consumer columns, register plugin ``sqla_tables``,
   then map the ORM ``User`` directly to the composed table and rebuild the
   ``RefreshToken`` / ``OAuthAccount`` mapped classes on the same registry.
2. **Repository building** — construct the three core repositories, each with
   its own lazy session from ``session_factory`` (per decision D1: per-repo
   singleton sessions; every mutation commits immediately).

Teardown is last-composition-wins (as today): the shared registry is disposed
and prior tables dropped before re-composing, so calling ``build_auth`` twice
on one registry remaps cleanly.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, Any, Literal, cast

from blenx_auth.core.plugins import AuthPlugin, resolve_plugin_order
from blenx_auth.core.settings import AuthSettings
from blenx_auth.sqlalchemy.base import AuthBase
from blenx_auth.sqlalchemy.metadata import (
    CORE_USER_COLUMNS,
    build_composed_user_table,
    map_user_model,
    register_extra_tables,
)
from blenx_auth.sqlalchemy.models import (
    make_oauth_account_model,
    make_refresh_token_model,
)
from blenx_auth.sqlalchemy.repositories import (
    SQLAlchemyOAuthAccountRepository,
    SQLAlchemyRefreshTokenRepository,
    SQLAlchemyUserRepository,
)

if TYPE_CHECKING:
    from sqlalchemy import Column, MetaData
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker


class SqlaStorageContext:
    """Compose the SQLAlchemy model family and build the core repositories."""

    backend: Literal["sqlalchemy"] = "sqlalchemy"

    def __init__(
        self,
        *,
        settings: AuthSettings,
        session_factory: async_sessionmaker[AsyncSession],
        plugins: Sequence[AuthPlugin] = (),
        consumer_table_columns: Sequence[Column[Any]] = (),
        tablename: str = "user",
    ) -> None:
        self._settings = settings
        self._session_factory = session_factory
        self._plugins = resolve_plugin_order(plugins)

        # Teardown (last-composition-wins): dispose the mapper registry and drop
        # every prior table so a re-composition cannot collide with the old map.
        registry = cast(Any, AuthBase).registry
        registry.dispose()
        metadata = AuthBase.metadata
        for table in list(metadata.tables.values()):
            metadata.remove(table)

        plugin_columns = [(p.name, p.sqla_columns) for p in self._plugins if p.sqla_columns]
        plugin_tables = [table for p in self._plugins for table in p.sqla_tables]

        user_table = build_composed_user_table(
            metadata=metadata,
            tablename=tablename,
            core_columns=CORE_USER_COLUMNS,
            plugin_columns=plugin_columns,
            consumer_columns=consumer_table_columns,
        )
        register_extra_tables(metadata=metadata, plugin_tables=plugin_tables)

        # Map the composed user table, then rebuild the related models so the
        # whole family shares one registry and their FKs resolve to the table.
        self._user_model = map_user_model(user_table, AuthBase)
        self._refresh_model = make_refresh_token_model(AuthBase)
        self._oauth_model = make_oauth_account_model(AuthBase)

        self._user_repo = SQLAlchemyUserRepository(session_factory(), model=self._user_model)
        self._refresh_repo = SQLAlchemyRefreshTokenRepository(
            session_factory(), model=self._refresh_model
        )
        self._oauth_repo = SQLAlchemyOAuthAccountRepository(
            session_factory(), model=self._oauth_model
        )

    @property
    def user_model(self) -> type:
        return self._user_model

    @property
    def refresh_model(self) -> type:
        return self._refresh_model

    @property
    def oauth_model(self) -> type:
        return self._oauth_model

    @property
    def metadata(self) -> MetaData:
        return AuthBase.metadata

    def new_session(self) -> AsyncSession:
        """Open a fresh session from ``session_factory`` (caller owns it)."""
        return self._session_factory()

    def build_user_repository(self) -> SQLAlchemyUserRepository:
        return self._user_repo

    def build_refresh_token_repository(self) -> SQLAlchemyRefreshTokenRepository:
        return self._refresh_repo

    def build_oauth_account_repository(self) -> SQLAlchemyOAuthAccountRepository:
        return self._oauth_repo


__all__ = ["SqlaStorageContext"]
