"""Async SQLAlchemy session factory helper.

This module provides ``create_session_factory`` so host applications can build
their own ``async_sessionmaker`` without importing FastAPI.
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)


def create_session_factory(
    database_url: str, *, debug: bool = False
) -> async_sessionmaker[AsyncSession]:
    """Build an async session factory for ``database_url``.

    ``debug`` controls SQL echo. The caller owns the engine lifecycle;
    ``async_sessionmaker`` does not hold a strong reference to it after
    creation, so the engine should be passed via the factory's ``bind``.
    """
    engine = create_async_engine(database_url, echo=debug, pool_pre_ping=True)
    return async_sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
    )
