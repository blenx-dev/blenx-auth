"""Tests for ``SqlaStorageContext``: model composition + repo wiring.

These drive real CRUD through the context-built repositories on an in-memory
SQLite engine (StaticPool), and verify the model-composition surface: plugin
``sqla_columns`` land on the composed ``User``, plugin ``sqla_tables`` are
registered on the shared metadata, and a second context on one registry remaps
cleanly (last-composition-wins teardown).
"""

from __future__ import annotations

from datetime import datetime

from blenx_auth.core.dto import NewOAuthLink, NewUser
from blenx_auth.core.plugins import AuthPlugin
from blenx_auth.core.settings import AuthSettings
from blenx_auth.sqlalchemy.context import SqlaStorageContext

from sqlalchemy import Boolean, Column, Integer, MetaData, String, Table
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import StaticPool


class Settings(AuthSettings):
    secret_key = "x" * 32


def _make_engine_and_factory() -> tuple[AsyncEngine, async_sessionmaker[AsyncSession]]:
    engine = create_async_engine(
        "sqlite+aiosqlite://",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    factory = async_sessionmaker(
        bind=engine, class_=AsyncSession, expire_on_commit=False, autoflush=False
    )
    return engine, factory


async def _create_all(engine: AsyncEngine, context: SqlaStorageContext) -> None:
    async with engine.begin() as conn:
        await conn.run_sync(context.metadata.create_all)


async def test_user_repository_crud_through_context() -> None:
    engine, factory = _make_engine_and_factory()
    context = SqlaStorageContext(settings=Settings(), session_factory=factory)
    await _create_all(engine, context)

    repo = context.build_user_repository()
    user = await repo.create(NewUser(email="a@example.com", hashed_password="h"))
    assert await repo.get_by_email("a@example.com") is not None
    assert (await repo.get_by_id(user.id)).id == user.id

    user.is_verified = True
    await repo.save(user)
    assert (await repo.get_by_email("a@example.com")).is_verified is True
    assert context.user_model is repo._model
    await engine.dispose()


async def test_refresh_and_oauth_repositories_through_context() -> None:
    engine, factory = _make_engine_and_factory()
    context = SqlaStorageContext(settings=Settings(), session_factory=factory)
    await _create_all(engine, context)

    users = context.build_user_repository()
    refresh = context.build_refresh_token_repository()
    oauth = context.build_oauth_account_repository()

    user = await users.create(NewUser(email="o@example.com", hashed_password="h"))
    token = await refresh.create(user_id=user.id, token_hash="hash-1", expires_at=datetime.now())
    assert (await refresh.get_by_hash("hash-1")).id == token.id
    await refresh.revoke(token.id)
    assert (await refresh.get_by_hash("hash-1")).revoked_at is not None

    link = await oauth.link(
        NewOAuthLink(
            provider="google",
            account_id="sub-1",
            account_email="o@example.com",
            user_id=user.id,
            access_token="at",
        )
    )
    found = await oauth.get_by_provider_account("google", "sub-1")
    assert found is not None and found.id == link.id
    await oauth.refresh_token(link.id, access_token="at-2", expires_at=2)
    refreshed = await oauth.get_by_provider_account("google", "sub-1")
    assert refreshed.access_token == "at-2"
    await engine.dispose()


def test_plugin_columns_and_tables_land_on_context() -> None:
    otp_table = Table("otp_codes", MetaData(), Column("id", Integer, primary_key=True))
    plugin = AuthPlugin(
        name="two_factor",
        sqla_columns=(Column("is_2fa_enabled", Boolean, default=False),),
        sqla_tables=(otp_table,),
    )
    context = SqlaStorageContext(
        settings=Settings(), session_factory=_make_engine_and_factory()[1], plugins=[plugin]
    )

    assert "is_2fa_enabled" in context.user_model.__table__.columns
    assert "otp_codes" in context.metadata.tables


def test_recomposition_is_idempotent() -> None:
    plugin = AuthPlugin(name="p", sqla_columns=(Column("nickname", String),))
    first = SqlaStorageContext(
        settings=Settings(), session_factory=_make_engine_and_factory()[1], plugins=[plugin]
    )
    assert "nickname" in first.user_model.__table__.columns

    # A second context on the same registry disposes the first and remaps cleanly.
    second = SqlaStorageContext(
        settings=Settings(), session_factory=_make_engine_and_factory()[1], plugins=[plugin]
    )
    assert "nickname" in second.user_model.__table__.columns
    assert "user" in second.metadata.tables
    assert first.metadata is second.metadata
