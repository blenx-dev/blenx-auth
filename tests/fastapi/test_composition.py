"""Integration tests for the composition root (Task 6).

These prove Tasks 1–5 end-to-end on the real ``SQLAlchemyAuth`` root: plugins
fold their table/read mixins into ``User`` / ``UserRead``, collisions raise at
construction, ``overrides`` resolve them, dependency order is topological, and
plugin ``router_factory`` outputs land in ``auth.routers``.

Note on shared registry: every composed construction disposes the shared
``AuthBase`` registry and re-maps the whole family, so the zero-plugin
backward-compatibility smoke test runs first (it must not regress the static
``User`` path), and these tests never open a database session.
"""

from __future__ import annotations

from typing import Any

import pytest
from blenx_auth.core.plugins import AuthPlugin
from blenx_auth.core.plugins.collisions import FieldCollisionError
from blenx_auth.core.plugins.hooks import AuthHooks
from blenx_auth.core.settings import AuthSettings
from blenx_auth.fastapi.composition import SQLAlchemyAuth
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import Mapped, mapped_column

from fastapi import APIRouter
from sqlalchemy import Integer, String


class Settings(AuthSettings):
    secret_key = "x" * 32
    jwt_algorithm = "HS256"
    access_token_expire_minutes = 30
    refresh_token_expire_days = 30
    email_verification_token_expire_minutes = 1440
    password_reset_token_expire_minutes = 60
    max_failed_login_attempts = 3
    account_lockout_minutes = 15
    login_rate_limit_per_minute = 0
    frontend_url = "http://localhost:5173"
    backend_url = "http://localhost:8000"
    google_client_id = ""
    google_client_secret = ""


def _factory() -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(class_=AsyncSession)


# -- fake plugin building blocks -------------------------------------------


class FavColorTableMixin:
    favorite_color: Mapped[str] = mapped_column(String(20))


class FavColorTableMixinV2:
    favorite_color: Mapped[int] = mapped_column(Integer)


class FavColorReadMixin(BaseModel):
    favorite_color: str


class FavoriteColorPlugin(AuthPlugin):
    def __init__(self, **kwargs: Any) -> None:
        super().__init__(
            name="favorite_color",
            table_mixin=FavColorTableMixin,
            read_mixin=FavColorReadMixin,
            **kwargs,
        )


def test_zero_plugins_backward_compatible() -> None:
    auth = SQLAlchemyAuth(settings=Settings(), session_factory=_factory())
    assert "email" in auth.User.__table__.columns
    assert "id" in auth.UserRead.model_fields
    assert auth.UserAdminUpdate is not None
    # backward-compat: no plugin contributed routers -> auth + users only
    assert len(auth.routers) == 2


def test_plugin_table_and_read_mixins_land_on_model_and_schema() -> None:
    auth = SQLAlchemyAuth(
        settings=Settings(),
        session_factory=_factory(),
        plugins=[FavoriteColorPlugin()],
    )
    assert "favorite_color" in auth.User.__table__.columns
    assert "favorite_color" in auth.UserRead.model_fields


def test_plugin_consumer_field_collision_raises() -> None:
    class ConsumerFavColorTableMixin:
        favorite_color: Mapped[str] = mapped_column(String(30))

    with pytest.raises(FieldCollisionError):
        SQLAlchemyAuth(
            settings=Settings(),
            session_factory=_factory(),
            plugins=[FavoriteColorPlugin()],
            consumer_table_mixin=ConsumerFavColorTableMixin,
        )


def test_overrides_resolve_field_collision() -> None:
    class ConsumerFavColorTableMixin:
        favorite_color: Mapped[int] = mapped_column(Integer)

    auth = SQLAlchemyAuth(
        settings=Settings(),
        session_factory=_factory(),
        plugins=[FavoriteColorPlugin()],
        consumer_table_mixin=ConsumerFavColorTableMixin,
        overrides={"FavColorTableMixin": ConsumerFavColorTableMixin},
    )
    col = auth.User.__table__.columns["favorite_color"]
    assert isinstance(col.type, Integer)  # comes from the override, not the plugin


def test_plugin_dependency_order_is_resolved() -> None:
    class FavColorReadMixin2(BaseModel):
        favorite_shade: str

    class ShadeTableMixin:
        favorite_shade: Mapped[str] = mapped_column(String(20))

    plugin_a = FavoriteColorPlugin()
    plugin_b = AuthPlugin(
        name="shade",
        table_mixin=ShadeTableMixin,
        read_mixin=FavColorReadMixin2,
        depends_on=("favorite_color",),
    )

    auth = SQLAlchemyAuth(
        settings=Settings(),
        session_factory=_factory(),
        plugins=[plugin_b, plugin_a],  # deliberately reversed
    )
    assert "favorite_color" in auth.User.__table__.columns
    assert "favorite_shade" in auth.User.__table__.columns
    assert [p.name for p in auth._plugins] == ["favorite_color", "shade"]


def test_plugin_router_factory_contributes_router() -> None:
    def router_factory(config: Any) -> APIRouter:
        router = APIRouter()

        @router.post("/2fa/verify")
        async def verify() -> dict[str, bool]:
            return {"ok": True}

        return router

    auth = SQLAlchemyAuth(
        settings=Settings(),
        session_factory=_factory(),
        plugins=[
            AuthPlugin(
                name="two_factor",
                table_mixin=FavColorTableMixin,
                read_mixin=FavColorReadMixin,
                router_factory=router_factory,
                hooks=AuthHooks(),
            )
        ],
    )
    paths = [r.path for router in auth.routers for r in router.routes]
    assert "/2fa/verify" in paths
