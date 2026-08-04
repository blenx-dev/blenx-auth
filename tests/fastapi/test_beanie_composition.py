"""Composition tests for the Beanie (MongoDB) root: ``BeanieAuth``.

Mirrors :mod:`tests.fastapi.test_composition` for the Mongo backend. A plugin's
table/read/create mixins are plain pydantic fields here (not SQLAlchemy
``Mapped`` columns) and land on the composed ``User`` document and the composed
schemas; collisions raise at construction, ``overrides`` resolve them, plugin
``router_factory`` output lands in ``auth.routers``, and the end-to-end case
drives the composed root over HTTP on a real MongoDB so the repositories, the
routers, and the (model-fields based) contract check all compose.

They require a reachable MongoDB (``MOTOR_URI``, defaulting to
``mongodb://localhost:27017``); when none is reachable the module is skipped.
"""

from __future__ import annotations

import os
import secrets
from contextlib import asynccontextmanager
from typing import Any

import pytest
from blenx_auth.beanie.models import OAuthAccount, RefreshToken
from blenx_auth.core.exceptions import AuthError
from blenx_auth.core.jwt import TokenService
from blenx_auth.core.plugins import AuthPlugin
from blenx_auth.core.plugins.collisions import FieldCollisionError
from blenx_auth.core.services import UserService
from blenx_auth.core.settings import AuthSettings
from blenx_auth.fastapi.class_builder_beanie import build_beanie_model
from blenx_auth.fastapi.composition import BeanieAuth
from blenx_auth.fastapi.exception_handlers import auth_error_handler
from fastapi.testclient import TestClient
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel
from pymongo import MongoClient

from beanie import init_beanie
from fastapi import APIRouter, FastAPI

TEST_SECRET = secrets.token_hex(32)
MOTOR_URI = os.environ.get("MOTOR_URI", "mongodb://localhost:27017")


def _mongo_available() -> bool:
    try:
        MongoClient(MOTOR_URI, serverSelectionTimeoutMS=1200).admin.command("ping")
        return True
    except Exception:  # noqa: BLE001 - any failure means no server to test against
        return False


pytestmark = pytest.mark.skipif(not _mongo_available(), reason="No reachable MongoDB server")


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


# -- fake plugin building blocks (beanie-flavored: plain pydantic fields) ----


class FavColorTableMixin:
    favorite_color: str | None = None


class FavColorReadMixin(BaseModel):
    favorite_color: str | None = None


class FavColorCreateMixin(BaseModel):
    favorite_color: str | None = None


class FavoriteColorPlugin(AuthPlugin):
    def __init__(self, **kwargs: Any) -> None:
        super().__init__(
            name="favorite_color",
            table_mixin=FavColorTableMixin,
            read_mixin=FavColorReadMixin,
            create_mixin=FavColorCreateMixin,
            **kwargs,
        )


def test_zero_plugins_backward_compatible() -> None:
    auth = BeanieAuth(settings=Settings())
    assert "email" in auth.User.model_fields
    assert "id" in auth.UserRead.model_fields
    assert auth.UserAdminUpdate is not None
    # backward-compat: no plugin contributed routers -> auth + users only
    assert len(auth.routers) == 2


def test_plugin_mixins_land_on_document_and_schema() -> None:
    auth = BeanieAuth(settings=Settings(), plugins=[FavoriteColorPlugin()])
    assert "favorite_color" in auth.User.model_fields
    assert "favorite_color" in auth.UserRead.model_fields
    assert "favorite_color" in auth.UserCreate.model_fields


def test_plugin_consumer_field_collision_raises() -> None:
    class ConsumerFavColorTableMixin:
        favorite_color: str | None = None

    with pytest.raises(FieldCollisionError):
        BeanieAuth(
            settings=Settings(),
            plugins=[FavoriteColorPlugin()],
            consumer_table_mixin=ConsumerFavColorTableMixin,
        )


def test_overrides_resolve_field_collision() -> None:
    class ConsumerFavColorTableMixin:
        favorite_color: str | None = None

    auth = BeanieAuth(
        settings=Settings(),
        plugins=[FavoriteColorPlugin()],
        consumer_table_mixin=ConsumerFavColorTableMixin,
        overrides={"FavColorTableMixin": ConsumerFavColorTableMixin},
    )
    assert "favorite_color" in auth.User.model_fields


def test_plugin_router_factory_contributes_router() -> None:
    def router_factory(config: Any) -> APIRouter:
        router = APIRouter()

        @router.post("/favorite/me")
        async def favorite() -> dict[str, bool]:
            return {"ok": True}

        return router

    auth = BeanieAuth(
        settings=Settings(),
        plugins=[AuthPlugin(name="favorite_color", router_factory=router_factory)],
    )
    paths = [route.path for router in auth.routers for route in router.routes]
    assert "/favorite/me" in paths


def test_build_beanie_model_collision() -> None:
    from blenx_auth.beanie.models import User as BeanieUser

    class FirstMixin:
        favorite_color: str | None = None

    class SecondMixin:
        favorite_color: str | None = None

    with pytest.raises(FieldCollisionError):
        build_beanie_model("User", BeanieUser, [FirstMixin, SecondMixin])


async def test_service_dependencies_and_accessors() -> None:
    auth = BeanieAuth(settings=Settings(), plugins=[FavoriteColorPlugin()])

    assert isinstance(auth.token_service, TokenService)
    assert auth.settings is auth._settings
    assert auth.user_model is auth.User
    assert auth.plugin_router_config("favorite_color") is not None
    assert auth.plugin_router_config("missing") is None

    verification = await auth.get_verification_service()
    assert verification is not None
    password_reset = await auth.get_password_reset_service()
    assert password_reset is not None
    user_service = await auth.get_user_service()
    assert isinstance(user_service, UserService)

    assert auth.get_user_repository() is auth._users
    assert auth.get_refresh_token_repository() is auth._refresh_tokens
    assert auth.get_oauth_account_repository() is auth._oauth_accounts


def test_end_to_end_http_flow() -> None:
    sync_client = MongoClient(MOTOR_URI)
    sync_client.drop_database("blenx_auth_test")
    sync_client.close()

    motor = AsyncIOMotorClient(MOTOR_URI)
    database = motor.blenx_auth_test

    auth = BeanieAuth(settings=Settings(), plugins=[FavoriteColorPlugin()])

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await init_beanie(
            database=database,
            document_models=[auth.User, RefreshToken, OAuthAccount],
        )
        yield
        motor.close()

    app = FastAPI(lifespan=lifespan)
    app.add_exception_handler(AuthError, auth_error_handler)
    for router in auth.routers:
        app.include_router(router)

    with TestClient(app) as client:
        # register carries the plugin field into the composed document
        r = client.post(
            "/auth/register",
            json={"email": "ann@example.com", "password": "password-123", "favorite_color": "blue"},
        )
        assert r.status_code == 201
        assert r.json()["favorite_color"] == "blue"

        # login issues a real token
        r = client.post(
            "/auth/login",
            json={"email": "ann@example.com", "password": "password-123"},
        )
        assert r.status_code == 200
        access = r.json()["access_token"]

        # /users/me round-trips the composed field from MongoDB
        r = client.get("/users/me", headers={"Authorization": f"Bearer {access}"})
        assert r.status_code == 200
        assert r.json()["email"] == "ann@example.com"
        assert r.json()["favorite_color"] == "blue"
