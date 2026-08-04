"""Tests for ``BeanieStorageContext``: document composition + repo wiring.

These need a reachable MongoDB (``MOTOR_URI``, defaulting to
``mongodb://localhost:27017``) and are skipped when none is available, mirroring
the other Beanie suites. They exercise the composed-document cache, the
``all_documents`` set, and real CRUD through the context-built repositories —
including the embedded-OAuth link/refresh flow.

The DB-backed tests each init Beanie with the *same* cached no-plugin composed
``User`` class (the class cache is intentionally left intact across them) and
drop the database for data isolation; ``reset_beanie_model_cache`` is exercised
only by the cache test itself.
"""

from __future__ import annotations

import os

import pytest
from blenx_auth.beanie.bootstrap import init_beanie_db
from blenx_auth.beanie.context import BeanieStorageContext
from blenx_auth.core.dto import NewOAuthLink, NewUser
from blenx_auth.core.plugins import AuthPlugin
from blenx_auth.core.settings import AuthSettings
from blenx_auth.fastapi.class_builder_beanie import reset_beanie_model_cache
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import MongoClient

from beanie import Document, PydanticObjectId

MOTOR_URI = os.environ.get("MOTOR_URI", "mongodb://localhost:27017")
DB_NAME = "blenx_auth_context_test"


def _mongo_available() -> bool:
    try:
        MongoClient(MOTOR_URI, serverSelectionTimeoutMS=1200).admin.command("ping")
        return True
    except Exception:  # noqa: BLE001 - any failure means no server to test against
        return False


pytestmark = pytest.mark.skipif(not _mongo_available(), reason="No reachable MongoDB server")


class Settings(AuthSettings):
    secret_key = "x" * 32


class FavColorMixin:
    favorite_color: str | None = None


class ExtraDocument(Document):
    value: str

    class Settings:
        name = "extra_documents"


async def _init_db() -> tuple[AsyncIOMotorClient, BeanieStorageContext]:
    client = AsyncIOMotorClient(MOTOR_URI)
    await client.drop_database(DB_NAME)
    context = BeanieStorageContext(settings=Settings())
    await init_beanie_db(database=client[DB_NAME])
    return client, context


async def test_user_repository_crud_through_context() -> None:
    client, context = await _init_db()

    repo = context.build_user_repository()
    user = await repo.create(NewUser(email="a@example.com", hashed_password="h"))
    assert isinstance(user.id, PydanticObjectId)
    assert await repo.get_by_email("a@example.com") is not None

    user.is_verified = True
    await repo.save(user)
    assert (await repo.get_by_email("a@example.com")).is_verified is True
    assert context.user_model is repo._model
    client.close()


async def test_embedded_oauth_link_and_refresh_through_context() -> None:
    client, context = await _init_db()

    users = context.build_user_repository()
    oauth = context.build_oauth_account_repository()

    user = await users.create(NewUser(email="o@example.com", hashed_password="h"))
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
    client.close()


def test_composes_user_with_plugin_mixin_and_documents() -> None:
    plugin = AuthPlugin(
        name="favorite_color",
        beanie_mixin=FavColorMixin,
        beanie_documents=(ExtraDocument,),
    )
    context = BeanieStorageContext(settings=Settings(), plugins=[plugin])

    assert "favorite_color" in context.user_model.model_fields
    docs = context.all_documents()
    assert context.user_model in docs
    assert ExtraDocument in docs
    assert any(getattr(d, "Settings", None) and d.Settings.name == "refresh_tokens" for d in docs)


def test_cache_returns_same_class_and_reset_rebuilds() -> None:
    plugin = AuthPlugin(name="favorite_color", beanie_mixin=FavColorMixin)
    first = BeanieStorageContext(settings=Settings(), plugins=[plugin])
    second = BeanieStorageContext(settings=Settings(), plugins=[plugin])
    assert first.user_model is second.user_model

    reset_beanie_model_cache()
    third = BeanieStorageContext(settings=Settings(), plugins=[plugin])
    assert third.user_model is not first.user_model
