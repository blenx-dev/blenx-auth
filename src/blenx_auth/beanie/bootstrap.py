"""Beanie document-registration helper (no FastAPI dependency).

``init_beanie`` is a thin wrapper around ``beanie.init_beanie`` that registers
the auth documents against a caller-supplied Motor client/database. Host apps
that already create their own ``AsyncIOMotorClient`` can pass its database here
and keep a single Mongo client for the whole app.
"""

from __future__ import annotations

from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from beanie import init_beanie
from blenx_auth.beanie.models import RefreshToken, User

DOCUMENT_MODELS = (User, RefreshToken)


async def init_beanie_db(database: AsyncIOMotorDatabase[Any]) -> None:
    """Register the auth ``Document`` classes on ``database``."""
    await init_beanie(database=database, document_models=DOCUMENT_MODELS)
