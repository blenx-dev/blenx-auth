"""Beanie (MongoDB) adapter for ``blenx_auth``.

MongoDB-native backend: documents, CRUD repositories, and the
:func:`init_beanie_db` helper implement the ports in
:mod:`blenx_auth.core.ports`, so the same core services run on MongoDB with
``ObjectId`` identity.
"""

from blenx_auth.beanie.bootstrap import DOCUMENT_MODELS, init_beanie_db
from blenx_auth.beanie.models import OAuthAccount, RefreshToken, User
from blenx_auth.beanie.repositories import (
    BeanieOAuthAccountRepository,
    BeanieRefreshTokenRepository,
    BeanieUserRepository,
)

__all__ = [
    "BeanieOAuthAccountRepository",
    "BeanieRefreshTokenRepository",
    "BeanieUserRepository",
    "DOCUMENT_MODELS",
    "OAuthAccount",
    "RefreshToken",
    "User",
    "init_beanie_db",
]
