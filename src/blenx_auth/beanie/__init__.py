"""Beanie (MongoDB) adapter for ``blenx_auth``.

MongoDB-native backend: documents, CRUD repositories, and the
:func:`init_beanie_db` helper implement the ports in
:mod:`blenx_auth.core.ports`, so the same core services run on MongoDB with
``ObjectId`` identity.

OAuth identities and passkeys are embedded in the ``User`` document
(:class:`OAuthAccountEmbedded`, :class:`PasskeyEmbedded`); refresh tokens
remain a top-level document.
"""

from blenx_auth.beanie.bootstrap import DOCUMENT_MODELS, init_beanie_db
from blenx_auth.beanie.models import OAuthAccountEmbedded, PasskeyEmbedded, RefreshToken, User
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
    "OAuthAccountEmbedded",
    "PasskeyEmbedded",
    "RefreshToken",
    "User",
    "init_beanie_db",
]
