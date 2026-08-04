"""Beanie storage context: composed ``User`` document + core repositories.

A storage context has exactly two responsibilities (see
:mod:`blenx_auth.core.storage`):

1. **Model building** — compose the ``User`` ``Document`` from the base
   ``User`` plus every plugin's ``beanie_mixin`` and the consumer document
   mixin (cached by :func:`build_beanie_model`), and collect the plugin
   ``beanie_documents`` that :meth:`all_documents` exposes for ``init_beanie``.
2. **Repository building** — construct the three core repositories, each bound
   to the composed user document / the ``RefreshToken`` document.

OAuth identities live embedded in the composed user document, so the OAuth
repository reads/updates the ``oauth_accounts`` array rather than a separate
collection.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Literal, NoReturn

from blenx_auth.beanie.models import RefreshToken
from blenx_auth.beanie.models import User as BeanieUser
from blenx_auth.beanie.repositories import (
    BeanieOAuthAccountRepository,
    BeanieRefreshTokenRepository,
    BeanieUserRepository,
)
from blenx_auth.core.plugins import AuthPlugin, resolve_plugin_order
from blenx_auth.core.settings import AuthSettings
from blenx_auth.fastapi.class_builder_beanie import build_beanie_model


class BeanieStorageContext:
    """Compose the Beanie document family and build the core repositories."""

    backend: Literal["beanie"] = "beanie"

    def __init__(
        self,
        *,
        settings: AuthSettings,
        plugins: Sequence[AuthPlugin] = (),
        consumer_document_mixin: type | None = None,
    ) -> None:
        self._settings = settings
        self._plugins = resolve_plugin_order(plugins)

        mixins: list[type] = [p.beanie_mixin for p in self._plugins if p.beanie_mixin is not None]
        if consumer_document_mixin is not None:
            mixins.append(consumer_document_mixin)

        self._user_model = build_beanie_model("User", BeanieUser, mixins)
        self._plugin_documents = tuple(doc for p in self._plugins for doc in p.beanie_documents)

        self._user_repo = BeanieUserRepository(model=self._user_model)
        self._refresh_repo = BeanieRefreshTokenRepository()
        self._oauth_repo = BeanieOAuthAccountRepository(model=self._user_model)

    @property
    def user_model(self) -> type:
        return self._user_model

    @property
    def metadata(self) -> None:
        return None

    def new_session(self) -> NoReturn:
        raise NotImplementedError(
            "Beanie has no session concept; persist plugin state via "
            "`deps.storage_context.all_documents()` and the document models."
        )

    def all_documents(self) -> tuple[type, ...]:
        """Every ``Document`` class a host app must register on ``init_beanie``."""
        return (self._user_model, RefreshToken, *self._plugin_documents)

    def build_user_repository(self) -> BeanieUserRepository:
        return self._user_repo

    def build_refresh_token_repository(self) -> BeanieRefreshTokenRepository:
        return self._refresh_repo

    def build_oauth_account_repository(self) -> BeanieOAuthAccountRepository:
        return self._oauth_repo


__all__ = ["BeanieStorageContext"]
