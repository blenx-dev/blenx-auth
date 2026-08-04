"""Composition dependencies handed to every plugin factory.

``CoreDeps`` is the **only** input a plugin factory receives (besides the
``ServiceRegistry``): the composed User model, the merged hooks, the token
service, the email sender, and the storage context. Nothing else leaks into
plugin code, which keeps every plugin a pure function of ``(deps, registry)``.

``User`` is a plain ``type`` because the composed model is backend-specific
(a SQLAlchemy mapped class or a Beanie ``Document``); plugins that need typed
fields reach them through the model's column/field surface at runtime.
"""

from __future__ import annotations

from dataclasses import dataclass

from blenx_auth.core.jwt import TokenService
from blenx_auth.core.plugins.hooks import AuthHooks
from blenx_auth.core.ports import EmailSender
from blenx_auth.core.storage import StorageContext


@dataclass(frozen=True, slots=True)
class CoreDeps:
    """The shared context every plugin factory receives at composition time."""

    User: type
    hooks: AuthHooks
    token_service: TokenService
    email_sender: EmailSender
    storage_context: StorageContext


__all__ = ["CoreDeps"]
