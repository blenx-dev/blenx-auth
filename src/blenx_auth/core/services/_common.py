"""Shared helpers for the core services (not part of the public API)."""

from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import Any

from blenx_auth.core.dto import IdT
from blenx_auth.core.exceptions import InvalidTokenError


def parse_subject(subject: str, parse: Callable[[str], IdT]) -> IdT:
    """Convert a JWT ``sub`` claim back to the configured id type.

    A malformed subject means the token is bogus even though its signature
    verified; raise the same error the signature path would. ``parse`` is the
    adapter's ``str -> id`` mapping (``uuid.UUID`` for the SQLAlchemy adapter,
    ``bson.ObjectId`` for the Beanie adapter) — both raise ``ValueError``
    on garbage input.
    """
    try:
        return parse(subject)
    except ValueError as exc:
        raise InvalidTokenError() from exc


# Default ``sub`` parser: the SQLAlchemy adapter's identity is ``uuid.UUID``.
# Declared as a module-level singleton so it can serve as a B008-safe default.
_PARSE_UUID_SUBJECT: Callable[[str], Any] = uuid.UUID
