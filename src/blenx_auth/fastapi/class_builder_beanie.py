"""Build a Beanie ``User`` document from a base document plus mixins.

Mirrors :mod:`blenx_auth.fastapi.class_builder_sqla` for the Mongo backend: the
composition root produces a document subclass that carries the base user fields
plus every plugin/consumer table mixin's fields. The collision check runs
before ``type(...)`` so a duplicate field fails at startup with a
``FieldCollisionError`` instead of a pydantic field-override.

``Settings`` (the collection name) is inherited from ``base_document`` — the
composed document maps the same ``"user"`` collection as the base.

Composition is cached by ``(name, base_document, mixins)``: a Beanie
``Document`` subclass is bound to a database on ``init_beanie``, so rebuilding
the same composition would produce a duplicate class on the same collection.
``reset_beanie_model_cache()`` clears the cache, which tests use to isolate
compositions.
"""

from __future__ import annotations

from collections.abc import Sequence

from beanie import Document
from blenx_auth.core.plugins.collisions import check_no_field_collisions

_cache: dict[tuple[object, ...], type[Document]] = {}


def build_beanie_model(
    name: str,
    base_document: type[Document],
    mixins: Sequence[type],
) -> type[Document]:
    """Build a ``Document`` subclass of ``base_document`` carrying ``mixins``.

    With no mixins the base document itself is returned unchanged: the default
    composition is the canonical static ``User``, which keeps every Beanie suite
    in one process registered against the same class.
    """
    if not mixins:
        return base_document
    key = (name, base_document, *tuple(mixins))
    cached = _cache.get(key)
    if cached is not None:
        return cached
    check_no_field_collisions(*mixins, kind="table")
    bases = (base_document, *mixins)
    composed = type(name, bases, {})
    _cache[key] = composed
    return composed


def reset_beanie_model_cache() -> None:
    """Clear the composed-document cache (used by tests for isolation)."""
    _cache.clear()


__all__ = ["build_beanie_model", "reset_beanie_model_cache"]
