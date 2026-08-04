"""Build a Beanie ``User`` document from a base document plus mixins.

Mirrors :mod:`blenx_auth.fastapi.class_builder_sqla` for the Mongo backend: the
composition root produces a document subclass that carries the base user fields
plus every plugin/consumer table mixin's fields. The collision check runs
before ``type(...)`` so a duplicate field fails at startup with a
``FieldCollisionError`` instead of a pydantic field-override.

``Settings`` (the collection name) is inherited from ``base_document`` — the
composed document maps the same ``"user"`` collection as the base.
"""

from __future__ import annotations

from collections.abc import Sequence

from beanie import Document
from blenx_auth.core.plugins.collisions import check_no_field_collisions


def build_beanie_model(
    name: str,
    base_document: type[Document],
    mixins: Sequence[type],
) -> type[Document]:
    """Build a ``Document`` subclass of ``base_document`` carrying ``mixins``."""
    check_no_field_collisions(*mixins, kind="table")
    bases = (base_document, *mixins)
    return type(name, bases, {})


__all__ = ["build_beanie_model"]
