"""Build a Pydantic user schema from a base plus plugin/consumer mixins.

Field-collision detection runs *before* model construction so a duplicate
field name surfaces as a clear ``FieldCollisionError`` at startup rather than
as confusing MRO shadowing.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, cast

from pydantic import BaseModel, create_model

from blenx_auth.core.plugins.collisions import check_no_field_collisions


def build_pydantic_model(
    name: str,
    base: type[BaseModel],
    kind: str,
    field_overrides: Mapping[str, tuple[Any, Any]] | None = None,
) -> type[BaseModel]:
    """Create ``name`` by subclassing ``base`` with every ``mixin``.

    ``kind`` (``"read"``/``"create"``/``"update"``) scopes the collision check.
    ``field_overrides`` replaces specific fields after composition (e.g. a
    backend-specific identity type); values are ``(annotation, default)`` pairs.
    """
    return cast(
        type[BaseModel],
        create_model(
            name,
            __base__=(base),
            **cast(dict[str, Any], field_overrides or {}),
        ),
    )
