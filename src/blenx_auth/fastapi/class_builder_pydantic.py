"""Build a Pydantic user schema from a base plus plugin/consumer mixins.

Field-collision detection runs *before* model construction so a duplicate
field name surfaces as a clear ``FieldCollisionError`` at startup rather than
as confusing MRO shadowing.
"""

from __future__ import annotations

from collections.abc import Sequence

from pydantic import BaseModel, create_model

from blenx_auth.core.plugins.collisions import check_no_field_collisions


def build_pydantic_model(
    name: str,
    base: type[BaseModel],
    mixins: Sequence[type[BaseModel]],
    kind: str,
) -> type[BaseModel]:
    """Create ``name`` by subclassing ``base`` with every ``mixin``.

    ``kind`` (``"read"``/``"create"``/``"update"``) scopes the collision check.
    """
    check_no_field_collisions(*mixins, kind=kind)
    return create_model(name, __base__=(base, *mixins))
