"""Field-collision detection between user-schema mixins.

Two mixins declaring the same field name (plugin/plugin or plugin/consumer) is
a hard startup error — there is no MRO-based "first one wins" fallback. The
only sanctioned resolution is the composition root's ``overrides`` parameter.
``email`` and ``password`` are reserved: they must never appear on any
create/update mixin, because those flows are owned by the dedicated
auth/email-change/password-reset machinery.
"""

from __future__ import annotations

RESERVED_UPDATE_FIELDS = frozenset({"email", "password"})


class FieldCollisionError(Exception):
    """Two mixins declare the same field for the same schema kind."""

    def __init__(self, kind: str, field: str, owner_a: str, owner_b: str) -> None:
        self.kind = kind
        self.field = field
        self.owner_a = owner_a
        self.owner_b = owner_b
        super().__init__(
            f"[{kind}] field '{field}' is declared by both "
            f"'{owner_a}' and '{owner_b}' — resolve via the "
            f"`overrides` param or remove the duplicate declaration."
        )


class ReservedFieldError(Exception):
    """A create/update mixin declares the reserved ``email``/``password`` field."""

    def __init__(self, kind: str, field: str, owner: str) -> None:
        self.kind = kind
        self.field = field
        self.owner = owner
        super().__init__(
            f"[{kind}] '{owner}' declares reserved field '{field}'. "
            f"email/password must not appear on create or update mixins; "
            f"use the dedicated auth/email-change/password-reset flows."
        )


def _declared_field_names(mixin: type) -> set[str]:
    """Return the field names a mixin declares.

    Pydantic mixins expose ``model_fields``; plain (SQLAlchemy ``Mapped``)
    mixins declare ``__annotations__``. Falling back keeps both kinds working
    with the same check.
    """
    model_fields = getattr(mixin, "model_fields", None)
    if model_fields is not None:
        return set(model_fields.keys())
    return set(getattr(mixin, "__annotations__", {}).keys())


def check_no_field_collisions(*mixins: type, kind: str) -> None:
    """Raise unless every mixin's declared fields are disjoint.

    ``kind`` is one of ``"table"``, ``"read"``, ``"create"``, ``"update"`` —
    used only for error messages and to scope the reserved-field rule
    (``email``/``password`` are reserved on ``create``/``update`` only).
    """
    owners: dict[str, str] = {}
    for mixin in mixins:
        for name in _declared_field_names(mixin):
            if kind in ("create", "update") and name in RESERVED_UPDATE_FIELDS:
                raise ReservedFieldError(kind, name, mixin.__name__)
            if name in owners and owners[name] != mixin.__name__:
                raise FieldCollisionError(kind, name, owners[name], mixin.__name__)
            owners[name] = mixin.__name__
