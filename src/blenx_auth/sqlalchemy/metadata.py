"""Explicit SQLAlchemy metadata + table composition (no mixin inheritance).

The core ``user`` columns are a plain tuple of :class:`~sqlalchemy.Column`
objects. A composition root composes them with plugin/consumer columns into a
single :class:`~sqlalchemy.Table` on one ``MetaData``, maps the ORM ``User``
directly to that table, and registers plugin-contributed extra tables on the
same metadata — so one metadata build drives both Alembic autogenerate and
``create_all``.

Rules:

- Column **copies** are used at build time. Module-level ``Column`` objects (the
  core tuple, or a plugin's) cannot be attached to a second ``Table``, so every
  column is copied on composition. That makes the builder idempotent: calling it
  twice produces two independent tables on the target metadata.
- A duplicate column name is a :class:`FieldCollisionError` raised *before* any
  ``Table`` is constructed — never a murky SQLAlchemy mapper error. Core columns
  own the names they declare; a plugin re-declaring ``email`` collides with
  ``core``.
- Extra plugin tables are merged onto the target metadata via ``to_metadata``,
  which is idempotent (a table already present is left untouched).
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any

from blenx_auth.core.plugins.collisions import FieldCollisionError
from sqlalchemy import (
    Boolean,
    Column,
    Date,
    DateTime,
    Integer,
    MetaData,
    String,
    Table,
    Uuid,
    func,
)

if TYPE_CHECKING:
    from sqlalchemy.orm import DeclarativeBase

#: The core ``user`` columns every backend maps (mirror of the static
#: ``BaseUserTableMixin``). Composed into a single ``Table`` at build time.
CORE_USER_COLUMNS: tuple[Column[Any], ...] = (
    Column("id", Uuid, primary_key=True, default=uuid.uuid4),
    Column("email", String(320), unique=True, index=True),
    Column("hashed_password", String(1024)),
    Column("is_active", Boolean, default=True),
    Column("is_superuser", Boolean, default=False),
    Column("is_verified", Boolean, default=False),
    Column("display_name", String(100), nullable=True),
    Column("created_at", DateTime(timezone=True), server_default=func.now()),
    Column(
        "updated_at",
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
    ),
    Column("email_verified_at", DateTime(timezone=True)),
    Column("failed_login_attempts", Integer, default=0),
    Column("locked_until", DateTime(timezone=True)),
    Column("password_reset_token_hash", String(64)),
    Column("password_reset_token_expires_at", DateTime(timezone=True)),
)


def _owner_groups(
    core_columns: Sequence[Column[Any]],
    plugin_columns: Sequence[tuple[str, Sequence[Column[Any]]]],
    consumer_columns: Sequence[Column[Any]],
) -> list[tuple[str, list[Column[Any]]]]:
    """Group every contributing column under its owner name, in order."""
    groups: list[tuple[str, list[Column[Any]]]] = [("core", list(core_columns))]
    for owner, cols in plugin_columns:
        groups.append((owner, list(cols)))
    if consumer_columns:
        groups.append(("consumer", list(consumer_columns)))
    return groups


def build_composed_user_table(
    *,
    metadata: MetaData,
    tablename: str = "user",
    core_columns: Sequence[Column[Any]] = CORE_USER_COLUMNS,
    plugin_columns: Sequence[tuple[str, Sequence[Column[Any]]]] = (),
    consumer_columns: Sequence[Column[Any]] = (),
) -> Table:
    """Compose the ``user`` ``Table`` on ``metadata`` from every column group.

    ``plugin_columns`` is a sequence of ``(owner_name, columns)`` pairs so a
    collision error names the plugin that owns the duplicate. All columns are
    copied (via the non-deprecated ``_copy``), keeping the builder idempotent
    across repeated calls after a registry teardown. A table already present on
    ``metadata`` is returned as-is.
    """
    existing = metadata.tables.get(tablename)
    if existing is not None:
        return existing
    owners: dict[str, str] = {}
    copies: list[Column[Any]] = []
    for owner, cols in _owner_groups(core_columns, plugin_columns, consumer_columns):
        for col in cols:
            if col.name in owners:
                raise FieldCollisionError("table", col.name, owners[col.name], owner)
            owners[col.name] = owner
            copies.append(col._copy())
    return Table(tablename, metadata, *copies)


def register_extra_tables(
    *, metadata: MetaData, plugin_tables: Sequence[Table]
) -> None:
    """Merge every plugin ``Table`` onto ``metadata`` (idempotent)."""
    for table in plugin_tables:
        if table.name not in metadata.tables:
            table.to_metadata(metadata)


def map_user_model(table: Table, base: type[DeclarativeBase]) -> type:
    """Map an ORM ``User`` class directly to the composed ``table``.

    The returned class is a real mapped entity on ``base``'s registry; it
    declares no relationships (the repositories reach related rows by foreign
    key, never through ORM relationships). Idempotent: if ``table`` is already
    mapped on the registry, the existing mapped class is returned.
    """
    for mapper in base.registry.mappers:
        if mapper.local_table is table:
            return mapper.class_
    return type("User", (base,), {"__table__": table})


def user_table_column_names(table: Table) -> set[str]:
    """The column names on a composed user table (for contract checks)."""
    return set(table.columns.keys())


__all__ = [
    "CORE_USER_COLUMNS",
    "build_composed_user_table",
    "map_user_model",
    "register_extra_tables",
    "user_table_column_names",
]
