"""Tests for the SQLAlchemy table/metadata builder (explicit composition).

These use a **real SQLite engine**: DDL via ``create_all`` plus an insert/query
round trip through a ``Session``, not just static attribute inspection.
"""

from __future__ import annotations

import pytest
from blenx_auth.core.plugins.collisions import FieldCollisionError
from blenx_auth.sqlalchemy.metadata import (
    CORE_USER_COLUMNS,
    build_composed_user_table,
    map_user_model,
    register_extra_tables,
)

from sqlalchemy import Boolean, Column, Integer, MetaData, String, Table, create_engine
from sqlalchemy.orm import DeclarativeBase, Session


def _make_base() -> type[DeclarativeBase]:
    class AuthBase(DeclarativeBase):
        pass

    return AuthBase


def test_core_columns_declared() -> None:
    names = {c.name for c in CORE_USER_COLUMNS}
    assert {"id", "email", "hashed_password", "is_active", "is_superuser", "is_verified"} <= names
    assert "email" in names
    assert "birthdate" in names
    assert "created_at" in names


def test_builds_real_table_with_round_trip() -> None:
    AuthBase = _make_base()
    engine = create_engine("sqlite:///:memory:")
    AuthBase.metadata.create_all(engine)

    User = map_user_model(
        build_composed_user_table(
            metadata=AuthBase.metadata,
            plugin_columns=[("p", (Column("is_2fa_enabled", Boolean, default=False),))],
        ),
        AuthBase,
    )
    # create_all AFTER mapping so the composed table (with plugin column) exists.
    AuthBase.metadata.create_all(engine)

    with Session(engine) as session:
        user = User(email="a@b.co", hashed_password="x")
        session.add(user)
        session.commit()

    with Session(engine) as session:
        fetched = session.query(User).filter_by(email="a@b.co").one()
        assert fetched.email == "a@b.co"
        assert fetched.is_2fa_enabled is False


def test_collision_with_core_column_raises() -> None:
    AuthBase = _make_base()
    with pytest.raises(FieldCollisionError) as exc:
        build_composed_user_table(
            metadata=AuthBase.metadata,
            plugin_columns=[("p", (Column("email", String),))],
        )
    assert exc.value.field == "email"
    assert exc.value.owner_a == "core"
    assert exc.value.owner_b == "p"


def test_collision_between_plugins_raises() -> None:
    AuthBase = _make_base()
    with pytest.raises(FieldCollisionError) as exc:
        build_composed_user_table(
            metadata=AuthBase.metadata,
            plugin_columns=[
                ("a", (Column("nickname", String),)),
                ("b", (Column("nickname", String),)),
            ],
        )
    assert exc.value.field == "nickname"
    assert exc.value.owner_a == "a"
    assert exc.value.owner_b == "b"


def test_build_is_idempotent_across_calls() -> None:
    AuthBase = _make_base()
    plugin_cols = (Column("nickname", String),)

    first = build_composed_user_table(
        metadata=AuthBase.metadata,
        plugin_columns=[("p", plugin_cols)],
    )
    second = build_composed_user_table(
        metadata=AuthBase.metadata,
        plugin_columns=[("p", plugin_cols)],
    )
    # A table already present on the metadata is returned as-is (idempotent).
    assert second is first
    assert first.metadata is AuthBase.metadata

    # And a tear-down + rebuild with the same column objects must not raise.
    registry = AuthBase.registry
    for _mapper in list(registry.mappers):
        registry.dispose()
    AuthBase.metadata.remove(first)
    rebuilt = build_composed_user_table(
        metadata=AuthBase.metadata,
        plugin_columns=[("p", plugin_cols)],
    )
    assert rebuilt is not first
    assert "nickname" in rebuilt.columns


def test_extra_tables_registered_idempotently() -> None:
    AuthBase = _make_base()
    otp = Table("otp_codes", MetaData(), Column("id", Integer, primary_key=True))

    register_extra_tables(metadata=AuthBase.metadata, plugin_tables=(otp,))
    register_extra_tables(metadata=AuthBase.metadata, plugin_tables=(otp,))

    assert "otp_codes" in AuthBase.metadata.tables
    assert list(AuthBase.metadata.tables).count("otp_codes") == 1


def test_mapped_user_model_exposes_table() -> None:
    AuthBase = _make_base()
    table = build_composed_user_table(metadata=AuthBase.metadata)
    User = map_user_model(table, AuthBase)

    assert User.__table__ is table
    assert table.name == "user"
    assert "email" in User.__table__.columns
