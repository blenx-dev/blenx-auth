"""Tests for :mod:`blenx_auth.fastapi.class_builder_sqla`.

These exercise the built model against a real SQLite engine — DDL via
``create_all`` and an insert/query round trip — because static attribute
inspection alone would not prove the class maps correctly.

Each test builds a fresh ``DeclarativeBase`` subclass: SQLAlchemy forbids two
classes named ``"User"`` on the same ``MetaData``, so sharing one base across
tests would trip the registry guard the very thing this module is about.
"""

from __future__ import annotations

import pytest
from blenx_auth.core.plugins.collisions import FieldCollisionError
from blenx_auth.fastapi.class_builder_sqla import build_sqla_model

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column


class CoreMixin:
    id: Mapped[int] = mapped_column(primary_key=True)


class PluginMixin:
    is_2fa_enabled: Mapped[bool] = mapped_column(default=False)


def test_build_sqla_model_creates_real_table() -> None:
    class AuthBase(DeclarativeBase):
        pass

    User = build_sqla_model("user", AuthBase, CoreMixin, [PluginMixin])

    engine = create_engine("sqlite:///:memory:")
    AuthBase.metadata.create_all(engine)  # must not raise

    assert "id" in User.__table__.columns
    assert "is_2fa_enabled" in User.__table__.columns


def test_build_sqla_model_round_trip() -> None:
    class AuthBase(DeclarativeBase):
        pass

    User = build_sqla_model("user", AuthBase, CoreMixin, [PluginMixin])

    engine = create_engine("sqlite:///:memory:")
    AuthBase.metadata.create_all(engine)

    with Session(engine) as session:
        session.add(User(is_2fa_enabled=True))
        session.commit()

    with Session(engine) as session:
        row = session.query(User).one()
        assert row.is_2fa_enabled is True


def test_build_sqla_model_raises_on_collision_before_ddl() -> None:
    class AuthBase(DeclarativeBase):
        pass

    class PluginMixinCollision:
        is_2fa_enabled: Mapped[bool] = mapped_column(default=False)

    with pytest.raises(FieldCollisionError):
        build_sqla_model("user", AuthBase, CoreMixin, [PluginMixin, PluginMixinCollision])
