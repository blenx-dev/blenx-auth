"""Tests for :mod:`blenx_auth.fastapi.class_builder_pydantic`."""

from __future__ import annotations

import pytest
from blenx_auth.core.plugins.collisions import FieldCollisionError
from blenx_auth.fastapi.class_builder_pydantic import build_pydantic_model
from pydantic import BaseModel


class IdMixin(BaseModel):
    id: str


class NicknameMixin(BaseModel):
    nickname: str


class DuplicateNicknameMixin(BaseModel):
    nickname: str


def test_base_plus_mixin_fields_are_combined() -> None:
    Model = build_pydantic_model("UserRead", IdMixin, [NicknameMixin], kind="read")
    fields = set(Model.model_fields.keys())
    assert {"id", "nickname"} <= fields


def test_colliding_mixins_raise_field_collision_error() -> None:
    with pytest.raises(FieldCollisionError):
        build_pydantic_model(
            "UserRead", IdMixin, [NicknameMixin, DuplicateNicknameMixin], kind="read"
        )


def test_zero_mixins_yields_base_fields_only() -> None:
    Model = build_pydantic_model("UserRead", IdMixin, [], kind="read")
    assert set(Model.model_fields.keys()) == {"id"}
    instance = Model(id="abc")
    assert instance.id == "abc"
