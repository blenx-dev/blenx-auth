"""Tests for :mod:`blenx_auth.core.plugins.collisions`."""

from __future__ import annotations

import pytest
from blenx_auth.core.plugins.collisions import (
    FieldCollisionError,
    ReservedFieldError,
    check_no_field_collisions,
)
from pydantic import BaseModel


class NicknameMixin(BaseModel):
    nickname: str


class PhoneMixin(BaseModel):
    phone: str


class DuplicateNicknameMixin(BaseModel):
    nickname: str


class TableEmailMixin:
    email: str


def test_disjoint_fields_do_not_raise() -> None:
    check_no_field_collisions(NicknameMixin, PhoneMixin, kind="table")


def test_shared_field_raises_with_owners_in_argument_order() -> None:
    with pytest.raises(FieldCollisionError) as exc_info:
        check_no_field_collisions(NicknameMixin, DuplicateNicknameMixin, kind="table")
    err = exc_info.value
    assert err.kind == "table"
    assert err.field == "nickname"
    assert err.owner_a == "NicknameMixin"
    assert err.owner_b == "DuplicateNicknameMixin"


def test_same_mixin_twice_does_not_raise() -> None:
    check_no_field_collisions(NicknameMixin, NicknameMixin, kind="table")


def test_create_mixin_declaring_password_raises_reserved() -> None:
    class BadCreate(BaseModel):
        password: str

    with pytest.raises(ReservedFieldError) as exc_info:
        check_no_field_collisions(BadCreate, kind="create")
    assert exc_info.value.field == "password"
    assert exc_info.value.owner == "BadCreate"


def test_update_mixin_declaring_email_raises_reserved() -> None:
    class BadUpdate(BaseModel):
        email: str

    with pytest.raises(ReservedFieldError) as exc_info:
        check_no_field_collisions(BadUpdate, kind="update")
    assert exc_info.value.field == "email"


def test_table_mixin_declaring_email_does_not_raise() -> None:
    check_no_field_collisions(TableEmailMixin, kind="table")
