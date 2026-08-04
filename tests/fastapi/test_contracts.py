"""Tests for :mod:`blenx_auth.core.contracts`."""

from __future__ import annotations

import pytest
from blenx_auth.core.contracts import (
    ContractMismatchError,
    run_contract_check,
    validate_beanie_contract,
    validate_sqlalchemy_contract,
)
from pydantic import BaseModel


def _fake_user_model(*columns: str) -> type:
    class _Model:
        __table__ = type("table", (), {"columns": {c: object() for c in columns}})()

    return _Model


User = _fake_user_model("id", "email", "birthdate", "is_active", "is_verified")


class ReadOK(BaseModel):
    id: str
    email: str


class ReadExtra(BaseModel):
    id: str
    phone: str


class CreateOK(BaseModel):
    email: str
    password: str
    birthdate: str | None = None


class UpdateOK(BaseModel):
    email: str | None = None
    is_active: bool | None = None


class UpdateBroken(BaseModel):
    email: str | None = None
    nickname: str | None = None


def test_all_fields_subset_passes() -> None:
    run_contract_check(User, ReadOK, CreateOK, UpdateOK)


def test_read_extra_field_raises() -> None:
    with pytest.raises(ExceptionGroup) as exc_info:
        run_contract_check(User, ReadExtra, CreateOK, UpdateOK)
    err = exc_info.value.exceptions[0]
    assert isinstance(err, ContractMismatchError)
    assert err.schema_label == "UserRead"
    assert err.missing_fields == {"phone"}
    assert "phone" in str(err)


def test_create_password_field_is_excluded() -> None:
    run_contract_check(User, ReadOK, CreateOK, UpdateOK)


def test_update_email_is_excluded_but_other_extra_raises() -> None:
    run_contract_check(User, ReadOK, CreateOK, UpdateOK)
    with pytest.raises(ExceptionGroup):
        run_contract_check(User, ReadOK, CreateOK, UpdateBroken)


def test_multiple_broken_schemas_all_reported() -> None:
    with pytest.raises(ExceptionGroup) as exc_info:
        run_contract_check(User, ReadExtra, CreateOK, UpdateBroken)
    errors = exc_info.value.exceptions
    assert len(errors) == 2
    labels = {err.schema_label for err in errors if isinstance(err, ContractMismatchError)}
    assert labels == {"UserRead", "UserUpdate"}
    messages = [str(err) for err in errors if isinstance(err, ContractMismatchError)]
    assert any("phone" in m for m in messages)
    assert any("nickname" in m for m in messages)


def test_model_fields_lookup_used_when_no_table() -> None:
    class BeanieLikeUser(BaseModel):
        id: str
        email: str
        birthdate: str | None = None

    class BeanieUpdate(BaseModel):
        email: str | None = None
        birthdate: str | None = None

    run_contract_check(BeanieLikeUser, ReadOK, CreateOK, BeanieUpdate)


def test_annotations_fallback_when_no_table_or_model_fields() -> None:
    class PlainUser:
        id: str
        email: str

    class PlainCreate(BaseModel):
        email: str
        password: str

    class PlainUpdate(BaseModel):
        email: str | None = None

    run_contract_check(PlainUser, ReadOK, PlainCreate, PlainUpdate)


def test_sqlalchemy_validator_uses_table_columns() -> None:
    validate_sqlalchemy_contract(User, ReadOK, CreateOK, UpdateOK)
    with pytest.raises(ExceptionGroup) as exc_info:
        validate_sqlalchemy_contract(User, ReadExtra, CreateOK, UpdateOK)
    assert exc_info.value.exceptions[0].schema_label == "UserRead"


def test_beanie_validator_uses_model_fields() -> None:
    class BeanieLikeUser(BaseModel):
        id: str
        email: str
        birthdate: str | None = None

    class BeanieUpdate(BaseModel):
        email: str | None = None
        birthdate: str | None = None

    validate_beanie_contract(BeanieLikeUser, ReadOK, CreateOK, BeanieUpdate)
    with pytest.raises(ExceptionGroup):
        validate_beanie_contract(BeanieLikeUser, ReadOK, CreateOK, UpdateBroken)


def test_run_contract_check_dispatches_on_backend_shape() -> None:
    class BeanieLikeUser(BaseModel):
        id: str
        email: str
        birthdate: str | None = None
        is_active: bool = True
        is_verified: bool = False

    # __table__ -> SQLAlchemy validator; model_fields -> Beanie validator.
    run_contract_check(User, ReadOK, CreateOK, UpdateOK)
    run_contract_check(BeanieLikeUser, ReadOK, CreateOK, UpdateOK)
