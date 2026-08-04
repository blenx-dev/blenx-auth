"""Tests for :mod:`blenx_auth.core.contracts`."""

from __future__ import annotations

import pytest
from blenx_auth.core.contracts import ContractMismatchError, run_contract_check
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
