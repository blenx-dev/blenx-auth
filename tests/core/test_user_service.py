"""Unit tests for :class:`UserService` (Task 7 update flow).

Covers the branches the HTTP tests don't reach: the ``model`` accessor, the
``get`` not-found path, the ``UserModelMappingError`` on undeclared fields,
and all three ``_model_fields`` lookups (``__table__`` for SQLAlchemy models,
``model_fields`` for Beanie/pydantic documents, ``__annotations__`` for plain
classes).
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest
from blenx_auth.core.exceptions import UserModelMappingError, UserNotFoundError
from blenx_auth.core.plugins.hooks import AuthHooks
from blenx_auth.core.services.user_service import UserService
from pydantic import BaseModel
from tests.fakes import FakeUser, FakeUsers


class SqlLikeModel:
    """Duck-typed SQLAlchemy model: columns live on ``__table__``."""

    __table__ = SimpleNamespace(columns={"id": None, "email": None})


class BeanieLikeModel(BaseModel):
    """Duck-typed Beanie document: fields live on ``model_fields``."""

    nickname: str | None = None


class PlainModel:
    """No ``__table__``/``model_fields``: fields come from ``__annotations__``."""

    nickname: str | None = None


class Payload(BaseModel):
    email: str | None = None
    nickname: str | None = None
    phone: str | None = None


def _service(model: type) -> UserService[uuid.UUID]:
    return UserService(repo=FakeUsers(), hooks=AuthHooks(), model=model)


def _seed(service: UserService[uuid.UUID]) -> FakeUser:
    user = FakeUser(email="me@example.com", hashed_password="hash")
    service._repo.rows["me@example.com"] = user  # type: ignore[attr-defined]
    return user


def test_model_property_returns_bound_model() -> None:
    service = _service(SqlLikeModel)
    assert service.model is SqlLikeModel


async def test_get_returns_user_by_id() -> None:
    service = _service(SqlLikeModel)
    user = _seed(service)
    assert await service.get(user.id) is user


async def test_get_raises_user_not_found() -> None:
    service = _service(SqlLikeModel)
    _seed(service)
    with pytest.raises(UserNotFoundError):
        await service.get(uuid.uuid4())


async def test_update_raises_user_not_found_for_missing_user() -> None:
    service = _service(SqlLikeModel)
    with pytest.raises(UserNotFoundError):
        await service.update(user_id=uuid.uuid4(), payload=Payload())


async def test_update_applies_known_field_from_table_columns() -> None:
    service = _service(SqlLikeModel)
    user = _seed(service)
    updated = await service.update(user_id=user.id, payload=Payload(email="new@example.com"))
    assert updated is user
    assert user.email == "new@example.com"


async def test_update_raises_model_mapping_error_for_unknown_field() -> None:
    service = _service(SqlLikeModel)
    user = _seed(service)
    with pytest.raises(UserModelMappingError) as excinfo:
        await service.update(user_id=user.id, payload=Payload(nickname="bob", phone="555"))
    assert "nickname" in str(excinfo.value)


async def test_update_uses_model_fields_for_beanie_documents() -> None:
    service = _service(BeanieLikeModel)
    user = _seed(service)
    await service.update(user_id=user.id, payload=Payload(nickname="ann"))
    assert user.nickname == "ann"


async def test_update_falls_back_to_annotations() -> None:
    service = _service(PlainModel)
    user = _seed(service)
    await service.update(user_id=user.id, payload=Payload(nickname="carol"))
    assert user.nickname == "carol"


async def test_update_unknown_field_raises_even_with_annotations_fallback() -> None:
    service = _service(PlainModel)
    user = _seed(service)
    with pytest.raises(UserModelMappingError):
        await service.update(user_id=user.id, payload=Payload(phone="555"))
