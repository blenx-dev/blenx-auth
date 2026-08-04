"""Unit tests for the Beanie repositories' injectable-model plumbing.

These cover the constructor branches the HTTP e2e doesn't hit (explicit
``model`` injection on the refresh-token and OAuth-account repositories) and
the DB-layer ``extra_fields`` validation that raises before any write — so no
running MongoDB is required.
"""

from __future__ import annotations

import pytest
from blenx_auth.beanie.models import RefreshToken, User
from blenx_auth.beanie.repositories import (
    BeanieOAuthAccountRepository,
    BeanieRefreshTokenRepository,
    BeanieUserRepository,
)
from blenx_auth.core.dto import NewUser
from blenx_auth.core.exceptions import UserModelMappingError


def test_refresh_repo_model_injection() -> None:
    repo = BeanieRefreshTokenRepository(model=RefreshToken)
    assert repo._model is RefreshToken
    assert BeanieRefreshTokenRepository()._model is RefreshToken


def test_oauth_repo_model_injection() -> None:
    repo = BeanieOAuthAccountRepository(model=User)
    assert repo._model is User
    assert BeanieOAuthAccountRepository()._model is User


async def test_user_repo_rejects_unknown_extra_field() -> None:
    repo = BeanieUserRepository()
    with pytest.raises(UserModelMappingError) as excinfo:
        await repo.create(
            NewUser(
                email="a@example.com",
                hashed_password="h",
                is_verified=False,
                extra_fields={"no_such_field": 1},
            )
        )
    assert "no_such_field" in str(excinfo.value)


async def test_user_repo_accepts_known_extra_field() -> None:
    repo = BeanieUserRepository()
    extra = repo._validated_extra_fields({"is_active": True})
    assert extra == {"is_active": True}
