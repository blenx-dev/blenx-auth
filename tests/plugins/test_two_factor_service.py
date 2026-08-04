"""Unit tests for :class:`TwoFactorService` (challenge-token verification).

The HTTP e2e test covers ``transform_login`` and the happy/challenge paths;
these cover the two remaining branches of ``verify``: a challenge token whose
``scope`` is not ``2fa_pending``, and one with no usable ``sub`` claim.
"""

from __future__ import annotations

import secrets
from types import SimpleNamespace

import pytest
from blenx_auth.core.exceptions import InvalidChallengeError
from blenx_auth.core.jwt import TokenService
from blenx_auth.core.schemas import LoginSuccess
from blenx_auth.plugins.two_factor import make_two_factor_plugin
from blenx_auth.plugins.two_factor.service import CHALLENGE_SCOPE, TwoFactorService

TEST_SECRET = secrets.token_hex(32)


def _settings() -> SimpleNamespace:
    return SimpleNamespace(
        secret_key=TEST_SECRET,
        jwt_algorithm="HS256",
        access_token_expire_minutes=30,
        refresh_token_expire_days=30,
    )


class AlwaysValidOtp:
    async def verify_code(self, user_id: str, code: str) -> None:
        return None


def _service() -> tuple[TwoFactorService, TokenService]:
    tokens = TokenService(_settings())
    return (
        TwoFactorService(otp_repo=AlwaysValidOtp(), token_service=tokens),
        tokens,
    )


async def test_verify_wrong_scope_raises() -> None:
    service, tokens = _service()
    wrong_scope = tokens.encode({"scope": "password_reset", "sub": "user-1"}, ttl_seconds=60)
    with pytest.raises(InvalidChallengeError):
        await service.verify(challenge_token=wrong_scope, code="123456")


async def test_verify_missing_sub_raises() -> None:
    service, tokens = _service()
    no_sub = tokens.encode({"scope": CHALLENGE_SCOPE}, ttl_seconds=60)
    with pytest.raises(InvalidChallengeError):
        await service.verify(challenge_token=no_sub, code="123456")


async def test_verify_happy_path_mints_access_token() -> None:
    service, tokens = _service()
    challenge = tokens.encode({"scope": CHALLENGE_SCOPE, "sub": "user-1"}, ttl_seconds=60)
    result = await service.verify(challenge_token=challenge, code="123456")
    assert result.kind == "token"
    assert tokens.decode_access_token(result.access_token) == "user-1"


async def test_transform_login_noop_before_service_built() -> None:
    plugin = make_two_factor_plugin(otp_repo=AlwaysValidOtp())
    hook = plugin.hooks.transform_login_result[0]
    user = SimpleNamespace(is_2fa_enabled=True, id="user-1", two_factor_type="otp")
    result = LoginSuccess(access_token="x")
    assert await hook(user, result) is result
