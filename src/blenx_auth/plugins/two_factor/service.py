"""Two-factor step-up service.

The service has two responsibilities:

- ``transform_login`` — the ``transform_login_result`` hook. When the user has
  2FA enabled it downgrades the ``LoginSuccess`` from ``POST /auth/login`` into
  a ``LoginChallenge`` carrying a short-lived ``challenge_token`` (scope
  ``"2fa_pending"``). When 2FA is off it returns the result untouched, so
  non-enrolled users never see a challenge step.
- ``verify`` — completes the login: checks the challenge token, validates the
  second factor against the ``otp_repo``, and only then mints the access token.

The ``otp_repo`` is injected (duck-typed): the plugin ships no TOTP library, so
the host app supplies the actual code verification (e.g. a pyotp-backed repo)
via the same constructor that builds the plugin.
"""

from __future__ import annotations

from typing import Any, Protocol

from blenx_auth.core.exceptions import InvalidChallengeError
from blenx_auth.core.jwt import TokenService
from blenx_auth.core.schemas import LoginChallenge, LoginSuccess

CHALLENGE_SCOPE = "2fa_pending"
CHALLENGE_TTL_SECONDS = 300


class OtpRepository(Protocol):
    """Code verification for one user; raises on a bad/missing code."""

    async def verify_code(self, user_id: str, code: str) -> None: ...


class TwoFactorService:
    def __init__(self, *, otp_repo: OtpRepository, token_service: TokenService) -> None:
        self._otp_repo = otp_repo
        self._token_service = token_service

    async def transform_login(
        self, user: Any, result: LoginSuccess
    ) -> LoginSuccess | LoginChallenge:
        """Turn a successful credential login into a challenge when 2FA is on."""
        if not getattr(user, "is_2fa_enabled", False):
            return result
        challenge_token = self._token_service.encode(
            {"scope": CHALLENGE_SCOPE, "sub": str(user.id)},
            ttl_seconds=CHALLENGE_TTL_SECONDS,
        )
        return LoginChallenge(
            flow=getattr(user, "two_factor_type", None) or "otp",
            challenge_token=challenge_token,
        )

    async def verify(self, *, challenge_token: str, code: str) -> LoginSuccess:
        """Complete a challenged login by validating the second factor."""
        claims = self._token_service.decode(challenge_token)
        if claims.get("scope") != CHALLENGE_SCOPE:
            raise InvalidChallengeError()
        user_id = claims.get("sub")
        if not isinstance(user_id, str) or not user_id:
            raise InvalidChallengeError()
        await self._otp_repo.verify_code(user_id=user_id, code=code)
        access_token = self._token_service.create_access_token(subject=user_id)
        return LoginSuccess(access_token=access_token)


__all__ = ["OtpRepository", "TwoFactorService"]
