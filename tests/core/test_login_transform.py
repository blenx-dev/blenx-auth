"""Tests for the login-result transform chain (Task 8).

``AuthenticationService.login`` wraps the token pair in a ``LoginSuccess``,
runs it through every ``transform_login_result`` hook (short-circuiting the
moment one returns a ``LoginChallenge``), and only then fires
``on_after_login`` side effects — so those effects reflect the final outcome
without knowing whether a challenge was issued.
"""

from __future__ import annotations

import secrets
from types import SimpleNamespace

from blenx_auth.core.jwt import TokenService
from blenx_auth.core.plugins.hooks import AuthHooks
from blenx_auth.core.schemas import LoginChallenge, LoginSuccess
from blenx_auth.core.services import (
    AuthenticationService,
    EmailVerificationService,
)
from blenx_auth.core.settings import AuthSettings
from tests.fakes import FakeEmailSender, FakeOAuthAccounts, FakeRefreshTokens, FakeUsers


def _settings() -> AuthSettings:
    return SimpleNamespace(
        secret_key=secrets.token_hex(32),
        jwt_algorithm="HS256",
        access_token_expire_minutes=30,
        refresh_token_expire_days=30,
        email_verification_token_expire_minutes=1440,
        password_reset_token_expire_minutes=60,
        max_failed_login_attempts=3,
        account_lockout_minutes=15,
        login_rate_limit_per_minute=0,
        frontend_url="http://localhost:5173",
        backend_url="http://localhost:8000",
        google_client_id="",
        google_client_secret=SimpleNamespace(get_secret_value=lambda: ""),
    )


class LoginHarness:
    def __init__(self, hooks: AuthHooks | None = None) -> None:
        self.settings = _settings()
        self.users = FakeUsers()
        self.refresh_tokens = FakeRefreshTokens()
        self.oauth_accounts = FakeOAuthAccounts()
        self.mail = FakeEmailSender()
        self.tokens = TokenService(self.settings)
        self.verification = EmailVerificationService(
            users=self.users,
            tokens=self.tokens,
            email_sender=self.mail,
            settings=self.settings,
        )
        self.auth = AuthenticationService(
            users=self.users,
            refresh_tokens=self.refresh_tokens,
            oauth_accounts=self.oauth_accounts,
            tokens=self.tokens,
            email_sender=self.mail,
            verification=self.verification,
            settings=self.settings,
            hooks=hooks,
        )

    async def seed(self, email: str = "a@example.com") -> None:
        await self.auth.register(email=email, password="password-123")


async def test_no_hooks_returns_plain_login_success() -> None:
    harness = LoginHarness()
    await harness.seed()
    result = await harness.auth.login(email="a@example.com", password="password-123")
    assert isinstance(result, LoginSuccess)
    assert result.kind == "token"
    assert result.access_token


async def test_identity_hook_preserves_login_success() -> None:
    async def identity(user, result):
        return result

    harness = LoginHarness(hooks=AuthHooks(transform_login_result=(identity,)))
    await harness.seed()
    result = await harness.auth.login(email="a@example.com", password="password-123")
    assert isinstance(result, LoginSuccess)
    assert result.kind == "token"


async def test_challenge_hook_downgrades_and_side_effects_fire_once() -> None:
    calls: list[str] = []

    async def issue_challenge(user, result):
        return LoginChallenge(flow="totp", challenge_token="ch-1")

    async def spy(user, outcome):
        calls.append("fired")

    harness = LoginHarness(
        hooks=AuthHooks(transform_login_result=(issue_challenge,), on_after_login=(spy,))
    )
    await harness.seed()
    result = await harness.auth.login(email="a@example.com", password="password-123")
    assert isinstance(result, LoginChallenge)
    assert result.kind == "challenge"
    assert result.flow == "totp"
    assert result.challenge_token == "ch-1"
    assert calls == ["fired"]  # on_after_login still ran, exactly once


async def test_challenge_short_circuits_remaining_transform_hooks() -> None:
    reached: list[str] = []

    async def issue_challenge(user, result):
        return LoginChallenge(flow="totp", challenge_token="ch-2")

    async def spy_never_called(user, result):
        reached.append("spy")
        return result

    async def noop_side_effect(user, outcome):
        return None

    harness = LoginHarness(
        hooks=AuthHooks(
            transform_login_result=(issue_challenge, spy_never_called),
            on_after_login=(noop_side_effect,),
        )
    )
    await harness.seed()
    result = await harness.auth.login(email="a@example.com", password="password-123")
    assert isinstance(result, LoginChallenge)
    assert reached == []  # chain stopped at the first challenge
