"""Unit tests for the auth services (framework-free, fake repositories).

Every test builds its own service instances so failures stay isolated. A
dedicated settings object with a short lockout threshold keeps the behaviour
deterministic regardless of ``.env``.
"""

from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from blenx_auth.core.dto import NewUser
from blenx_auth.core.exceptions import (
    AccountLockedError,
    EmailAlreadyExistsError,
    InactiveAccountError,
    InvalidCredentialsError,
    InvalidRefreshTokenError,
    InvalidTokenError,
    PasswordPolicyError,
    PermissionDeniedError,
)
from blenx_auth.core.jwt import TokenService
from blenx_auth.core.password import verify_password
from blenx_auth.core.services import (
    AuthenticationService,
    EmailVerificationService,
    PasswordResetService,
)
from blenx_auth.core.settings import AuthSettings
from blenx_auth.fastapi.permissions import (
    Permission,
    make_permission_guards,
    permissions_for,
)

from .fakes import FakeEmailSender, FakeOAuthAccounts, FakeRefreshTokens, FakeUser, FakeUsers

TEST_SECRET = secrets.token_hex(32)


def _settings(*, max_failed: int = 3) -> AuthSettings:
    return SimpleNamespace(
        secret_key=TEST_SECRET,
        jwt_algorithm="HS256",
        access_token_expire_minutes=30,
        refresh_token_expire_days=30,
        email_verification_token_expire_minutes=1440,
        password_reset_token_expire_minutes=60,
        max_failed_login_attempts=max_failed,
        account_lockout_minutes=15,
        login_rate_limit_per_minute=0,
        frontend_url="http://localhost:5173",
        backend_url="http://localhost:8000",
        google_client_id="",
        google_client_secret=SimpleNamespace(get_secret_value=lambda: ""),
    )


class AuthHarness:
    """A ready-made stack of fakes + services for one test."""

    def __init__(self, *, max_failed: int = 3) -> None:
        self.settings = _settings(max_failed=max_failed)
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
        self.reset = PasswordResetService(
            users=self.users,
            refresh_tokens=self.refresh_tokens,
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
        )


@pytest.fixture
def harness() -> AuthHarness:
    return AuthHarness()


async def test_register_normalizes_email_and_requires_policy(harness: AuthHarness) -> None:
    user = await harness.auth.register(email="  Ann@Example.COM ", password="password-123")
    assert user.email == "ann@example.com"
    assert user.is_verified is False
    assert verify_password("password-123", user.hashed_password)
    assert any("verify-email" in m.body for m in harness.mail.sent)


async def test_register_duplicate_and_weak_password(harness: AuthHarness) -> None:
    await harness.auth.register(email="ann@example.com", password="password-123")
    with pytest.raises(EmailAlreadyExistsError):
        await harness.auth.register(email="ann@example.com", password="password-123")
    with pytest.raises(PasswordPolicyError):
        await harness.auth.register(email="other@example.com", password="short")


async def test_concurrent_duplicate_insert_raises_domain_error(harness: AuthHarness) -> None:
    """Bypassing the service pre-check, the repo still maps a duplicate to the
    domain error — parity with the SQLAlchemy/Beanie backends under a race."""
    await harness.users.create(NewUser(email="race@example.com", hashed_password="x"))
    with pytest.raises(EmailAlreadyExistsError):
        await harness.users.create(NewUser(email="race@example.com", hashed_password="x"))


async def test_login_issues_pair_and_clears_failures(harness: AuthHarness) -> None:
    await harness.auth.register(email="ann@example.com", password="password-123")
    pair = await harness.auth.login(email="ann@example.com", password="password-123")
    assert pair.access_token
    assert pair.expires_in == harness.settings.access_token_expire_minutes * 60
    assert len(harness.refresh_tokens.rows) == 1


async def test_login_rejects_unknown_and_wrong_password(harness: AuthHarness) -> None:
    await harness.auth.register(email="ann@example.com", password="password-123")
    with pytest.raises(InvalidCredentialsError):
        await harness.auth.login(email="other@example.com", password="password-123")
    with pytest.raises(InvalidCredentialsError):
        await harness.auth.login(email="ann@example.com", password="wrong")


async def test_login_locks_after_max_attempts(harness: AuthHarness) -> None:
    harness.settings.max_failed_login_attempts = 2
    await harness.auth.register(email="ann@example.com", password="password-123")
    with pytest.raises(InvalidCredentialsError):
        await harness.auth.login(email="ann@example.com", password="wrong-1")
    with pytest.raises(AccountLockedError):
        await harness.auth.login(email="ann@example.com", password="wrong-2")


async def test_login_unlocks_after_cooldown(harness: AuthHarness) -> None:
    harness.settings.max_failed_login_attempts = 2
    harness.settings.account_lockout_minutes = 0
    await harness.auth.register(email="ann@example.com", password="password-123")
    with pytest.raises(InvalidCredentialsError):
        await harness.auth.login(email="ann@example.com", password="wrong-1")
    with pytest.raises(AccountLockedError):
        await harness.auth.login(email="ann@example.com", password="wrong-2")
    past = datetime.now(UTC) - timedelta(minutes=1)
    user = await harness.users.get_by_email("ann@example.com")
    user.locked_until = past
    await harness.users.save(user)
    pair = await harness.auth.login(email="ann@example.com", password="password-123")
    assert pair.access_token


async def test_refresh_rotation_and_reuse_detection(harness: AuthHarness) -> None:
    await harness.auth.register(email="ann@example.com", password="password-123")
    pair = await harness.auth.login(email="ann@example.com", password="password-123")
    rotated = await harness.auth.refresh(pair.refresh_token)
    assert rotated.refresh_token != pair.refresh_token
    with pytest.raises(InvalidRefreshTokenError):
        await harness.auth.refresh(pair.refresh_token)
    # reuse detection revokes the *whole family* (including the rotated token)
    active = [r for r in harness.refresh_tokens.rows.values() if r.revoked_at is None]
    assert len(active) == 0


async def test_logout_revokes_token(harness: AuthHarness) -> None:
    await harness.auth.register(email="ann@example.com", password="password-123")
    pair = await harness.auth.login(email="ann@example.com", password="password-123")
    await harness.auth.logout(pair.refresh_token)
    with pytest.raises(InvalidRefreshTokenError):
        await harness.auth.refresh(pair.refresh_token)


async def test_logout_all_revokes_every_session(harness: AuthHarness) -> None:
    await harness.auth.register(email="ann@example.com", password="password-123")
    first = await harness.auth.login(email="ann@example.com", password="password-123")
    await harness.auth.login(email="ann@example.com", password="password-123")
    user = await harness.users.get_by_email("ann@example.com")
    await harness.auth.logout_all(user.id)
    with pytest.raises(InvalidRefreshTokenError):
        await harness.auth.refresh(first.refresh_token)


async def test_email_verification_flow(harness: AuthHarness) -> None:
    user = await harness.auth.register(email="ann@example.com", password="password-123")
    assert not user.is_verified
    token = harness.tokens.create_email_verification_token(str(user.id))
    await harness.verification.verify(token)
    user = await harness.users.get_by_email("ann@example.com")
    assert user.is_verified
    assert user.email_verified_at is not None


async def test_resend_verification_noops_when_verified(harness: AuthHarness) -> None:
    user = await harness.auth.register(email="ann@example.com", password="password-123")
    await harness.verification.verify(harness.tokens.create_email_verification_token(str(user.id)))
    await harness.verification.resend(user)
    assert len(harness.mail.sent) == 1


async def test_forgot_password_emails_link(harness: AuthHarness) -> None:
    await harness.auth.register(email="ann@example.com", password="password-123")
    await harness.reset.request_reset(email="ann@example.com")
    assert any("reset-password" in m.body for m in harness.mail.sent)


async def test_reset_password_changes_credentials(harness: AuthHarness) -> None:
    await harness.auth.register(email="ann@example.com", password="password-123")
    pair = await harness.auth.login(email="ann@example.com", password="password-123")
    await harness.reset.request_reset(email="ann@example.com")
    token = next(m.body.split("token=")[1] for m in harness.mail.sent if "reset-password" in m.body)
    await harness.reset.reset(token, "brand-new-99")
    with pytest.raises(InvalidRefreshTokenError):
        await harness.auth.refresh(pair.refresh_token)


async def test_reset_revokes_sessions(harness: AuthHarness) -> None:
    await harness.auth.register(email="ann@example.com", password="password-123")
    pair = await harness.auth.login(email="ann@example.com", password="password-123")
    await harness.reset.request_reset(email="ann@example.com")
    token = next(m.body.split("token=")[1] for m in harness.mail.sent if "reset-password" in m.body)
    await harness.reset.reset(token, "brand-new-99")
    with pytest.raises(InvalidRefreshTokenError):
        await harness.auth.refresh(pair.refresh_token)


async def test_oauth_login_creates_then_reuses(harness: AuthHarness) -> None:
    pair = await harness.auth.oauth_login(
        provider="google",
        account_id="sub-1",
        account_email="O@Example.com",
        oauth_access_token="at",
    )
    user = await harness.users.get_by_email("o@example.com")
    assert pair.access_token
    assert user.is_verified
    assert len(harness.oauth_accounts.rows) == 1
    await harness.auth.oauth_login(
        provider="google",
        account_id="sub-1",
        account_email="o@example.com",
        oauth_access_token="at",
    )
    assert len(harness.users.rows) == 1
    assert len(harness.oauth_accounts.rows) == 1


async def test_oauth_login_links_existing_unverified_user(harness: AuthHarness) -> None:
    await harness.auth.register(email="o@example.com", password="password-123")
    user = await harness.users.get_by_email("o@example.com")
    assert user.is_verified is False
    await harness.auth.oauth_login(
        provider="google",
        account_id="sub-1",
        account_email="o@example.com",
        oauth_access_token="at",
    )
    assert user.is_verified
    assert len(harness.oauth_accounts.rows) == 1


async def test_oauth_login_rejects_inactive(harness: AuthHarness) -> None:
    await harness.auth.register(email="o@example.com", password="password-123")
    user = await harness.users.get_by_email("o@example.com")
    user.is_active = False
    with pytest.raises(InactiveAccountError):
        await harness.auth.oauth_login(
            provider="google",
            account_id="sub-1",
            account_email="o@example.com",
            oauth_access_token="at",
        )


async def test_authenticate_access_token(harness: AuthHarness) -> None:
    user = await harness.auth.register(email="ann@example.com", password="password-123")
    resolved = await harness.auth.authenticate_access_token(
        harness.tokens.create_access_token(str(user.id))
    )
    assert resolved.id == user.id
    with pytest.raises(InvalidTokenError):
        await harness.auth.authenticate_access_token("garbage")
    user.is_active = False
    with pytest.raises(InactiveAccountError):
        await harness.auth.authenticate_access_token(
            harness.tokens.create_access_token(str(user.id))
        )


async def test_password_hashes_are_argon2id(harness: AuthHarness) -> None:
    await harness.auth.register(email="ann@example.com", password="password-123")
    user = await harness.users.get_by_email("ann@example.com")
    assert user.hashed_password != "password-123"
    assert user.hashed_password.startswith("$argon2id$")


async def _active(user):
    return user


async def test_roles_and_permissions() -> None:
    admin = FakeUser(email="a@example.com", hashed_password="h", is_superuser=True)
    customer = FakeUser(email="c@example.com", hashed_password="h")
    assert permissions_for(admin) == frozenset(Permission)
    assert permissions_for(customer) == frozenset()
    guards = make_permission_guards(_active)
    with pytest.raises(PermissionDeniedError):
        await guards.require_admin()(customer)
    await guards.require_admin()(admin)
    with pytest.raises(PermissionDeniedError):
        await guards.require_role("admin")(customer)
    await guards.require_role("admin")(admin)
