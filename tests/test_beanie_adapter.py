"""Adapter-parity tests for the Beanie (MongoDB) backend.

These drive the same auth services used by the SQLAlchemy/fakes suites through
the Beanie repositories, proving the core is storage-agnostic with zero changes
to business logic.

They require a reachable MongoDB (``MOTOR_URI``, defaulting to
``mongodb://localhost:27017``) because Beanie is an async ODM built on Motor;
``mongomock`` does not ship an async client compatible with Beanie. When no
server is reachable the whole module is skipped.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from types import SimpleNamespace

import pytest
from blenx_auth.beanie.bootstrap import init_beanie_db
from blenx_auth.beanie.repositories import (
    BeanieOAuthAccountRepository,
    BeanieRefreshTokenRepository,
    BeanieUserRepository,
)
from blenx_auth.core.dto import NewUser
from blenx_auth.core.exceptions import (
    AccountLockedError,
    EmailAlreadyExistsError,
    InactiveAccountError,
    InvalidCredentialsError,
    InvalidRefreshTokenError,
    InvalidTokenError,
    PasswordPolicyError,
)
from blenx_auth.core.jwt import TokenService
from blenx_auth.core.password import verify_password
from blenx_auth.core.services import (
    AuthenticationService,
    EmailVerificationService,
    PasswordResetService,
)
from blenx_auth.core.settings import AuthSettings
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import MongoClient

from beanie import PydanticObjectId

from .fakes import FakeEmailSender

TEST_SECRET = secrets.token_hex(32)
MOTOR_URI = os.environ.get("MOTOR_URI", "mongodb://localhost:27017")


def _mongo_available() -> bool:
    try:
        MongoClient(MOTOR_URI, serverSelectionTimeoutMS=1200).admin.command("ping")
        return True
    except Exception:  # noqa: BLE001  - any failure means no server to test against
        return False


pytestmark = pytest.mark.skipif(not _mongo_available(), reason="No reachable MongoDB server")


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


@dataclass
class AuthHarness:
    """A fully-wired service stack backed by the Beanie repositories."""

    auth: AuthenticationService
    settings: AuthSettings
    tokens: TokenService
    users: BeanieUserRepository
    refresh_tokens: BeanieRefreshTokenRepository
    oauth_accounts: BeanieOAuthAccountRepository
    verification: EmailVerificationService
    reset: PasswordResetService
    mail: FakeEmailSender


@pytest.fixture
async def harness() -> AuthHarness:
    client = AsyncIOMotorClient(MOTOR_URI)
    await client.drop_database("blenx_auth_test")
    await init_beanie_db(database=client.blenx_auth_test)
    settings = _settings()
    tokens = TokenService(settings)
    users = BeanieUserRepository()
    refresh_tokens = BeanieRefreshTokenRepository()
    oauth_accounts = BeanieOAuthAccountRepository()
    parse_subject = PydanticObjectId
    mail = FakeEmailSender()
    verification = EmailVerificationService(
        users=users,
        tokens=tokens,
        email_sender=mail,
        settings=settings,
        parse_subject=parse_subject,
    )
    reset = PasswordResetService(
        users=users,
        refresh_tokens=refresh_tokens,
        tokens=tokens,
        email_sender=mail,
        settings=settings,
        parse_subject=parse_subject,
    )
    auth = AuthenticationService(
        users=users,
        refresh_tokens=refresh_tokens,
        oauth_accounts=oauth_accounts,
        tokens=tokens,
        email_sender=mail,
        verification=verification,
        settings=settings,
        parse_subject=parse_subject,
    )
    return AuthHarness(
        auth=auth,
        settings=settings,
        tokens=tokens,
        users=users,
        refresh_tokens=refresh_tokens,
        oauth_accounts=oauth_accounts,
        verification=verification,
        reset=reset,
        mail=mail,
    )


async def test_register_normalizes_email_and_requires_policy(harness: AuthHarness) -> None:
    user = await harness.auth.register(email="  Ann@Example.COM ", password="password-123")
    assert user.email == "ann@example.com"
    assert user.is_verified is False
    assert isinstance(user.id, PydanticObjectId)
    assert verify_password("password-123", user.hashed_password)
    assert any("verify-email" in m.body for m in harness.mail.sent)


async def test_ids_round_trip_through_jwt_subject(harness: AuthHarness) -> None:
    """``str(id) -> JWT sub -> parse_subject`` must survive the ObjectId mode."""
    user = await harness.auth.register(email="ids@example.com", password="password-123")
    resolved = await harness.auth.authenticate_access_token(
        harness.tokens.create_access_token(str(user.id))
    )
    assert resolved.id == user.id


async def test_register_duplicate_and_weak_password(harness: AuthHarness) -> None:
    await harness.auth.register(email="ann@example.com", password="password-123")
    with pytest.raises(EmailAlreadyExistsError):
        await harness.auth.register(email="ann@example.com", password="password-123")
    with pytest.raises(PasswordPolicyError):
        await harness.auth.register(email="other@example.com", password="short")


async def test_concurrent_duplicate_insert_raises_domain_error(harness: AuthHarness) -> None:
    await harness.users.create(NewUser(email="race@example.com", hashed_password="x"))
    with pytest.raises(EmailAlreadyExistsError):
        await harness.users.create(NewUser(email="race@example.com", hashed_password="x"))


async def test_login_issues_pair_and_clears_failures(harness: AuthHarness) -> None:
    await harness.auth.register(email="ann@example.com", password="password-123")
    pair = await harness.auth.login(email="ann@example.com", password="password-123")
    assert pair.access_token
    assert pair.expires_in == harness.settings.access_token_expire_minutes * 60


async def test_login_rejects_unknown_and_wrong_password(harness: AuthHarness) -> None:
    await harness.auth.register(email="ann@example.com", password="password-123")
    with pytest.raises(InvalidCredentialsError):
        await harness.auth.login(email="ghost@example.com", password="password-123")
    with pytest.raises(InvalidCredentialsError):
        await harness.auth.login(email="ann@example.com", password="wrong")


async def test_lockout_over_threshold(harness: AuthHarness) -> None:
    await harness.auth.register(email="a@example.com", password="password-123")
    for _ in range(2):
        with pytest.raises(InvalidCredentialsError):
            await harness.auth.login(email="a@example.com", password="wrong")
    with pytest.raises(AccountLockedError):
        await harness.auth.login(email="a@example.com", password="wrong")
    with pytest.raises(AccountLockedError):
        await harness.auth.login(email="a@example.com", password="password-123")


async def test_verify_and_refresh_rotation(harness: AuthHarness) -> None:
    await harness.auth.register(email="a@example.com", password="password-123")
    pair = await harness.auth.login(email="a@example.com", password="password-123")
    verify_token = next(
        m.body.split("token=")[1] for m in harness.mail.sent if "verify-email" in m.body
    )
    await harness.verification.verify(verify_token)

    new_pair = await harness.auth.refresh(pair.refresh_token)
    assert new_pair.access_token
    with pytest.raises(InvalidRefreshTokenError):
        await harness.auth.refresh(pair.refresh_token)  # reuse after rotation
    await harness.auth.logout(new_pair.refresh_token)
    with pytest.raises(InvalidRefreshTokenError):
        await harness.auth.refresh(new_pair.refresh_token)


async def test_password_reset_flow(harness: AuthHarness) -> None:
    await harness.auth.register(email="a@example.com", password="password-123")
    await harness.reset.request_reset(email="a@example.com")
    reset_token = next(
        m.body.split("token=")[1] for m in harness.mail.sent if "reset-password" in m.body
    )
    await harness.reset.reset(reset_token, "brand-new-99")
    with pytest.raises(InvalidCredentialsError):
        await harness.auth.login(email="a@example.com", password="password-123")
    await harness.auth.login(email="a@example.com", password="brand-new-99")


async def test_oauth_login_creates_then_reuses(harness: AuthHarness) -> None:
    pair = await harness.auth.oauth_login(
        provider="google",
        account_id="sub-1",
        account_email="O@Example.com",
        oauth_access_token="at",
    )
    assert pair.access_token
    user = await harness.users.get_by_email("o@example.com")
    assert user.is_verified
    await harness.auth.oauth_login(
        provider="google",
        account_id="sub-1",
        account_email="o@example.com",
        oauth_access_token="at",
    )
    assert await harness.users.get_by_email("o@example.com") is not None


async def test_authenticate_access_token(harness: AuthHarness) -> None:
    user = await harness.auth.register(email="ann@example.com", password="password-123")
    resolved = await harness.auth.authenticate_access_token(
        harness.tokens.create_access_token(str(user.id))
    )
    assert resolved.id == user.id
    with pytest.raises(InvalidTokenError):
        await harness.auth.authenticate_access_token("garbage")
    user.is_active = False
    await harness.users.save(user)
    with pytest.raises(InactiveAccountError):
        await harness.auth.authenticate_access_token(
            harness.tokens.create_access_token(str(user.id))
        )
