"""Core authentication flows (register / login / refresh / OAuth).

Owns every decision the auth module makes about *who may act*: registration
with policy enforcement, credential verification with lockout guarding,
refresh-token rotation with reuse (family) detection, and OAuth account
linking. Persistence details never appear here — this service talks only to the
``UserRepository``/``RefreshTokenRepository``/``OAuthAccountRepository`` ports,
the ``TokenService``, and an ``EmailSender``, so it is fully unit-testable with
fakes and framework-free.

Security notes:
- Lockout: ``failed_login_attempts`` climb to ``max_failed_login_attempts``;
  on the final failure the account is locked for ``account_lockout_minutes``
  and the counter resets (the lock, not the count, is the state).
- Refresh rotation: every successful refresh revokes the presented token and
  issues a new one. Presenting an already-revoked-but-valid token is treated
  as family compromise: every outstanding token for that user is revoked.
- Login never reveals whether the address exists: unknown email and wrong
  password both surface as :class:`InvalidCredentialsError`.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, date, datetime, timedelta
from typing import Any, Generic

from blenx_auth.core.dto import IdT, NewOAuthLink, NewUser, TokenPair
from blenx_auth.core.exceptions import (
    AccountLockedError,
    EmailAlreadyExistsError,
    InactiveAccountError,
    InvalidCredentialsError,
    InvalidRefreshTokenError,
    InvalidTokenError,
    TokenError,
)
from blenx_auth.core.jwt import TokenService, hash_token
from blenx_auth.core.password import hash_password, validate_password, verify_password
from blenx_auth.core.plugins.hooks import AuthHooks, run_side_effects, run_transform_chain
from blenx_auth.core.ports import (
    EmailSender,
    OAuthAccountRepository,
    RefreshTokenRepository,
    UserAccount,
    UserRepository,
)
from blenx_auth.core.schemas import LoginChallenge, LoginSuccess
from blenx_auth.core.services._common import _PARSE_UUID_SUBJECT, parse_subject
from blenx_auth.core.services.verification import EmailVerificationService
from blenx_auth.core.settings import AuthSettings


class AuthenticationService(Generic[IdT]):
    """Core authentication flows (register / login / refresh / OAuth)."""

    def __init__(
        self,
        *,
        users: UserRepository[IdT],
        refresh_tokens: RefreshTokenRepository[IdT],
        oauth_accounts: OAuthAccountRepository[IdT],
        tokens: TokenService,
        email_sender: EmailSender,
        verification: EmailVerificationService[IdT],
        settings: AuthSettings,
        parse_subject: Callable[[str], IdT] = _PARSE_UUID_SUBJECT,
        hooks: AuthHooks | None = None,
    ) -> None:
        self._users = users
        self._refresh_tokens = refresh_tokens
        self._oauth_accounts = oauth_accounts
        self._tokens = tokens
        self._email_sender = email_sender
        self._verification = verification
        self._settings = settings
        self._parse_id = parse_subject
        self._hooks = hooks or AuthHooks()

    async def register(
        self,
        *,
        email: str,
        password: str,
        birthdate: date | None = None,
        extra_fields: dict[str, Any] | None = None
    ) -> UserAccount[IdT]:
        """Create an unverified account, then mail its verification link.

        ``email`` is normalized to lowercase so the unique index and all
        lookups are case-insensitive by construction. Raises
        :class:`EmailAlreadyExistsError` on collision, including a concurrent
        insert whose duplicate the backend repository translates into the same
        domain error (SQLAlchemy ``IntegrityError`` or Mongo
        ``DuplicateKeyError``) — so the race never leaks a storage exception.
        """
        validate_password(password)
        email = email.lower().strip()
        existing = await self._users.get_by_email(email)
        if existing is not None:
            raise EmailAlreadyExistsError()
        user = await self._users.create(
            NewUser(
                email=email,
                hashed_password=hash_password(password),
                is_verified=False,
                birthdate=birthdate,
                extra_fields=extra_fields or {},
            )
        )
        await self._verification.resend(user)
        await run_side_effects(self._hooks.on_after_register, user)
        return user

    async def login(
        self,
        *,
        email: str,
        password: str,
        device_name: str | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> LoginSuccess | LoginChallenge:
        """Verify credentials and produce a login result.

        Failed attempts are counted toward the lockout threshold; a locked
        account raises :class:`AccountLockedError` until the cooldown elapses.

        On success the token pair is wrapped in a :class:`LoginSuccess` and
        passed through the ``transform_login_result`` hook chain (locked
        decision #3: the chain stops early the moment a hook returns a
        :class:`LoginChallenge`). ``transform_login_result`` runs **before**
        ``on_after_login`` so those side effects reflect the final outcome
        without needing to know whether a challenge was issued.
        """
        user = await self._users.get_by_email(email.lower().strip())
        if user is None:
            raise InvalidCredentialsError()
        if user.locked_until is not None and user.locked_until > datetime.now(UTC):
            retry_after = max(0, int((user.locked_until - datetime.now(UTC)).total_seconds()))
            raise AccountLockedError(retry_after=retry_after)
        if not verify_password(password, user.hashed_password):
            await self._register_failed_attempt(user)
            raise InvalidCredentialsError()
        if not user.is_active:
            raise InactiveAccountError()
        user.failed_login_attempts = 0
        user.locked_until = None
        await self._users.save(user)
        pair = await self._issue_tokens(
            user, device_name=device_name, ip_address=ip_address, user_agent=user_agent
        )
        result: LoginSuccess | LoginChallenge = LoginSuccess(
            access_token=pair.access_token,
            refresh_token=pair.refresh_token,
            expires_in=pair.expires_in,
            token_type=pair.token_type,
        )
        result = await run_transform_chain(self._hooks.transform_login_result, user, result)
        await run_side_effects(self._hooks.on_after_login, user, {})
        return result

    async def oauth_login(
        self,
        *,
        provider: str,
        account_id: str,
        account_email: str,
        oauth_access_token: str,
        oauth_expires_at: int | None = None,
        oauth_refresh_token: str | None = None,
        device_name: str | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> TokenPair:
        """Find-or-create the user for a verified provider identity.

        An existing OAuth link is reused as-is; otherwise the account is linked
        to the matching email, creating a verified user when none exists and
        marking an existing unverified user as verified.
        """
        account = await self._oauth_accounts.get_by_provider_account(provider, account_id)
        email = account_email.lower().strip()
        if account is not None:
            linked = await self._require_active(await self._users.get_by_id(account.user_id))
            if email != linked.email:
                linked.email = email
                await self._users.save(linked)
            return await self._issue_tokens(
                linked, device_name=device_name, ip_address=ip_address, user_agent=user_agent
            )

        user = await self._users.get_by_email(email)
        if user is None:
            user = await self._users.create(
                NewUser(email=email, hashed_password="", is_verified=True)
            )
        else:
            user = await self._require_active(user)
            user.is_verified = True
            user.email_verified_at = user.email_verified_at or datetime.now(UTC)
            await self._users.save(user)

        await self._oauth_accounts.link(
            NewOAuthLink(
                provider=provider,
                account_id=account_id,
                account_email=email,
                user_id=user.id,
                access_token=oauth_access_token,
                expires_at=oauth_expires_at,
                refresh_token=oauth_refresh_token,
            )
        )
        return await self._issue_tokens(
            user, device_name=device_name, ip_address=ip_address, user_agent=user_agent
        )

    async def refresh(
        self,
        refresh_token: str,
        *,
        device_name: str | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> TokenPair:
        """Rotate a valid refresh token into a fresh pair.

        The presented token is revoked on success. Presenting an already
        revoked (but cryptographically valid) token means the session family is
        compromised: every outstanding token for that user is revoked.
        """
        subject = self._tokens.decode_refresh_token(refresh_token)
        user_id = parse_subject(subject, self._parse_id)
        row = await self._refresh_tokens.get_by_hash(hash_token(refresh_token))
        if row is None:
            raise InvalidRefreshTokenError()
        if row.revoked_at is not None:
            await self._refresh_tokens.revoke_all_for_user(row.user_id)
            raise InvalidRefreshTokenError("Refresh token has already been used.")
        await self._refresh_tokens.revoke(row.id)
        user = await self._users.get_by_id(user_id)
        if user is None:
            raise InvalidRefreshTokenError()
        return await self._issue_tokens(
            user, device_name=device_name, ip_address=ip_address, user_agent=user_agent
        )

    async def logout(self, refresh_token: str) -> None:
        """Revoke the presented refresh token (idempotent)."""
        try:
            self._tokens.decode_refresh_token(refresh_token)
        except TokenError:
            return
        row = await self._refresh_tokens.get_by_hash(hash_token(refresh_token))
        if row is not None:
            await self._refresh_tokens.revoke(row.id)

    async def logout_all(self, user_id: IdT) -> None:
        """Revoke every outstanding refresh token for ``user_id``."""
        await self._refresh_tokens.revoke_all_for_user(user_id)

    async def authenticate_access_token(self, token: str) -> UserAccount[IdT]:
        """Resolve a valid access token to its active user."""
        subject = self._tokens.decode_access_token(token)
        user = await self._users.get_by_id(parse_subject(subject, self._parse_id))
        if user is None:
            raise InvalidTokenError()
        if not user.is_active:
            raise InactiveAccountError()
        return user

    async def _register_failed_attempt(self, user: UserAccount[IdT]) -> None:
        """Count a failed login and lock the account once the threshold hits."""
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= self._settings.max_failed_login_attempts:
            user.locked_until = datetime.now(UTC) + timedelta(
                minutes=self._settings.account_lockout_minutes
            )
            user.failed_login_attempts = 0
            await self._users.save(user)
            raise AccountLockedError(retry_after=self._settings.account_lockout_minutes * 60)
        await self._users.save(user)

    async def _require_active(
        self, user: UserAccount[IdT] | None
    ) -> UserAccount[IdT]:
        """Return ``user`` when active, else raise the domain error."""
        if user is None:
            raise InvalidCredentialsError()
        if not user.is_active:
            raise InactiveAccountError()
        return user

    async def _issue_tokens(
        self,
        user: UserAccount[IdT],
        *,
        device_name: str | None,
        ip_address: str | None,
        user_agent: str | None,
    ) -> TokenPair:
        """Mint an access + refresh pair and persist the refresh row."""
        raw_refresh = self._tokens.create_refresh_token(str(user.id))
        await self._refresh_tokens.create(
            user_id=user.id,
            token_hash=hash_token(raw_refresh),
            expires_at=datetime.now(UTC) + self._tokens.refresh_expires_delta(),
            device_name=device_name,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        return TokenPair(
            access_token=self._tokens.create_access_token(str(user.id)),
            refresh_token=raw_refresh,
            expires_in=self._settings.access_token_expire_minutes * 60,
        )
