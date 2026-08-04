"""Password recovery (request / reset)."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Generic

from blenx_auth.core.dto import EmailMessage, IdT
from blenx_auth.core.exceptions import (
    ExpiredTokenError,
    InvalidTokenError,
)
from blenx_auth.core.jwt import TokenService, hash_token
from blenx_auth.core.password import hash_password, validate_password
from blenx_auth.core.ports import (
    EmailSender,
    RefreshTokenRepository,
    UserRepository,
)
from blenx_auth.core.services._common import _PARSE_UUID_SUBJECT, parse_subject
from blenx_auth.core.settings import AuthSettings


class PasswordResetService(Generic[IdT]):
    """Password recovery (request / reset)."""

    def __init__(
        self,
        *,
        users: UserRepository[IdT],
        refresh_tokens: RefreshTokenRepository[IdT],
        tokens: TokenService,
        email_sender: EmailSender,
        settings: AuthSettings,
        parse_subject: Callable[[str], IdT] = _PARSE_UUID_SUBJECT,
    ) -> None:
        self._users = users
        self._refresh_tokens = refresh_tokens
        self._tokens = tokens
        self._email_sender = email_sender
        self._settings = settings
        self._parse_id = parse_subject

    async def request_reset(self, email: str) -> None:
        """Issue and mail a password-reset token.

        Deliberately succeeds whether or not the address exists, so this
        endpoint cannot be used to enumerate registered emails.
        """
        user = await self._users.get_by_email(email)
        if user is None:
            return
        token = self._tokens.create_password_reset_token(str(user.id))
        user.password_reset_token_hash = hash_token(token)
        user.password_reset_token_expires_at = datetime.now(UTC) + timedelta(
            minutes=self._settings.password_reset_token_expire_minutes
        )
        await self._users.save(user)
        url = f"{self._settings.frontend_url}/auth/reset-password?token={token}"
        await self._email_sender.send(
            EmailMessage(
                to=user.email,
                subject="Reset your password",
                body=f"Reset your password by opening:\n{url}",
            )
        )

    async def reset(self, token: str, new_password: str) -> None:
        """Validate the token, set the new password, and invalidate the token.

        Also revokes every refresh token and clears any lockout: a password
        change must end existing sessions and regain access.
        """
        validate_password(new_password)
        subject = self._tokens.verify_password_reset_token(token)
        user = await self._users.get_by_id(parse_subject(subject, self._parse_id))
        if user is None:
            raise InvalidTokenError()
        if user.password_reset_token_hash != hash_token(token):
            raise InvalidTokenError("Password reset token has already been used.")
        if (
            user.password_reset_token_expires_at is None
            or user.password_reset_token_expires_at < datetime.now(UTC)
        ):
            raise ExpiredTokenError()

        user.hashed_password = hash_password(new_password)
        user.password_reset_token_hash = None
        user.password_reset_token_expires_at = None
        user.failed_login_attempts = 0
        user.locked_until = None
        await self._users.save(user)
        await self._refresh_tokens.revoke_all_for_user(user.id)
