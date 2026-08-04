"""Email-address proof of ownership (verify / resend)."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Generic

from blenx_auth.core.dto import EmailMessage, IdT
from blenx_auth.core.exceptions import InvalidTokenError
from blenx_auth.core.jwt import TokenService
from blenx_auth.core.ports import EmailSender, UserAccount, UserRepository
from blenx_auth.core.services._common import _PARSE_UUID_SUBJECT, parse_subject
from blenx_auth.core.settings import AuthSettings


class EmailVerificationService(Generic[IdT]):
    """Email-address proof of ownership (verify / resend)."""

    def __init__(
        self,
        *,
        users: UserRepository[IdT],
        tokens: TokenService,
        email_sender: EmailSender,
        settings: AuthSettings,
        parse_subject: Callable[[str], IdT] = _PARSE_UUID_SUBJECT,
    ) -> None:
        self._users = users
        self._tokens = tokens
        self._email_sender = email_sender
        self._settings = settings
        self._parse_id = parse_subject

    async def verify(self, token: str) -> None:
        """Mark the token's subject verified. Idempotent for already-verified
        accounts (re-verification succeeds rather than erroring)."""
        subject = self._tokens.verify_email_verification_token(token)
        user = await self._users.get_by_id(parse_subject(subject, self._parse_id))
        if user is None:
            raise InvalidTokenError()
        if user.is_verified:
            return
        user.is_verified = True
        user.email_verified_at = datetime.now(UTC)
        await self._users.save(user)

    async def resend(self, user: UserAccount[IdT]) -> None:
        """Send a fresh verification email. No-op once verified."""
        if user.is_verified:
            return
        token = self._tokens.create_email_verification_token(str(user.id))
        url = f"{self._settings.frontend_url}/auth/verify-email?token={token}"
        await self._email_sender.send(
            EmailMessage(
                to=user.email,
                subject="Verify your email",
                body=f"Verify your email address by opening:\n{url}",
            )
        )
