"""Outbound email: the port plus the shipped no-op sender.

The auth module only ever depends on :class:`EmailSender` (a structural
``Protocol``) — never on a concrete mailer — so delivery can be a no-op in
development, a queue in staging, or an SMTP/API integration in production
without touching business logic.

The port and message type live in the core (``blenx_auth.core.ports`` /
``blenx_auth.core.dto``); this module adds the no-op :class:`NullEmailSender`
plus the :func:`get_email_sender` factory, which is what the FastAPI adapter
wires per environment.
"""

from __future__ import annotations

import logging

from blenx_auth.core.dto import EmailMessage
from blenx_auth.core.ports import EmailSender

logger = logging.getLogger(__name__)


class NullEmailSender:
    """Development/no-op sender.

    Logs at ``INFO`` instead of delivering. Safe for local dev, test
    environments, and anywhere email delivery is not (yet) configured — the
    full auth flows run with it installed.
    """

    async def send(self, message: EmailMessage) -> None:
        logger.info(
            "[email/%s] subject='%s' body='%s'",
            message.to,
            message.subject,
            message.body,
        )


def get_email_sender() -> EmailSender:
    """Email-sender factory (the environment's mailer).

    Currently returns the no-op sender. Swap this factory for a real
    ``EmailSender`` implementation (SMTP, Resend, SES, ...) when outbound
    delivery is configured — nothing else in the codebase needs to change.
    """
    return NullEmailSender()


__all__ = ["EmailMessage", "EmailSender", "NullEmailSender", "get_email_sender"]
