"""Request schemas for the two-factor plugin's own endpoints."""

from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, Field


class TwoFactorVerifyRequest(BaseModel):
    """Payload for ``POST /2fa/verify``: the challenge token plus the code."""

    challenge_token: str
    code: Annotated[str, Field(min_length=6, max_length=6)]


__all__ = ["TwoFactorVerifyRequest"]
