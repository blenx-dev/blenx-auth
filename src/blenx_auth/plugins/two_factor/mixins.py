"""Mixins the two-factor plugin contributes to the user table and schemas.

- ``TwoFactorTableMixin`` — the two new ``user`` columns (SQLAlchemy
  ``Mapped`` style, folded into the composed model by the composition root).
- ``TwoFactorReadMixin`` / ``TwoFactorCreateMixin`` — the corresponding
  Pydantic fields on ``UserRead`` / ``UserCreate``.
"""

from __future__ import annotations
from typing import Literal

from pydantic import BaseModel

from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column


class TwoFactorTableMixin:
    is_2fa_enabled: Mapped[bool] = mapped_column(default=False)
    two_factor_type: Mapped[str | None] = mapped_column(String(20), default=None)


class TwoFactorReadMixin(BaseModel):
    is_2fa_enabled: bool
    two_factor_type: Literal['app', 'email'] | None = None

class TwoFactorUpdateMixin(BaseModel):
    is_2fa_enabled: bool | None = None
    two_factor_type: Literal['app', 'email'] | None = None


__all__ = ["TwoFactorUpdateMixin", "TwoFactorReadMixin", "TwoFactorTableMixin"]
