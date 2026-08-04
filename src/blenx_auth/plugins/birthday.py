"""Two-factor reference plugin.

Enabling it is exactly:

    auth = SQLAlchemyAuth(
        settings=settings,
        session_factory=session_factory,
        plugins=[make_two_factor_plugin(otp_repo=my_totp_repo)],
    )

``make_two_factor_plugin`` is fully self-contained: the composition root seeds
the plugin's router factory during construction (``self.routers`` is built in
``__init__``), which binds one ``TwoFactorService`` on the root's
``TokenService``; the ``transform_login_result`` hook and the ``/2fa/verify``
router share that single instance, so a login challenge always verifies against
the same secret/issuer the service minted.
"""

from __future__ import annotations


from blenx_auth.core.plugins import AuthPlugin
from pydantic import field_validator
from pydantic import Field
"""Mixins the two-factor plugin contributes to the user table and schemas.

- ``TwoFactorTableMixin`` — the two new ``user`` columns (SQLAlchemy
  ``Mapped`` style, folded into the composed model by the composition root).
- ``TwoFactorReadMixin`` / ``TwoFactorCreateMixin`` — the corresponding
  Pydantic fields on ``UserRead`` / ``UserCreate``.
"""

from datetime import date
from sqlalchemy import Date
from pydantic import BaseModel

from sqlalchemy.orm import Mapped, mapped_column


class BirthdayMixin:
    birthday: Mapped[date | None] = mapped_column(Date,default=None)

class BirthdayReadMixin(BaseModel):
    birthday: date | None = None


__all__ = ["BirthdayUpdateMixin", "BirthdayUpdateMixin", "BirthdayMixin"]



def make_birthday_plugin(min_age = 18) -> AuthPlugin:
    """Build the two-factor ``AuthPlugin`` bound to ``otp_repo``.

    ``otp_repo`` must satisfy the :class:`OtpRepository` protocol — it owns the
    actual code verification (e.g. backed by ``pyotp``), which the library does
    not ship.
    """ 
    class BirthdayUpdateMixin:
        birthday: date | None = None

        @field_validator("birthday")
        @classmethod
        def verify_birthday(cls, value: date | None) -> date | None:
            if value is None:
                return value
            today = date.today()
            age = (
                today.year
                - value.year
                - ((today.month, today.day) < (value.month, value.day))
            )
            if age < min_age:
                raise ValueError(f"You must be at least {min_age} years old.")

            return value

    return AuthPlugin(
        name="birthday",
        table_mixin=BirthdayMixin,
        read_mixin=BirthdayReadMixin,
        update_mixin=BirthdayUpdateMixin,
    )


__all__ = ["make_birthday_plugin"]
