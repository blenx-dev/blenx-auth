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

from typing import Any

from blenx_auth.core.plugins import AuthPlugin
from blenx_auth.core.plugins.hooks import AuthHooks
from blenx_auth.plugins.two_factor.mixins import (
    TwoFactorUpdateMixin,
    TwoFactorReadMixin,
    TwoFactorTableMixin,
)
from blenx_auth.plugins.two_factor.router import make_two_factor_router
from blenx_auth.plugins.two_factor.service import OtpRepository, TwoFactorService
from fastapi import APIRouter


def make_two_factor_plugin(*, otp_repo: OtpRepository) -> AuthPlugin:
    """Build the two-factor ``AuthPlugin`` bound to ``otp_repo``.

    ``otp_repo`` must satisfy the :class:`OtpRepository` protocol — it owns the
    actual code verification (e.g. backed by ``pyotp``), which the library does
    not ship.
    """
    holder: dict[str, TwoFactorService] = {}

    def _service(config: Any) -> TwoFactorService:
        if "service" not in holder:
            holder["service"] = TwoFactorService(
                otp_repo=otp_repo,
                token_service=config.token_service,
            )
        return holder["service"]

    def router_factory(config: Any) -> APIRouter:
        service = _service(config)

        async def get_service() -> TwoFactorService:
            return service

        return make_two_factor_router(config, get_service=get_service)

    async def transform_login(user: Any, result: Any) -> Any:
        if "service" not in holder:
            return result
        return await holder["service"].transform_login(user, result)

    return AuthPlugin(
        name="two_factor",
        table_mixin=TwoFactorTableMixin,
        read_mixin=TwoFactorReadMixin,
        update_mixin=TwoFactorUpdateMixin,
        hooks=AuthHooks(transform_login_result=(transform_login,)),
        router_factory=router_factory,
    )


__all__ = ["make_two_factor_plugin"]
