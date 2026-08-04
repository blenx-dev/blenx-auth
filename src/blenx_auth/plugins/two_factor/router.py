"""HTTP endpoints for the two-factor plugin (``/2fa``).

``make_two_factor_router(config, *, get_service)`` is reconciled with the
composition root's ``AuthPlugin.router_factory(config)`` call: the root passes
the :class:`PluginRouterConfig`; the plugin supplies the ``get_service``
dependency (a bound ``TwoFactorService``) through its own closure.

NOTE: this module intentionally omits ``from __future__ import annotations``
for the same reason as :mod:`blenx_auth.fastapi.routers.auth`: the route's
``Depends(get_service)`` references the caller's closure, which FastAPI's
``eval_str`` cannot resolve from a deferred string annotation.
"""

from collections.abc import Awaitable, Callable
from typing import Annotated

from blenx_auth.core.schemas import LoginSuccess
from blenx_auth.fastapi.routers._provider import PluginRouterConfig
from blenx_auth.plugins.two_factor.schemas import TwoFactorVerifyRequest
from blenx_auth.plugins.two_factor.service import TwoFactorService
from fastapi import APIRouter, Depends


def make_two_factor_router(
    config: PluginRouterConfig,
    *,
    get_service: Callable[..., Awaitable[TwoFactorService]],
) -> APIRouter:
    router = APIRouter(prefix="/2fa", tags=["2fa"])

    @router.post("/verify", response_model=LoginSuccess, summary="Complete a 2FA challenge")
    async def verify(
        data: TwoFactorVerifyRequest,
        service: Annotated[TwoFactorService, Depends(get_service)],
    ) -> LoginSuccess:
        """Exchange a challenge token + code for a real access token."""
        return await service.verify(challenge_token=data.challenge_token, code=data.code)

    return router


__all__ = ["make_two_factor_router"]
