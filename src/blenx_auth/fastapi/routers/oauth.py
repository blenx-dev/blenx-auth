"""Generic OAuth login router.

Builds the browser OAuth round-trip for any OAuth2 provider client that can
produce an authorization URL, exchange a code for a token, and resolve a
provider identity:

- ``GET {prefix}/authorize`` — redirects the browser to the provider's consent
  screen with a short-lived signed ``state`` (minted by :class:`TokenService`),
  so the callback accepts only authorize round-trips this server started (CSRF
  protection for the login redirect) without needing server-side state.
- ``GET {prefix}/callback`` — verifies ``state``, exchanges the code, resolves
  ``(account_id, account_email)``, finds-or-creates the user via
  :meth:`AuthenticationService.oauth_login`, and redirects the browser to the
  frontend's ``/oauth-callback`` with the new token pair as query parameters.

Google is wired by passing ``GoogleOIDCOAuth2`` with its ``get_id_email``;
GitHub/Microsoft/etc. are wired by passing their httpx_oauth client plus a
``get_id_email``-equivalent callable.

NOTE: this module intentionally omits ``from __future__ import annotations``
for the same reason as :mod:`blenx_auth.fastapi.routers.auth`.
"""

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import KW_ONLY, dataclass
from typing import Annotated, Any, Protocol, Required, Unpack

from fastapi.responses import RedirectResponse

from blenx_auth.core.exceptions import InvalidTokenError
from blenx_auth.core.impl_protocols import AuthBackend
from blenx_auth.core.services import AuthenticationService
from blenx_auth.fastapi.routers._provider import AuthRouterConfig, AuthRouterConfigOverrides
from fastapi import APIRouter, Depends, Request


class OAuthClient(Protocol):
    """The httpx_oauth-compatible surface the generic router needs."""

    name: str
    base_scopes: list[str] | None

    async def get_authorization_url(
        self,
        redirect_uri: str,
        state: str | None = None,
        scope: list[str] | None = None,
    ) -> str: ...

    async def get_access_token(
        self,
        code: str,
        redirect_uri: str,
        code_verifier: str | None = None,
    ) -> Mapping[str, Any]: ...


class OAuthRouterConfigOverrides(AuthRouterConfigOverrides):
    client: Required[OAuthClient]
    get_id_email: Required[Callable[[str], Awaitable[tuple[str, str | None]]]]
    backend_url: str
    frontend_url: str


@dataclass
class OAuthRouterConfig(AuthRouterConfig):
    _: KW_ONLY
    client: OAuthClient
    get_id_email: Callable[[str], Awaitable[tuple[str, str | None]]]
    backend_url: str
    frontend_url: str


def make_oauth_router(
    auth: AuthBackend[Any],
    **overrides: Unpack[OAuthRouterConfigOverrides],
) -> APIRouter:
    """Build an OAuth login router for ``client`` bound to ``get_authentication_service``."""

    config = OAuthRouterConfig(**overrides)
    router = APIRouter(prefix=config.prefix, tags=config.tags)
    redirect_uri = f"{config.backend_url}{config.prefix}/callback"
    get_authentication_service = auth.get_authentication_service

    @router.get(
        "/authorize",
        summary=f"Start {config.client.name} sign-in",
    )
    async def oauth_authorize() -> RedirectResponse:
        """Redirect the browser to the provider's consent screen."""
        state = auth.token_service.create_oauth_state()
        url = await config.client.get_authorization_url(
            redirect_uri=redirect_uri,
            state=state,
            scope=config.client.base_scopes,
        )
        return RedirectResponse(url)

    @router.get(
        "/callback",
        include_in_schema=False,
        summary=f"{config.client.name} sign-in callback",
    )
    async def oauth_callback(
        request: Request,
        auth_service: Annotated[AuthenticationService[Any], Depends(get_authentication_service)],
        code: str,
        state: str | None = None,
    ) -> RedirectResponse:
        """Exchange the authorization code, find-or-create the user, and hand
        the token pair to the frontend."""
        if state is None:
            raise InvalidTokenError("Missing OAuth state.")
        auth.token_service.verify_oauth_state(state)

        token = await config.client.get_access_token(code, redirect_uri=redirect_uri)
        account_id, account_email = await config.get_id_email(token["access_token"])

        ip = request.client.host if request.client is not None else None
        user_agent = request.headers.get("user-agent")
        pair = await auth_service.oauth_login(
            provider=config.client.name,
            account_id=account_id,
            account_email=account_email or "",
            oauth_access_token=token["access_token"],
            oauth_expires_at=token.get("expires_at"),
            oauth_refresh_token=token.get("refresh_token"),
            ip_address=ip,
            user_agent=user_agent,
        )
        return RedirectResponse(
            url=(
                f"{config.frontend_url}/oauth-callback"
                f"?access_token={pair.access_token}&refresh_token={pair.refresh_token}"
            )
        )

    return router


__all__ = ["OAuthClient", "make_oauth_router"]
