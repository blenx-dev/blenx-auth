"""Google OAuth2 client for the FastAPI inbound adapter.

Wraps ``httpx_oauth``'s OAuth2 base with Google's OIDC ``userinfo`` endpoint so
the login flow gets a stable provider-subject id (``sub``) and the account
email in one call. This lives under :mod:`blenx_auth.fastapi` because it is an
inbound integration for the OAuth login route; the core auth services never
import it.
"""

from typing import Any, cast

from httpx_oauth.exceptions import GetIdEmailError, GetProfileError
from httpx_oauth.oauth2 import OAuth2

from blenx_auth.core.settings import AuthSettings

AUTHORIZE_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
ACCESS_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"  # noqa: S105
REFRESH_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"  # noqa: S105
REVOKE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/revoke"  # noqa: S105
PROFILE_ENDPOINT = "https://openidconnect.googleapis.com/v1/userinfo"

BASE_SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
]


class GoogleOIDCOAuth2(OAuth2):
    """Google OAuth2 client using the OIDC userinfo endpoint instead of
    the legacy REST API or the People API."""

    def __init__(self, client_id: str, client_secret: str) -> None:
        super().__init__(
            client_id,
            client_secret,
            AUTHORIZE_ENDPOINT,
            ACCESS_TOKEN_ENDPOINT,
            refresh_token_endpoint=REFRESH_TOKEN_ENDPOINT,
            revoke_token_endpoint=REVOKE_TOKEN_ENDPOINT,
            name="google",
            base_scopes=BASE_SCOPES,
            token_endpoint_auth_method="client_secret_post",  # noqa: S106
            revocation_endpoint_auth_method="client_secret_post",  # noqa: S106
        )

    async def get_profile(self, token: str) -> dict[str, Any]:
        async with self.get_httpx_client() as client:
            response = await client.get(
                PROFILE_ENDPOINT,
                headers={**self.request_headers, "Authorization": f"Bearer {token}"},
            )
            if response.status_code >= 400:
                raise GetProfileError(response=response)
            return cast(dict[str, Any], response.json())

    async def get_id_email(self, token: str) -> tuple[str, str | None]:
        try:
            profile = await self.get_profile(token)
        except GetProfileError as e:
            raise GetIdEmailError(response=e.response) from e

        # OIDC userinfo returns "sub" as the stable user id
        return profile["sub"], profile.get("email")


def get_google_oauth_client(settings: AuthSettings) -> GoogleOIDCOAuth2:
    """Create a Google OAuth2 client for the given settings."""
    return GoogleOIDCOAuth2(
        settings.google_client_id,
        settings.google_client_secret,
    )


__all__ = ["GoogleOIDCOAuth2", "get_google_oauth_client"]
