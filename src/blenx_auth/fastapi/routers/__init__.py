"""Router factories bound to a composition root."""

from blenx_auth.fastapi.routers._provider import AuthProvider
from blenx_auth.fastapi.routers.auth import make_auth_router
from blenx_auth.fastapi.routers.oauth import OAuthClient, make_oauth_router
from blenx_auth.fastapi.routers.users import make_users_router

__all__ = [
    "AuthProvider",
    "OAuthClient",
    "make_auth_router",
    "make_oauth_router",
    "make_users_router",
]
