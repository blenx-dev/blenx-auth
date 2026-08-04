"""FastAPI integration subpackage for ``blenx_auth``.

Importing this subpackage pulls in FastAPI and Starlette. The core package
``blenx_auth`` remains framework-free.

The recommended way to wire auth into a host app is the **composition roots**:

- :class:`blenx_auth.fastapi.SQLAlchemyAuth` / :class:`blenx_auth.fastapi.BeanieAuth`
  expose the service and current-user dependencies for one storage backend.
- Router *factories* (:func:`make_auth_router`, :func:`make_users_router`,
  :func:`make_oauth_router`) build the endpoint surface bound to a root.
- :func:`auth_error_handler` renders every :class:`AuthError` as JSON.
"""

from blenx_auth.fastapi.composition import BeanieAuth, SQLAlchemyAuth
from blenx_auth.fastapi.current_user import (
    CurrentUserDeps,
    bearer_scheme,
    make_current_user_dependencies,
)
from blenx_auth.fastapi.exception_handlers import auth_error_handler
from blenx_auth.fastapi.google_oauth import (
    GoogleOIDCOAuth2,
    get_google_oauth_client,
)
from blenx_auth.fastapi.permissions import (
    Permission,
    PermissionGuards,
    make_permission_guards,
    permissions_for,
    roles_for,
)
from blenx_auth.fastapi.routers import (
    AuthProvider,
    OAuthClient,
    make_auth_router,
    make_oauth_router,
    make_users_router,
)

__all__ = [
    "AuthProvider",
    "BeanieAuth",
    "CurrentUserDeps",
    "GoogleOIDCOAuth2",
    "OAuthClient",
    "Permission",
    "PermissionGuards",
    "SQLAlchemyAuth",
    "auth_error_handler",
    "bearer_scheme",
    "get_google_oauth_client",
    "make_auth_router",
    "make_current_user_dependencies",
    "make_oauth_router",
    "make_permission_guards",
    "make_users_router",
    "permissions_for",
    "roles_for",
]
