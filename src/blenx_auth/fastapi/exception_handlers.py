"""Exception handlers for the auth module.

:func:`auth_error_handler` is registered on the host ``FastAPI`` app and renders
every :class:`~blenx_auth.core.exceptions.AuthError` as an RFC 7807-shaped JSON
response, so route code never maps errors by hand.
"""

from __future__ import annotations

from fastapi.responses import JSONResponse

from blenx_auth.core.exceptions import AuthError
from fastapi import Request


async def auth_error_handler(request: Request, exc: Exception) -> JSONResponse:
    """Render an :class:`AuthError` as a JSON ``{detail: ...}`` response.

    ``request`` is deliberately untyped because the handler contract only needs
    to satisfy Starlette's registration signature; FastAPI validates the
    ``Exception`` subclass and this handler's return type at startup.
    """
    assert isinstance(exc, AuthError)
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
        headers=exc.headers or None,
    )


__all__ = ["auth_error_handler"]
