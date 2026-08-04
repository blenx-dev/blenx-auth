"""The ``/auth`` router (bound to a composition root).

This module owns the endpoint surface only: it maps HTTP requests onto the
services, reads request metadata (client IP, user agent) for refresh-token
rows, and lets the registered :class:`AuthError` handler render failures. No
business rules live here.

``register_schema`` / ``user_read_schema`` are parametrized through
:class:`~blenx_auth.fastapi.routers._provider.AuthRouterConfig` so a
composition root can substitute its dynamically-composed schemas; when absent,
the default ``RegisterRequest`` / ``UserRead`` schemas are used.

NOTE: this module intentionally omits ``from __future__ import annotations``.
Route signatures reference the composition root's dependency closures inside
``Depends(...)``; FastAPI resolves them with
``inspect.signature(..., eval_str=True)``, which cannot resolve deferred string
annotations, so they are evaluated eagerly instead.
"""

from collections.abc import Awaitable, Callable
from typing import Annotated, Any, Unpack

from blenx_auth.core.impl_protocols import AuthBackend
from blenx_auth.core.ports import UserAccount
from blenx_auth.core.schemas import (
    ForgotPasswordRequest,
    LoginChallenge,
    LoginRequest,
    LoginResponse,
    LoginSuccess,
    LogoutRequest,
    RefreshRequest,
    RegisterRequest,
    ResetPasswordRequest,
    TokenResponse,
    UserRead,
    VerifyEmailRequest,
)
from blenx_auth.core.services import (
    AuthenticationService,
    EmailVerificationService,
    PasswordResetService,
)
from blenx_auth.fastapi.routers._provider import (
    AuthRouterConfigOverrides,
    merge_router_config,
)
from fastapi import APIRouter, Depends, Request, Response, status

ServiceDep = Callable[..., Awaitable[AuthenticationService[Any]]]

# Registration fields owned by the core create schema; everything else on the
# request is a consumer/plugin-declared field and flows through to the model.
_CORE_REGISTER_FIELDS = frozenset({"email", "password", "birthdate"})


def _client_metadata(request: Request) -> tuple[str | None, str | None, str | None]:
    """Request-side metadata recorded on refresh-token rows (audit/tracing)."""
    ip = request.client.host if request.client is not None else None
    user_agent = request.headers.get("user-agent")
    return ip, user_agent, None


def make_auth_router(
    auth: AuthBackend[Any],
    **options: Unpack[AuthRouterConfigOverrides],
) -> APIRouter:
    """Build the ``/auth`` router bound to ``auth`` (a composition root)."""
    config = merge_router_config(auth, options, prefix="/auth")
    router = APIRouter(prefix=config.prefix, tags=config.tags)
    register_schema = config.register_schema or RegisterRequest
    user_read_schema = config.user_read_schema or UserRead
    get_authentication_service = auth.get_authentication_service
    get_verification_service = auth.get_verification_service
    get_password_reset_service = auth.get_password_reset_service
    get_current_user = auth.get_current_user

    @router.post(
        "/register",
        response_model=user_read_schema,
        status_code=status.HTTP_201_CREATED,
        summary="Register a new account",
    )
    async def register(
        payload: register_schema,  # type: ignore[valid-type]
        auth_service: Annotated[AuthenticationService[Any], Depends(get_authentication_service)],
    ) -> UserAccount[Any]:
        """Create an unverified account and mail its verification link."""
        payload_fields = payload.model_dump()  # type: ignore[attr-defined]
        extra_fields = {
            name: value
            for name, value in payload_fields.items()
            if name not in _CORE_REGISTER_FIELDS
        }
        return await auth_service.register(
            email=payload.email,  # type: ignore[attr-defined]
            password=payload.password,  # type: ignore[attr-defined]
            birthdate=payload.birthdate,  # type: ignore[attr-defined]
            extra_fields=extra_fields,
        )

    @router.post(
        "/login",
        response_model=LoginResponse,
        summary="Exchange credentials for tokens",
    )
    async def login(
        payload: LoginRequest,
        request: Request,
        auth_service: Annotated[AuthenticationService[Any], Depends(get_authentication_service)],
    ) -> LoginSuccess | LoginChallenge:
        """Authenticate and issue an access + refresh pair.

        Returns the :data:`LoginResponse` discriminated union: a plain
        ``LoginSuccess`` (``kind == "token"``) unless a ``transform_login_result``
        hook downgraded the result to a ``LoginChallenge`` (``kind == "challenge"``,
        e.g. a second factor is required).
        """
        ip, user_agent, _ = _client_metadata(request)
        return await auth_service.login(
            email=payload.email,
            password=payload.password,
            ip_address=ip,
            user_agent=user_agent,
        )

    @router.post("/refresh", response_model=TokenResponse, summary="Rotate a refresh token")
    async def refresh(
        payload: RefreshRequest,
        request: Request,
        auth_service: Annotated[AuthenticationService[Any], Depends(get_authentication_service)],
    ) -> TokenResponse:
        """Rotate a refresh token into a fresh pair (revokes the presented token)."""
        ip, user_agent, _ = _client_metadata(request)
        pair = await auth_service.refresh(
            payload.refresh_token,
            ip_address=ip,
            user_agent=user_agent,
        )
        return TokenResponse.from_pair(pair)

    @router.post(
        "/logout",
        status_code=status.HTTP_204_NO_CONTENT,
        summary="Revoke a refresh token",
    )
    async def logout(
        payload: LogoutRequest,
        auth_service: Annotated[AuthenticationService[Any], Depends(get_authentication_service)],
    ) -> Response:
        """Revoke the presented refresh token (idempotent)."""
        await auth_service.logout(payload.refresh_token)
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @router.post(
        "/logout-all",
        status_code=status.HTTP_204_NO_CONTENT,
        summary="Revoke every session for the current user",
    )
    async def logout_all(
        user: Annotated[UserAccount[Any], Depends(get_current_user)],
        auth_service: Annotated[AuthenticationService[Any], Depends(get_authentication_service)],
    ) -> Response:
        """End every outstanding session for the authenticated user."""
        await auth_service.logout_all(user.id)
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @router.post(
        "/verify",
        status_code=status.HTTP_204_NO_CONTENT,
        summary="Verify an email address",
    )
    async def verify_email(
        payload: VerifyEmailRequest,
        verification: Annotated[EmailVerificationService[Any], Depends(get_verification_service)],
    ) -> Response:
        """Consume an email-verification token (idempotent)."""
        await verification.verify(payload.token)
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @router.post(
        "/resend-verification",
        status_code=status.HTTP_204_NO_CONTENT,
        summary="Resend the verification email",
    )
    async def resend_verification(
        user: Annotated[UserAccount[Any], Depends(get_current_user)],
        verification: Annotated[EmailVerificationService[Any], Depends(get_verification_service)],
    ) -> Response:
        """Mail a fresh verification link to the authenticated user."""
        await verification.resend(user)
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @router.post(
        "/forgot-password",
        status_code=status.HTTP_204_NO_CONTENT,
        summary="Request a password-reset email",
    )
    async def forgot_password(
        payload: ForgotPasswordRequest,
        reset: Annotated[PasswordResetService[Any], Depends(get_password_reset_service)],
    ) -> Response:
        """Mail a reset link; succeeds silently for unknown addresses."""
        await reset.request_reset(payload.email)
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @router.post(
        "/reset-password",
        status_code=status.HTTP_204_NO_CONTENT,
        summary="Reset the password with a token",
    )
    async def reset_password(
        payload: ResetPasswordRequest,
        reset: Annotated[PasswordResetService[Any], Depends(get_password_reset_service)],
    ) -> Response:
        """Set a new password, revoke all sessions, and invalidate the token."""
        await reset.reset(payload.token, payload.new_password)
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    return router


__all__ = ["make_auth_router"]
