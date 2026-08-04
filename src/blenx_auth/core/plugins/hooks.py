"""Declarative hook points plugins (and consumers) register on the auth flows.

Every hook field is a tuple of async callables (never ``Optional``), so
composing two hook sources is always plain tuple concatenation (see
:func:`merge_hooks`). All hooks except ``transform_login_result`` are
"call all, in order, ignore the return value": they either complete or raise
to reject. ``transform_login_result`` is the one chained hook — each hook
receives the previous hook's output and the chain stops early the moment a
hook returns a ``LoginChallenge`` (duck-typed here on a ``kind`` attribute to
avoid a circular import with the login schemas; see Task 8 for the concrete
types).
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

# A fire-and-forget hook (e.g. "send a welcome email").
HookFn = Callable[..., Awaitable[None]]

# A custom password-policy validator (raises to reject).
ValidatorFn = Callable[[str, Any], Awaitable[None]]

# A login-result transformer. Forward-referenced as ``Any`` until the
# ``LoginSuccess`` / ``LoginChallenge`` types exist (Task 8).
TransformFn = Callable[[Any, Any], Awaitable[Any]]


@dataclass(frozen=True, slots=True)
class AuthHooks:
    """The full set of extension points on the auth flows."""

    on_after_register: tuple[HookFn, ...] = ()
    on_after_login: tuple[HookFn, ...] = ()
    on_after_update: tuple[HookFn, ...] = ()
    validate_password: tuple[ValidatorFn, ...] = ()
    transform_login_result: tuple[TransformFn, ...] = ()


def merge_hooks(base: AuthHooks, other: AuthHooks) -> AuthHooks:
    """Compose two hook sources by tuple concatenation (base first)."""
    return AuthHooks(
        on_after_register=base.on_after_register + other.on_after_register,
        on_after_login=base.on_after_login + other.on_after_login,
        on_after_update=base.on_after_update + other.on_after_update,
        validate_password=base.validate_password + other.validate_password,
        transform_login_result=base.transform_login_result + other.transform_login_result,
    )


async def run_side_effects(hooks: tuple[HookFn, ...], *args: Any) -> None:
    """Call every hook in order, ignoring return values (raise propagates)."""
    for hook in hooks:
        await hook(*args)


async def run_validators(hooks: tuple[ValidatorFn, ...], *args: Any) -> None:
    """Call every validator in order; the first raise aborts the rest."""
    for hook in hooks:
        await hook(*args)


async def run_transform_chain(hooks: tuple[TransformFn, ...], user: Any, initial: Any) -> Any:
    """Chain login-result transforms.

    Each hook receives ``(user, current_result)`` and returns the next result.
    The chain stops early the moment a hook returns an object whose ``kind``
    attribute equals ``"challenge"`` (duck-typed here to keep this module free
    of the login schemas; see Task 8 for the concrete types).
    """
    current = initial
    for hook in hooks:
        current = await hook(user, current)
        if getattr(current, "kind", None) == "challenge":
            return current
    return current
