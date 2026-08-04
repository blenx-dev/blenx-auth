"""Tests for :mod:`blenx_auth.core.plugins.hooks`."""

from __future__ import annotations

import pytest
from blenx_auth.core.plugins.hooks import (
    AuthHooks,
    merge_hooks,
    run_side_effects,
    run_transform_chain,
    run_validators,
)


def _make(tag: str, order: list[str]):
    async def hook(*args: object) -> None:
        order.append(tag)

    return hook


async def test_merge_hooks_concatenates_every_field_in_order() -> None:
    order: list[str] = []
    base = AuthHooks(
        on_after_register=(_make("r1", order), _make("r2", order)),
        on_after_login=(_make("l1", order),),
        on_after_update=(_make("u1", order),),
        validate_password=(_make("v1", order),),
        transform_login_result=(_make("t1", order),),
    )
    other = AuthHooks(
        on_after_register=(_make("r3", order), _make("r4", order), _make("r5", order)),
        on_after_login=(_make("l2", order),),
        on_after_update=(_make("u2", order),),
        validate_password=(_make("v2", order),),
        transform_login_result=(_make("t2", order),),
    )

    merged = merge_hooks(base, other)

    assert len(merged.on_after_register) == 5
    assert len(merged.on_after_login) == 2
    assert len(merged.on_after_update) == 2
    assert len(merged.validate_password) == 2
    assert len(merged.transform_login_result) == 2

    await run_side_effects(merged.on_after_register)
    assert order == ["r1", "r2", "r3", "r4", "r5"]


async def test_run_side_effects_calls_every_hook_once_in_order() -> None:
    order: list[str] = []
    hooks = tuple(_make(tag, order) for tag in ("a", "b", "c"))

    await run_side_effects(hooks, 1, "x", None)

    assert order == ["a", "b", "c"]


async def test_run_validators_calls_all_and_propagates_first_raise() -> None:
    order: list[str] = []

    async def first(email: str, data: object) -> None:
        order.append("first")

    async def second(email: str, data: object) -> None:
        order.append("second")

    async def third(email: str, data: object) -> None:
        order.append("third")
        raise ValueError("boom")

    async def never(email: str, data: object) -> None:
        order.append("never")

    with pytest.raises(ValueError):
        await run_validators((first, second, third, never), "a@b.c", {})
    assert order == ["first", "second", "third"]


async def test_run_transform_chain_all_hooks_run_no_challenge() -> None:
    order: list[int] = []

    async def h1(user: object, current: dict) -> dict:
        order.append(1)
        return {**current, "step": 1}

    async def h2(user: object, current: dict) -> dict:
        order.append(2)
        return {**current, "step": 2}

    async def h3(user: object, current: dict) -> dict:
        order.append(3)
        return {**current, "step": 3}

    result = await run_transform_chain((h1, h2, h3), "user", {"step": 0})

    assert order == [1, 2, 3]
    assert result["step"] == 3


async def test_run_transform_chain_short_circuits_on_challenge() -> None:
    order: list[int] = []

    async def h1(user: object, current: object) -> object:
        order.append(1)
        return object()

    class Challenge:
        kind = "challenge"

    async def h2(user: object, current: object) -> object:
        order.append(2)
        return Challenge()

    async def h3(user: object, current: object) -> object:
        order.append(3)
        return current

    result = await run_transform_chain((h1, h2, h3), "user", object())

    assert order == [1, 2]
    assert getattr(result, "kind", None) == "challenge"
