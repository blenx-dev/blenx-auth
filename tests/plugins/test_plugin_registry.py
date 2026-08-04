"""Tests for :mod:`blenx_auth.core.plugins` (plugin registry + ordering)."""

from __future__ import annotations

import pytest
from blenx_auth.core.plugins import (
    AuthPlugin,
    PluginCycleError,
    PluginDependencyError,
    resolve_plugin_order,
)


def plugin(name: str, deps: tuple[str, ...] = ()) -> AuthPlugin:
    return AuthPlugin(name=name, depends_on=deps)


def test_linear_dependency_chain() -> None:
    a, b, c = plugin("a"), plugin("b", ("a",)), plugin("c", ("b",))
    order = resolve_plugin_order([c, b, a])
    assert [p.name for p in order] == ["a", "b", "c"]


def test_missing_dependency_raises() -> None:
    with pytest.raises(PluginDependencyError) as exc_info:
        resolve_plugin_order([plugin("a", ("that_name",))])
    assert exc_info.value.name == "a"
    assert exc_info.value.missing == ["that_name"]


def test_cycle_raises() -> None:
    with pytest.raises(PluginCycleError):
        resolve_plugin_order([plugin("a", ("b",)), plugin("b", ("a",))])


def test_order_is_deterministic() -> None:
    plugins = [plugin("b", ("a",)), plugin("a"), plugin("c", ("b",))]
    first = resolve_plugin_order(plugins)
    second = resolve_plugin_order(plugins)
    assert first == second


def test_diamond_dependency() -> None:
    a = plugin("a")
    b = plugin("b", ("a",))
    c = plugin("c", ("a",))
    d = plugin("d", ("b", "c"))
    order = [p.name for p in resolve_plugin_order([d, c, b, a])]

    assert order.index("a") < order.index("b")
    assert order.index("a") < order.index("c")
    assert order.index("b") < order.index("d")
    assert order.index("c") < order.index("d")
