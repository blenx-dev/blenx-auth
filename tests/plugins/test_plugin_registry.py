"""Tests for :mod:`blenx_auth.core.plugins` (plugin registry + ordering)."""

from __future__ import annotations

import pytest
from blenx_auth.core.plugins import (
    AuthPlugin,
    PluginCycleError,
    PluginDependencyError,
    resolve_plugin_order,
)
from blenx_auth.core.plugins.hooks import AuthHooks


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


def test_plugin_declares_factory_contributions() -> None:
    from sqlalchemy import Boolean, Column, MetaData, Table

    otp_table = Table("otps", MetaData(), Column("id", Boolean))
    p = AuthPlugin(
        name="p",
        sqla_columns=(Column("is_enabled", Boolean),),
        sqla_tables=(otp_table,),
        beanie_mixin=object,
        beanie_documents=(object,),
        read_mixin=object,
        create_mixin=object,
        update_mixin=object,
        repository_factory=lambda deps, registry: object(),
        service_factory=lambda deps, registry: object(),
        hooks_factory=lambda deps, registry: AuthHooks(),
        router_factory=lambda deps, registry: object(),
        depends_on=("x",),
    )
    assert p.name == "p"
    assert [c.name for c in p.sqla_columns] == ["is_enabled"]
    assert p.sqla_tables == (otp_table,)
    assert p.beanie_mixin is object
    assert p.beanie_documents == (object,)
    assert p.repository_factory is not None
    assert p.service_factory is not None
    assert p.hooks_factory is not None
    assert p.router_factory is not None
    assert p.depends_on == ("x",)


def test_plugin_defaults_are_empty() -> None:
    p = AuthPlugin(name="bare")
    assert p.sqla_columns == ()
    assert p.sqla_tables == ()
    assert p.beanie_mixin is None
    assert p.beanie_documents == ()
    assert p.read_mixin is None
    assert p.create_mixin is None
    assert p.update_mixin is None
    assert p.hooks == AuthHooks()
    assert p.repository_factory is None
    assert p.service_factory is None
    assert p.hooks_factory is None
    assert p.router_factory is None
