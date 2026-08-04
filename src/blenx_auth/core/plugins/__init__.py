"""Plugin registry: declarative ``AuthPlugin`` records and dependency ordering.

A plugin is a pure declaration of what it contributes to a composition root:
mixins for the user table/schemas, hooks, a router factory, related models, and
its dependency order. Nothing here imports FastAPI or a storage backend, so
plugins are framework-free and unit-testable.

Ordering: ``resolve_plugin_order`` topologically sorts ``depends_on`` edges via
``graphlib.TopologicalSorter``. A missing dependency or a cycle is a hard
startup error — not a warning, not a silent reordering.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from graphlib import CycleError, TopologicalSorter
from typing import Any

from blenx_auth.core.plugins.hooks import AuthHooks


class PluginDependencyError(Exception):
    """A plugin depends on a plugin that was not provided."""

    def __init__(self, name: str, missing: list[str]) -> None:
        self.name = name
        self.missing = missing
        super().__init__(f"plugin '{name}' depends on missing plugin(s): {missing}")


class PluginCycleError(Exception):
    """The plugin dependency graph contains a cycle."""

    def __init__(self, cycle_members: list[str]) -> None:
        self.cycle_members = cycle_members
        super().__init__(
            f"circular plugin dependency detected among: {cycle_members}"
        )


@dataclass(frozen=True, slots=True)
class AuthPlugin:
    """What one plugin contributes to a composition root."""

    name: str
    table_mixin: type | None = None
    read_mixin: type | None = None
    create_mixin: type | None = None
    update_mixin: type | None = None
    hooks: AuthHooks = AuthHooks()
    router_factory: Callable[..., Any] | None = None
    related_models: tuple[type, ...] = ()
    depends_on: tuple[str, ...] = ()


def resolve_plugin_order(plugins: Sequence[AuthPlugin]) -> list[AuthPlugin]:
    """Return ``plugins`` ordered so every dependency precedes its dependents.

    Missing dependencies and cycles raise (hard startup errors).
    """
    by_name = {p.name: p for p in plugins}

    for p in plugins:
        missing = [d for d in p.depends_on if d not in by_name]
        if missing:
            raise PluginDependencyError(p.name, missing)

    graph = {p.name: set(p.depends_on) for p in plugins}
    try:
        order = list(TopologicalSorter(graph).static_order())
    except CycleError as e:
        cycle_members = list(e.args[1]) if len(e.args) > 1 else []
        raise PluginCycleError(cycle_members) from e

    return [by_name[name] for name in order]
