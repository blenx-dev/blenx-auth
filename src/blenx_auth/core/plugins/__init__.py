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
from typing import TYPE_CHECKING, Any

from blenx_auth.core.plugins.hooks import AuthHooks

if TYPE_CHECKING:
    from blenx_auth.core.deps import CoreDeps
    from blenx_auth.core.registry import ServiceRegistry
    from sqlalchemy import Column, Table


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
        super().__init__(f"circular plugin dependency detected among: {cycle_members}")


@dataclass(frozen=True, slots=True)
class AuthPlugin:
    """What one plugin contributes to a composition root.

    Schema contributions: ``sqla_columns`` / ``sqla_tables`` are the SQLAlchemy
    user-table columns and extra tables; ``beanie_mixin`` / ``beanie_documents``
    are the Beanie document mixin and extra documents; the ``*_mixin`` fields
    are the Pydantic schema mixins.

    Behavioral contributions: ``hooks`` (static) plus the factory hooks
    ``repository_factory`` / ``service_factory`` / ``hooks_factory`` /
    ``router_factory``. Every factory receives exactly ``(CoreDeps, ServiceRegistry)``
    and registers whatever it builds; services are only ever obtained through
    the registry.
    """

    name: str
    sqla_columns: tuple[Column[Any], ...] = ()
    sqla_tables: tuple[Table, ...] = ()
    beanie_mixin: type | None = None
    beanie_documents: tuple[type, ...] = ()
    read_mixin: type | None = None
    create_mixin: type | None = None
    update_mixin: type | None = None
    hooks: AuthHooks = AuthHooks()
    repository_factory: RepositoryFactory | None = None
    service_factory: ServiceFactory | None = None
    hooks_factory: HooksFactory | None = None
    router_factory: Callable[..., Any] | None = None
    depends_on: tuple[str, ...] = ()

    # Deprecated (transition only, removed with the composition rewrite):
    # the SQLAlchemy/Beanie mixin-based schema contributions they stand in for.
    table_mixin: type | None = None
    related_models: tuple[type, ...] = ()


# A plugin factory builds one object (repository, service, or hooks) from the
# composition context. It registers what it builds under plugin-chosen names
# and pulls its own dependencies from ``registry``; a missing dependency
# surfaces as a :class:`ServiceNotFoundError` at startup.
RepositoryFactory = Callable[["CoreDeps", "ServiceRegistry"], object]
ServiceFactory = Callable[["CoreDeps", "ServiceRegistry"], object]
HooksFactory = Callable[["CoreDeps", "ServiceRegistry"], AuthHooks]


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


__all__ = [
    "AuthPlugin",
    "HooksFactory",
    "PluginCycleError",
    "PluginDependencyError",
    "RepositoryFactory",
    "ServiceFactory",
    "resolve_plugin_order",
]
