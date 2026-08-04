"""Service registry: the single namespace every composed object is built from.

The composition root registers repositories, services, and plugin-provided
objects under string names; factories and routers obtain them exclusively
through :class:`ServiceRegistry` (never by constructing dependencies by hand).

Semantics are deliberately strict:

- :meth:`ServiceRegistry.set` on a name that is already registered raises
  :class:`DuplicateServiceError` — a double registration is a startup bug, not
  a silent overwrite.
- :meth:`ServiceRegistry.get` never returns ``None``. A missing name raises
  :class:`ServiceNotFoundError`; an entry whose runtime type does not satisfy
  ``expected_type`` raises :class:`ServiceTypeError`. Callers therefore get a
  concrete instance or a precise startup error, never a ``None`` to paper over.
- :meth:`ServiceRegistry.has` is the only non-raising membership check.

This module is framework-free and lives under ``core`` so both the SQLAlchemy
and Beanie composition paths share one implementation.
"""

from __future__ import annotations

from typing import TypeVar

T = TypeVar("T")


class ServiceRegistryError(Exception):
    """Base class for every registry failure (startup errors)."""


class ServiceNotFoundError(ServiceRegistryError, LookupError):
    """A requested service was never registered."""

    def __init__(self, name: str) -> None:
        self.name = name
        super().__init__(f"service '{name}' is not registered — check plugin ordering.")


class ServiceTypeError(ServiceRegistryError, TypeError):
    """A service was registered, but under the wrong type."""

    def __init__(self, name: str, expected: type[object], actual: type[object]) -> None:
        self.name = name
        self.expected = expected
        self.actual = actual
        super().__init__(
            f"service '{name}' is registered as {actual.__name__}, expected {expected.__name__}."
        )


class DuplicateServiceError(ServiceRegistryError, ValueError):
    """A name was registered twice by different composition steps."""

    def __init__(self, name: str) -> None:
        self.name = name
        super().__init__(f"service '{name}' is already registered.")


class ServiceRegistry:
    """An explicit name → instance namespace with fail-fast lookups."""

    __slots__ = ("_services",)

    def __init__(self) -> None:
        self._services: dict[str, object] = {}

    def set(self, name: str, instance: object) -> None:
        """Register ``instance`` under ``name`` (raises on duplicates)."""
        if name in self._services:
            raise DuplicateServiceError(name)
        self._services[name] = instance

    def get(self, name: str, expected_type: type[T]) -> T:
        """Return the registered instance of ``expected_type``, else raise.

        Never returns ``None``: a missing name raises :class:`ServiceNotFoundError`
        and a type mismatch raises :class:`ServiceTypeError`.
        """
        instance = self._services.get(name)
        if instance is None:
            raise ServiceNotFoundError(name)
        if not isinstance(instance, expected_type):
            raise ServiceTypeError(name, expected_type, type(instance))
        return instance

    def has(self, name: str) -> bool:
        """Return whether ``name`` is registered (the only non-raising check)."""
        return name in self._services

    def __contains__(self, name: str) -> bool:
        return self.has(name)


__all__ = [
    "DuplicateServiceError",
    "ServiceNotFoundError",
    "ServiceRegistry",
    "ServiceRegistryError",
    "ServiceTypeError",
]
