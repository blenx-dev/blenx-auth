"""Tests for the service registry (fail-fast composition namespace)."""

from __future__ import annotations

import pytest
from blenx_auth.core.registry import (
    DuplicateServiceError,
    ServiceNotFoundError,
    ServiceRegistry,
    ServiceTypeError,
)


class _Mailer:
    def send(self) -> None: ...


class _SpamMailer:
    def send(self) -> None: ...


def test_set_and_get_round_trip() -> None:
    registry = ServiceRegistry()
    mailer = _Mailer()
    registry.set("email_sender", mailer)
    assert registry.get("email_sender", _Mailer) is mailer


def test_get_missing_raises() -> None:
    registry = ServiceRegistry()
    with pytest.raises(ServiceNotFoundError) as exc_info:
        registry.get("email_sender", _Mailer)
    assert exc_info.value.name == "email_sender"


def test_get_type_mismatch_raises() -> None:
    registry = ServiceRegistry()
    registry.set("email_sender", _SpamMailer())
    with pytest.raises(ServiceTypeError) as exc_info:
        registry.get("email_sender", _Mailer)
    assert exc_info.value.name == "email_sender"
    assert exc_info.value.expected is _Mailer
    assert exc_info.value.actual is _SpamMailer


def test_set_duplicate_raises() -> None:
    registry = ServiceRegistry()
    registry.set("x", _Mailer())
    with pytest.raises(DuplicateServiceError) as exc_info:
        registry.set("x", _Mailer())
    assert exc_info.value.name == "x"


def test_has_and_contains() -> None:
    registry = ServiceRegistry()
    assert not registry.has("email_sender")
    assert "email_sender" not in registry
    registry.set("email_sender", _Mailer())
    assert registry.has("email_sender")
    assert "email_sender" in registry


def test_get_never_returns_none() -> None:
    """get() on an absent name must raise, never hand back None."""
    registry = ServiceRegistry()
    with pytest.raises(ServiceNotFoundError):
        registry.get("anything", _Mailer)


def test_subclass_satisfies_expected_type() -> None:
    class SubMailer(_Mailer):
        pass

    registry = ServiceRegistry()
    sub = SubMailer()
    registry.set("email_sender", sub)
    assert registry.get("email_sender", _Mailer) is sub


def test_singleton_identity() -> None:
    """get() returns the exact same instance every time (singleton behavior)."""
    registry = ServiceRegistry()
    mailer = _Mailer()
    registry.set("email_sender", mailer)
    assert registry.get("email_sender", _Mailer) is mailer
    assert registry.get("email_sender", _Mailer) is registry.get("email_sender", _Mailer)


def test_get_any_object_with_object_expected_type() -> None:
    registry = ServiceRegistry()
    value = object()
    registry.set("plain", value)
    assert registry.get("plain", object) is value
