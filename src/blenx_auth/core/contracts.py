"""Startup contract check between the composed user schemas and the User model.

The composition root builds ``UserRead`` / ``UserCreate`` / ``UserUpdate`` from
plugin and consumer mixins, and builds the ``User`` model (a SQLAlchemy mapped
class or a Beanie document) from the storage context. These are two independent
declarations of the same user shape, so the root runs :func:`run_contract_check`
at construction time to prove they agree: every declared schema field must exist
as a column/field on ``User``.

The check is split by backend so each validator uses the exact field surface of
its model:

- :func:`validate_sqlalchemy_contract` — columns via ``User.__table__.columns``.
- :func:`validate_beanie_contract` — fields via pydantic ``model_fields``.
- :func:`run_contract_check` dispatches on ``hasattr(User, "__table__")``.

``password`` (``UserCreate``) and ``email``/``password`` (``UserUpdate``) are
excluded by design — those values are handled by the dedicated auth flows and
are deliberately not stored as user columns.

This is a startup-failure message a third-party integrator will read, so the
error text names the schema and the offending fields explicitly, and every
broken schema is reported at once (an ``ExceptionGroup``) rather than
fail-fast on the first.
"""

from __future__ import annotations


class ContractMismatchError(Exception):
    """A schema declares a field that is not a column on the User model."""

    def __init__(self, schema_label: str, missing_fields: set[str]) -> None:
        self.schema_label = schema_label
        self.missing_fields = missing_fields
        super().__init__(
            f"{schema_label} declares field(s) {sorted(missing_fields)} "
            f"not present as column(s) on the User model."
        )


def validate_sqlalchemy_contract(
    User: type, UserRead: type, UserCreate: type, UserUpdate: type
) -> None:
    """Raise unless every schema field is a column on the ``User`` table."""
    _raise_on_mismatch(
        set(User.__table__.columns.keys()),  # type: ignore[attr-defined]
        UserRead,
        UserCreate,
        UserUpdate,
    )


def validate_beanie_contract(
    User: type, UserRead: type, UserCreate: type, UserUpdate: type
) -> None:
    """Raise unless every schema field is a pydantic field on ``User``."""
    _raise_on_mismatch(_field_names(User), UserRead, UserCreate, UserUpdate)


def run_contract_check(User: type, UserRead: type, UserCreate: type, UserUpdate: type) -> None:
    """Backend-dispatch on the ``User`` model's shape and validate the contract."""
    if hasattr(User, "__table__"):
        validate_sqlalchemy_contract(User, UserRead, UserCreate, UserUpdate)
    else:
        validate_beanie_contract(User, UserRead, UserCreate, UserUpdate)


def _raise_on_mismatch(
    model_columns: set[str], UserRead: type, UserCreate: type, UserUpdate: type
) -> None:
    checks: tuple[tuple[type, str, set[str]], ...] = (
        (UserRead, "UserRead", set()),
        (UserCreate, "UserCreate", {"password"}),
        (UserUpdate, "UserUpdate", {"password", "email"}),
    )

    errors: list[ContractMismatchError] = []
    for schema, label, excluded in checks:
        fields = _field_names(schema) - excluded
        missing = fields - model_columns
        if missing:
            errors.append(ContractMismatchError(label, missing))

    if errors:
        raise ExceptionGroup("contract check failed", errors)


def _field_names(model: type) -> set[str]:
    """Return the field/column names a model declares.

    Pydantic models expose ``model_fields``; plain classes fall back to
    ``__annotations__`` so the check works for lightweight test doubles too.
    """
    model_fields = getattr(model, "model_fields", None)
    if model_fields is not None:
        return set(model_fields.keys())
    return set(getattr(model, "__annotations__", {}).keys())


__all__ = [
    "ContractMismatchError",
    "run_contract_check",
    "validate_beanie_contract",
    "validate_sqlalchemy_contract",
]
