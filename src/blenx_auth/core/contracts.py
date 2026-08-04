"""Startup contract check between the composed user schemas and the User model.

The composition root builds ``UserRead`` / ``UserCreate`` / ``UserUpdate`` from
plugin and consumer mixins, and builds the ``User`` ORM model from table
mixins. These are two independent declarations of the same user shape, so the
root runs :func:`run_contract_check` at construction time to prove they agree:
every declared schema field must exist as a column on ``User``.

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


def run_contract_check(User: type, UserRead: type, UserCreate: type, UserUpdate: type) -> None:
    """Raise unless every declared schema field maps to a column/field on ``User``.

    The composed model is duck-typed for the field surface so both backends
    work: SQLAlchemy exposes columns via ``__table__``; Beanie exposes pydantic
    ``model_fields``. All mismatches across all three schemas are reported
    together in one ``ExceptionGroup`` of :class:`ContractMismatchError`.
    """
    model_columns = _model_field_names(User)

    checks: tuple[tuple[type, str, set[str]], ...] = (
        (UserRead, "UserRead", set()),
        (UserCreate, "UserCreate", {"password"}),
        (UserUpdate, "UserUpdate", {"password", "email"}),
    )

    errors: list[ContractMismatchError] = []
    for schema, label, excluded in checks:
        fields = _model_field_names(schema) - excluded
        missing = fields - model_columns
        if missing:
            errors.append(ContractMismatchError(label, missing))

    if errors:
        raise ExceptionGroup("contract check failed", errors)


def _model_field_names(model: type) -> set[str]:
    """Return the field/column names a composed model declares."""
    table = getattr(model, "__table__", None)
    if table is not None:
        return set(table.columns.keys())
    model_fields = getattr(model, "model_fields", None)
    if model_fields is not None:
        return set(model_fields.keys())
    return set(getattr(model, "__annotations__", {}).keys())


__all__ = ["ContractMismatchError", "run_contract_check"]
