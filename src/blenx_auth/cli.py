"""`blenx-auth` command-line interface: the ``migrate sync`` command.

Plugins are configured per-consumer, so static Alembic migrations cannot be
shipped. ``blenx-auth migrate sync`` rebuilds the SQLAlchemy ``MetaData`` from
the plugins currently configured on the app's auth object and runs Alembic's
``--autogenerate`` against it, producing a migration the human reviews and
applies with ``alembic upgrade head`` — this command **never** applies
migrations itself.

Requires the ``migrations`` extra: ``pip install "blenx-auth[migrations]"``.
"""

from __future__ import annotations

import importlib
import inspect
import re
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import click
from alembic import command as alembic_command
from alembic.config import Config
from alembic.script import ScriptDirectory

from blenx_auth.core.plugins import AuthPlugin
from blenx_auth.sqlalchemy.metadata import build_composed_user_table, register_extra_tables
from sqlalchemy import MetaData

#: Environment variable that supplies ``--app`` when the option is omitted.
APP_ENV_VAR = "BLENX_AUTH_APP"

_DROP_RE = re.compile(r"\b(?:drop_column|drop_table)\b")


@click.group()
def migrate() -> None:
    """Autogenerate Alembic migrations from the configured plugin schema."""


# The console script resolves directly to the ``migrate`` group, so the
# documented `blenx-auth migrate sync` form is a nested alias group that shares
# the same ``sync`` command (the flat `blenx-auth sync` form works too).
@migrate.group(name="migrate")
def migrate_alias() -> None:
    """Autogenerate Alembic migrations from the configured plugin schema."""


@migrate.command()
@click.option(
    "--app",
    "app_ref",
    envvar=APP_ENV_VAR,
    required=True,
    metavar="MODULE:ATTRIBUTE",
    help=(
        "Dotted module path and attribute of the FastAPI app (or a zero-argument "
        "app factory), e.g. myproject.app:app. Also readable from "
        f"{APP_ENV_VAR}."
    ),
)
@click.option(
    "--base",
    "base_ref",
    default=None,
    metavar="MODULE:ATTRIBUTE",
    help=(
        "Dotted module path and attribute of the consumer's declarative Base; its "
        "tables are included in the same diff alongside the plugin schema."
    ),
)
@click.option(
    "--alembic-ini",
    "alembic_ini",
    default="alembic.ini",
    show_default=True,
    help="Path to the alembic.ini configuration file.",
)
@click.option(
    "-m",
    "--message",
    default="sync plugin schema",
    show_default=True,
    help="Revision message written into the generated migration.",
)
def sync(
    app_ref: str,
    base_ref: str | None,
    alembic_ini: str,
    message: str,
) -> None:
    """Generate (never apply) a migration for the currently configured plugins.

    Builds a ``MetaData`` from the plugin list on the app's auth object and runs
    Alembic ``revision --autogenerate`` against it. The generated file is
    printed for review; applying it stays a separate, manual
    ``alembic upgrade head`` step.
    """
    app = _load_app(app_ref)
    auth = _get_auth(app)
    if auth is None:
        raise click.ClickException(
            "No auth object found on the app (expected `app.auth`). Attach your "
            "blenx-auth composition root to the app, e.g. `app.auth = auth` in your "
            "app factory."
        )
    plugins = _get_plugins(auth)
    if not plugins:
        raise click.ClickException(
            "The auth object has no plugins configured (expected `auth.plugins` or "
            "`auth._plugins`). Pass `plugins=[...]` to your composition root before "
            "running `migrate sync`."
        )

    base = _load_object(base_ref, option="--base") if base_ref else None
    metadata = _build_metadata(auth, plugins, base)

    cfg = Config(alembic_ini)
    cfg.attributes["target_metadata"] = metadata
    generated = _generate_revision(cfg, message)
    _report_generated(generated)


migrate_alias.add_command(sync)


def _load_object(import_string: str, *, option: str) -> Any:
    """Import ``module.path:attribute`` and return the attribute value."""
    if ":" not in import_string:
        raise click.ClickException(
            f"{option} must be in 'module.path:attribute' form, got {import_string!r}."
        )
    module_name, attribute = import_string.split(":", 1)
    try:
        module = importlib.import_module(module_name)
    except ImportError as exc:
        raise click.ClickException(
            f"Could not import module {module_name!r} for {option}: {exc}"
        ) from exc
    try:
        return getattr(module, attribute)
    except AttributeError as exc:
        raise click.ClickException(
            f"Module {module_name!r} has no attribute {attribute!r} for {option}."
        ) from exc


def _is_zero_arg_callable(obj: Any) -> bool:
    """Whether ``obj`` is callable with no required positional arguments."""
    if not callable(obj):
        return False
    try:
        signature = inspect.signature(obj)
    except (TypeError, ValueError):
        return False
    return all(
        param.default is not param.empty or param.kind in (param.VAR_POSITIONAL, param.VAR_KEYWORD)
        for param in signature.parameters.values()
    )


def _load_app(app_ref: str) -> Any:
    """Load the app, calling it first if ``app_ref`` names a zero-arg factory."""
    app = _load_object(app_ref, option="--app")
    if _is_zero_arg_callable(app):
        return app()
    return app


def _get_auth(app: Any) -> Any | None:
    """The auth object reachable from the app (expected ``app.auth``)."""
    return getattr(app, "auth", None)


def _get_plugins(auth: Any) -> Sequence[AuthPlugin] | None:
    """The configured plugin list on the auth object.

    Reads the public ``plugins`` attribute, falling back to the composition
    roots' internal ``_plugins``.
    """
    plugins = getattr(auth, "plugins", None)
    if plugins is None:
        plugins = getattr(auth, "_plugins", None)
    return plugins


def _auth_metadata(auth: Any) -> MetaData | None:
    """The SQLAlchemy ``MetaData`` the auth root composed (if any).

    For ``SQLAlchemyAuth`` this is ``AuthBase.metadata`` after construction —
    the ``user`` / ``refresh_tokens`` / ``oauth_account`` tables with every
    plugin table-mixin column already folded in. Beanie roots and fakes return
    ``None``.
    """
    user_model = getattr(auth, "user_model", None)
    metadata = getattr(user_model, "metadata", None)
    return metadata if isinstance(metadata, MetaData) else None


def _build_metadata(
    auth: Any,
    plugins: Sequence[AuthPlugin],
    base: Any | None,
) -> MetaData:
    """Compose the target ``MetaData`` for autogenerate.

    Starts from the consumer's ``Base.metadata`` when ``--base`` is given, then
    merges the auth root's composed tables (capturing ``table_mixin`` plugin
    columns), then applies the plugins' ``sqla_columns`` / ``sqla_tables``
    contributions.
    """
    metadata = MetaData()

    if base is not None:
        for table in base.metadata.tables.values():
            table.to_metadata(metadata)

    source = _auth_metadata(auth)
    if source is not None:
        for table in source.tables.values():
            table.to_metadata(metadata)

    plugin_columns = [(p.name, p.sqla_columns) for p in plugins if p.sqla_columns]
    if plugin_columns:
        user_table = metadata.tables.get("user")
        if user_table is None:
            build_composed_user_table(metadata=metadata, plugin_columns=plugin_columns)
        else:
            existing = set(user_table.columns.keys())
            for _, columns in plugin_columns:
                for column in columns:
                    if column.name not in existing:
                        user_table.append_column(column._copy())
                        existing.add(column.name)

    register_extra_tables(
        metadata=metadata,
        plugin_tables=[table for p in plugins for table in p.sqla_tables],
    )
    return metadata


def _generate_revision(cfg: Config, message: str) -> Path:
    """Run ``revision --autogenerate`` and return the new migration file's path."""
    script = ScriptDirectory.from_config(cfg)
    versions_dir = Path(script.versions)
    before = {path.name for path in versions_dir.glob("*.py")}
    alembic_command.revision(cfg, autogenerate=True, message=message)
    generated = [path for path in versions_dir.glob("*.py") if path.name not in before]
    if not generated:
        raise click.ClickException("Alembic did not produce a new revision file.")
    return generated[0]


def _report_generated(path: Path) -> None:
    """Post-generation safety check: warn on drops, never apply anything."""
    contents = path.read_text(encoding="utf-8")
    if _has_drops(contents):
        click.secho(
            "WARNING: the generated migration drops column(s)/table(s). This usually "
            "means a plugin was disabled or changed — dropping columns or tables can "
            "lose data. Review it carefully before applying.",
            fg="yellow",
        )
    click.secho(f"Generated migration: {path}", fg="green")
    click.echo("Review the migration, then apply it manually with:  alembic upgrade head")


def _has_drops(contents: str) -> bool:
    """Whether the migration's ``upgrade()`` drops anything.

    Only the upgrade body counts: Alembic's ``downgrade()`` always mirrors
    creates with the corresponding drops, so scanning the whole file would flag
    every migration.
    """
    upgrade_start = contents.find("def upgrade()")
    downgrade_start = contents.find("def downgrade()")
    if upgrade_start != -1 and downgrade_start != -1:
        contents = contents[upgrade_start:downgrade_start]
    return _DROP_RE.search(contents) is not None


__all__ = ["APP_ENV_VAR", "migrate", "migrate_alias", "sync"]
