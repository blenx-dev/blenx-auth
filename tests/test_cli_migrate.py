"""Tests for ``blenx-auth migrate sync`` (dynamic plugin-schema autogenerate).

Each test builds a throwaway Alembic environment (ini + env.py + template) in a
tmp dir with a file-backed SQLite database, plus a tiny "consumer app" module
exposing ``app.auth`` with a plugin list. The sync command is exercised through
the click ``CliRunner`` exactly as a user would call it.
"""

from __future__ import annotations

import sys
from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from alembic import command as alembic_command
from alembic.config import Config
from blenx_auth.cli import migrate, sync
from click.testing import CliRunner

if TYPE_CHECKING:
    from click.testing import Result

ALEMBIC_INI = """\
[alembic]
script_location = %(here)s
prepend_sys_path = .
path_separator = os
sqlalchemy.url = sqlite:///%(here)s/test.db

[loggers]
keys = root,sqlalchemy,alembic

[handlers]
keys = console

[formatters]
keys = generic

[logger_root]
level = WARNING
handlers = console
qualname =

[logger_sqlalchemy]
level = WARNING
handlers =
qualname = sqlalchemy.engine

[logger_alembic]
level = INFO
handlers =
qualname = alembic

[handler_console]
class = StreamHandler
args = (sys.stderr,)
level = NOTSET
formatter = generic

[formatter_generic]
format = %%(levelname)-5.5s [%%(name)s] %%(message)s
datefmt = %%H:%M:%S
"""

ENV_PY = """\
from alembic import context
from sqlalchemy import engine_from_config, pool

config = context.config

target_metadata = config.attributes.get("target_metadata")


def run_migrations_offline() -> None:
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()
    connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
"""

SCRIPT_MAKO = """\
\"\"\"${message}

Revision ID: ${up_revision}
Revises: ${down_revision | comma,n}
Create Date: ${create_date}

\"\"\"
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
${imports if imports else ""}

# revision identifiers, used by Alembic.
revision: str = ${repr(up_revision)}
down_revision: Union[str, Sequence[str], None] = ${repr(down_revision)}
branch_labels: Union[str, Sequence[str], None] = ${repr(branch_labels)}
depends_on: Union[str, Sequence[str], None] = ${repr(depends_on)}


def upgrade() -> None:
    \"\"\"Upgrade schema.\"\"\"
    ${upgrades if upgrades else "pass"}


def downgrade() -> None:
    \"\"\"Downgrade schema.\"\"\"
    ${downgrades if downgrades else "pass"}
"""

# -- consumer app modules (written to disk, imported by `sync`) --------------

APP_WITH_NICKNAME = """\
from types import SimpleNamespace

from blenx_auth.core.plugins import AuthPlugin
from sqlalchemy import Column, String

app = SimpleNamespace(
    auth=SimpleNamespace(
        _plugins=[AuthPlugin(name="nickname", sqla_columns=(Column("nickname", String),))]
    )
)
"""

# A root whose composed metadata is the core-only user table (no plugin columns)
# but which still has a configured plugin list — mirrors a disabled plugin.
APP_CORE_ONLY = """\
from types import SimpleNamespace

from blenx_auth.core.plugins import AuthPlugin
from blenx_auth.sqlalchemy.metadata import build_composed_user_table
from sqlalchemy import MetaData

_metadata = MetaData()
build_composed_user_table(metadata=_metadata)

app = SimpleNamespace(
    auth=SimpleNamespace(
        user_model=SimpleNamespace(metadata=_metadata),
        _plugins=[AuthPlugin(name="two_factor")],
    )
)
"""

APP_NO_AUTH = """\
from types import SimpleNamespace

app = SimpleNamespace()
"""

APP_NO_PLUGINS = """\
from types import SimpleNamespace

app = SimpleNamespace(auth=SimpleNamespace(_plugins=[]))
"""

APP_FACTORY = """\
from types import SimpleNamespace

from blenx_auth.core.plugins import AuthPlugin
from sqlalchemy import Column, String


def app() -> SimpleNamespace:
    return SimpleNamespace(
        auth=SimpleNamespace(
            _plugins=[AuthPlugin(name="nickname", sqla_columns=(Column("nickname", String),))]
        )
    )
"""

CONSUMER_BASE = """\
from sqlalchemy import Column, Integer, String
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


class Profile(Base):
    __tablename__ = "profile"
    id = Column(Integer, primary_key=True)
    bio = Column(String)
"""


@pytest.fixture
def migration_env(tmp_path: Path) -> Path:
    """A self-contained Alembic environment (ini + env.py + template)."""
    (tmp_path / "versions").mkdir()
    (tmp_path / "alembic.ini").write_text(ALEMBIC_INI, encoding="utf-8")
    (tmp_path / "env.py").write_text(ENV_PY, encoding="utf-8")
    (tmp_path / "script.py.mako").write_text(SCRIPT_MAKO, encoding="utf-8")
    return tmp_path


@pytest.fixture(autouse=True)
def _clear_imported_apps() -> Iterator[None]:
    """Drop the throwaway app modules from ``sys.modules`` between tests."""
    yield
    for name in list(sys.modules):
        if name.startswith("app_") or name == "consumer_base":
            sys.modules.pop(name, None)


def _write_app(env: Path, module: str, body: str) -> None:
    (env / f"{module}.py").write_text(body, encoding="utf-8")


def _invoke_sync(
    monkeypatch: pytest.MonkeyPatch,
    env: Path,
    app_module: str,
    *args: str,
    envvar: str | None = None,
) -> Result:
    monkeypatch.syspath_prepend(str(env))
    runner = CliRunner()
    if envvar is not None:
        return runner.invoke(
            sync,
            ["--alembic-ini", str(env / "alembic.ini"), *args],
            env={"BLENX_AUTH_APP": envvar},
        )
    return runner.invoke(
        sync,
        ["--app", f"{app_module}:app", "--alembic-ini", str(env / "alembic.ini"), *args],
    )


def _newest_migration(env: Path) -> Path:
    candidates = sorted(
        (env / "versions").glob("*.py"),
        key=lambda p: p.stat().st_mtime,
    )
    assert candidates, "no migration files were generated"
    return candidates[-1]


def _apply_all(env: Path) -> None:
    alembic_command.upgrade(Config(str(env / "alembic.ini")), "head")


def test_sync_no_base_generates_plugin_migration(
    monkeypatch: pytest.MonkeyPatch,
    migration_env: Path,
) -> None:
    _write_app(migration_env, "app_create", APP_WITH_NICKNAME)

    result = _invoke_sync(monkeypatch, migration_env, "app_create")

    assert result.exit_code == 0, result.output
    migration = _newest_migration(migration_env)
    contents = migration.read_text(encoding="utf-8")
    assert "create_table('user'" in contents
    assert "nickname" in contents
    assert "drop_column" not in contents


def test_sync_with_base_includes_consumer_tables(
    monkeypatch: pytest.MonkeyPatch,
    migration_env: Path,
) -> None:
    _write_app(migration_env, "app_create", APP_WITH_NICKNAME)
    _write_app(migration_env, "consumer_base", CONSUMER_BASE)

    result = _invoke_sync(
        monkeypatch,
        migration_env,
        "app_create",
        "--base",
        "consumer_base:Base",
    )

    assert result.exit_code == 0, result.output
    contents = _newest_migration(migration_env).read_text(encoding="utf-8")
    assert "create_table('profile'" in contents
    assert "create_table('user'" in contents
    assert "nickname" in contents


def test_sync_disabled_plugin_warns_on_drop(
    monkeypatch: pytest.MonkeyPatch,
    migration_env: Path,
) -> None:
    _write_app(migration_env, "app_create", APP_WITH_NICKNAME)
    result = _invoke_sync(monkeypatch, migration_env, "app_create", "-m", "with nickname")
    assert result.exit_code == 0, result.output
    _apply_all(migration_env)

    _write_app(migration_env, "app_drop", APP_CORE_ONLY)
    result = _invoke_sync(monkeypatch, migration_env, "app_drop", "-m", "nickname disabled")

    assert result.exit_code == 0, result.output
    assert "drops column(s)/table(s)" in result.output
    contents = _newest_migration(migration_env).read_text(encoding="utf-8")
    assert "op.drop_column('user', 'nickname')" in contents


def test_sync_without_auth_raises(
    monkeypatch: pytest.MonkeyPatch,
    migration_env: Path,
) -> None:
    _write_app(migration_env, "app_noauth", APP_NO_AUTH)

    result = _invoke_sync(monkeypatch, migration_env, "app_noauth")

    assert result.exit_code == 1
    assert "auth object" in result.output


def test_sync_without_plugins_raises(
    monkeypatch: pytest.MonkeyPatch,
    migration_env: Path,
) -> None:
    _write_app(migration_env, "app_noplugins", APP_NO_PLUGINS)

    result = _invoke_sync(monkeypatch, migration_env, "app_noplugins")

    assert result.exit_code == 1
    assert "no plugins configured" in result.output


def test_sync_app_factory_is_called(
    monkeypatch: pytest.MonkeyPatch,
    migration_env: Path,
) -> None:
    _write_app(migration_env, "app_factory", APP_FACTORY)

    result = _invoke_sync(monkeypatch, migration_env, "app_factory")

    assert result.exit_code == 0, result.output
    assert "Generated migration" in result.output


def test_sync_never_applies_migrations(
    monkeypatch: pytest.MonkeyPatch,
    migration_env: Path,
) -> None:
    from sqlalchemy import create_engine, inspect

    _write_app(migration_env, "app_create", APP_WITH_NICKNAME)

    result = _invoke_sync(monkeypatch, migration_env, "app_create")

    assert result.exit_code == 0, result.output
    engine = create_engine(f"sqlite:///{migration_env / 'test.db'}")
    inspector = inspect(engine)
    # Alembic's autogenerate itself creates an empty ``alembic_version`` table;
    # the real check is that the generated migration's ``user`` table was never
    # applied — `sync` only generates, it never runs `upgrade`.
    assert not inspector.has_table("user")
    assert not inspector.has_table("profile")


def test_sync_app_readable_from_env_var(
    monkeypatch: pytest.MonkeyPatch,
    migration_env: Path,
) -> None:
    _write_app(migration_env, "app_create", APP_WITH_NICKNAME)

    result = _invoke_sync(
        monkeypatch,
        migration_env,
        "app_create",
        "-m",
        "from env var",
        envvar="app_create:app",
    )

    assert result.exit_code == 0, result.output
    contents = _newest_migration(migration_env).read_text(encoding="utf-8")
    assert "from env var" in contents


def test_group_accepts_both_flat_and_nested_forms(
    monkeypatch: pytest.MonkeyPatch,
    migration_env: Path,
) -> None:
    _write_app(migration_env, "app_create", APP_WITH_NICKNAME)
    monkeypatch.syspath_prepend(str(migration_env))
    runner = CliRunner()
    ini = str(migration_env / "alembic.ini")

    flat = runner.invoke(migrate, ["sync", "--app", "app_create:app", "--alembic-ini", ini])
    assert flat.exit_code == 0, flat.output
    _apply_all(migration_env)

    nested = runner.invoke(
        migrate,
        ["migrate", "sync", "--app", "app_create:app", "--alembic-ini", ini],
    )
    assert nested.exit_code == 0, nested.output
