"""Build a SQLAlchemy ``User`` model from a declarative base plus mixins.

The built class is a genuine mapped entity: ``create_all`` on the base's
``MetaData`` produces the real table and ``Session`` round-trips work. The
collision check runs *before* ``type(...)`` is called so a duplicate column
name fails at startup with a ``FieldCollisionError`` instead of a murky
SQLAlchemy mapper error.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import TYPE_CHECKING, Any, cast

from blenx_auth.core.plugins.collisions import check_no_field_collisions

if TYPE_CHECKING:
    from blenx_auth.sqlalchemy.models import OAuthAccount, RefreshToken, User


def build_sqla_model(
    tablename: str,
    auth_base: type,
    core_mixin: type,
) -> type:
    """Build the ``User`` entity mapped to ``tablename`` on ``auth_base``.

    ``core_mixin`` carries the base user columns; ``mixins`` are the
    plugin/consumer table mixins (their ``Mapped[...]`` annotations become
    columns). The class name is always ``"User"`` because the auth models'
    relationships reference ``'User'`` by name.
    """
    check_no_field_collisions(kind="table")
    bases = (auth_base, core_mixin)
    return type("User", bases, {"__tablename__": tablename})


def build_sqla_models(
    *,
    auth_base: type,
    core_mixin: type,
    tablename: str,
    refresh_token_factory: Callable[[type], type],
    oauth_account_factory: Callable[[type], type],
) -> tuple[type[User], type[RefreshToken], type[OAuthAccount]]:
    """Rebuild the whole mapped set (``User``, ``RefreshToken``, ``OAuthAccount``)
    on ``auth_base`` and return the three classes.

    A composed ``User`` must coexist with ``RefreshToken``/``OAuthAccount`` on
    one registry, and the previous mapping (the static models, or a prior
    composition) must be torn down first: SQLAlchemy forbids re-mapping the
    ``user`` table while another class owns it. This teardown is
    "last composition wins" — a host app holds exactly one composition root.

    The returned classes are cast to the static models' types: they are
    dynamically rebuilt with the same base columns (plus any plugin/consumer
    table mixins), so their column surface is a strict superset and repository
    code sees the static type.
    """
    registry = cast(Any, auth_base).registry
    registry.dispose()
    metadata = cast(Any, auth_base).metadata
    for table in list(metadata.tables.values()):
        metadata.remove(table)

    refresh_token = cast("type[RefreshToken]", refresh_token_factory(auth_base))
    oauth_account = cast("type[OAuthAccount]", oauth_account_factory(auth_base))
    user = cast("type[User]", build_sqla_model(tablename, auth_base, core_mixin ))
    return user, refresh_token, oauth_account


__all__ = ["build_sqla_model", "build_sqla_models"]
