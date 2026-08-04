"""Declarative base shared by the SQLAlchemy ORM models.

Import any model modules that should be discoverable by Alembic autogenerate
here (see the host app's ``alembic/env.py``).
"""

from __future__ import annotations

import uuid

from sqlalchemy.orm import DeclarativeBase


class AuthBase(DeclarativeBase):
    """Declarative base for the auth models.

    This is intentionally a **separate MetaData** from the host app's
    declarative base during the build-alongside phase: the ``user`` and
    ``oauth_account`` tables may also be mapped by another declarative base on a
    separate MetaData, and two declarative classes cannot register the same
    table on one MetaData.
    """


UserId = uuid.UUID
"""The SQLAlchemy adapter's primary-key type (``uuid.UUID``)."""
