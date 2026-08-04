"""User profile/account CRUD beyond the auth flows (update, lookup)."""

from __future__ import annotations

from typing import Generic

from pydantic import BaseModel

from blenx_auth.core.dto import IdT
from blenx_auth.core.exceptions import UserModelMappingError, UserNotFoundError
from blenx_auth.core.plugins.hooks import AuthHooks, run_side_effects
from blenx_auth.core.ports import UserAccount, UserRepository


class UserService(Generic[IdT]):
    """Profile/account operations for a composed user model.

    Like the other core services this is framework- and storage-free: it talks
    only to the ``UserRepository`` port, the composed ``model`` (used to
    validate update fields against real columns), and the ``on_after_update``
    hooks. The ``model`` is duck-typed for the columns/fields lookup so both
    the SQLAlchemy adapter (``model.__table__``) and the Beanie adapter
    (``model.model_fields``) work.
    """

    def __init__(
        self,
        *,
        repo: UserRepository[IdT],
        hooks: AuthHooks,
        model: type,
    ) -> None:
        self._repo = repo
        self._hooks = hooks
        self._model = model

    @property
    def model(self) -> type:
        """The composed user model this service was bound to."""
        return self._model

    async def get(self, user_id: IdT) -> UserAccount[IdT]:
        """Return the account with ``user_id``, else raise
        :class:`UserNotFoundError`."""
        user = await self._repo.get_by_id(user_id)
        if user is None:
            raise UserNotFoundError(user_id)
        return user

    async def update(self, *, user_id: IdT, payload: BaseModel) -> UserAccount[IdT]:
        """Apply a partial update to ``user_id`` and persist it.

        Only fields the caller actually set are applied
        (``model_dump(exclude_unset=True)`` — locked decision #8), and only if
        they map to a real attribute on the composed model
        (:class:`UserModelMappingError` otherwise). ``on_after_update`` side
        effects run with ``(user, updates)`` before the save.
        """
        user = await self._repo.get_by_id(user_id)
        if user is None:
            raise UserNotFoundError(user_id)

        updates = payload.model_dump(exclude_unset=True)
        known_fields = self._model_fields()
        for name, value in updates.items():
            if name not in known_fields:
                raise UserModelMappingError(name)
            setattr(user, name, value)

        await run_side_effects(self._hooks.on_after_update, user, updates)
        await self._repo.save(user)
        return user

    def _model_fields(self) -> set[str]:
        table = getattr(self._model, "__table__", None)
        if table is not None:
            return set(table.columns.keys())
        model_fields = getattr(self._model, "model_fields", None)
        if model_fields is not None:
            return set(model_fields.keys())
        return set(getattr(self._model, "__annotations__", {}).keys())


__all__ = ["UserService"]
