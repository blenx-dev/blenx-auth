async def register(
    self,
    *,
    email: str,
    password: str,
    birthdate: date | None = None,
    extra: dict[str, Any] | None = None
) -> UserAccount[IdT]:
    """Create an unverified account, then mail its verification link.

    ``email`` is normalized to lowercase so the unique index and all
    lookups are case-insensitive by construction. Raises
    :class:`EmailAlreadyExistsError` on collision, including a concurrent
    insert whose duplicate the backend repository translates into the same
    domain error (SQLAlchemy ``IntegrityError`` or Mongo
    ``DuplicateKeyError``) — so the race never leaks a storage exception.
    """
    validate_password(password)
    email = email.lower().strip()
    existing = await self._users.get_by_email(email)
    if existing is not None:
        raise EmailAlreadyExistsError()
    user = await self._users.create(
        NewUser(
            email=email,
            hashed_password=hash_password(password),
            is_verified=False,
            birthdate=birthdate,
            extra_data=extra or {},
        )
    )
    await self._verification.resend(user)
    return user