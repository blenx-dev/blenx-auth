"""Password hashing and policy validation (Argon2id via pwdlib).

pwdlib's ``PasswordHash.recommended()`` resolves to an Argon2id hasher with
current secure defaults (memory cost, iterations, parallelism). Encapsulating
hashing here means services and tests never see the hashing library directly:
swap ``hash_password``/``verify_password`` implementations without touching
business logic.
"""

from __future__ import annotations

from pwdlib import PasswordHash
from pwdlib.exceptions import UnknownHashError

from blenx_auth.core.constants import PasswordPolicy
from blenx_auth.core.exceptions import PasswordPolicyError

_password_hasher = PasswordHash.recommended()


def hash_password(password: str) -> str:
    """Return an Argon2id hash of ``password``.

    Callers are expected to run :func:`validate_password` first; this function
    intentionally hashes whatever it is given so it stays a pure primitive.
    """
    return _password_hasher.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    """Return True when ``plain`` matches the stored Argon2id ``hashed``.

    A stored hash with an unrecognized prefix (e.g. a legacy or corrupt value)
    is treated as a mismatch rather than raised, so a bad row can never turn
    into a server error — it is simply a failed login.
    """
    try:
        return _password_hasher.verify(plain, hashed)
    except UnknownHashError:
        return False


def validate_password(password: str) -> None:
    """Enforce the password policy, raising :class:`PasswordPolicyError` on the
    first violation.

    The maximum length guards against hashing pathological inputs (CPU/memory
    DoS via an enormous password); the minimum is the weak-auth floor. Both
    bounds are defined once in :mod:`blenx_auth.core.constants`.
    """
    if len(password) < PasswordPolicy.MIN_LENGTH:
        raise PasswordPolicyError(
            f"Password must be at least {PasswordPolicy.MIN_LENGTH} characters long."
        )
    if len(password) > PasswordPolicy.MAX_LENGTH:
        raise PasswordPolicyError(
            f"Password must be at most {PasswordPolicy.MAX_LENGTH} characters long."
        )
