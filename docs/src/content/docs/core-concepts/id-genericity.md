# ID Genericity (IdT)

blenx-auth is designed to be agnostic of the underlying identity type used by different storage systems.

## Core Principle

- Protocols and dataclasses are parameterized with `IdT` (Identity Type)
- Allows UUID (SQLAlchemy), ULID, or any other ID type to be used without changing the core contracts
- This pattern ensures that identity schemes are completely adapter-chosen

## Implementation Details

### Core Constants

```python
# constants.py
from typing import TypeVar

IdT = TypeVar("IdT")  # Generic identity type parameter
```

### Protocol Parameterization

All CRUD protocols parameterized with `IdT`:
```python
class UserRepository(Protocol[IdT]): ...
class RefreshTokenRepository(Protocol[IdT]): ...
class OAuthAccountRepository(Protocol[IdT]): ...
```

### Example: SQLAlchemy vs Beanie

**SQLAlchemy ID**: `UUID(ID: str)`

**Beanie ID**: `ObjectId` from Motor/PyTile → mapped to string representation

### Token Strategy Subjects

```python
# TokenStrategy.create_access_token(subject: str)
```

- Subjects must be strings for cross-identity compatibility
- Mapping happens at adapter layer; core never sees raw ID types

## ID Type Support Matrix

| Adapter Type | Identity Type | Suitable For |
|--------------|---------------|--------------|
| SQLAlchemy   | `uuid.UUID`   | Default backend |
| Beanie       | `ulid.ULID`   | MongoDB backend |
| ULID Mode    | `ulid.ULID`   | Additional session strategy (F5d) |

## Migration Path

- Adding ULID support adds new repository trios (one per adapter) but doesn't modify core contracts
- No runtime configurator needed — adapter-choice is permanent per repository instantiation
