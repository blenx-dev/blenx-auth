# Extending User Model Properties

blenx-auth is designed so that consumers can add custom fields to the user model. This works for both SQLAlchemy and Beanie backends, and the extended fields flow through the full auth stack — from creation through to the read response.

## How It Works

The library uses **structural protocols** for its repositories. This means any user model that satisfies the `UserAccount` protocol is accepted — you don't need to subclass anything from the library.

### The Core Constraint

The `UserAccount` protocol defines the **minimum** fields the auth system needs:

```python
class UserAccount(Protocol[IdT]):
    id: IdT
    email: str
    hashed_password: str
    is_active: bool
    is_superuser: bool
    is_verified: bool
    birthdate: date | None
    created_at: datetime
    email_verified_at: datetime | None
    failed_login_attempts: int
    locked_until: datetime | None
    password_reset_token_hash: str | None
    password_reset_token_expires_at: datetime | None
```

Any class that has **at least** these fields (plus any additional ones you add) satisfies the protocol.

## SQLAlchemy Extension

Add fields directly to your User model — they coexist with the existing columns:

```python
# myapp/models.py
from sqlalchemy.orm import Mapped, mapped_column, relationship
from blenx_auth.sqlalchemy.models import User as AuthBaseUser
from sqlalchemy import String

class User(AuthBaseUser):
    """Extended user model with custom fields."""

    __tablename__ = "user"  # Same table name — no migration needed for new columns

    phone_number: Mapped[str | None] = mapped_column(String(20), nullable=True)
    department: Mapped[str | None] = mapped_column(String(100), nullable=True)
    employee_id: Mapped[str | None] = mapped_column(String(50), nullable=True)
    # Add any other custom fields here
```

Because SQLAlchemy uses inheritance, the new columns are added to the same table. The auth system only reads/writes the protocol fields — your custom fields are invisible to it but available to your application code.

## Beanie Extension

Add fields directly to your Document — they become additional MongoDB document fields:

```python
# myapp/models.py
from blenx_auth.beanie.models import User as AuthBaseUser

class User(AuthBaseUser):
    """Extended user document with custom fields."""

    phone_number: str | None = None
    department: str | None = None
    employee_id: str | None = None
    # Add any other custom fields here
```

## Pydantic Schema Extension

Extend `UserRead` to include your custom fields in API responses:

```python
# myapp/schemas.py
from blenx_auth.core.schemas import UserRead as BaseUserRead
from pydantic import EmailStr
from datetime import date, datetime

class UserRead(BaseUserRead):
    """Extended user schema with custom fields."""

    phone_number: str | None = None
    department: str | None = None
    employee_id: str | None = None
```

The `model_config = ConfigDict(from_attributes=True)` on the base class ensures that ORM/Document objects with extra attributes are still accepted — the extra fields are simply ignored during deserialization and included during serialization.

## Registration with Custom Fields

When registering a new user, pass custom fields through the `extra` parameter of the registration flow:

```python
from blenx_auth.core.services.authentication import AuthenticationService

# In your registration endpoint or service:
user = await auth_service.register(
    email="user@example.com",
    password="SecurePass123!",
    birthdate=date(1990, 1, 1),
)

# After creation, set custom fields and save
user.phone_number = "+1234567890"
user.department = "Engineering"
await user_repo.save(user)
```

The `register` method itself only handles auth-core fields (email, password, birthdate). Custom fields are set on the returned user object and persisted separately.

## User Update with Custom Fields

Updating custom fields follows the same pattern:

```python
# Fetch user
user = await user_repo.get_by_id(user_id)

# Modify custom fields
user.phone_number = "+9876543210"
user.department = "Product"

# Persist
await user_repo.save(user)
```

## Full Example: FastAPI Integration

```python
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from blenx_auth.fastapi import SQLAlchemyAuth, make_auth_router
from myapp.models import User
from myapp.schemas import UserRead

router = APIRouter()

class RegisterRequest(BaseModel):
    email: str
    password: str
    department: str | None = None
    phone_number: str | None = None

@router.post("/register", response_model=UserRead)
async def register(data: RegisterRequest, auth: SQLAlchemyAuth = Depends(get_auth)):
    user = await auth.authentication_service.register(
        email=data.email,
        password=data.password,
    )
    # Set custom fields
    user.department = data.department
    user.phone_number = data.phone_number
    await auth.user_repo.save(user)
    return user
```

## Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| Protocol-based repositories | Any model shape works — no inheritance required |
| No core changes for extensions | Custom fields never touch library code |
| Separate save for custom fields | Auth flow handles auth logic; app handles domain logic |
| `from_attributes=True` on schemas | ORM/Document objects with extra fields are accepted automatically |

## Summary

1. **Extend your storage model** (SQLAlchemy or Beanie) with custom fields
2. **Extend `UserRead`** in your app to include custom fields in responses
3. **Set custom fields** on the user object after creation or during updates
4. **Save** the user through the repository — no special library integration needed

The library's protocol-based design means your extended user model works everywhere the base model works, with zero coupling to the library's internals.
