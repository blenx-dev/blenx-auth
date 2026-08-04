---
title: "Custom Backends"
---

# Custom Backends

blenx-auth is designed for easy substitution with custom storage backends. You don’t need to subclass anything or modify the library. Just implement the core protocols and provide them to the auth manager.

## 1. Implement the Repository Protocols

All three repositories are plain `Protocol` classes in `blenx_auth.core.ports`. A custom backend means writing three classes that satisfy:

- `UserRepository` — CRUD for the user table/document
- `RefreshTokenRepository` — CRUD for refresh-token rows
- `OAuthAccountRepository` — CRUD for OAuth-linked accounts

Example:

```python
import datetime
import uuid
from blenx_auth.core.ports import (
    UserRepository,
    RefreshTokenRepository,
    OAuthAccountRepository,
)
from blenx_auth.core.dto import NewUser, NewOAuthLink
from blenx_auth.core.ports import UserAccount

class InMemoryUser:
    def __init__(self, id, email, hashed_password):
        self.id = id
        self.email = email
        self.hashed_password = hashed_password

class MyUserRepository:
    """Custom backend: implement the interface, nothing else required."""
    def __init__(self):
        self._users = {}

    async def get_by_email(self, email: str) -> UserAccount[uuid.UUID] | None:
        return self._users.get(email)

    async def get_by_id(self, user_id: uuid.UUID) -> UserAccount[uuid.UUID] | None:
        for u in self._users.values():
            if u.id == user_id:
                return u
        return None

    async def create(self, data: NewUser) -> UserAccount[uuid.UUID]:
        user = InMemoryUser(
            id=uuid.uuid4(),
            email=data.email,
            hashed_password=data.hashed_password,
        )
        self._users[user.email] = user
        return user

    async def save(self, user: UserAccount[uuid.UUID]) -> None:
        self._users[user.email] = user
```

Repeat for `RefreshTokenRepository` and `OAuthAccountRepository`.

## 2. Use It With the Auth Manager

Pass your backend implementations to the manager or services:

```python
from blenx_auth.core.services.authentication import AuthenticationService

auth_service = AuthenticationService(
    users=MyUserRepository(),
    refresh_tokens=MyRefreshTokenRepository(),
    oauth_accounts=MyOAuthAccountRepository(),
    tokens=your_token_strategy,
    email_sender=your_email_sender,
    settings=your_settings,
)
```

## 3. FastAPI Composition

For FastAPI, implement the composition root:

```python
from fastapi import Depends
from blenx_auth.fastapi.composition import AuthCompositionRoot

class MyAuthRoot(AuthCompositionRoot):
    def get_user_repository(self):
        return MyUserRepository()
    
    def get_refresh_token_repository(self):
        return MyRefreshTokenRepository()
    
    # etc.
```

No subclassing of shipped classes, no framework code in the core, no special imports.

## Key Constraints

- Repositories must be **async**.
- `create` must raise `EmailAlreadyExistsError` on duplicate emails.
- `save` mutates rows in-place; services handle persistence logic.
