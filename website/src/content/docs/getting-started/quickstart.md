---
title: "Quick Start"
---

# Quick Start

Wire up blenx-auth in 3 steps: pick a backend, bind the services, and hand the result to the router factories.

## 1. Choose a Backend

```python
# SQLAlchemy (default) — create a session factory
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

engine = create_async_engine("postgresql+asyncpg://user:pass@localhost/db")
session_factory = async_sessionmaker(engine, expire_on_commit=False)
```

## 2. Create the Auth Composition Root

```python
from blenx_auth.fastapi import SQLAlchemyAuth, make_auth_router, make_users_router
from myapp.settings import settings  # your AuthSettings-compatible object

auth = SQLAlchemyAuth(settings=settings, session_factory=session_factory)
```

## 3. Mount the Routers

```python
from fastapi import FastAPI

app = FastAPI()
app.include_router(make_auth_router(auth))
app.include_router(make_users_router(auth))
```

That's it. You now have working JWT authentication with email verification, password reset, and Google OAuth.

## Minimal FastAPI App

```python
from fastapi import FastAPI
from blenx_auth.fastapi import SQLAlchemyAuth, make_auth_router, make_users_router

app = FastAPI()
auth = SQLAlchemyAuth(settings=settings, session_factory=session_factory)
app.include_router(make_auth_router(auth))
app.include_router(make_users_router(auth))
```

## Next Steps

- [Configure settings](#configuration)
- [Add OAuth providers](#oauth)
- [Set up permissions](#permissions)
