---
title: "blenx-auth"
---

Reusable authentication library for FastAPI applications.

> **Status:** Beta. Open for feedback.

## Features

- JWT-based access and refresh token rotation
- Email verification and password reset flows
- Google OIDC OAuth client
- Argon2id password hashing
- Account lockout after repeated failures
- Role / permission guards
- Protocol-based repository contracts (SQLAlchemy + Beanie/MongoDB backends included)
- Framework-agnostic core (no FastAPI required to use services)

## Installation

```bash
# Core — no web framework dependency
pip install blenx-auth

# With FastAPI integration layer (pulls the SQLAlchemy backend too)
pip install blenx-auth[fastapi]

# With the SQLAlchemy backend only (DB driver is your choice)
pip install blenx-auth[sqlalchemy]

# With the Beanie (MongoDB) adapter
pip install blenx-auth[beanie]
```

## Structure

```
src/blenx_auth/
├── __init__.py
├── core/                   # Framework- and storage-free business core
│   ├── constants.py        # Security invariants / enums
│   ├── exceptions.py       # Domain exceptions
│   ├── dto.py              # Plain data objects crossing the ports
│   ├── ports.py            # Repository + email-sender protocols
│   ├── email.py            # NullEmailSender + get_email_sender factory
│   ├── password.py         # Argon2id hashing + policy
│   ├── jwt.py              # TokenService
│   ├── schemas.py          # Pydantic wire models (FastAPI adapter)
│   ├── settings.py         # AuthSettings protocol (pure Python)
│   └── services/           # AuthenticationService, EmailVerificationService,
│                           # PasswordResetService
├── sqlalchemy/             # SQLAlchemy (PostgreSQL) adapter — default backend
│   ├── base.py             # AuthBase + UserId (uuid)
│   ├── models.py           # User / RefreshToken / OAuthAccount ORM models
│   ├── repositories.py     # SQLAlchemy*Repository protocol implementations
│   └── session.py          # create_session_factory(...) helper
├── beanie/                 # Beanie (MongoDB) adapter — optional [beanie]
│   ├── models.py           # User / RefreshToken / OAuthAccount Documents
│   ├── bootstrap.py        # init_beanie_db(...) helper
│   └── repositories.py     # Beanie*Repository protocol implementations
└── fastapi/                # Optional FastAPI integration subpackage [fastapi]
    ├── __init__.py
    ├── composition.py      # SQLAlchemyAuth / BeanieAuth composition roots
    ├── current_user.py     # Current-user dependency factory
    ├── exception_handlers.py  # auth_error_handler
    ├── google_oauth.py     # Google OIDC client (pure httpx-oauth)
    ├── permissions.py      # make_permission_guards(...) dependency factories
    └── routers/            # make_auth_router / make_users_router / make_oauth_router
```

The host application wire-up is a **composition root**: pick a backend, bind the
services, and hand the result to the router factories.

```python
from blenx_auth.fastapi import SQLAlchemyAuth, make_auth_router, make_users_router

auth = SQLAlchemyAuth(settings=settings, session_factory=session_factory)
app.include_router(make_auth_router(auth))
app.include_router(make_users_router(auth))
```

## Examples

See the `examples/` directory for:
- `standalone.py` — wiring core services to in-memory fakes (no DB, no web framework)
- `sqlalchemy_example.py` — using the SQLAlchemy repositories
- `beanie_example.py` — using the Beanie (MongoDB) repositories

## License

MIT
