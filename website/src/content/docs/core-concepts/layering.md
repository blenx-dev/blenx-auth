---
title: "Layering"
---

# Layering

blenx-auth follows a strict three-layer architecture to maintain separation of concerns and ensure reusability across frameworks and storage backends.

## Layers

### L1: Core (`blenx_auth/core/`)
- Pure Python — no framework dependencies, no storage engine dependencies
- Contains:
  - Protocols (`UserRepository`, `RefreshTokenRepository`, `OAuthAccountRepository`, `TokenStrategy`, `EmailSender`, `AuthSettings`)
  - Domain exceptions
  - Business logic`)
  - DTOs and schemas
- Configuration is designed to be importable with only the package's direct dependencies (pydantic, pyjwt, etc.). It must not import `fastapi`, `starlette`, or any storage engine.

### L2: Adapters (`blenx_auth/adapters/{backend}/`)
- Storage backends + DB-session strategies
- Implements the core protocols
- Contains:
   - ORM/ODM models (SQLAlchemy, Beanie)
   - Repository implementations
   - Session factories and helpers
   - Token strategies tied to a specific storage backend (if applicable)
- May import core types but not vice versa.

### L3: Integrations (`blenx_auth/integrations/{framework}/`)
- Framework-specific wiring (currently only FastAPI)
- Thin mapping of L1/L2 to HTTP
- Contains:
   - FastAPI dependencies
   - API routers
   - Permission guards
   - Error handlers
   - Transport mechanisms (Bearer, Cookie)
- Imports everything (core, adapters, framework) but is optional — the core and adapters work without it.

## Dependency Rules

1. **Dependencies point downward only**
   - Core imports nothing from adapters or integrations
   - Adapters import only from core
   - Integrations import from core and adapters (and the framework)

2. **Core purity**
   - Core must be importable with no `fastapi`/`fastapi_users`/`starlette` installed (enforced by CI)

3. **Policy lives only in core services**
   - Adapters never carry policy (they only persist and retrieve data)
   - Integrations never carry policy (they only map to HTTP)
   - All business rules (lockout, token semantics, password policy) reside in core services

## Benefits

- **Framework agnosticism**: The same core can be used with FastAPI, Django, Flask, or even non-web contexts (CLI tools, workers).
- **Storage agnosticism**: Switch between SQLAlchemy, Beanie, or a custom backend without changing application logic.
- **Testability**: Core services can be unit-tested with in-memory fakes without requiring a database or web server.
