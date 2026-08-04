# Features

New capabilities beyond the current extracted code. **Priority-ordered**:
foundation first, each feature lists what it depends on. Token-method roadmap
(JWT → Cookie → Redis → DB session) is driven by F5; see the callout there.

## Backend principle

- **SQLAlchemy is the default backend.** Any feature that needs persistence
  ships its SQLAlchemy implementation first — it is what `apps/api` runs on, it
  is the tested reference, and it is what ships out of the box.
- **Every backend is replaceable.** The core knows nothing about storage: it
  depends only on the repository `Protocol`s. A new first-party backend (Beanie,
  F4) is additive; a user can also implement a fully custom backend by writing
  classes that satisfy the same `Protocol`s — no subclassing, no framework code.
- Parity rule: no feature is considered done until its default (SQLAlchemy)
  implementation and at least one non-default implementation pass the same
  adapter-parity suite (F4/F9).

Target architecture:

```
blenx_auth
├── core/                 # pure Python, runs anywhere (no FastAPI, no fastapi-users)
│   ├── constants.py
│   ├── exceptions.py
│   ├── types.py          # Protocol contracts + dataclasses (generic over ID type)
│   ├── settings.py       # AuthSettings Protocol only
│   ├── email.py          # EmailSender Protocol + NullEmailSender
│   ├── password.py
│   ├── jwt.py            # TokenService (JWT strategy — primary)
│   ├── strategy.py       # NEW: TokenStrategy Protocol + JWTTokenStrategy (+ Redis)
│   ├── schemas.py        # Pydantic wire models
│   ├── service.py        # Auth services (business logic)
│   ├── manager.py        # NEW: fastapi-users-style facade over adapters
│   └── oauth.py          # NEW: provider-agnostic OAuth client protocol
├── adapters/             # persistence + DB-backed session strategies
│   ├── sqlalchemy/       # DEFAULT backend — models + repositories + session
│   │                     #   factory + sessions table (what apps/api uses)
│   └── beanie/           # additive backend — MongoDB (Beanie) models +
│                         #   repositories (UUID or ULID)
└── integrations/
    └── fastapi/          # NEW: optional FastAPI wiring (dependencies, routes,
        │                 #   permissions, transports, ported OAuth router)
        └── transports.py # NEW: Bearer + Cookie transports
```

## F1. Pure-Python core package

_Foundation — no dependencies. Everything builds on this._

Guarantee `blenx_auth.core` is importable and fully functional with zero
third-party framework dependencies.

- [ ] Move `constants.py`, `exceptions.py`, `types.py`, `settings.py`, `email.py`, `password.py`, `jwt.py`, `schemas.py`, `service.py` under `blenx_auth/core/`
- [x] Parameterize the core over the id type: `IdT` generics in `types.py`/`service.py`, so identity is adapter-chosen — `uuid.UUID` for SQLAlchemy, Mongo `ObjectId` for Beanie — with no runtime configurator; a future ULID mode just adds a repository trio per adapter
- [x] Keep `schemas.py` on Pydantic only (no FastAPI `EmailStr` dependency; use `pydantic[email]`)
- [ ] Add CI/test guard: `pytest` run against a venv with only the core dependencies installed (no `fastapi`, no `fastapi_users`)
- [ ] Export the public API from `blenx_auth.core` (`__init__.py`) so consumers import one namespace

## F2. `blenx_auth.core.manager` — UserManager facade

_Depends on: F1. Defaults to the core JWT strategy, so it is usable immediately._

A fastapi-users-style manager that owns the whole auth lifecycle over any
adapter, giving consumers a single entry point.

- [ ] Define a `UserManager` that composes the existing services
  (`AuthenticationService`, `EmailVerificationService`, `PasswordResetService`)
  and exposes: `register`, `login`, `oauth_login`, `refresh`, `logout`,
  `logout_all`, `verify`, `resend_verification`, `forgot_password`,
  `reset_password`, `authenticate`
- [ ] Constructor takes only adapter contracts: `users`, `refresh_tokens`, `oauth_accounts` repositories, a `TokenStrategy`, `EmailSender`, and `AuthSettings`
- [ ] Ship the JWT `TokenStrategy` as the default (see F5 priority order)
- [ ] Mirror fastapi-users callbacks as extension points (`on_after_register`,
  `on_after_login`, `on_after_forgot_password`, ...) as async hooks
- [ ] Ship a default configuration object (secret, token lifetimes, lockout policy) alongside the `AuthSettings` protocol
- [ ] Wire the SQLAlchemy repositories (F3) as the default backend in the shipped wiring; Beanie (F4) and user-provided backends are drop-in alternatives

**Custom backends:** because `UserManager` takes repository *Protocols*, a user
backend is just classes implementing `UserRepository`,
`RefreshTokenRepository`, and `OAuthAccountRepository` (F1 `types.py`). No
subclassing of shipped classes, no imports from any adapter, no framework code
in the core.

**`TokenStrategy` Protocol (core contract — users implement this to swap JWT
for any custom method):**

```python
from datetime import timedelta
from typing import Protocol

from blenx_auth.exceptions import ExpiredTokenError, InvalidTokenError


class TokenStrategy(Protocol):
    """Everything the UserManager needs from a token implementation.

    Implement this to replace JWT with, e.g., opaque DB-session tokens (F5d),
    a Redis store (F5c), or a proprietary format. All subjects are strings
    (the user id as ``str``); verify methods must raise the domain errors
    (``InvalidTokenError`` / ``ExpiredTokenError``) so HTTP mapping stays
    uniform, and never return a subject for a bad token.
    """

    # ---- minting ---------------------------------------------------------
    def create_access_token(self, subject: str) -> str: ...
    def create_refresh_token(self, subject: str) -> str: ...
    def create_email_verification_token(self, subject: str) -> str: ...
    def create_password_reset_token(self, subject: str) -> str: ...

    # ---- verification (raise on failure) ---------------------------------
    def decode_access_token(self, token: str) -> str: ...
    def decode_refresh_token(self, token: str) -> str: ...
    def verify_email_verification_token(self, token: str) -> str: ...
    def verify_password_reset_token(self, token: str) -> str: ...

    # ---- OAuth state (CSRF round-trip) -----------------------------------
    def create_oauth_state(self) -> str: ...
    def verify_oauth_state(self, token: str) -> None: ...

    # ---- TTLs (persisted on refresh-token rows) --------------------------
    def access_expires_delta(self) -> timedelta: ...
    def refresh_expires_delta(self) -> timedelta: ...
```

Notes:

- `TokenService` (`jwt.py`) already satisfies this protocol structurally, so it
  *is* the default `JWTTokenStrategy` — no wrapping adapter needed.
- A custom strategy is passed straight to the manager:
  `UserManager(..., tokens=MyCustomStrategy(...))`. The services never know
  which strategy is installed.
- Keep subjects as strings: this is what lets UUID (SQLAlchemy) and
  Mongo `ObjectId` (Beanie, F4) id schemes share one strategy surface.

## F3. SQLAlchemy adapter

_Depends on: F1 (layout), F2 (manager consumes it). Mostly a move — the existing
code is already SQLAlchemy, so this is cheap and unblocks the FastAPI wiring.
**This is the default backend** (Backend principle): it ships in the base
install, it is what `apps/api` uses, and it is the parity reference for F4._

Move the existing SQLAlchemy models/repositories into a first-class adapter and
make it DB-agnostic SQLAlchemy (sync + async optional).

- [x] Move `models/*`, `repositories/*` under `blenx_auth/adapters/sqlalchemy/`
- [x] Keep a `create_session_factory(database_url, *, debug=False)` factory; drop the import-time engine entirely
- [x] Provide repository classes that satisfy the core `Protocol`s (already the case) plus the async session type
- [ ] Add a `sessions` table + `SQLAlchemySessionRepository` to back the default DB-session strategy (F5d)
- [ ] Add Alembic autogenerate support: `Base.metadata` discoverable from `blenx_auth.adapters.sqlalchemy`
- [ ] Ship SQLAlchemy in the default install (it is the backend `apps/api` runs on); add an optional `sqlalchemy` extra only if/when the base install is intentionally backend-free

## F4. Beanie (MongoDB) adapter

_Depends on: F1, F3 (pattern established). Additive backend — SQLAlchemy
remains the default (Backend principle). Include ULID identity support._

Parity adapter so the same core works on MongoDB.

- [x] Add `src/blenx_auth/adapters/beanie/` with Beanie `Document` models (user, refresh token, oauth account) satisfying the core `Protocol`s
- [x] Implement `BeanieUserRepository`, `BeanieRefreshTokenRepository`, `BeanieOAuthAccountRepository`
- [x] Adapter-chosen identity: Mongo `ObjectId` (`PydanticObjectId`) is the Beanie primary-key type, `uuid.UUID` the SQLAlchemy one — one document/repository trio per adapter, no runtime id-type configurator
- [x] Add a Beanie session/db bootstrap helper (`init_beanie(...)`)
- [x] Add an optional `beanie` extra to `pyproject.toml`
- [x] Add adapter-parity tests (same suite run against the Beanie repositories; note: requires a reachable MongoDB via `MOTOR_URI` — `mongomock` ships no async client)
- [x] Run the full parity suite against the Beanie repositories' `ObjectId` identity (single mode, no parametrization)

## F5. Token strategy layer

_Depends on: F2 (manager takes a strategy); DB-session strategies land with
their adapter (F3/F4)._

**Token-method roadmap (priority order):**

1. **JWT — primary & default.** Wrap the existing `TokenService` as
   `JWTTokenStrategy`. Used by `UserManager` out of the box.
2. **Cookie transport.** Not a strategy but the next delivery method: carry the
   JWT in an HTTP-only cookie instead of a Bearer header (framework-side, lands
   in F7 `transports.py`). No core changes.
3. **Redis.** `RedisTokenStrategy` for server-side, revocable/denylist-able
   access tokens (fastapi-users `RedisStrategy` equivalent). Optional `redis` extra.
4. **DB-backed session.** Opaque session tokens stored in the adapter's own
   `sessions` table/collection — works on **SQLAlchemy or Beanie** (whichever
   adapter the consumer uses). Fully revocable, survives server restarts.
   SQLAlchemy version is the default; Beanie is parity (Backend principle).

- [ ] Adopt the `TokenStrategy` Protocol defined in F2 as the single seam (JWT is the reference implementation)
- [ ] Rename/alias `TokenService` as `JWTTokenStrategy` (primary; already satisfies the protocol)
- [ ] Add `RedisTokenStrategy` (step 3; optional `redis` extra)
- [ ] Add `SQLAlchemySessionStrategy` backed by the F3 `sessions` table — **default** DB-session strategy
- [ ] Add `BeanieSessionStrategy` backed by the F4 `sessions` collection (parity)
- [ ] Add a `Transport` concept (Bearer first, Cookie in F7) distinct from strategy, matching fastapi-users' strategy/transport split
- [ ] Let `UserManager` accept any strategy

## F6. Provider-agnostic OAuth

_Depends on: F1, F2. Independent of adapters._

Replace the `httpx-oauth`-based `google_oauth.py` with a core OAuth protocol so
any provider plugs in.

- [ ] Define `OAuthProvider` Protocol (`name`, `authorization_url`, `exchange_code`, `userinfo`, `base_scopes`)
- [ ] Add `GoogleProvider` backed by plain `httpx` (drop `httpx-oauth`)
- [ ] Add `GitHubProvider`, `AppleProvider` as optional extras
- [ ] Keep `oauth_login` service method unchanged — it already takes provider/account_id/email/tokens generically
- [ ] Remove the `httpx_oauth` dependency (currently also in IMPROVEMENTS task 5)

## F7. Optional FastAPI integration

_Depends on: F2 (manager), F3 (SQLAlchemy), F5 (transports), ported OAuth (IMPROVEMENTS task 4)._

Web-framework wiring lives only in an optional subpackage so the core stays pure.

- [ ] Move `dependencies.py`, `routes.py`, `permissions.py` under `blenx_auth/integrations/fastapi/`
- [ ] Add `transports.py` with `BearerTransport` (default) and `CookieTransport` (step 2 of F5)
- [ ] Refactor the FastAPI wiring to build everything from a `UserManager` + a host-provided settings/session provider
- [ ] Default the wiring to the SQLAlchemy backend (F3) — the setup `apps/api` will consume; a one-line factory override swaps in Beanie or a user backend
- [ ] Add the ported Google OAuth router (IMPROVEMENTS task 4) into this subpackage
- [ ] Expose the single `auth_error_handler` for `AuthError` JSON rendering
- [ ] Publish as optional extra: `pip install blenx-auth[fastapi]` (with `sqlalchemy` in the default extra set)

## F8. Rate limiting / login hardening

_Depends on: F5 (shares the Redis integration)._

The `_enforce_rate_limit` hook is a deliberate no-op today.

- [ ] Implement a Redis leaky-bucket limiter as an optional strategy plugged into `AuthenticationService.login`
- [ ] Raise `RateLimitExceededError` with `Retry-After` when the budget is exhausted
- [ ] Keep the in-process lockout guard as the always-on default

## F9. Consumer test kit

_Depends on: F2. Useful to every downstream feature._

Make the package easy to consume and test.

- [ ] Ship `blenx_auth.testing` with `InMemoryUserRepository`, `InMemoryRefreshTokenRepository`, `InMemoryOAuthAccountRepository`, and a `FakeEmailSender`
- [ ] Add a `pytest` fixture helper that builds a fully-wired `UserManager` with fakes
- [ ] Add `examples/` for: in-memory (no framework), SQLAlchemy (FastAPI integration), and Beanie

## F10. Package hygiene

_Continuous — runs in parallel with F1–F9; completes the release._

- [ ] Add `pre-commit`/CI: `ruff`, `mypy --strict`, and the no-framework import test
- [ ] Add a changelog (`CHANGELOG.md`) starting at `0.2.0`
- [ ] Publish readiness: `python -m build` + `twine check`; release to PyPI (or internal index) after F1–F7
