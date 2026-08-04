# Changelog

## 0.3.0

Ports & Adapters (Hexagonal) migration.

- Make `blenx_auth.fastapi` (and `blenx_auth`) importable with **no** storage
  backend installed: `fastapi/composition.py` no longer imports SQLAlchemy or
  Beanie at module load — each backend's SDK is imported lazily inside its
  composition root's constructor.
- Add a `sqlalchemy` optional extra and make the `fastapi` extra depend on it,
  so `pip install "blenx-auth[fastapi]"` alone is usable with the default
  SQLAlchemy backend; `beanie` remains opt-in.

- Split the package into a framework- and storage-free `core/`
  (constants, exceptions, dto, ports, services, settings, email),
  two storage adapters (`sqlalchemy/` — default — and `beanie/`),
  and a thin `fastapi/` inbound adapter with `routers/` factories.
- Add composition roots (`SQLAlchemyAuth` / `BeanieAuth`) that expose the
  service and current-user dependencies for each storage backend.
- Add `make_auth_router` / `make_users_router` / `make_oauth_router` router
  factories bound to a composition root.
- Move current-user dependencies and the exception handler into
  `fastapi.current_user` and `fastapi.exception_handlers`.
- Remove all legacy top-level shims (`types.py`, `service.py`, `jwt.py`,
  `password.py`, `email.py`, `settings.py`, `constants.py`, `exceptions.py`,
  `schemas.py`, `google_oauth.py`) and the old `adapters/` tree; all consumers
  now import from `core.*`, `sqlalchemy.*`, `beanie.*`, or `fastapi.*`.
- Relocate the test suite from `src/tests/` to `tests/`.

## 0.2.0

Phase 2 — extraction complete.

- Extract authentication into a standalone `blenx-auth` package (hatchling, `src/` layout).
- Make the core framework-free: services, protocols, and repositories import
  without FastAPI installed.
- Move FastAPI-coupled code into the optional `blenx_auth.fastapi` subpackage.
- Add Google OIDC signed-state flow, Argon2id hashing, refresh-token rotation,
  account lockout, and role/permission guards.
- Remove all dead `fastapi-users` code.
- Add examples and the no-framework import guard.
