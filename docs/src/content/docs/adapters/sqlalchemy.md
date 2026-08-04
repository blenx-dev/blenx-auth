# Improvements

Tasks to fix and harden the current `blenx-auth` package. Ordered so that
independent work lands first; each task lists the ones it depends on.

## 1. Remove dead fastapi-users code

_Independent — no dependencies. Unblocks everything else._

The package still ships five modules that were deleted from `apps/api` during
its migration to the service-based auth. They are the only users of
`fastapi-users` and they collide with the live models.

- [x] Delete `src/blenx_auth/config.py` — fastapi-users `AuthenticationBackend` (JWTStrategy/RedisStrategy/BearerTransport)
- [x] Delete `src/blenx_auth/users.py` — `BaseUserManager` / `UUIDIDMixin` / `get_user_db` dependency
- [x] Delete `src/blenx_auth/user_schemas.py` — `fastapi_users.schemas.BaseUser*` subclasses
- [x] Delete `src/blenx_auth/router.py` — legacy `OAuth2AuthorizeCallback` Google callback
- [x] Delete `src/blenx_auth/models/users.py` — second `User`/`OAuthAccount` classes on the fastapi-users `Base`
  - Note: this module currently collides with `models/user.py` (two `User` classes) and calls
    `get_settings()` unawaited at import (`models/users.py:20`), which raises `NotImplementedError`.

## 2. Migrate the API's auth tests into the package

_Independent — no dependencies. Do this early: it locks in current behavior as
a safety net before the refactors in 3–6._

`libs/blenx-auth/tests/` is empty. The API owns 441 lines of tests covering
exactly the copied code.

- [x] Port `apps/api/tests/test_auth_service.py` (service-layer, framework-free fakes)
- [x] Port `apps/api/tests/fakes.py` (fake repositories, fake email sender)
- [ ] Port `apps/api/tests/conftest.py` as needed (skipped: app-specific FastAPI TestClient)
- [ ] Port `apps/api/tests/test_auth_api.py` after Phase 2 wiring

## 3. Make the core pure Python (no FastAPI imports)

_Independent refactor — no dependencies. Run the tests migrated in 2 to verify._

The business-logic layer is already framework-free, but FastAPI leaks into
modules that should be importable anywhere.

- [x] `settings.py` — drop `from fastapi import Depends` and the `get_settings()` FastAPI dependency; keep the pure `AuthSettings` Protocol
- [x] `db/session.py` — keep the `create_session_factory` factory; remove the import-time env engine (`AsyncSessionLocal`, `get_db_session`)
- [x] `repositories/*.py` — remove the `SessionDep` aliases and `get_*_repository` FastAPI dependency functions; keep the pure SQLAlchemy repository classes
- [x] `email.py` — keep `get_email_sender` only as a plain factory (no `Depends` usage remains after the above)
- [x] Add `tests/test_no_framework_import.py` (e.g. `tests/test_no_framework_import.py`) asserting `blenx_auth.core` (and any subpackage) imports without `fastapi`, `fastapi_users`, or `starlette` installed
- [x] Move the FastAPI-coupled modules (`dependencies.py`, `routes.py`, `permissions.py`) into `blenx_auth.fastapi` integration subpackage so the default install is framework-free

## 4. Port the current OAuth flow from `apps/api`

_Depends on: 1 (old callback deleted), 3 (port the routes into the new
integration subpackage). TokenService oauth-state methods are pure core._

The lib's old `router.py` implemented the *old* fastapi-users callback. The API
now uses a signed-state flow in `apps/api/app/auth/oauth.py`
(`/auth/google/authorize` + `/auth/google/callback` via
`AuthenticationService.oauth_login`). The lib must replicate that instead.

- [x] `TokenService.create_oauth_state` / `verify_oauth_state` already present in core `jwt.py`
- [x] `google_oauth.py` client exposes `get_authorization_url`, `get_access_token`, `base_scopes`, `name` (required by the flow
- [ ] Port `oauth.py` (authorize + callback routes) into the FastAPI integration subpackage - [x] Port `oauth.py` into `blenx_auth.fastapi.oauth`

## 5. Strip framework-specific dependencies from `pyproject.toml`

_Depends on: 1 (fastapi-users/redis now unused), 3 (fastapi → extra),
4 (google_oauth rework for httpx-oauth)._

- [x] Remove `fastapi-users[oauth,sqlalchemy]>=15.0.5` (never present in extracted package)
- [x] Remove `redis>=8.1.0` (never present in extracted package)
- [x] Move `fastapi` to `[project.optional-dependencies] fastapi`
  so `pip install blenx-auth` pulls no web framework
- [ ] `httpx-oauth`: after task 1 the `httpx_oauth.integrations.fastapi` import is gone, but
  `google_oauth.py` still imports `httpx_oauth.oauth2`/`exceptions`. Full removal is part of
  F6 (FEATURES.md) — replace the client with plain `httpx` there.

## 6. Harden the settings seam

_Depends on: 1 (redis_url removal), 3 (drop the FastAPI dependency), and the
UserManager from F2 (FEATURES.md) for the host-passed settings story._

The current `AuthSettings` protocol carries fields only the dead code reads.

- [x] Remove `redis_url` from `AuthSettings`
- [x] Add `google_client_secret: SecretStr` to `AuthSettings`
- [ ] Drop the `get_settings` override dance; the host app passes a settings object straight to the manager/adapters (see F2)

## 7. Fill in `examples/`

_Depends on: 3 (standalone core)._

`examples/` is empty while the README references it.

- [x] Add `examples/standalone.py` — in-memory fakes, no DB, no web framework
- [x] Add `examples/sqlalchemy_example.py` — SQLAlchemy repositories wired to a session factory

## 8. Sync docs and package metadata

_Depends on: 1, 3 (layout settles after the subpackage split)._

- [x] Update `README.md` structure tree to the post-split layout
- [x] Update the README feature list to reflect framework-agnostic core + optional FastAPI integration
- [x] Bump version to `0.2.0` after the breaking cleanup

## 9. Wire `apps/api` to consume the package (Phase 2)

_Depends on: all of the above._

The README says the API still uses its own copy.

- [ ] Add `blenx-auth` as a path dependency of `apps/api`
- [ ] Delete `apps/api/app/auth/*` and `apps/api/app/email/__init__.py` in favor of the lib
- [ ] In `apps/api/app/main.py`, override the lib's settings/session seams with the app's `Settings` and session factory
- [ ] Re-run the full API test suite and manual auth flows end-to-end
