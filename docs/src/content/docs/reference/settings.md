# Release Strategy

How `blenx-auth` goes from an extracted directory to a published, stable
package without breaking `apps/api` in the process.

## Context

- Monorepo managed with `uv`. The root `pyproject.toml` is the whole app
  ("styleos-backend", `[tool.uv] package = false`); `apps/api` has no
  pyproject of its own.
- `libs/blenx-auth` is already a standalone, buildable package (hatchling,
  `src/` layout, own `pyproject.toml`).
- `apps/api` still runs its own copy of the auth code. `blenx-auth` is a
  line-faithful replica, minus the fastapi-users cruft still present today
  (see IMPROVEMENTS.md).

## Goals

1. `blenx-auth` becomes the single source of truth for auth, consumed by
   `apps/api` first, other services later.
2. The *public* surface (see "Public API" below) is explicit and stable.
3. Nothing ships to a registry until a real consumer has run against it.

## Phase gates

| Phase | Trigger | Version | Registry |
| ----- | ------- | ------- | -------- |
| **1 — Extraction** (now) | Copy + cleanup + core purity (IMPROVEMENTS 1–8, F1–F2) | `0.1.0` | none |
| **2 — Adoption** | `apps/api` consumes via workspace path; full API suite green (IMPROVEMENTS 9) | `0.2.0` | internal only |
| **3 — Completeness** | F1–F7 + adapter parity (SQLAlchemy + Beanie), docs, examples | `0.3.0` | internal index |
| **4 — Public** | ≥ 2 external consumers; surface frozen | `1.0.0` | PyPI |

**Rule:** no phase starts until the previous gate's suite is green. Phase 2 is
the first real validation of the API surface — treat anything that hurts there
as a design defect, not a consumer defect.

## Versioning

Semantic Versioning from `0.1.0`.

- `0.x` — `minor` bumps may break the public API **if** the break is
  documented in the changelog and `apps/api` is updated in the same change.
  `patch` bumps are strictly non-breaking.
- `1.0.0` — public API frozen. Breaking changes require a major bump and a
  deprecation cycle (two releases) after that.

### Public API (stability surface)

Stable from Phase 2 onward:

- `blenx_auth.core`: protocols (`UserRepository`, `RefreshTokenRepository`,
  `OAuthAccountRepository`, `TokenStrategy`, `EmailSender`, `AuthSettings`),
  domain exceptions, the services, `UserManager`, wire schemas.
- Adapter public constructors (`SQLAlchemyUserRepository`, session factories,
  `Beanie*Repository`, shipped `*SessionStrategy`).
- `blenx_auth.exceptions` error hierarchy.

Everything else (module internals, unexported helpers) is private; changes
there do not require a minor bump.

## Compatibility policy

Every release candidate must pass:

1. Core unit suite (services against in-memory fakes).
2. The no-framework import guard (core imports with no `fastapi` /
   `fastapi_users` / `starlette` installed).
3. Adapter parity suite — the same behavioral tests against in-memory fakes,
   SQLAlchemy, and Beanie (UUID and ULID id modes).
4. The full `apps/api` test suite (via the workspace dependency).

Breaking-change checklist for a `0.x` minor: (a) update consumers in the same
commit, (b) changelog entry, (c) run the parity + API suites, (d) tag.

## Packaging & distribution

### Install profiles

- **Base install** = core + `sqlalchemy` (default backend, Backend principle
  in FEATURES.md). This is what `apps/api` runs on and what a new consumer
  gets by default.
- **Extras:**
  - `[fastapi]` — integrations subpackage (deps, routes, transports, error
    handler, OAuth router).
  - `[beanie]` — MongoDB adapter.
  - `[redis]` — Redis token strategy + rate limiter.
  - `[oauth]` — non-Google providers (GitHub, Apple).
  - `[smtp]` — real email sender (ReSMTP/SES/etc. wrappers).

Rationale: keep the base install small and framework-free so CLI tools,
workers, and non-web services can use the core without pulling a web stack.

### Build & publish mechanics

- Build with hatchling (already configured): `uv build` (produces sdist + wheel).
- Publish with `uv publish` (replaces `twine`); run `twine check` in CI before
  publishing.
- Tag `blenx-auth-vX.Y.Z`; changelog entry per release (`CHANGELOG.md`, F10).
- **Version management is automated** via release-please
  (`.github/workflows/release-please.yml`): conventional commits touching
  `libs/blenx-auth/` drive the next version, a release PR bumps
  `pyproject.toml` + `CHANGELOG.md`, and merging it creates the tag and GitHub
  Release, which triggers `.github/workflows/release.yml` to build and publish
  to PyPI. `bump-minor-pre-major: true` keeps breaking changes inside `0.x`
  (minor bump) instead of jumping to `1.0.0`; reaching `1.0.0` is an explicit
  decision (`release-as`).
- Registry: **internal index until `1.0.0`**, then PyPI (MIT license supports
  public distribution; a `blenx` org namespace on PyPI keeps the name).
- Python support: `>=3.11`; CI matrix `3.11`, `3.12`, `3.13`.

## Integrating `apps/api` (Phase 2 mechanics)

Recommended: convert to a **uv workspace** rather than an editable path pin.

- `[tool.workspace] members = ["libs/blenx-auth"]` in the root `pyproject.toml`.
- Root adds `blenx-auth` as a dependency via
  `[tool.uv.sources] blenx-auth = { workspace = true }`.
- One unified lockfile/venv; `apps/api` imports `blenx_auth.*` directly.

Steps (owned by IMPROVEMENTS 9):

1. Add the workspace dependency.
2. Override the lib's settings + session seams with the app's `Settings` and
   session factory (`app/main.py`).
3. Delete `apps/api/app/auth/*` and `apps/api/app/email/` once parity is shown.
4. Keep the Alembic migrations untouched — the lib maps the *same* table names,
   so no migration is needed for adoption.

## Rollback

- Keep the `apps/api/app/auth` copy until Phase 3 is green. Reverting Phase 2 =
  `git revert` + re-point the import, no data or schema impact (identical
  tables).

## Explicitly out of scope

- No daily/canary releases; releases are gated by the suites above.
- Release versions, tags, and changelog entries are automated via release-please
  (see "Build & publish mechanics"); the *decision to release* is the human
  merging of the release PR. Publishing to a registry remains gated on the CI
  suites.
- No vendoring into consumers; path/workspace or registry dependency only.
