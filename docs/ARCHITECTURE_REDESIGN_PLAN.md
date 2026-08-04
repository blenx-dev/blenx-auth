# blenx-auth Architecture Redesign — Implementation Plan

Target: local coding agent, executed task-by-task, in order. Each task has a
fixed scope, exact signatures, and an acceptance check. Do not proceed to
task N+1 until task N's acceptance check passes.

This plan supersedes the composition layer of `docs/PLUGINS_ARCH.md`. The core
services (`core/services/*`), ports (`core/ports.py`), schemas (`core/schemas.py`),
domain exceptions, and the HTTP routers are preserved and only adapted where the
new composition requires it. The *composition / model-building / plugin* layers
are rebuilt per the attached architecture spec.

---

## 0. Locked decisions (approved by the user — do not re-derive)

1. **Repo provenance.** `SqlaStorageContext` / `BeanieStorageContext` build the
   User model **and** the User / RefreshToken / OAuthAccount repositories.
   `build_auth` registers those repositories into the `ServiceRegistry`.
2. **Auth dependency surface.** The `Auth` object keeps the existing FastAPI
   dependency surface (`get_authentication_service`, `get_verification_service`,
   `get_password_reset_service`, `get_user_service`, `get_current_user` /
   `_active` / `_verified` / `_superuser`, `CurrentUser` / `CurrentActiveUser` /
   `CurrentVerifiedUser` / `CurrentSuperUser`). Each closure pulls its singleton
   from the `ServiceRegistry`.
3. **One metadata build.** The SQLAlchemy metadata builder registers the core
   User columns + plugin/consumer User columns **and** plugin-contributed extra
   `Table` objects in one build. A single `metadata` drives both Alembic
   autogenerate and `create_all`.
4. **Two-factor plugin is self-contained.** `make_two_factor_plugin()` takes no
   `otp_repo` argument. It discovers the backend via
   `CoreDeps.storage_context`, owns per-backend OTP persistence (a separate
   table for SQLAlchemy, a separate document for Beanie — never fields on the
   composed `User`), owns enrollment, and ships a stdlib-only TOTP verifier so
   no host library is required. Tests that pass `FakeOtpRepo` are rewritten.
5. **Passkeys: model structure only.** Beanie `User` gains an embedded
   `passkeys` field; SQLAlchemy gains symmetric passkey columns on the user
   table. No WebAuthn logic, no endpoints, no service.
6. **Tests: evolve.** The existing 178 tests are adapted to the new API, not
   deleted. Services / routers / ports keep their coverage. New suites are added
   for the spec's comprehensive list (below).
7. **No SQLAlchemy mixin inheritance for schema generation.** The core User
   columns are a tuple of plain `Column` objects; the table builder composes a
   single `Table`; the ORM `User` is mapped directly to it. Duplicate column
   names raise `FieldCollisionError` before anything is mapped. Beanie keeps
   inheritance-based composition (base document + mixins + cached class).
8. **Fail-fast everywhere.** Missing plugin dependency, plugin cycle, field
   collision, missing/wrong-typed registry entry, and contract mismatch are all
   startup errors — never warnings, never silent reordering, never MRO
   shadowing. `ServiceRegistry.get` never returns `None`.
9. **Strong typing.** `Any` is allowed only where a circular import would be
   required (plugin `router_factory` return type in framework-free `core/`,
   dynamic-model casts). Everything else is fully typed.
10. **Router order.** Core routers first (`/auth`, `/users`), then plugin
    routers in plugin topological order. Routers obtain services exclusively via
    the registry; they never construct services directly.

---

## 1. Target architecture

```
                  build_auth(storage_context, settings, email_sender, plugins, ...)
                                     │
         ┌───────────────────────────┼───────────────────────────────┐
         │                           │                               │
  [model + schema composition]  [ServiceRegistry build]        [routers]
         │                           │                               │
  SqlaStorageContext ──────►  core repos + services            /auth /users
  or BeanieStorageContext      (singletons)                    + plugin routers
         │                    CoreDeps.in                           │
  compose User model          (User, hooks, tokens,                │
  + extra tables/docs         email, storage_context)              │
                                                                    │
  plugins (topologically ordered) ──► repository_factory → service_factory → hooks_factory
```

- `SQLAlchemyAuth` / `BeanieAuth` become **thin wrappers**: they construct the
  matching storage context and delegate to the single backend-independent
  `build_auth`. All service/router wiring lives in `build_auth`.
- Storage contexts own **two** responsibilities: model building and repository
  building. No services, routers, hooks, or schemas live in a storage context.
- Plugins declare contributions; `build_auth` constructs the service graph and
  the `ServiceRegistry`.

---

## 2. New modules and signatures

### 2.1 `src/blenx_auth/core/registry.py` (new)

```python
class ServiceNotFoundError(LookupError): ...
    # name of the missing service
class ServiceTypeError(TypeError): ...
    # name + expected type + actual type

class ServiceRegistry:
    def __init__(self) -> None: ...
    def set(self, name: str, instance: object) -> None: ...
    def get(self, name: str, expected_type: type[T]) -> T: ...
        # raises ServiceNotFoundError if absent (never returns None)
        # raises ServiceTypeError if instance is not an instance of expected_type
    def has(self, name: str) -> bool: ...
    def __contains__(self, name: str) -> bool: ...
```

- `set` on an existing name raises `ValueError` (double-registration is a
  startup bug, not a silent overwrite).

### 2.2 `src/blenx_auth/core/storage.py` (new — framework-free)

```python
class StorageContext(Protocol):
    backend: Literal["sqlalchemy", "beanie"]
    def build_user_repository(self) -> UserRepository[Any]: ...
    def build_refresh_token_repository(self) -> RefreshTokenRepository[Any]: ...
    def build_oauth_account_repository(self) -> OAuthAccountRepository[Any]: ...
    # Plugin persistence hooks (see 2.7):
    def new_session(self) -> Any: ...                 # sqlalchemy only; raises on beanie
    def metadata(self) -> Any: ...                    # MetaData | None
    def all_documents(self) -> tuple[type, ...]: ...  # beanie: core + plugin docs
```

### 2.3 `src/blenx_auth/core/deps.py` (new — framework-free)

```python
@dataclass(frozen=True, slots=True)
class CoreDeps:
    User: type                 # composed user model
    hooks: AuthHooks           # merged base + static plugin hooks
    token_service: TokenService
    email_sender: EmailSender
    storage_context: StorageContext
```

Every plugin `repository_factory` / `service_factory` / `hooks_factory` /
`router_factory` receives exactly `(deps: CoreDeps, registry: ServiceRegistry)`.

### 2.4 `src/blenx_auth/core/plugins/__init__.py` (extend)

`AuthPlugin` keeps `name`, `read_mixin`, `create_mixin`, `update_mixin`,
`hooks`, `depends_on`; `table_mixin` / `related_models` are **replaced**:

```python
@dataclass(frozen=True, slots=True)
class AuthPlugin:
    name: str
    # schema contributions
    sqla_columns: tuple[Column, ...] = ()          # SQLAlchemy user-table columns
    sqla_tables: tuple[Table, ...] = ()            # extra SQLAlchemy tables (metadata)
    beanie_mixin: type | None = None               # Beanie User document mixin
    beanie_documents: tuple[type, ...] = ()        # extra Beanie documents (e.g. 2FA OTP)
    read_mixin: type | None = None
    create_mixin: type | None = None
    update_mixin: type | None = None
    # behavioral contributions
    hooks: AuthHooks = AuthHooks()                 # static hooks (kept for simple plugins)
    repository_factory: Callable[[CoreDeps, ServiceRegistry], object] | None = None
    service_factory: Callable[[CoreDeps, ServiceRegistry], object] | None = None
    hooks_factory: Callable[[CoreDeps, ServiceRegistry], AuthHooks] | None = None
    router_factory: Callable[..., Any] | None = None   # Any: core is FastAPI-free
    depends_on: tuple[str, ...] = ()
```

`resolve_plugin_order` (topological, missing/cycle errors) is kept unchanged.
`Column` / `Table` are imported under `TYPE_CHECKING` only (core stays
framework-free). Plugins construct `Column`/`Table` objects in their own modules.

### 2.5 `src/blenx_auth/core/contracts.py` (split validation)

Keep `ContractMismatchError`. Replace the duck-typed single check with:

```python
def validate_sqlalchemy_contract(User, UserRead, UserCreate, UserUpdate) -> None:
    # model columns from User.__table__.columns; excluded = {"password"} on
    # create, {"password", "email"} on update (as today). ExceptionGroup.

def validate_beanie_contract(User, UserRead, UserCreate, UserUpdate) -> None:
    # model fields from User.model_fields; same exclusions. ExceptionGroup.

def run_contract_check(User, UserRead, UserCreate, UserUpdate) -> None:
    # dispatch on hasattr(User, "__table__") → sqlalchemy, else beanie
```

`build_auth` calls `run_contract_check` after models + schemas are composed.

### 2.6 `src/blenx_auth/sqlalchemy/metadata.py` (new — table/metadata builder)

Replaces the mixin-inheritance path in `class_builder_sqla.py` (that module is
retired for the composition path).

```python
CORE_USER_COLUMNS: tuple[Column, ...]          # moved out of BaseUserTableMixin
#    Column("id", Uuid, primary_key=True, default=uuid.uuid4)
#    Column("email", String(320), unique=True, index=True)
#    Column("hashed_password", String(1024))
#    Column("is_active", Boolean, default=True)
#    ... every column currently on BaseUserTableMixin

def build_composed_user_table(
    *,
    metadata: MetaData,
    tablename: str,
    core_columns: tuple[Column, ...] = CORE_USER_COLUMNS,
    plugin_columns: Sequence[tuple[str, tuple[Column, ...]]],   # (owner, cols)
    consumer_columns: tuple[Column, ...] = (),
) -> Table:
    # duplicate column name → FieldCollisionError("table", name, owner_a, owner_b)
    # returns Table(tablename, metadata, *cols) — idempotent via Table(name, metadata, ...)

def register_extra_tables(*, metadata, plugin_tables) -> None:
    # for each Table t: t.to_metadata(metadata) — idempotent (skips if present)

def map_user_model(table: Table, base: type) -> type:
    # return type("User", (base,), {"__table__": table}) — the ORM model is the
    # composed Table; no relationships, no mixins.
```

Teardown semantics (last-composition-wins) preserved from today: dispose the
registry, drop prior tables, re-map `RefreshToken` / `OAuthAccount` and the
composed `User` on the shared `AuthBase` metadata. Idempotency: calling
`build_auth` twice on one registry returns a consistent remap (tested).

Passkeys (decision 5): `CORE_USER_COLUMNS` does NOT carry passkeys; passkeys are
contributed by the storage context as symmetric user-table columns
(`credential_id`, `public_key`, `counter`, etc.) so the feature is opt-in and
model-only.

### 2.7 Storage contexts

`src/blenx_auth/sqlalchemy/context.py` (new):

```python
class SqlaStorageContext:
    backend = "sqlalchemy"
    def __init__(self, *, settings, session_factory, plugins, consumer_table_columns,
                 tablename="user") -> None:
        # 1. resolve plugin order; collect plugin sqla_columns + sqla_tables
        # 2. build composed user Table on AuthBase.metadata + register extra tables
        # 3. map_user_model → self.user_model; rebuild RefreshToken/OAuthAccount
    def build_user_repository(self) -> SQLAlchemyUserRepository: ...
    def build_refresh_token_repository(self) -> SQLAlchemyRefreshTokenRepository: ...
    def build_oauth_account_repository(self) -> SQLAlchemyOAuthAccountRepository: ...
    def new_session(self) -> AsyncSession: ...    # session_factory() — repos own it
    @property
    def metadata(self) -> MetaData: ...
    @property
    def user_model(self) -> type: ...
    @property
    def refresh_model(self) -> type: ...
    @property
    def oauth_model(self) -> type: ...
```

`src/blenx_auth/beanie/context.py` (new):

```python
class BeanieStorageContext:
    backend = "beanie"
    def __init__(self, *, settings, plugins, consumer_document_mixin=None) -> None:
        # compose User document: build_beanie_model(base=BeanieUser,
        #   mixins=[plugin.beanie_mixin ...] + consumer) with cache
        # collect plugin.beanie_documents
    def build_user_repository(self) -> BeanieUserRepository: ...
    def build_refresh_token_repository(self) -> BeanieRefreshTokenRepository: ...
    def build_oauth_account_repository(self) -> BeanieOAuthAccountRepository: ...
    def all_documents(self) -> tuple[type, ...]: ...
    @property
    def user_model(self) -> type: ...
```

**Session-lifecycle decision (D1).** SQLAlchemy repositories keep their existing
session-bound CRUD implementation and constructor. The storage context creates
one session from `session_factory` per repository (sessions are lazy — no DB
connection until first query) and the repository instances are singletons
registered in the `ServiceRegistry`. Each repository's session is kept for the
root's lifetime; every mutation commits immediately (as today), so cross-repo
reads always see committed state. This is the "session lifecycle" the spec
assigns to the SQLAlchemy layer. `SQLAlchemyAuth.get_db_session` remains
available on the wrapper for host apps that need request-scoped sessions, but
the composed services no longer depend on it.

### 2.8 `src/blenx_auth/beanie/models.py` (embed OAuth + passkeys)

- `OAuthAccountEmbedded(BaseModel)` — `id: PydanticObjectId`,
  `oauth_name`, `access_token`, `expires_at`, `refresh_token`, `account_id`,
  `account_email`. Carries an `id` so `refresh_token(account_id)` still works.
- `PasskeyEmbedded(BaseModel)` — passkey credential fields (model structure
  only).
- `User` gains `oauth_accounts: list[OAuthAccountEmbedded] = []` and
  `passkeys: list[PasskeyEmbedded] = []`.
- `RefreshToken` stays a top-level document with `user_id` (no Beanie `Link`).
- The old top-level `OAuthAccount` document is removed; `BeanieOAuthAccountRepository`
  is rewritten to query the embedded array on the composed `User`
  (`find_one({"oauth_accounts.oauth_name": ..., "oauth_accounts.account_id": ...})`),
  append on `link`, and update the matched embedded account on `refresh_token`.
- `build_beanie_model` gains a class cache keyed by `(name, base, mixins)`;
  `reset_beanie_model_cache()` is exposed for tests.

### 2.9 `src/blenx_auth/fastapi/composition.py` (rewrite)

```python
@dataclass(frozen=True, slots=True)
class Auth:
    User: type
    UserRead: type
    UserCreate: type
    UserUpdate: type
    UserAdminUpdate: type
    hooks: AuthHooks
    registry: ServiceRegistry
    routers: list[APIRouter]
    metadata: Any                      # SQLAlchemy MetaData | None (beanie)

    # dependency closures (each pulls its singleton from self.registry):
    async def get_authentication_service(self) -> AuthenticationService[Any]: ...
    async def get_verification_service(self) -> EmailVerificationService[Any]: ...
    async def get_password_reset_service(self) -> PasswordResetService[Any]: ...
    async def get_user_service(self) -> UserService[Any]: ...
    # get_current_user family + Current* aliases via make_current_user_dependencies(...)

    # alias attributes for the routers (AuthProvider protocol):
    register_schema / user_read_schema / user_update_schema / user_admin_update_schema
    token_service / settings / user_model

def build_auth(
    *,
    storage_context: StorageContext,
    settings: AuthSettings,
    email_sender: EmailSender | None = None,
    parse_subject: Callable[[str], Any] | None = None,   # default uuid.UUID / PydanticObjectId by backend
    plugins: Sequence[AuthPlugin] = (),
    consumer_read_mixin: type | None = None,
    consumer_create_mixin: type | None = None,
    consumer_update_mixin: type | None = None,
    consumer_admin_update_mixin: type | None = None,
    overrides: Mapping[str, type] | None = None,
    base_hooks: AuthHooks | None = None,
) -> Auth: ...
```

`build_auth` order (fixed):
1. `resolve_plugin_order(plugins)`.
2. Compose schemas (`UserRead` / `UserCreate` / `UserUpdate` / `UserAdminUpdate`)
   via `build_pydantic_model` with read/create/update mixins; Beanie overrides
   `id` with `PydanticObjectId`.
3. `run_contract_check(user_model, ...)` (backend-dispatched).
4. Build `TokenService`, merge hooks (base + each plugin's `hooks`), construct
   `CoreDeps`.
5. Create `ServiceRegistry`; register core repos from the storage context
   (`"user_repository"`, `"refresh_token_repository"`, `"oauth_account_repository"`).
6. Per plugin (topological order): `repository_factory` → `service_factory` →
   `hooks_factory`; each runs with `(deps, registry)` and registers under
   plugin-chosen names. Missing deps surface as `ServiceNotFoundError`.
7. Build core services from the registered repos and register them:
   `"authentication"`, `"verification"`, `"password_reset"`, `"user"`.
8. `make_current_user_dependencies(auth.get_authentication_service)`.
9. Routers: `[make_auth_router(auth), make_users_router(auth), *plugin_routers]`
   where each plugin router is `plugin.router_factory(deps, registry)`.

`SQLAlchemyAuth` / `BeanieAuth` become thin wrappers that construct the storage
context and call `build_auth`, then re-export the `Auth` surface (attribute
delegation). Their constructor signatures are unchanged so host apps keep
working.

### 2.10 Two-factor plugin redesign (`src/blenx_auth/plugins/two_factor/`)

`make_two_factor_plugin()` — no arguments.

- **Stdlib TOTP** (new `totp.py`): RFC 6238 TOTP + `pyotp`-compatible
  provisioning-URI generation using `hmac`/`hashlib`/`base64` only.
- **Persistence**: plugin-owned, per backend, never on the composed `User`.
  - SQLAlchemy: `TwoFactorOtpTable` (user_id FK, secret, otp type) contributed
    via `sqla_tables`; repo queries the composed table with a session from
    `deps.storage_context.new_session()`.
  - Beanie: `TwoFactorOtpDocument` (user_id, secret) contributed via
    `beanie_documents`; repo queries it.
- **Contributions**:
  - `sqla_columns`: `is_2fa_enabled` (Boolean), `two_factor_type` (String(20)).
  - `beanie_mixin`: the same two fields.
  - `read_mixin` / `create_mixin`: `is_2fa_enabled`, `two_factor_type`.
  - `repository_factory`: builds + registers the backend OTP repo
    (`"two_factor.otp_repo"`), selected via `CoreDeps.storage_context.backend`.
  - `service_factory`: builds `TwoFactorService` from the registered OTP repo +
    `deps.token_service`; registers `"two_factor.service"`.
  - `hooks_factory`: returns `AuthHooks(transform_login_result=(svc.transform_login,))`.
  - `router_factory`: `/2fa` router with `verify` **plus** self-service
    `enable` / `disable` (enrollment owned by the plugin).
- The old `OtpRepository` protocol is internal to the plugin; the `otp_repo`
  constructor argument is gone.

---

## 3. Service graph & ordering rules

- Order is a topological sort over `depends_on` (existing `resolve_plugin_order`).
- Within one plugin: repository → service → hooks.
- Across plugins: all core repos first, then plugin repos/services/hooks in
  plugin order, then core services, then routers (core, then plugin). A plugin
  service may pull any earlier-registered service via `registry.get`.
- Every factory is a function of `(deps, registry)`; there is **no** side-channel
  wiring and no plugin can instantiate another plugin's internals.
- `registry.set` collisions, `registry.get` misses, and wrong types are startup
  errors.

---

## 4. Test plan

### 4.1 Adapt existing tests (keep coverage)

- `tests/fastapi/test_composition.py`, `tests/test_fastapi_composition.py` —
  construction + router surface against the new `Auth`/wrappers.
- `tests/fastapi/test_beanie_composition.py` — Beanie composition + cache/reset.
- `tests/fastapi/test_class_builder_sqla.py` — rewritten for the table-based
  builder (still exercises `create_all` + insert/query round-trip).
- `tests/fastapi/test_contracts.py` — split validators + dispatch.
- `tests/test_sqla_repositories_e2e.py`, `tests/test_beanie_repos_validation.py`
  — adapted to storage-context-built repos and the embedded Beanie OAuth model.
- `tests/plugins/test_two_factor_e2e.py`, `test_two_factor_service.py` —
  rewritten for the self-contained plugin (no `FakeOtpRepo`; real stdlib TOTP).
- `tests/fastapi/test_current_user.py`, `test_user_update.py`, `test_auth_service.py`,
  `tests/core/*`, `tests/plugins/test_plugin_registry.py`, `test_hooks.py`,
  `test_collisions.py` — unchanged or minimally adapted.

### 4.2 New suites (spec list)

- Registry: `set`/`get`/`has`, missing → `ServiceNotFoundError`, wrong type →
  `ServiceTypeError`, double-set → `ValueError`, singleton identity.
- Plugin factory ordering: repo before service before hooks within a plugin;
  topological order across plugins; router built last.
- Dependency failures: factory `registry.get` miss → `ServiceNotFoundError` at
  build time; missing plugin dependency / cycle (existing coverage extended).
- Collision detection in the table builder: plugin vs plugin, plugin vs
  consumer, core vs plugin.
- Metadata/model idempotency: two `build_auth` calls on one registry remap
  cleanly; extra plugin tables registered exactly once.
- SQLAlchemy CRUD through the storage context; Beanie CRUD through the context
  (embedded OAuth link/refresh).
- Contract validation: SQLAlchemy and Beanie paths each fail at startup with all
  mismatches reported together.
- Router construction: core routers first, plugin routers after; plugin router
  routes reach services through the registry.
- Full composition: no plugins, one plugin, two plugins with a dependency edge,
  consumer mixins, `overrides`.
- Two-factor e2e on **both** backends: enable → login challenge → verify →
  token; wrong code → error; disabled user skips the challenge.

---

## 5. Execution order (with acceptance checks)

1. `core/registry.py` + tests → `pytest tests/ -k registry` green.
2. `core/plugins/__init__.py` field swap + factory types; update
   `test_plugin_registry.py` → green.
3. `sqlalchemy/metadata.py` (CORE_USER_COLUMNS, table builder, mapper, extra
   tables) + rewritten `test_class_builder_sqla.py` → green (real SQLite
   round-trip).
4. `beanie/models.py` embedded OAuth/passkeys + cache/reset; adapt
   `BeanieOAuthAccountRepository`; adapt beanie repo tests → green.
5. Storage contexts (`sqlalchemy/context.py`, `beanie/context.py`) + repo wiring
   → storage-context repo tests green.
6. `core/contracts.py` split validation + `test_contracts.py` → green.
7. `composition.py` rewrite: `build_auth` + `Auth` + thin wrappers; adapt
   `test_composition.py` / `test_fastapi_composition.py` → green.
8. Two-factor plugin self-contained redesign + `totp.py` + enrollment router;
   rewrite 2FA tests → green on both backends.
9. Passkey model structure (SQLAlchemy columns + Beanie embedded field) +
   contract tests.
10. Full sweep: adapt every remaining test; add the new suites (4.2).
11. Update `examples/fastapi_example.py` + docs (`website/src/content/docs/`)
    to the new API; rebuild docs site.
12. Final gate: `pytest` (full), `ruff check src tests examples`,
    `mypy src/blenx_auth`, `pytest --cov=blenx_auth` (TOTAL ≥ 95%), commit.

---

## 6. Risks / open items (verify empirically during implementation)

- **Beanie embedded OAuth**: `get_by_provider_account` must match an element of
  the embedded array; uniqueness moves from a Mongo unique index to
  application-level. Confirm `refresh_token(account_id)` against the embedded
  `id`.
- **Beanie plugin documents**: the 2FA `TwoFactorOtpDocument` must be included in
  `init_beanie_db`'s document set; `BeanieStorageContext.all_documents()` feeds
  `beanie/bootstrap.py`.
- **SQLAlchemy singleton sessions**: long-lived per-repo sessions are lazy
  (no premature DB connection) but hold one connection pool checkout on first
  use; the composed services commit per operation so cross-repo consistency
  holds. Re-verify the full e2e suite on the in-memory SQLite engine.
- **`Table.to_metadata`** for plugin extra tables: confirm constraints/indexes
  copy over, and idempotency across repeated `build_auth`.
- **Mapper coexistence**: mapping the composed `User` via `__table__` while the
  static `User` may already own the `user` table requires the existing
  dispose-then-remap teardown; confirm the composed class has no relationship
  attributes the routers rely on.
