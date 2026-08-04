# blenx-auth Plugin Extensibility — Implementation Plan

Target: local coding agent, executed task-by-task, in order. Each task has a
fixed scope, exact code/signatures, and an acceptance check. Do not proceed to
task N+1 until task N's acceptance check passes. Do not deviate from locked
signatures — they were chosen to keep later tasks unambiguous.

---

## 0. Locked decisions (do not re-derive, do not ask — implement as stated)

1. `AuthHooks` fields are `tuple[Callable, ...]`, not `Optional[Callable]`.
   Composing two hook sources is always plain tuple concatenation.
2. All hooks except `transform_login_result` are "call all, in order,
   ignore return value" (fire-and-forget or raise-to-reject).
3. `transform_login_result` is the one exception: chained, each hook receives
   the previous hook's output, and the chain **stops early** the moment any
   hook returns a `LoginChallenge` instead of `LoginSuccess`.
4. Plugin composition order = topological sort of `AuthPlugin.depends_on`
   via `graphlib.TopologicalSorter`. Missing dependency or cycle = hard
   startup error, not a warning.
5. Field name collisions between any two mixins (plugin/plugin,
   plugin/consumer) are a hard startup error. There is no MRO-based
   "first one wins" fallback anywhere in this system.
6. The only sanctioned way to resolve a collision is the explicit
   `overrides: dict[str, type]` param on the composition root, keyed by
   the *mixin class's* `__name__`.
7. `email` and `password` must never appear as fields on any
   create-mixin/update-mixin (plugin or consumer). This is enforced by
   `check_no_field_collisions`, not by convention.
8. PATCH semantics always use `model_dump(exclude_unset=True)` — never
   plain `model_dump()` — in the update path.
9. Login response is a discriminated union (`LoginSuccess | LoginChallenge`
   on a `kind` literal field), not a bare token string, from this point
   forward, even for consumers with no 2FA plugin enabled (they just never
   see `LoginChallenge` in practice).
10. New file tree additions live under `core/plugins/`, `fastapi/class_builder_*.py`,
    and `plugins/<plugin_name>/`, exactly as laid out in Task 0.1.

If at any point implementing a task requires contradicting one of these
10 points, stop and flag it — do not silently resolve the contradiction.

---

## Task 0.1 — Create directory scaffold

Create these empty (or `__init__.py`-only) files/dirs if they don't exist:

```
core/plugins/__init__.py
core/plugins/hooks.py
core/plugins/collisions.py
core/contracts.py                      # extend if exists, else create
fastapi/class_builder_pydantic.py
fastapi/class_builder_sqla.py
plugins/__init__.py
plugins/two_factor/__init__.py
plugins/two_factor/mixins.py
plugins/two_factor/service.py
plugins/two_factor/router.py
plugins/two_factor/schemas.py
tests/plugins/test_hooks.py
tests/plugins/test_collisions.py
tests/plugins/test_plugin_registry.py
tests/fastapi/test_class_builder_sqla.py
tests/fastapi/test_class_builder_pydantic.py
tests/fastapi/test_contracts.py
tests/fastapi/test_composition.py
tests/plugins/test_two_factor_e2e.py
```

**Acceptance:** `find . -name "*.py" -newer <marker>` shows all paths above exist.

---

## Task 1 — `core/plugins/hooks.py`

### 1.1 Implement

```python
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Union

HookFn = Callable[..., Awaitable[None]]
ValidatorFn = Callable[[str, Any], Awaitable[None]]

# Forward refs resolved once LoginSuccess/LoginChallenge exist (Task 8).
# Until then, type as Any to avoid circular import; tighten in Task 8.
TransformFn = Callable[[Any, Any], Awaitable[Any]]


@dataclass(frozen=True, slots=True)
class AuthHooks:
    on_after_register: tuple[HookFn, ...] = ()
    on_after_login: tuple[HookFn, ...] = ()
    on_after_update: tuple[HookFn, ...] = ()
    validate_password: tuple[ValidatorFn, ...] = ()
    transform_login_result: tuple[TransformFn, ...] = ()


def merge_hooks(base: AuthHooks, other: AuthHooks) -> AuthHooks:
    return AuthHooks(
        on_after_register=base.on_after_register + other.on_after_register,
        on_after_login=base.on_after_login + other.on_after_login,
        on_after_update=base.on_after_update + other.on_after_update,
        validate_password=base.validate_password + other.validate_password,
        transform_login_result=base.transform_login_result + other.transform_login_result,
    )


async def run_side_effects(hooks: tuple[HookFn, ...], *args: Any) -> None:
    for hook in hooks:
        await hook(*args)


async def run_validators(hooks: tuple[ValidatorFn, ...], *args: Any) -> None:
    for hook in hooks:
        await hook(*args)


async def run_transform_chain(hooks: tuple[TransformFn, ...], user: Any, initial: Any) -> Any:
    """
    Runs hooks in order. Each receives (user, current_result) and returns
    the next result. Stops early if a hook returns an object whose `kind`
    attribute equals "challenge" (duck-typed here to avoid circular import
    with the login schemas module — see Task 8 for the concrete types).
    """
    current = initial
    for hook in hooks:
        current = await hook(user, current)
        if getattr(current, "kind", None) == "challenge":
            return current
    return current
```

### 1.2 Tests — `tests/plugins/test_hooks.py`

Write tests for:
- `merge_hooks` concatenates tuples in order (base first, then other) for
  every field — assert on a hook with 2 base + 3 other = 5 in correct order.
- `run_side_effects` calls every hook exactly once, in order (use a list +
  `.append` side effect to assert order).
- `run_validators` calls every validator even if none raise; if one raises,
  propagates immediately without calling the rest (assert via a mock that's
  never called).
- `run_transform_chain`: 3 hooks, none return `kind == "challenge"` → all 3
  called, final result returned.
- `run_transform_chain`: 3 hooks, hook #2 returns an object with
  `kind == "challenge"` → hook #3 is never called, hook #2's result returned.

**Acceptance:** `pytest tests/plugins/test_hooks.py -v` — all pass, 100% line
coverage on `hooks.py` (`pytest --cov=core.plugins.hooks --cov-report=term-missing`).

---

## Task 2 — `core/plugins/collisions.py`

### 2.1 Implement

```python
from typing import Any

RESERVED_UPDATE_FIELDS = frozenset({"email", "password"})


class FieldCollisionError(Exception):
    def __init__(self, kind: str, field: str, owner_a: str, owner_b: str):
        self.kind = kind
        self.field = field
        self.owner_a = owner_a
        self.owner_b = owner_b
        super().__init__(
            f"[{kind}] field '{field}' is declared by both "
            f"'{owner_a}' and '{owner_b}' — resolve via the "
            f"`overrides` param or remove the duplicate declaration."
        )


class ReservedFieldError(Exception):
    def __init__(self, kind: str, field: str, owner: str):
        self.kind = kind
        self.field = field
        self.owner = owner
        super().__init__(
            f"[{kind}] '{owner}' declares reserved field '{field}'. "
            f"email/password must not appear on create or update mixins; "
            f"use the dedicated auth/email-change/password-reset flows."
        )


def _declared_field_names(mixin: type) -> set[str]:
    model_fields = getattr(mixin, "model_fields", None)
    if model_fields is not None:
        return set(model_fields.keys())
    return set(getattr(mixin, "__annotations__", {}).keys())


def check_no_field_collisions(*mixins: type, kind: str) -> None:
    owners: dict[str, str] = {}
    for mixin in mixins:
        for name in _declared_field_names(mixin):
            if kind in ("create", "update") and name in RESERVED_UPDATE_FIELDS:
                raise ReservedFieldError(kind, name, mixin.__name__)
            if name in owners and owners[name] != mixin.__name__:
                raise FieldCollisionError(kind, name, owners[name], mixin.__name__)
            owners[name] = mixin.__name__
```

### 2.2 Tests — `tests/plugins/test_collisions.py`

- Two mixins, disjoint fields, `kind="table"` → no exception.
- Two mixins, one shared field name, `kind="table"` → `FieldCollisionError`
  raised; assert `.field`, `.owner_a`, `.owner_b` are correct (order matters:
  `owner_a` = the mixin declared first in the call args).
- Same mixin class instance passed twice (edge case: a plugin's own mixin
  compared against itself) → must NOT raise (guard clause
  `owners[name] != mixin.__name__` handles this — write the test to prove it).
- A create-mixin declaring `password` → `ReservedFieldError`.
- An update-mixin declaring `email` → `ReservedFieldError`.
- A **table** mixin (`kind="table"`) declaring `email` → must NOT raise
  (reserved-field check only applies to create/update, not table/read).

**Acceptance:** `pytest tests/plugins/test_collisions.py -v` all pass, 100%
coverage on `collisions.py`.

---

## Task 3 — `core/plugins/__init__.py`

### 3.1 Implement

```python
from dataclasses import dataclass
from graphlib import TopologicalSorter, CycleError
from typing import Any, Callable, Sequence

from core.plugins.hooks import AuthHooks


class PluginDependencyError(Exception):
    def __init__(self, name: str, missing: list[str]):
        self.name = name
        self.missing = missing
        super().__init__(f"plugin '{name}' depends on missing plugin(s): {missing}")


class PluginCycleError(Exception):
    def __init__(self, cycle_members: list[str]):
        self.cycle_members = cycle_members
        super().__init__(f"circular plugin dependency detected among: {cycle_members}")


@dataclass(frozen=True, slots=True)
class AuthPlugin:
    name: str
    table_mixin: type | None = None
    read_mixin: type | None = None
    create_mixin: type | None = None
    update_mixin: type | None = None
    hooks: AuthHooks = AuthHooks()
    router_factory: Callable[..., Any] | None = None
    related_models: tuple[type, ...] = ()
    depends_on: tuple[str, ...] = ()


def resolve_plugin_order(plugins: Sequence[AuthPlugin]) -> list[AuthPlugin]:
    by_name = {p.name: p for p in plugins}

    for p in plugins:
        missing = [d for d in p.depends_on if d not in by_name]
        if missing:
            raise PluginDependencyError(p.name, missing)

    graph = {p.name: set(p.depends_on) for p in plugins}
    try:
        order = list(TopologicalSorter(graph).static_order())
    except CycleError as e:
        cycle_members = list(e.args[1]) if len(e.args) > 1 else []
        raise PluginCycleError(cycle_members) from e

    return [by_name[name] for name in order]
```

Note: `AuthPlugin(hooks=AuthHooks())` as a dataclass default requires
`AuthHooks` itself to be frozen/hashable-safe as a default value — it is,
since it's a frozen dataclass of tuples. No `field(default_factory=...)`
needed, but if your Python/dataclasses version complains about mutable
defaults, switch to `field(default_factory=AuthHooks)` — test will catch this.

### 3.2 Tests — `tests/plugins/test_plugin_registry.py`

- 3 plugins, linear dependency chain (`c` depends on `b`, `b` depends on `a`)
  → `resolve_plugin_order` returns `[a, b, c]`.
- Plugin depends on a name not in the list → `PluginDependencyError`,
  assert `.missing == ["that_name"]`.
- Two plugins depending on each other → `PluginCycleError` raised.
- Plugins with no `depends_on` at all, given in arbitrary input order →
  order is stable/deterministic (assert twice with same input gives same
  output — `TopologicalSorter` is deterministic for a given insertion order,
  confirm this holds).
- Diamond dependency (`d` depends on `b` and `c`; both `b` and `c` depend on
  `a`) → `a` appears before both `b` and `c`, both appear before `d`.

**Acceptance:** `pytest tests/plugins/test_plugin_registry.py -v` all pass.

---

## Task 4 — Class builders

### 4.1 `fastapi/class_builder_pydantic.py`

```python
from typing import Sequence
from pydantic import BaseModel, create_model
from core.plugins.collisions import check_no_field_collisions


def build_pydantic_model(
    name: str,
    base: type[BaseModel],
    mixins: Sequence[type[BaseModel]],
    kind: str,
) -> type[BaseModel]:
    check_no_field_collisions(*mixins, kind=kind)
    return create_model(name, __base__=(base, *mixins))
```

### 4.2 `fastapi/class_builder_sqla.py`

```python
from typing import Sequence
from core.plugins.collisions import check_no_field_collisions


def build_sqla_model(
    tablename: str,
    auth_base: type,
    core_mixin: type,
    mixins: Sequence[type],
) -> type:
    check_no_field_collisions(*mixins, kind="table")
    bases = (auth_base, core_mixin, *mixins)
    return type("User", bases, {"__tablename__": tablename})
```

### 4.3 Tests — `tests/fastapi/test_class_builder_pydantic.py`

- Base has field `id: str`; one mixin adds `nickname: str`; result model has
  both fields in `model_fields`.
- Two mixins with colliding field name → `FieldCollisionError` propagates
  unchanged (do not catch/wrap it here).
- Zero mixins → result model == base's fields only, and instantiates fine.

### 4.4 Tests — `tests/fastapi/test_class_builder_sqla.py`

**Must use a real SQLite in-memory engine — do not just assert on
`__table__.columns`, actually create the schema:**

```python
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase

def test_build_sqla_model_creates_real_table():
    class AuthBase(DeclarativeBase):
        pass

    class CoreMixin:
        id: Mapped[int] = mapped_column(primary_key=True)

    class PluginMixin:
        is_2fa_enabled: Mapped[bool] = mapped_column(default=False)

    User = build_sqla_model("user", AuthBase, CoreMixin, [PluginMixin])

    engine = create_engine("sqlite:///:memory:")
    AuthBase.metadata.create_all(engine)   # must not raise

    assert "is_2fa_enabled" in User.__table__.columns.keys()
    assert "id" in User.__table__.columns.keys()
```

- Same test pattern but with two plugin mixins that collide on a column
  name → assert `FieldCollisionError` raised BEFORE `create_all` is reached
  (i.e., raised by `build_sqla_model` itself, not by SQLAlchemy at
  `create_all` time — this proves your check runs first).
- Test that the dynamically built class supports a round-trip insert/query
  via a `Session` (not just DDL) — insert a row, query it back, assert the
  plugin-mixin field value survives.

**Acceptance:** all tests in both files pass; the SQLA test specifically
must exercise `create_all()` and one insert/query round trip, not just
static attribute inspection — this is the highest-risk part of the whole
plan and a passing static assertion without a real engine round trip is not
sufficient sign-off.

---

## Task 5 — `core/contracts.py`

### 5.1 Implement (extend existing if a version already exists; else create)

```python
from typing import Any


class ContractMismatchError(Exception):
    def __init__(self, schema_label: str, missing_fields: set[str]):
        self.schema_label = schema_label
        self.missing_fields = missing_fields
        super().__init__(
            f"{schema_label} declares field(s) {sorted(missing_fields)} "
            f"not present as column(s) on the User model."
        )


def run_contract_check(User: type, UserRead: type, UserCreate: type, UserUpdate: type) -> None:
    model_columns = set(User.__table__.columns.keys())

    checks = (
        (UserRead, "UserRead", set()),
        (UserCreate, "UserCreate", {"password"}),
        (UserUpdate, "UserUpdate", {"password", "email"}),
    )

    errors: list[ContractMismatchError] = []
    for schema, label, excluded in checks:
        fields = set(schema.model_fields.keys()) - excluded
        missing = fields - model_columns
        if missing:
            errors.append(ContractMismatchError(label, missing))

    if errors:
        combined = "\n".join(str(e) for e in errors)
        raise ContractMismatchError("multiple schemas", set()) from None if False else \
            ExceptionGroup("contract check failed", errors) if hasattr(__builtins__, "ExceptionGroup") else \
            RuntimeError(combined)
```

**Note on the exception-aggregation branch above:** if the project's Python
version is 3.11+, replace the final `if/else` chain with a clean
`raise ExceptionGroup("contract check failed", errors)`. If targeting <3.11,
just `raise RuntimeError(combined)`. **Pick one, do not ship the fallback
chain as-is** — it's written defensively here because the Python version
wasn't confirmed; check `python --version` / `pyproject.toml` first and
hardcode the correct branch.

### 5.2 Tests — `tests/fastapi/test_contracts.py`

- All three schemas' fields subset of model columns → no exception.
- `UserRead` has an extra field not on the model → exception raised,
  mentions `UserRead` and the field name.
- `UserCreate` has `password` field but model has no `password` column →
  must NOT raise (excluded set works).
- `UserUpdate` has `email` field → must NOT raise (excluded), but if
  `UserUpdate` has some *other* field not on the model → must raise.
- Multiple schemas simultaneously broken → single raised error/group
  contains info about all of them, not just the first (verify whichever
  branch you picked from 5.1 surfaces all mismatches, not just one).

**Acceptance:** tests pass; confirm manually that error message printed to
console (`pytest -v -s`) is legible enough to hand to a consumer without
further explanation — this is a startup-failure message a third-party
integrator will read, treat clarity as a real requirement, not a nice-to-have.

---

## Task 6 — Composition root: `fastapi/composition.py`

### 6.1 Implement

Locate the existing `SQLAlchemyAuth` class. Replace its `__init__` with:

```python
from typing import Sequence
from core.plugins import AuthPlugin, resolve_plugin_order
from core.plugins.hooks import AuthHooks, merge_hooks
from core.contracts import run_contract_check
from fastapi.class_builder_sqla import build_sqla_model
from fastapi.class_builder_pydantic import build_pydantic_model


class SQLAlchemyAuth(Generic[UserT]):
    def __init__(
        self,
        *,
        session_factory,
        token_service,
        email_sender,
        plugins: Sequence[AuthPlugin] = (),
        consumer_table_mixin: type | None = None,
        consumer_read_mixin: type | None = None,
        consumer_create_mixin: type | None = None,
        consumer_update_mixin: type | None = None,
        consumer_admin_update_mixin: type | None = None,
        overrides: dict[str, type] | None = None,
        base_hooks: AuthHooks = AuthHooks(),
        tablename: str = "user",
    ):
        self._plugins = resolve_plugin_order(plugins)
        overrides = overrides or {}

        def collect(attr: str, consumer_mixin: type | None) -> list[type]:
            mixins = [
                getattr(p, attr) for p in self._plugins if getattr(p, attr) is not None
            ]
            if consumer_mixin is not None:
                mixins.append(consumer_mixin)
            return [overrides.get(m.__name__, m) for m in mixins]

        self.User = build_sqla_model(
            tablename, AuthBase, BaseUserTableMixin,
            collect("table_mixin", consumer_table_mixin),
        )
        self.UserRead = build_pydantic_model(
            "UserRead", BaseUserRead,
            collect("read_mixin", consumer_read_mixin), kind="read",
        )
        self.UserCreate = build_pydantic_model(
            "UserCreate", BaseUserCreate,
            collect("create_mixin", consumer_create_mixin), kind="create",
        )
        self.UserUpdate = build_pydantic_model(
            "UserUpdate", BaseUserUpdate,
            collect("update_mixin", consumer_update_mixin), kind="update",
        )
        self.UserAdminUpdate = build_pydantic_model(
            "UserAdminUpdate", BaseUserAdminUpdate,
            collect("update_mixin", consumer_admin_update_mixin), kind="update",
        )

        run_contract_check(self.User, self.UserRead, self.UserCreate, self.UserUpdate)

        self.hooks = base_hooks
        for p in self._plugins:
            self.hooks = merge_hooks(self.hooks, p.hooks)

        self._session_factory = session_factory
        self._token_service = token_service
        self._email_sender = email_sender

        self._build_services()
        self._build_routers()

    def _build_services(self) -> None:
        # Wire AuthenticationService / UserService / etc. using self.User,
        # self.hooks, self._session_factory, self._token_service,
        # self._email_sender. Preserve existing service construction logic
        # from the current composition.py — only the User/hooks inputs change,
        # not the service classes themselves.
        raise NotImplementedError("port existing service wiring here")

    def _build_routers(self) -> None:
        self.routers: list = [
            make_auth_router(self._auth_router_config()),
            make_users_router(self._users_router_config()),
        ]
        for p in self._plugins:
            if p.router_factory is not None:
                self.routers.append(p.router_factory(self._plugin_router_config(p)))

    def _auth_router_config(self):
        raise NotImplementedError("port from existing composition.py")

    def _users_router_config(self):
        raise NotImplementedError("port from existing composition.py")

    def _plugin_router_config(self, plugin: AuthPlugin):
        raise NotImplementedError(
            "define what a plugin router factory needs — at minimum: "
            "session_factory, token_service, self.User, self.UserRead"
        )
```

**Agent instruction:** the three `NotImplementedError` methods must be filled
in using the *existing* pre-plugin `composition.py` logic — do not invent new
service-wiring behavior. Diff against the current file, extract the service
construction and router-config-building code verbatim into these methods,
substituting `self.User`/`self.hooks` wherever the old code referenced a
hardcoded `User` import or empty hooks.

Repeat the identical pattern for `BeanieAuth` in the same file — same
constructor shape, same `collect()` helper, differs only in
`build_sqla_model` → an equivalent Beanie document builder (if one doesn't
exist yet, write `fastapi/class_builder_beanie.py` mirroring
`class_builder_sqla.py`'s shape: `type(name, (base_document, *mixins), {"Settings": ...})`).

### 6.2 Tests — `tests/fastapi/test_composition.py`

- Instantiate `SQLAlchemyAuth` with zero plugins, zero consumer mixins →
  succeeds, `self.User`/`self.UserRead`/etc. exist and pass contract check
  (this is the backward-compatibility smoke test — must not regress
  existing non-plugin usage).
- Instantiate with one fake plugin (a minimal `AuthPlugin` with just a
  `table_mixin` and `read_mixin`) → `self.User` has the plugin's column,
  `self.UserRead` has the plugin's field.
- Instantiate with a plugin AND a consumer mixin both declaring the same
  field name, no `overrides` given → raises `FieldCollisionError` at
  construction time (not later, not at first request).
- Same as above, but WITH `overrides={"PluginMixinClassName": ConsumerMixin}`
  → succeeds, and the resulting field's type/definition comes from the
  override, not the original plugin mixin (assert on the actual field
  annotation, not just absence of an exception).
- Two plugins, `plugin_b.depends_on = ("plugin_a",)`, passed in reverse
  order `[plugin_b, plugin_a]` → construction still succeeds (proves
  `resolve_plugin_order` is actually being called, order doesn't matter
  to the caller).
- `self.routers` contains a router contributed by a plugin's
  `router_factory` (assert route path membership, e.g. `/2fa/verify` is in
  `[r.path for r in plugin_router.routes]`).

**Acceptance:** all pass. This task's tests are the integration proof for
everything built in Tasks 1–5 — do not skip any of the six cases above.

---

## Task 7 — User update service + routes

### 7.1 `core/services/user_service.py` — add method

```python
async def update(self, *, user_id: "UUID", payload: "BaseModel") -> "UserT":
    user = await self._repo.get(user_id)
    if user is None:
        raise UserNotFoundError(user_id)

    updates = payload.model_dump(exclude_unset=True)
    for name, value in updates.items():
        if name not in self._model.__table__.columns:
            raise UserModelMappingError(name)
        setattr(user, name, value)

    await run_side_effects(self._hooks.on_after_update, user, updates)
    await self._repo.save(user)
    return user
```

`UserService` must already (or now) accept `hooks: AuthHooks` and
`model: type` in its constructor — if it doesn't currently, add both as
required kwargs and update its call site in `composition.py`'s
`_build_services`.

### 7.2 `fastapi/routers/users.py` — add routes

```python
@router.patch("/me", response_model=user_read_schema)
async def update_me(
    data: user_update_schema,
    user=Depends(current_active_user),
    service=Depends(get_user_service),
):
    return await service.update(user_id=user.id, payload=data)


@router.patch("/{user_id}", response_model=user_read_schema)
async def admin_update_user(
    user_id: "UUID",
    data: user_admin_update_schema,
    _=Depends(current_superuser),
    service=Depends(get_user_service),
):
    return await service.update(user_id=user_id, payload=data)
```

`user_update_schema` / `user_admin_update_schema` are parametrized into the
router factory the same way `user_read_schema` already is — extend
`AuthRouterConfig` (or equivalent) with these two fields, sourced from
`SQLAlchemyAuth.UserUpdate` / `.UserAdminUpdate`.

### 7.3 Tests — `tests/fastapi/test_user_update.py` (add to scaffold if missing)

- `PATCH /users/me` with `{"nickname": "bob"}` when user also has an
  untouched `phone` field with existing value → after update, `phone` is
  unchanged (proves `exclude_unset=True` is actually wired through, not
  just present in source).
- `PATCH /users/me` with a body containing `is_active` (not in
  `UserUpdate` schema) → 422, since it's not a declared field and
  `extra="forbid"` is set on `BaseUserUpdate`.
- `PATCH /users/{id}` as non-superuser → 403 (or 401, depending on existing
  auth dependency behavior — match whatever `current_superuser` already
  does elsewhere in the codebase).
- `PATCH /users/{id}` as superuser with `{"is_active": false}` → succeeds,
  field updated.
- Update payload referencing a nonexistent `user_id` → `UserNotFoundError`
  surfaces as whatever HTTP status the existing exception-handler mapping
  uses for that error (check existing error-handling middleware, don't
  invent a new status code here).

**Acceptance:** all pass, no regression in existing `test_users.py`.

---

## Task 8 — Login response union + transform-chain wiring

### 8.1 New schemas — locate wherever existing auth response schemas live
(likely `fastapi/schemas.py` or `core/schemas.py`) and add:

```python
from typing import Literal, Annotated, Union
from pydantic import BaseModel, Field


class LoginSuccess(BaseModel):
    kind: Literal["token"] = "token"
    access_token: str


class LoginChallenge(BaseModel):
    kind: Literal["challenge"] = "challenge"
    flow: str
    challenge_token: str


LoginResponse = Annotated[Union[LoginSuccess, LoginChallenge], Field(discriminator="kind")]
```

### 8.2 `AuthenticationService.login()` — modify return path

Find the existing `login` method. At the point it currently constructs
and returns a token response, change to:

```python
async def login(self, email: str, password: str) -> "LoginSuccess | LoginChallenge":
    user = await self._authenticate(email, password)  # existing logic, unchanged
    token = self._token_service.encode({"sub": str(user.id)})
    result: LoginSuccess = LoginSuccess(access_token=token)

    result = await run_transform_chain(self._hooks.transform_login_result, user, result)

    await run_side_effects(self._hooks.on_after_login, user, {})
    return result
```

Note the ordering: `transform_login_result` runs BEFORE `on_after_login`
fires. This is intentional — `on_after_login` side effects (e.g. "log that
a login happened") should reflect the final outcome, but do not themselves
need to know whether a challenge was issued; keep them decoupled. If a
future plugin needs `on_after_login` to only fire on *actual* successful
completion (not on a challenge being issued), that plugin should hook
`transform_login_result` instead of `on_after_login` — do not special-case
this in `AuthenticationService`.

### 8.3 Router change

Wherever `POST /auth/login` currently declares `response_model=...`, change
to `response_model=LoginResponse`.

### 8.4 Tests — `tests/core/test_login_transform.py`

- No hooks registered → `login()` returns a plain `LoginSuccess`.
- One `transform_login_result` hook that always returns its input unchanged
  → `login()` still returns `LoginSuccess`.
- One `transform_login_result` hook that returns `LoginChallenge(...)`
  regardless of input → `login()` returns that `LoginChallenge`, and
  `on_after_login` hooks (assert via a spy) still fired exactly once.
- Two `transform_login_result` hooks, first returns `LoginChallenge`,
  second is a spy → spy is never called (proves short-circuit).

**Acceptance:** all pass.

---

## Task 9 — Reference plugin: `plugins/two_factor/`

### 9.1 `mixins.py`

```python
from datetime import date
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import String
from pydantic import BaseModel


class TwoFactorTableMixin:
    is_2fa_enabled: Mapped[bool] = mapped_column(default=False)
    two_factor_type: Mapped[str | None] = mapped_column(String(20), default=None)


class TwoFactorReadMixin(BaseModel):
    is_2fa_enabled: bool
    two_factor_type: str | None = None


class TwoFactorCreateMixin(BaseModel):
    is_2fa_enabled: bool = False
```

### 9.2 `schemas.py`

```python
from pydantic import BaseModel, Field
from typing import Annotated


class TwoFactorVerifyRequest(BaseModel):
    challenge_token: str
    code: Annotated[str, Field(min_length=6, max_length=6)]
```

### 9.3 `service.py`

```python
from core.schemas import LoginSuccess, LoginChallenge  # adjust import path to Task 8 location


class TwoFactorService:
    def __init__(self, *, otp_repo, token_service):
        self._otp_repo = otp_repo
        self._token_service = token_service

    async def transform_login(self, user, result: LoginSuccess) -> "LoginSuccess | LoginChallenge":
        if not getattr(user, "is_2fa_enabled", False):
            return result
        challenge_token = self._token_service.encode(
            {"scope": "2fa_pending", "sub": str(user.id)}, ttl_seconds=300,
        )
        return LoginChallenge(
            flow=user.two_factor_type or "otp",
            challenge_token=challenge_token,
        )

    async def verify(self, *, challenge_token: str, code: str) -> LoginSuccess:
        claims = self._token_service.decode(challenge_token)
        if claims.get("scope") != "2fa_pending":
            raise InvalidChallengeError()
        user_id = claims["sub"]
        await self._otp_repo.verify_code(user_id=user_id, code=code)  # raises on bad code
        access_token = self._token_service.encode({"sub": user_id})
        return LoginSuccess(access_token=access_token)
```

Adjust `token_service.encode`/`.decode` signature to match whatever the
existing `TokenService` actually exposes — check the current implementation
before assuming `ttl_seconds` is a supported kwarg; if it isn't, add it
there first (small, additive change) rather than working around it here.

### 9.4 `router.py`

```python
from fastapi import APIRouter, Depends
from plugins.two_factor.schemas import TwoFactorVerifyRequest
from plugins.two_factor.service import TwoFactorService
from core.schemas import LoginSuccess


def make_two_factor_router(get_service) -> "APIRouter":
    router = APIRouter(prefix="/2fa", tags=["2fa"])

    @router.post("/verify", response_model=LoginSuccess)
    async def verify(
        data: TwoFactorVerifyRequest,
        service: TwoFactorService = Depends(get_service),
    ):
        return await service.verify(challenge_token=data.challenge_token, code=data.code)

    return router
```

`make_two_factor_router` signature must match whatever
`AuthPlugin.router_factory` is actually called with in
`composition.py._build_routers` (Task 6) — reconcile the two signatures
now; likely `router_factory(config)` where `config` exposes a
`get_service` dependency-provider callable, matching the pattern of
`make_auth_router`/`make_users_router`.

### 9.5 `__init__.py`

```python
from core.plugins import AuthPlugin
from core.plugins.hooks import AuthHooks
from plugins.two_factor.mixins import (
    TwoFactorTableMixin, TwoFactorReadMixin, TwoFactorCreateMixin,
)
from plugins.two_factor.router import make_two_factor_router


def make_two_factor_plugin(*, transform_login) -> AuthPlugin:
    return AuthPlugin(
        name="two_factor",
        table_mixin=TwoFactorTableMixin,
        read_mixin=TwoFactorReadMixin,
        create_mixin=TwoFactorCreateMixin,
        hooks=AuthHooks(transform_login_result=(transform_login,)),
        router_factory=make_two_factor_router,
    )
```

`transform_login` is passed in by the consumer's composition call (it needs
a bound `TwoFactorService` instance), e.g.:

```python
two_factor_service = TwoFactorService(otp_repo=..., token_service=...)
auth = SQLAlchemyAuth(
    ...,
    plugins=[make_two_factor_plugin(transform_login=two_factor_service.transform_login)],
)
```

### 9.6 Tests — `tests/plugins/test_two_factor_e2e.py`

Full stack test, real SQLite engine, real FastAPI `TestClient`:

1. Compose `SQLAlchemyAuth` with the two_factor plugin enabled.
2. Register a user with `is_2fa_enabled=True`.
3. `POST /auth/login` with correct credentials → response `kind == "challenge"`,
   has a `challenge_token`.
4. `POST /2fa/verify` with that token and correct code → response
   `kind == "token"`, has `access_token`.
5. `POST /2fa/verify` with wrong code → error response (matches existing
   error-handling convention).
6. Register a second user with `is_2fa_enabled=False`, login → response
   `kind == "token"` directly, no challenge step.
7. Confirm `User.__table__.columns` includes `is_2fa_enabled`,
   `two_factor_type` and the app boots without contract-check errors.

**Acceptance:** all pass. This test is the final proof that Tasks 1–9
compose correctly end to end — a failure here means an earlier task's
acceptance check was insufficient, go back and add the missing case rather
than patching around it in this file.

---

## Execution order summary

```
Task 0.1 → Task 1 → Task 2 → Task 3 → Task 4 → Task 5 → Task 6 → Task 7 → Task 8 → Task 9
```

Strictly sequential — every task after 0.1 imports from at least one prior
task's module. Run the full test suite (`pytest`) after each task, not just
the new file's tests, to catch regressions in existing (non-plugin) auth
flows immediately rather than at the end.

## Definition of done

- `pytest` — full suite green, including all pre-existing tests.
- `pytest --cov=core --cov=fastapi --cov=plugins --cov-report=term-missing`
  — no untested branches in any file created/modified above.
- A consumer using zero plugins and zero consumer mixins still boots and
  passes exactly as before this work started (Task 6.2's first test case
  is the guard for this — do not relax it).
- `plugins/two_factor` works end-to-end per Task 9.6 with no manual class
  composition by the consumer — enabling it is exactly
  `plugins=[make_two_factor_plugin(...)]` in the `SQLAlchemyAuth(...)` call.