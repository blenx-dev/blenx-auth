# Right Abstractions

Design notes on the seams that make `blenx-auth` reusable across frameworks,
storage backends, and deployment shapes. These are the contracts that must
survive refactors; everything else is implementation detail.

## 1. Layering

```
L1 core/         pure Python — protocols, policy, manager. No framework, no storage.
L2 adapters/     storage backends + DB-session strategies. Implement L1 protocols.
L3 integrations/ framework wiring (FastAPI). Thin mapping of L1/L2 to HTTP.
```

Rules:

- Dependencies point **downward only**: core imports nothing from adapters or
  integrations; adapters import core types; integrations import everything.
- Core must import with no `fastapi`/`fastapi_users`/`starlette` installed
  (enforced by a CI import guard, F1).
- Adapters never carry policy; integrations never carry policy; policy lives
  in core services only.

## 2. The protocol seams (load-bearing contracts)

### Repositories — CRUD only, no policy

`UserRepository`, `RefreshTokenRepository`, `OAuthAccountRepository`
(`core/types.py`). Three design rules:

- Methods persist facts and return rows; they never decide (no lockout logic,
  no token semantics). `login`, lockout, rotation, single-use all live in the
  services.
- Rows are mutated in place by services and re-saved (`UserRepository.save`)
  so policy edits (lockout counters, verification flags) are plain attribute
  changes.
- `create` must surface a concurrent-uniqueness error for email collision
  (`IntegrityError`), which the service translates to the domain error.

### TokenStrategy — the token seam

Defined in FEATURES F2. Key property: **subjects are strings** (user id as
`str`), so UUID (SQLAlchemy) and ULID (Beanie) share one strategy surface. A
strategy either returns a token string or raises the domain token errors
(`InvalidTokenError`/`ExpiredTokenError`) — never a framework error.

### EmailSender — the mail seam

`EmailSender.send(EmailMessage)` (`core/email.py`), with `NullEmailSender` as
the shipped default. Consumers swap in a real mailer without touching policy.

### AuthSettings — the configuration seam

A structural `Protocol`, not a concrete settings class: any object with the
required fields satisfies it. The host supplies its own settings object; the
core ships a default dataclass for tests/examples. The `get_settings` FastAPI
dependency stays **out of core** (it belongs to the FastAPI integration).

### OAuthProvider — the provider seam

`name`, `authorization_url`, `exchange_code`, `userinfo`, `base_scopes`
(F6). `AuthenticationService.oauth_login` is already provider-agnostic
(`service.py`): it takes provider/account_id/email/tokens and never touches
provider specifics.

## 3. ID genericity (`IdT`)

- Core protocols and dataclasses are parameterized over the id type, default
  `uuid.UUID` (fastapi-users does the same via `UUIDIDMixin`).
- `TokenStrategy` keeps subjects as strings so the strategy layer is id-agnostic.
- Beanie keys documents on ULID (`ulid-py`, already a root dependency —
  currently unused in `apps/api`, so ULID support here matches planned product
  direction). The manager/core must never call methods that assume UUID.

## 4. Strategy vs Transport

- **Strategy** (core): creates and validates tokens. `JWTTokenStrategy` is the
  default; Redis and DB-session strategies are alternatives.
- **Transport** (integrations): how the credential travels on the wire —
  Bearer header vs HTTP-only cookie. Transports are framework-side because
  they read the request/response; they contain no token logic.
- This mirrors fastapi-users and keeps "which token format" independent from
  "where the token lives" (header/cookie/DB/Redis).

## 5. The manager as composition root

`UserManager` composes services + a `TokenStrategy` + repositories +
`EmailSender` + settings into the object consumers actually hold. It is thin:

- It delegates every operation to the services (register, login, refresh,
  logout, verify, reset, oauth).
- It owns the **extension callbacks** (`on_after_register`, `on_after_login`,
  ...) as async hooks — the seams consumers override for custom behavior.
- It must not re-implement policy. If a rule lives in a service, the manager
  forwards; it never duplicates the decision.

## 6. Policy placement (single home for each rule)

| Rule | Home |
| ---- | ---- |
| Lockout thresholds, rotation, single-use semantics | `AuthenticationService` |
| Password policy, hashing | `core/password.py` |
| Token lifetime claims | `TokenStrategy` |
| Email verification / password reset token single-use | `EmailVerificationService` / `PasswordResetService` |
| Persistence mechanics | repositories |
| HTTP rendering of errors | integration error handler |

## 7. Errors: domain exceptions with HTTP hints

`AuthError` carries `status_code` and optional `headers`
(`core/exceptions.py`). This is a deliberate, pragmatic coupling:

- **Kept because** status codes (`401`, `403`, `409`, `429`) are stable domain
  facts for an auth library, and a single integration handler renders the whole
  hierarchy in one place (`auth_error_handler`).
- **Rejected alternative:** a separate HTTP mapper in the integration layer.
  It would duplicate the `status_code`/`headers` knowledge, drift, and cost
  nothing in practice.
- **Boundary rule:** errors carry *presentation hints*, never framework
  objects (no `HTTPException`, no `Response`). Raising framework exceptions
  inside core is forbidden.

## 8. Logging

Core must use the **standard library `logging`**, not `loguru`. The current
`email.py` imports `loguru` (`email.py:18`) — that forces a logging library on
every consumer. Fix in the core-purity pass (IMPROVEMENTS task 3): library code
logs via `logging.getLogger(__name__)`; host apps keep their own logging setup.

## 9. Transactionality

Repositories commit per call today (`create`/`save`/`revoke*` each commit).
Multi-step operations such as `oauth_login` (create user + link account) span
two commits — an acceptable default for an auth library with no internal
cross-entity invariants.

- If a later feature needs atomic multi-write, add an explicit **UnitOfWork**
  seam at the adapter boundary rather than widening the repository protocols —
  the protocols stay simple, and a transactional adapter wraps them.

## 10. Rate limiting seam

Core defines the hook (`_enforce_rate_limit`, currently a deliberate no-op)
and the error (`RateLimitExceededError` with `Retry-After`). Implementations
(Redis leaky bucket, F8) plug in at the same seam. The in-process lockout guard
is the always-on default; an external limiter is additive and must not change
login semantics when absent.

## 11. What must never enter core

- HTTP / framework imports (`fastapi`, `starlette`, ASGI/WSGI types).
- Storage engines (SQLAlchemy session types, Motor/Beanie document types in
  signatures).
- Concrete mailers, concrete rate limiters, concrete providers.
- Logging *implementations* (see §8).
- Module-level singletons bound at import time (the current `db/session.py`
  engine-from-env is the counterexample to fix).

If a type forces one of these onto core, it belongs one layer up.
