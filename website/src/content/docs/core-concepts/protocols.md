---
title: "Core Protocols"
---

# Core Protocols

blenx-auth defines several protocols (interfaces) that form the seams between layers. These protocols must remain stable — everything else is implementation detail.

## Repository Protocols

Defined in `blenx_auth.core.ports` (and re-exported from `blenx_auth.core.types`).

### `UserRepository[IdT]`

```python
class UserRepository(Protocol[IdT]):
    async def get_by_id(self, user_id: IdT) -> User | None: ...
    async def get_by_email(self, email: str) -> User | None: ...
    async def get_by_oauth_account(self, provider: str, account_id: str) -> User | None: ...
    async def create(self, user: User) -> User: ...
    async def save(self, user: User) -> User: ...
```

- **CRUD only** — no policy logic (lockout, rotation, verification)
- Returns domain objects (not ORM models)
- `create` must surface concurrent uniqueness errors for email collisions

### `RefreshTokenRepository[IdT]`

```python
class RefreshTokenRepository(Protocol[IdT]):
    async def get(self, token_hash: str) -> RefreshToken | None: ...
    async def create(self, token: RefreshToken) -> RefreshToken: ...
    async def revoke(self, token_hash: str) -> None: ...
    async def revoke_all_for_user(self, user_id: IdT) -> None: ...
```

- Handles refresh token lifecycle
- Token hashing is done by the service, not the repository

### `OAuthAccountRepository[IdT]`

```python
class OAuthAccountRepository(Protocol[IdT]):
    async def get_by_provider_and_account_id(self, provider: str, account_id: str) -> OAuthAccount | None: ...
    async def create(self, account: OAuthAccount) -> OAuthAccount: ...
    async def get_by_user_id(self, user_id: IdT) -> list[OAuthAccount]: ...
```

## TokenStrategy Protocol

Defined in `blenx_auth.core.strategy` (FEATURES F2).

```python
class TokenStrategy(Protocol):
    def create_access_token(self, subject: str) -> str: ...
    def create_refresh_token(self, subject: str) -> str: ...
    def create_email_verification_token(self, subject: str) -> str: ...
    def create_password_reset_token(self, subject: str) -> str: ...

    def decode_access_token(self, token: str) -> str: ...
    def decode_refresh_token(self, token: str) -> str: ...
    def verify_email_verification_token(self, token: str) -> str: ...
    def verify_password_reset_token(self, token: str) -> str: ...

    def create_oauth_state(self) -> str: ...
    def verify_oauth_state(self, token: str) -> None: ...

    def access_expires_delta(self) -> timedelta: ...
    def refresh_expires_delta(self) -> timedelta: ...
```

- **Subjects are strings** — user id as `str`, so UUID (SQLAlchemy) and ULID (Beanie) share one strategy surface
- Raises domain errors: `InvalidTokenError`, `ExpiredTokenError`
- `TokenService` (JWT implementation) already satisfies this protocol structurally

## EmailSender Protocol

```python
class EmailSender(Protocol):
    async def send(self, message: EmailMessage) -> None: ...
```

- `NullEmailSender` is the shipped default (logs to stdout)
- Real implementations (SMTP, SES, etc.) satisfy this protocol

## AuthSettings Protocol

A structural `Protocol`, not a concrete class — any object with the required fields satisfies it.

```python
class AuthSettings(Protocol):
    secret_key: str
    access_token_expires_minutes: int
    refresh_token_expires_days: int
    email_verification_token_expires_hours: int
    password_reset_token_expires_hours: int
    max_failed_attempts: int
    lockout_duration_minutes: int
    google_client_id: str
    google_client_secret: SecretStr
    ...
```

- Host app supplies its own settings object (Pydantic Settings, dataclass, etc.)
- Core ships a default dataclass for tests/examples
