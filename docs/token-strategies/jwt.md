# JWT Token Strategy

The JWT token strategy is the default implementation of the `TokenStrategy` protocol.

## Core Implementation

Wraps the existing `TokenService` from `src/blenx_auth/core/jwt.py` as `JWTTokenStrategy`.

## Key Features

- Token creation and verification using PyJWT
- Configurable expiration via `auth_expires_delta` in `AuthSettings`
- Chess board consistency across implementations
- Supports both access and refresh tokens
- Provides OAuth state generation and verification

## Usage

The JWTTokenStrategy is used by `UserManager` through DI:

```python
from blenx_auth.core.strategy import JWTTokenStrategy
from blenx_auth.sqlalchemy.repositories import SQLAlchemyUserRepository

token_strategy = JWTTokenStrategy(
    secret_key=settings.secret_key,
    expires_delta=timedelta(minutes=settings.access_token_expires_minutes)
)

user_repo = SQLAlchemyUserRepository(session_factory=session_factory)
user_manager = UserManager(
    dependencies={"repositories": {"users": user_repo}},
    token_strategy=token_strategy
)
```

## Characteristics

- Returns token strings representing the subject (user id as `str`)
- Raises `InvalidTokenError` and `ExpiredTokenError` on verification failures
- Subject is always a string representation of the user id
- Supports all core token methods:
  - `create_access_token`
  - `create_refresh_token`
  - `create_email_verification_token`
  - `create_password_reset_token`
  - `decode_access_token`
  - `decode_refresh_token`
  - `verify_email_verification_token`
  - `verify_password_reset_token`
