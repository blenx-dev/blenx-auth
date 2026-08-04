---
title: "Testing"
---

# Testing

blenx-auth ships with a comprehensive test harness designed to simplify unit and integration testing. All components are framework- and storage-agnostic, making tests fast and isolated.

## 1. In-Memory Fakes for Unit Tests

### Core Fakes

```python
from unittest.mock import AsyncMock
from datetime import datetime
from blenx_auth.core.dto import NewUser, NewOAuthLink
from blenx_auth.core.ports import (
    UserRepository,
    RefreshTokenRepository,
    OAuthAccountRepository,
)

# Minimal, fast fakes for unit-testing services
class FakeUserRepo(UserRepository):
    def __init__(self):
        self.store = {}
        self._next_id = 1

    async def get_by_email(self, email: str):
        return self.store.get(email)

    async def get_by_id(self, user_id):
        return next((u for u in self.store.values() if u.id == user_id), None)

    async def create(self, data: NewUser):
        user = type("User", (), {
            "id": self._next_id,
            "email": data.email,
            "hashed_password": data.hashed_password,
            "is_verified": data.is_verified,
            "is_superuser": data.is_superuser,
            "is_active": True,
            "created_at": datetime.utcnow(),
        })()
        self.store[data.email] = user
        self._next_id += 1
        return user

    async def save(self, user):
        self.store[user.email] = user
```

### Integration Tests

For integration tests against real databases, see `examples/standalone.py`, `examples/sqlalchemy_example.py`, and `examples/beanie_example.py`.

## 2. Custom Backend Testing

When implementing a custom storage backend, reuse the same pattern with your classes.

Example: Custom in-memory store with extended fields

```python
class UserWithExt:
    """Your domain model with extra fields."""
    def __init__(self, id, email, hashed_password, **extra):
        self.id = id
        self.email = email
        self.hashed_password = hashed_password
        # Arbitrary user extensions
        for k, v in (extra or {}).items():
            setattr(self, k, v)
        self.created_at = datetime.utcnow()

class CustomUserRepository:
    def __init__(self):
        self.users = {}

    async def get_by_email(self, email):
        return self.users.get(email)

    async def create(self, data):
        # Merge extra fields into user
        extra = getattr(data, 'extra_fields', {})
        user = UserWithExt(
            id=uuid.uuid4(),
            email=data.email,
            hashed_password=data.hashed_password,
            **extra
        )
        self.users[user.email] = user
        return user

    # ... other methods
```

## 3. Service-Level Testing

Services depend only on ports, so tests never need a real database or email sender:

```python
async def test_register_with_custom_field():
    user_repo = FakeUserRepo()
    auth_svc = AuthenticationService(
        users=user_repo,
        refresh_tokens=FakeRefreshTokenRepo(),
        oauth_accounts=FakeOAuthRepo(),
        tokens=FakeTokenService(),
        email_sender=AsyncMock(),
        settings=test_settings,
    )

    # Pass extra field via extended registration flow
    user = await auth_svc.register(
        email="user@example.com",
        password="StrongPass123",
        extra={"department": "Engineering", "employee_id": 12345}
    )

    assert hasattr(user, "department")
    assert user.department == "Engineering"
```

## 4. FastAPI TestClient Integration

FastAPI integration tests exercise the whole stack without network I/O:

```python
from fastapi.testclient import TestClient

def test_create_user_with_extra_field():
    # Your test app setup
    app = FastAPI()
    # ... register routes with custom backend
    client = TestClient(app)

    response = client.post(
        "/users/",
        json={
            "email": "user@example.com",
            "password": "Secure123!",
            "department": "Marketing",  # Your custom field
        }
    )
    assert response.status_code == 201
    data = response.json()
    assert data["department"] == "Marketing"
```

## Key Testing Principles

1. **Isolation**: Test services with fake repositories – no database needed
2. **Behavior Focus**: Tests assert domain behavior, not implementation details
3. **Adapter Parity**: Same test suite works for in-memory, real PostgreSQL, and Beanie/MongoDB
4. **Extension Support**: Tests work with custom fields added via extension points
5. **Speed**: Unit tests run in milliseconds; integration tests target real backends but remain fast

Run the test suite:
```bash
pytest tests/
```
This executes:
- Core service unit tests
- Storage adapter parity tests (SQLite/Mongo in-memory)
- Full FastAPI integration tests (in-memory)