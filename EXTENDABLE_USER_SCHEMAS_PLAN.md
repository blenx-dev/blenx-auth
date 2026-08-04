# Implementation Plan: Extensible User Schemas & Custom Fields in `blenx-auth`

This document details the architectural plan to allow consumers of `blenx-auth` to extend base user models and schemas with custom fields, enabling custom serialization and validation rules (similar to `fastapi-users`).

---

## 💡 Architectural Overview & Comparison with `fastapi-users`

In `fastapi-users`, custom fields and schema extensibility rely on two pillars:
1. **Pydantic Inheritance Hierarchy**: Consumers extend base schemas (`BaseUser`, `BaseUserCreate`, `BaseUserUpdate`) to add custom fields (e.g. `first_name`, `organization_id`).
2. **Router & Service Parametrization**: Router factories and backend services accept consumer-provided schema types for validation (request payloads) and serialization (`response_model`).

In `blenx-auth`, we follow the same pattern:
- **Schemas**: Provide base Pydantic models (`BaseUserRead`, `BaseRegisterRequest`, `BaseUserUpdate`) in `blenx_auth.core.schemas`.
- **DTOs / Services**: Update `NewUser` and service layer methods (`auth_service.register(...)`) to accept `extra_data` or payload dictionaries so custom fields pass cleanly from HTTP validation to DB repositories.
- **Router Factory**: Update `make_auth_router` (and router configs) to take `user_read_schema`, `user_create_schema`, and `user_update_schema` parameters, allowing FastAPI endpoints to validate and serialize custom payloads seamlessly.

---

## 🛠️ Step-by-Step Implementation Plan

### Phase 1: Base Schema Hierarchy (`blenx_auth.core.schemas`)
- Provide extendable base Pydantic classes:
  - `BaseUserRead` (with `model_config = ConfigDict(from_attributes=True)`)
  - `BaseRegisterRequest`
  - `BaseUserUpdate` (optional for profile updates)
- Retain backwards-compatible default models (`UserRead`, `RegisterRequest`).

```python
# blenx_auth/core/schemas.py
class BaseUserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    email: EmailStr
    is_active: bool
    is_superuser: bool
    is_verified: bool

class UserRead(BaseUserRead):
    """Default UserRead schema if consumer does not provide custom fields."""
    pass

class BaseRegisterRequest(BaseModel):
    email: EmailStr
    password: str

class RegisterRequest(BaseRegisterRequest):
    """Default Register payload schema."""
    pass
```

---

### Phase 2: DTO & Service Layer Flexibility (`blenx_auth.core.dto` & `services`)
- Update `NewUser` DTO to accept custom dictionary data or keyword parameters:
  ```python
  @dataclass(slots=True, frozen=True)
  class NewUser:
      email: str
      hashed_password: str
      is_verified: bool = False
      is_superuser: bool = False
      extra_data: dict[str, Any] = field(default_factory=dict)
  ```
- Update `AuthenticationService.register(...)` to forward unhandled/extra schema fields to `UserRepository.create(...)`.

---

### Phase 3: Router Parameterization in FastAPI (`blenx_auth.fastapi`)
- Update `AuthRouterConfig` and `make_auth_router` to accept schema overrides:
  - `user_read_schema: type[BaseModel] = UserRead`
  - `user_create_schema: type[BaseModel] = RegisterRequest`
- Set `response_model=user_read_schema` on endpoints (`POST /register`, `GET /me`).
- Use `user_create_schema` for request payload validation in endpoint handlers.

---

### Phase 4: Storage Adapters (SQLAlchemy / Beanie)
- Ensure ORM models (`SQLAlchemyBaseUserTable` / `Beanie` documents) can be inherited or extended by consumer applications.
- Update `UserRepository.create(...)` in storage adapters to unpack `extra_data` onto the DB model instance.

---

### Phase 5: Verification & End-to-End Tests
- Create `tests/test_custom_user_schema.py`.
- Define custom schemas in test:
  ```python
  class CustomUserRead(BaseUserRead):
      nickname: str
      avatar_url: str | None = None

  class CustomUserCreate(BaseRegisterRequest):
      nickname: str
  ```
- Wire up `make_auth_router(..., user_read_schema=CustomUserRead, user_create_schema=CustomUserCreate)`.
- Assert HTTP request validation works (422 on invalid payload) and responses serialize the custom fields (`nickname`).

---

### Phase 6: Documentation & Usage Guide
- Add a new section in `docs/` or `README.md` titled **Extending User Schemas & Custom Fields** with complete code snippets.
