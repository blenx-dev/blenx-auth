# Redis Token Strategy

Planned feature (F5c) - Server-side, revocable tokens using Redis.

## Overview

- `RedisTokenStrategy` for server-side access tokens
- Implements revocable token storage via Redis sets
- Functions as a drop-in replacement for JWT strategy in `UserManager`
- Optional dependency (`[redis]` extra)

## Implementation Status

Not yet implemented. See `FEATURES.md` F5 for roadmap.

## Design Notes

- Uses Redis SET to track valid token identifiers
- Access tokens include a jti (JWT ID) for lookup
- On token validation, check Redis for presence
- Revocation: remove jti from Redis
- Optional automatic cleanup of expired entries via Redis TTL
