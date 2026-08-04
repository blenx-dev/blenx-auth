---
title: "Installation"
---

# Installation

Install blenx-auth from PyPI or your private registry.

## Core Install

```bash
pip install blenx-auth
```

## Optional Extras

| Extra | Description |
|-------|-------------|
| `fastapi` | FastAPI integration layer + SQLAlchemy backend |
| `sqlalchemy` | SQLAlchemy backend only |
| `beanie` | Beanie (MongoDB) adapter |
| `redis` | Redis token strategy + rate limiter |
| `oauth` | Non-Google OAuth providers (GitHub, Apple) |
| `smtp` | Real email sender (ReSMTP/SES/etc.) |

```bash
# Full stack with FastAPI + SQLAlchemy + Redis
pip install blenx-auth[fastapi,redis]
```

## Requirements

- Python >= 3.11
- No framework required for core usage

## Development

```bash
git clone https://github.com/kupras06/styleos.git
cd styleos/libs/blenx-auth
pip install -e ".[fastapi,beanie,redis]"
```
