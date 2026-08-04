---
title: "Examples"
description: Implementation examples for blenx-auth using in-memory, SQLAlchemy, and Beanie backends.
---

# Examples

The examples below show how to wire up `blenx-auth` against different backends. Each
example is a self-contained program you can run to exercise the full auth lifecycle.

## Available Examples

1. **[Standalone example](/examples/standalone/)** — Wires the core services to in-memory
   fakes (no database, no web framework). Demonstrates that `blenx_auth` works without
   FastAPI installed.
2. **[SQLAlchemy example](/examples/sqlalchemy/)** — Wires the SQLAlchemy repositories to a
   real database session.
3. **[Beanie example](/examples/beanie/)** — Wires the Beanie (MongoDB) repositories behind
   the same services, demonstrating storage-agnosticism.
4. **[FastAPI example](/examples/fastapi/)** — A complete FastAPI app wired to the
   `SQLAlchemyAuth` composition root, including protected endpoints and the error handler.

## How to run examples

The source for each example lives alongside this documentation and can also be copied into
your own application and run directly.

```bash
# Standalone (no extra dependencies)
python examples/standalone.py

# SQLAlchemy
pip install -e ".[sqlalchemy]"
python examples/sqlalchemy_example.py

# Beanie (MongoDB)
pip install -e ".[beanie]"
python examples/beanie_example.py

# FastAPI (in-memory SQLite; swap the engine for Postgres in production)
pip install -e ".[fastapi]"
python examples/fastapi_example.py
```
