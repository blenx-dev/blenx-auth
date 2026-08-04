# Examples

For detailed implementation examples, please refer to the `examples/` directory in the root of this repository.

## Available Examples

1. **`standalone.py`**: Demonstrates how to wire up the core services using in-memory fakes (no database, no web framework).
2. **`sqlalchemy_example.py`**: Demonstrates the use of SQLAlchemy repositories for persistence.
3. **`beanie_example.py`**: Demonstrates the use of Beanie (MongoDB) repositories for persistence.

## How to run examples

```bash
# For standalone
python examples/standalone.py

# For SQLAlchemy
pip install -e ".[sqlalchemy]"
python examples/sqlalchemy_example.py

# For Beanie
pip install -e ".[beanie]"
python examples/beanie_example.py
```
