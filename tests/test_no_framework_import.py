"""Assert that importing ``blenx_auth`` and its core subpackages does not
require ``fastapi``, ``fastapi_users``, or ``starlette``.

This is a light-weight guard: we parse the AST of each core module and check
that none of the forbidden top-level packages are imported. The optional
``blenx_auth.fastapi`` subpackage is explicitly excluded because it is the
integration boundary and *is* allowed to import those packages, as are runtime
plugins under ``blenx_auth.plugins`` (they ship routers bound to FastAPI).
"""

from __future__ import annotations

import ast
import pathlib

import pytest

CORE_PACKAGE = pathlib.Path(__file__).parent.parent / "src" / "blenx_auth"
FORBIDDEN = {"fastapi", "fastapi_users", "starlette"}
ALLOWED_PACKAGES = {"fastapi", "plugins"}


@pytest.mark.parametrize("py_path", sorted(CORE_PACKAGE.rglob("*.py")))
def test_core_module_has_no_framework_imports(py_path: pathlib.Path) -> None:
    rel = py_path.relative_to(CORE_PACKAGE)
    # The fastapi integration subpackage and runtime plugins are explicitly
    # allowed to import FastAPI and Starlette.
    if rel.parts[0] in ALLOWED_PACKAGES:
        return

    tree = ast.parse(py_path.read_text())
    offending: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                if top in FORBIDDEN:
                    offending.append(f"import {alias.name}")
        elif isinstance(node, ast.ImportFrom) and node.module:
            top = node.module.split(".")[0]
            if top in FORBIDDEN:
                offending.append(f"from {node.module} import ...")

    assert not offending, f"{rel} imports forbidden framework packages:\n" + "\n".join(offending)
