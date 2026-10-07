"""Import scanners shared by the architecture tests."""

from __future__ import annotations

import ast
from pathlib import Path


def extract_imports(file_path: Path) -> list[str]:
    """Return fully-qualified module names imported in *file_path*.

    Handles both ``import X.Y`` and ``from X.Y import ...`` forms,
    including ``TYPE_CHECKING`` guarded imports.
    """
    source = file_path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(file_path))
    imports: list[str] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.append(node.module)

    return imports
