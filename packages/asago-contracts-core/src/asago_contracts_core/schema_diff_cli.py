"""Command-line entry point for the schema-diff check.

The package imports ``schema_diff``, so running ``python -m
asago_contracts_core.schema_diff`` warns about executing a module the package
already imported. This module is not part of the package's imports, so the
documented command runs cleanly.
"""

from __future__ import annotations

from .schema_diff import main

if __name__ == "__main__":
    raise SystemExit(main())
