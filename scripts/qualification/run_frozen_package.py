"""Command-line entry point for authoring-free frozen package execution.

The command accepts optional JSON fixtures for setup and one Garak generation.
It never imports the consumer authoring package or creates an authoring client.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from frozen_runtime import execute_frozen_package


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package", type=Path)
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--setup-fixture", type=Path)
    parser.add_argument("--generation-fixture", type=Path)
    args = parser.parse_args(argv)
    setup_values = _load_json(args.setup_fixture, default={})
    generation = _load_json(args.generation_fixture, default=None)

    def setup_dispatch(operation: str, arguments: dict[str, Any]) -> dict[str, Any]:
        del arguments
        value = (
            setup_values.get(operation, setup_values)
            if isinstance(setup_values, dict)
            else {}
        )
        if not isinstance(value, dict):
            raise ValueError(f"setup fixture for {operation} must be an object")
        return value

    def generation_dispatch(**kwargs: Any) -> dict[str, Any]:
        del kwargs
        if not isinstance(generation, dict):
            raise ValueError("a generation fixture is required for execution")
        return generation

    result = execute_frozen_package(
        args.package,
        setup_dispatch=setup_dispatch,
        generation_dispatch=generation_dispatch,
        receipt_path=args.receipt,
    )
    if args.receipt is None:
        print(json.dumps(result.receipt, sort_keys=True, indent=2))
    return 0 if result.status.value in {"completed", "incomplete"} else 1


def _load_json(path: Path | None, *, default: Any) -> Any:
    if path is None:
        return default
    return json.loads(path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    raise SystemExit(main())
