#!/usr/bin/env python3
"""Copy the contract documents the shared core owns into its package.

``asago_contracts_core`` reads the composed schema and the ownership rules from
its own data directory, so a reader needs no checkout, and its tests read the
handoff kit and the condition vectors from the package too, so they run after
extraction. The producer's ``data/contracts/`` stays the authority; this script
copies it, and ``tests/test_contracts_core_data.py`` fails when the copies
differ.

Usage:
    python3 scripts/sync_handoff_package_data.py [--check]

``--check`` reports drift and exits 1 without writing.
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "data" / "contracts"
PACKAGE = ROOT / "packages" / "asago-contracts-core"
DATA = PACKAGE / "src" / "asago_contracts_core" / "data"
TEST_DATA = PACKAGE / "tests" / "data"

# The documents the package reads at run time.
FILES = (
    (CONTRACTS / "scenario-handoff" / "ownership-rules.json", DATA / "ownership-rules.json"),
    (
        CONTRACTS / "scenario-handoff" / "handoff-v5" / "schema.json",
        DATA / "handoff-v5" / "schema.json",
    ),
    # The same rules in the kit layout the validator tests load.
    (
        CONTRACTS / "scenario-handoff" / "ownership-rules.json",
        TEST_DATA / "scenario-handoff" / "ownership-rules.json",
    ),
)

# The directories the package's tests read.
TREES = (
    (
        CONTRACTS / "scenario-handoff" / "handoff-v5",
        TEST_DATA / "scenario-handoff" / "handoff-v5",
    ),
    (
        CONTRACTS / "tool-call-condition" / "tool-call-condition-v2" / "vectors",
        TEST_DATA / "tool-call-condition" / "tool-call-condition-v2" / "vectors",
    ),
)


def _files(root: Path) -> set[Path]:
    return {path.relative_to(root) for path in root.rglob("*") if path.is_file()}


def _tree_drift(source: Path, target: Path) -> list[Path]:
    """Return the relative paths that differ, including stale target files."""

    source_files = _files(source)
    if not target.is_dir():
        return sorted(source_files)
    target_files = _files(target)
    drifted = source_files - target_files
    for relative in source_files & target_files:
        if (source / relative).read_bytes() != (target / relative).read_bytes():
            drifted.add(relative)
    return sorted(drifted | (target_files - source_files))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="report drift, write nothing")
    args = parser.parse_args(argv)

    drifted: list[tuple[str, Path, Path]] = []
    for source, target in FILES:
        content = source.read_bytes()
        if target.is_file() and target.read_bytes() == content:
            continue
        drifted.append(("differs", source, target))
        if not args.check:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)

    for source, target in TREES:
        for relative in _tree_drift(source, target):
            drifted.append(("differs", source / relative, target / relative))
            if not args.check:
                (target / relative).parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source / relative, target / relative)

    for action, _source, target in drifted:
        print(f"{action}: {target.relative_to(ROOT)}")
    return 1 if args.check and drifted else 0


if __name__ == "__main__":
    sys.exit(main())
