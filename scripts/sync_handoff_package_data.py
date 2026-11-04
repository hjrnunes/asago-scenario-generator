#!/usr/bin/env python3
"""Copy the contract documents the shared core owns into its package.

``asago_contracts_core`` reads the scenario-handoff contract from its own data
directory, so a reader needs no checkout, and its tests read the whole contract
tree and the condition vectors from the package too, so they run after
extraction. The producer's ``data/contracts/`` stays the authority; this script
copies it byte for byte, removes what the authority no longer holds, and
``tests/test_contracts_core_data.py`` fails when the copies differ.

The installed copy keeps the authority's layout, so ``<data>/scenario-handoff``
is the contract directory and ``<data>`` is the spec root the reader loads.

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

# The directories the package reads, and the same trees in its test data.
TREES = (
    (CONTRACTS / "scenario-handoff", DATA / "scenario-handoff"),
    (CONTRACTS / "scenario-handoff", TEST_DATA / "scenario-handoff"),
    (
        CONTRACTS / "tool-call-condition" / "tool-call-condition-v2" / "vectors",
        TEST_DATA / "tool-call-condition" / "tool-call-condition-v2" / "vectors",
    ),
)


# Paths an earlier layout installed; the whole-contract copy replaces them.
RETIRED = (
    DATA / "ownership-rules.json",
    DATA / "handoff-v5",
    TEST_DATA / "scenario-handoff" / "handoff-v5",
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


def _sync_tree(source: Path, target: Path) -> None:
    """Write the source's files into the target and drop what it no longer holds."""

    source_files = _files(source)
    for relative in sorted(source_files):
        destination = target / relative
        if destination.is_file() and destination.read_bytes() == (
            source / relative
        ).read_bytes():
            continue
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / relative, destination)
    if not target.is_dir():
        return
    for relative in sorted(_files(target) - source_files):
        (target / relative).unlink()
    for directory in sorted(
        (path for path in target.rglob("*") if path.is_dir()),
        key=lambda path: len(path.parts),
        reverse=True,
    ):
        if not any(directory.iterdir()):
            directory.rmdir()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="report drift, write nothing")
    args = parser.parse_args(argv)

    drifted: list[Path] = []
    for source, target in TREES:
        drifted.extend(target / relative for relative in _tree_drift(source, target))
        if not args.check:
            _sync_tree(source, target)
    for retired in RETIRED:
        if not retired.exists():
            continue
        drifted.append(retired)
        if not args.check:
            if retired.is_dir():
                shutil.rmtree(retired)
            else:
                retired.unlink()

    for target in drifted:
        print(f"differs: {target.relative_to(ROOT)}")
    return 1 if args.check and drifted else 0


if __name__ == "__main__":
    sys.exit(main())
