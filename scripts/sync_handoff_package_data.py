#!/usr/bin/env python3
"""Copy the handoff contract documents into the ``asago_handoff`` package.

``asago_handoff`` reads the composed schema and the ownership rules from its own
data directory, so a reader needs no checkout. The producer's
``data/contracts/scenario-handoff/`` stays the authority; this script copies it,
and ``packages/asago-handoff/tests/test_contract_data.py`` fails when the copies
differ.

Usage:
    python3 scripts/sync_handoff_package_data.py [--check]

``--check`` reports drift and exits 1 without writing.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "data" / "contracts" / "scenario-handoff"
TARGET = ROOT / "packages" / "asago-handoff" / "src" / "asago_handoff" / "data"
DOCUMENTS = (
    Path("ownership-rules.json"),
    Path("handoff-v5") / "schema.json",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="report drift, write nothing")
    args = parser.parse_args(argv)

    drifted: list[Path] = []
    for relative in DOCUMENTS:
        source = SOURCE / relative
        target = TARGET / relative
        content = source.read_bytes()
        if target.is_file() and target.read_bytes() == content:
            continue
        drifted.append(relative)
        if not args.check:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)

    for relative in drifted:
        action = "differs" if args.check else "copied"
        print(f"{action}: {relative}")
    return 1 if args.check and drifted else 0


if __name__ == "__main__":
    sys.exit(main())
