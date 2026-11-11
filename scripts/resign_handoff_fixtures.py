#!/usr/bin/env python3
"""Sign the report fixtures' scenario handoffs under the current handoff contract.

``tests/fixtures/generate_report`` holds recorded generate outputs, and each
``scenarios/SCN-*.yaml`` is an enveloped scenario handoff. The producer's writer
round-trips every one byte for byte. When the handoff schema version changes,
this script restates each fixture's version label and its contract fact, signs
the handoff under the current digest domain, and writes it through the
producer's own writer, so no digest or envelope field is edited by hand.

Usage:
    uv run python scripts/resign_handoff_fixtures.py [--check | --write]

``--check`` (the default) lists each fixture the writer would change and exits 1
without writing. ``--write`` rewrites those fixtures.

The script covers the enveloped report fixtures only. The bare handoffs under
``tests/fixtures/condition_contradictions`` carry no envelope. Their
``content_digest`` is ``handoff_payload_digest`` over the whole document, the
condition contradiction sweep reads them raw, and this script leaves them alone.
A digest tool that frames the whole document would sign the report fixtures
wrongly, because the writer frames the payload without the envelope.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

import yaml

from asago_scenario_generator.stpa.infra.yaml_io import yaml_document
from asago_scenario_generator.stpa.scenario_prod.handoff import (
    HANDOFF_SCHEMA_VERSION,
    finalize_handoff,
    handoff_document,
    read_handoff_document,
    verify_handoff_digest,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "generate_report"
CONTRACT_FACT = "producer handoff contract "


def fixture_paths(root: Path = FIXTURES) -> list[Path]:
    """Return every scenario handoff the report fixtures hold under *root*."""
    return sorted(root.glob("*/scenarios/SCN-*.yaml"))


def signed_text(path: Path) -> str:
    """Return the text the writer publishes for the fixture at *path*."""
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    document["schema_version"] = HANDOFF_SCHEMA_VERSION
    document.pop("content_digest", None)
    for fact in document["sourced_facts"]:
        if fact["source"].startswith(CONTRACT_FACT):
            fact["source"] = f"{CONTRACT_FACT}{HANDOFF_SCHEMA_VERSION}"
    handoff = finalize_handoff(read_handoff_document(document))
    verify_handoff_digest(handoff)
    return yaml_document(handoff_document(handoff))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--check",
        action="store_true",
        help="list the fixtures the writer would change and exit 1 (the default)",
    )
    mode.add_argument(
        "--write", action="store_true", help="rewrite the fixtures the writer changes"
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=FIXTURES,
        help="the fixture directory to read (default: tests/fixtures/generate_report)",
    )
    args = parser.parse_args(argv)

    paths = fixture_paths(args.root)
    if not paths:
        print(f"no scenario handoffs under {args.root}", file=sys.stderr)
        return 1
    drifted = []
    for path in paths:
        text = signed_text(path)
        if path.read_text(encoding="utf-8") == text:
            continue
        drifted.append(path)
        if args.write:
            path.write_text(text, encoding="utf-8")
    for path in drifted:
        print(f"{'rewrote' if args.write else 'differs'}: {path}")
    outcome = "rewritten" if args.write else "differ"
    print(f"{len(paths)} fixture(s) examined, {len(drifted)} {outcome}")
    return 1 if drifted and not args.write else 0


if __name__ == "__main__":
    sys.exit(main())
