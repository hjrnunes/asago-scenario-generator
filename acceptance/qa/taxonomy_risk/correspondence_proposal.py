#!/usr/bin/env python3
"""External QA for typed correspondence proposal generation."""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

from correspondence_support import produce_proposals


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="asago-correspondence-proposal-") as root:
        artifact, payload = produce_proposals(Path(root))
        rows = payload.get("proposals") or []
        assert len(rows) == 1, "expected one deterministic proposal"
        row = rows[0]
        assert row["proposal_id"].startswith("corrp:v1:")
        assert row["relation_kind"] == "same_mechanism"
        assert row["provenance"]["evidence_source"] == "exact_id"
        assert "left_ref" not in row and "right_ref" not in row
        assert "status" not in row
        assert artifact.name == "correspondence-proposals.yaml"
    print("correspondence proposal external QA: 5/5 passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # noqa: BLE001 - executable QA boundary
        print(f"correspondence proposal external QA: FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
