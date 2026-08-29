#!/usr/bin/env python3
"""External QA for canonical correspondence artifact persistence."""

from __future__ import annotations

import hashlib
import sys
import tempfile
from pathlib import Path

from correspondence_support import produce_proposals, publish_reconciliation


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="asago-correspondence-artifact-") as root:
        workspace = Path(root)
        proposal_artifact, proposals = produce_proposals(workspace)
        proposal_bytes = proposal_artifact.read_bytes()
        assert hashlib.sha256(proposal_bytes).hexdigest()
        reconciliation_artifact, result = publish_reconciliation(
            workspace, proposals, adjudicate=True
        )
        assert reconciliation_artifact.name == "correspondence-reconciliation.yaml"
        assert result["semantic_digest"]
        assert not list(workspace.rglob("*.tmp"))
        assert not list(workspace.rglob("*.partial"))
        assert proposal_artifact.read_bytes() == proposal_bytes
    print("correspondence artifact external QA: 4/4 passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # noqa: BLE001 - executable QA boundary
        print(f"correspondence artifact external QA: FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
