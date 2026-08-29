#!/usr/bin/env python3
"""External QA for typed correspondence reconciliation."""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

from correspondence_support import produce_proposals, publish_reconciliation


def main() -> int:
    with tempfile.TemporaryDirectory(
        prefix="asago-correspondence-reconciliation-"
    ) as root:
        workspace = Path(root)
        _, proposals = produce_proposals(workspace)
        _, open_result = publish_reconciliation(workspace, proposals, adjudicate=False)
        assert open_result["accepted_relations"] == []
        assert open_result["proposals"][0]["status"] == "unresolved"
        _, confirmed_result = publish_reconciliation(
            workspace, proposals, adjudicate=True
        )
        assert confirmed_result["is_valid"] is True
        assert len(confirmed_result["accepted_relations"]) == 1
        assert confirmed_result["proposals"][0]["status"] == "confirmed"
        assert confirmed_result["network_calls"] == 0
        assert confirmed_result["model_calls"] == 0
    print("correspondence reconciliation external QA: 5/5 passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # noqa: BLE001 - executable QA boundary
        print(
            f"correspondence reconciliation external QA: FAIL: {exc}", file=sys.stderr
        )
        raise SystemExit(1) from exc
