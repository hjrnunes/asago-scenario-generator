#!/usr/bin/env python3
"""External offline compatibility QA for correspondence."""

from __future__ import annotations

import os
import sys

from correspondence_support import run_workflow_compatibility


def main() -> int:
    assert "ASAGO_SCENARIO_GENERATOR_QA_PIPELINE" not in os.environ
    observations = {
        workflow: run_workflow_compatibility(workflow)
        for workflow in ("taxonomy/risk", "STPA")
    }
    for workflow, observation in observations.items():
        assert observation["exit_match"], f"{workflow}: {observation['detail']}"
        assert observation["artifacts_match"], f"{workflow}: artifact drift"
        assert observation["counts_match"], f"{workflow}: count drift"
        assert observation["prompts_match"], f"{workflow}: prompt drift"
        assert observation["sidecars_present"], f"{workflow}: sidecars not exercised"
        assert observation["no_phase2_output"], f"{workflow}: Phase 2 output leaked"
    print("correspondence compatibility external QA: 12/12 passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # noqa: BLE001 - executable QA boundary
        print(f"correspondence compatibility external QA: FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
