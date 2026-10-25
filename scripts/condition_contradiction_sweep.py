#!/usr/bin/env python3
"""Run the pre-publication tool-call condition check over saved handoffs, offline.

Each argument is a ``generate`` output directory: ``scenarios/*.yaml`` plus
the ``target-observations.yaml`` and ``target-realization.yaml`` the run
wrote, and the run's ``execution-target-profile.json`` (or the one named by
``--target-profile``). The profile must be the one the observations were
paired with. Nothing is sent anywhere: the check reads only these files::

    uv run python scripts/condition_contradiction_sweep.py OUTPUT_DIR [...]

The report counts, per directory, the bound conditions checked, the
scenarios refused under each rule, and the undecidable cases, with every
example. A refused condition goes to the existing Stage 5 correction; one
that still fails after the corrections is published without its condition
(as ``reply`` or ``analytical_only``), so a refusal costs no scenario, and
at most the scenario's tool-call condition.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

import yaml

from asago_scenario_generator.models.target_realization import (
    TargetRealizationResult,
)
from asago_scenario_generator.stpa.models.execution_classification import (
    ExecutionTargetProfile,
)
from asago_scenario_generator.stpa.scenario_prod.condition_check import (
    build_condition_universe,
)
from asago_scenario_generator.stpa.scenario_prod.realized_operation import (
    realized_operation,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.condition_contradictions import (
    assess_handoff,
)
from asago_scenario_generator.stpa.scenario_prod.target_observations import (
    TargetObservationSnapshot,
)

RULES = ("a", "b", "c")


def sweep_directory(
    output_dir: Path, target_profile: Path | None = None
) -> dict[str, Any]:
    """Check every handoff of one ``generate`` output directory."""

    profile_path = target_profile or output_dir / "execution-target-profile.json"
    profile = ExecutionTargetProfile.model_validate(
        json.loads(profile_path.read_text())
    )
    observations = TargetObservationSnapshot.model_validate(
        yaml.safe_load((output_dir / "target-observations.yaml").read_text())
    )
    if observations.target_profile_digest != profile.semantic_digest:
        raise ValueError(
            f"{profile_path} is not the profile the observations in "
            f"{output_dir} were paired with"
        )
    realization = TargetRealizationResult.model_validate(
        yaml.safe_load((output_dir / "target-realization.yaml").read_text())
    )
    universe = build_condition_universe(
        execution_target_profile=profile,
        target_operation=None,
        target_observations=observations,
    )
    handoffs = sorted((output_dir / "scenarios").glob("*.yaml"))
    rows = []
    for path in handoffs:
        handoff = yaml.safe_load(path.read_text())
        action = (handoff.get("lineage") or {}).get("control_action_id")
        operation = realized_operation(realization, action) if action else None
        result = assess_handoff(
            handoff,
            universe,
            control_action_operation=(
                operation.reference.operation_id if operation is not None else None
            ),
        )
        if result is None:
            continue
        rows.append(
            {
                "scenario_id": handoff["scenario_id"],
                "ica_slot_id": (handoff.get("lineage") or {}).get("ica_slot_id"),
                "condition": handoff["tool_call_condition"],
                "refused": [
                    {"rule": item.rule, "code": item.code, "detail": item.detail}
                    for item in result.refused
                ],
                "undecidable": [
                    {"rule": item.rule, "detail": item.detail}
                    for item in result.undecidable
                ],
            }
        )
    return _summary(output_dir, profile_path, len(handoffs), rows)


def _summary(
    output_dir: Path, profile_path: Path, handoffs: int, rows: list[dict]
) -> dict[str, Any]:
    refused = [row for row in rows if row["refused"]]
    return {
        "directory": str(output_dir),
        "target_profile": str(profile_path),
        "handoffs": handoffs,
        "checked": len(rows),
        "refused_scenarios": len(refused),
        "refused_by_rule": {
            rule: sum(
                any(item["rule"] == rule for item in row["refused"]) for row in rows
            )
            for rule in RULES
        },
        "undecidable_by_rule": dict(
            Counter(item["rule"] for row in rows for item in row["undecidable"])
        ),
        "undecidable_scenarios": sum(bool(row["undecidable"]) for row in rows),
        "examples": [row for row in rows if row["refused"] or row["undecidable"]],
    }


def render(summaries: list[dict[str, Any]]) -> str:
    """Render the sweep as Markdown."""

    lines = ["# Tool-call condition check: offline sweep", ""]
    for summary in summaries:
        lines += [
            f"## {summary['directory']}",
            "",
            f"- handoffs: {summary['handoffs']}; bound conditions checked: "
            f"{summary['checked']}",
            "- refused scenarios: "
            f"{summary['refused_scenarios']} (rule a: "
            f"{summary['refused_by_rule']['a']}, rule b: "
            f"{summary['refused_by_rule']['b']}, rule c: "
            f"{summary['refused_by_rule']['c']})",
            "- undecidable cases: "
            + (
                ", ".join(
                    f"rule {rule}: {count}"
                    for rule, count in sorted(summary["undecidable_by_rule"].items())
                )
                or "none"
            )
            + f" ({summary['undecidable_scenarios']} scenarios)",
            "",
        ]
        for row in summary["examples"]:
            condition = json.dumps(row["condition"]["comparisons"], sort_keys=True)
            lines.append(
                f"- {row['scenario_id']} ({row['ica_slot_id']}): `{condition}`"
            )
            for item in row["refused"]:
                lines.append(f"  - refused, rule {item['rule']}: {item['detail']}")
            for item in row["undecidable"]:
                lines.append(f"  - undecidable, rule {item['rule']}: {item['detail']}")
        lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("output_dirs", nargs="+", type=Path)
    parser.add_argument(
        "--target-profile",
        type=Path,
        help="profile to use for every directory instead of its own copy",
    )
    parser.add_argument("--json", action="store_true", help="print JSON")
    args = parser.parse_args(argv)
    summaries = [
        sweep_directory(directory, args.target_profile)
        for directory in args.output_dirs
    ]
    if args.json:
        print(json.dumps(summaries, indent=2, sort_keys=True))
    else:
        print(render(summaries))
    return 0


if __name__ == "__main__":
    sys.exit(main())
