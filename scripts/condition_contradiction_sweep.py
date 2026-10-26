#!/usr/bin/env python3
"""Run the pre-publication tool-call condition check over saved handoffs, offline.

Each argument is a ``generate`` output directory: ``scenarios/*.yaml`` plus
the ``target-observations.yaml`` and ``target-realization.yaml`` the run
wrote, and the run's ``execution-target-profile.json`` (or the one named by
``--target-profile``). The profile must be the one the observations were
paired with. Nothing is sent anywhere: the check reads only these files::

    uv run python scripts/condition_contradiction_sweep.py OUTPUT_DIR [...]

The report states what happens to a refused condition (``RECOVERY``) and
counts, per directory and in total, the bound conditions checked, the
scenarios refused under each rule, which are the scenarios at risk of losing
their tool-call condition, and the undecidable cases under each rule, with
every example.
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

RECOVERY = (
    "A refused condition fails Stage 5 validation, so the scenario goes "
    "through the existing Stage 5 condition correction request, with a second "
    "correction only when the scenario would otherwise publish as "
    "analytical_only. If the condition still fails, the scenario is published "
    "without a tool_call_condition and records the reason in "
    "condition_omitted_reason. No scenario is dropped: each refused scenario "
    "is at risk of losing its tool-call condition, nothing more. An "
    "undecidable case is reported only, in the run's candidate diagnostics "
    "(synthesis-manifest.yaml) and in this sweep; it changes nothing in the "
    "scenario."
)


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
        "at_risk_of_losing_condition": [row["scenario_id"] for row in refused],
        "dropped_scenarios": 0,
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


def report(summaries: list[dict[str, Any]]) -> dict[str, Any]:
    """Return the sweep with its recovery statement and totals."""

    return {
        "recovery": RECOVERY,
        "directories": summaries,
        "total": {
            "directories": len(summaries),
            "handoffs": sum(item["handoffs"] for item in summaries),
            "checked": sum(item["checked"] for item in summaries),
            "refused_by_rule": _rule_totals(summaries, "refused_by_rule"),
            "undecidable_by_rule": _rule_totals(summaries, "undecidable_by_rule"),
            "at_risk_of_losing_condition": sum(
                len(item["at_risk_of_losing_condition"]) for item in summaries
            ),
            "dropped_scenarios": 0,
        },
    }


def _rule_totals(summaries: list[dict[str, Any]], key: str) -> dict[str, int]:
    return {rule: sum(item[key].get(rule, 0) for item in summaries) for rule in RULES}


def _table(summaries: list[dict[str, Any]]) -> list[str]:
    """One row per directory: checked, refused and undecidable per rule, at risk."""

    lines = [
        "| directory | handoffs | checked | refused a/b/c | undecidable a/b/c "
        "| at risk | dropped |",
        "| --- | ---: | ---: | --- | --- | ---: | ---: |",
    ]
    for item in summaries:
        refused = "/".join(str(item["refused_by_rule"].get(rule, 0)) for rule in RULES)
        undecidable = "/".join(
            str(item["undecidable_by_rule"].get(rule, 0)) for rule in RULES
        )
        lines.append(
            f"| {item['directory']} | {item['handoffs']} | {item['checked']} | "
            f"{refused} | {undecidable} | "
            f"{len(item['at_risk_of_losing_condition'])} | 0 |"
        )
    return lines


def _at_risk(count: int, handoffs: int, ids: list[str]) -> str:
    named = f" ({', '.join(ids)})" if ids else ""
    return (
        f"- scenarios at risk of losing their tool_call_condition: {count} of "
        f"{handoffs} handoffs{named}; scenarios dropped: 0"
    )


def render(summaries: list[dict[str, Any]]) -> str:
    """Render the sweep as Markdown."""

    total = report(summaries)["total"]
    lines = [
        "# Tool-call condition check: offline sweep",
        "",
        "## What happens to a refused condition",
        "",
        RECOVERY,
        "",
        "## Total",
        "",
        f"- directories: {total['directories']}; handoffs: {total['handoffs']}; "
        f"bound conditions checked: {total['checked']}",
        "- refused scenarios by rule: "
        + ", ".join(f"rule {rule}: {total['refused_by_rule'][rule]}" for rule in RULES),
        "- undecidable cases by rule: "
        + ", ".join(
            f"rule {rule}: {total['undecidable_by_rule'][rule]}" for rule in RULES
        ),
        _at_risk(total["at_risk_of_losing_condition"], total["handoffs"], []),
        "",
        *_table(summaries),
        "",
    ]
    for summary in summaries:
        ids = summary["at_risk_of_losing_condition"]
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
            _at_risk(len(ids), summary["handoffs"], ids),
            "",
        ]
        for row in summary["examples"]:
            condition = json.dumps(row["condition"]["comparisons"], sort_keys=True)
            lines.append(
                f"- {row['scenario_id']} ({row['ica_slot_id']}): `{condition}`"
            )
            for item in row["refused"]:
                lines.append(f"  - refused, rule {item['rule']}: {item['detail']}")
            if row["refused"]:
                lines.append(
                    "  - recovery: the existing Stage 5 condition correction; "
                    "if still refused, published without a tool_call_condition"
                )
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
        print(json.dumps(report(summaries), indent=2, sort_keys=True))
    else:
        print(render(summaries))
    return 0


if __name__ == "__main__":
    sys.exit(main())
