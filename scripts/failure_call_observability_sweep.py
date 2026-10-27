#!/usr/bin/env python3
"""Count analytical-only handoffs before and after the failure-call rule, offline.

Each argument is a ``generate`` output directory: ``scenarios/*.yaml``, the
run's ``execution-target-profile.json`` and its ``observation-contract.yaml``
(the default contract when the run wrote none). Nothing is sent anywhere: the
sweep reads only these files::

    uv run python scripts/failure_call_observability_sweep.py OUTPUT_DIR [...] \
        [--example TARGET_ID:SCN-ID ...] [--json]

For every handoff published as ``analytical_only`` the sweep applies the
Stage 5 rule (``failure_call_criterion``) to the published criteria, as Stage
5 does to a reply's criteria:

- ``after``: with the handoff's own ``semantic_failure_call``. A handoff
  without one is unchanged.
- ``after_proxy``: for a handoff without a failure call, with a call of the
  operation its failure criterion names (the documented operation of
  authority ``criterion_observed_operation``). This is an upper bound, not a
  prediction: a reply sets ``failure_call`` to null when the failure is not a
  call of that operation, for example a returned result or a reply, and the
  proxy cannot tell.

A handoff whose condition failed was demoted by the old routing; the new
routing keeps its command-attempt claim, which the rule applied to the
demoted criteria reproduces. A scenario the rule makes executable carries no
bound condition in the saved handoff either way.

Every handoff also gets a ``condition`` class: what Stage 5 now publishes as
its tool-call condition. A handoff whose discriminating condition failed
validation, that has no bound condition and no reply-level claim (the reply
route wins), and whose failure call the rule makes observable is
``derived_not_called`` for a ``missing_call`` (code derives
``not_called(<operation>)``) and ``incorrect_call_no_condition`` for an
``incorrect_call`` (code derives nothing). Every other handoff is
``unchanged``. ``condition_proxy`` marks an unchanged handoff with a failed
condition and no failure call whose failure criterion names a recorded
operation: its failure call would decide between the two, so it bounds them
from above.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import yaml

from asago_scenario_generator.stpa.models.execution_classification import (
    ExecutionTargetProfile,
)
from asago_scenario_generator.stpa.observation_contract import (
    FailureCall,
    ObservationContract,
    ObservationCriterion,
    assess_observation_criteria,
    default_observation_contract,
    failure_call_criterion,
    load_observation_contract,
)

ANALYTICAL = "analytical_only"
DERIVED = "derived_not_called"
INCORRECT = "incorrect_call_no_condition"
UNCHANGED = "unchanged"
# How a publication note begins when the condition failed after its corrections.
_CONDITION_FAILED = "The discriminating condition failed validation after"
PROXY_AUTHORITY = "criterion_observed_operation"
# The demotion note the old routing wrote on a criterion whose condition failed.
_CONDITION_DEMOTION = "Not observable: the discriminating condition failed"


def recorded_operations(profile: ExecutionTargetProfile) -> tuple[str, ...]:
    """Return the operation IDs the profile declares, as Stage 5 reads them."""

    return tuple(
        operation.operation_id
        for resource in profile.resources
        for operation in resource.operations
    )


def _contract(output_dir: Path) -> ObservationContract:
    path = output_dir / "observation-contract.yaml"
    return (
        load_observation_contract(path)
        if path.exists()
        else (default_observation_contract())
    )


def _criteria(handoff: Mapping[str, Any]) -> list[ObservationCriterion]:
    observation = handoff.get("observation") or {}
    return [
        ObservationCriterion.model_validate(item)
        for item in observation.get("criteria") or []
    ]


def _proxy_operations(
    handoff: Mapping[str, Any], operations: Sequence[str]
) -> list[str]:
    return [
        item["name"]
        for item in handoff.get("documented_operations") or []
        if item.get("authority") == PROXY_AUTHORITY and item.get("name") in operations
    ]


def _after(
    criteria: list[ObservationCriterion],
    failure_call: FailureCall | None,
    contract: ObservationContract,
    operations: tuple[str, ...],
) -> str:
    """Return the disposition Stage 5 publishes with ``failure_call``."""

    added = failure_call_criterion(
        failure_call,
        contract,
        operations,
        taken_ids=tuple(item.criterion_id for item in criteria),
    )
    if added is None:
        return assess_observation_criteria(criteria, contract).disposition
    return assess_observation_criteria([*criteria, added], contract).disposition


def _population(criteria: list[ObservationCriterion]) -> str:
    if any(item.reason.startswith(_CONDITION_DEMOTION) for item in criteria):
        return "condition_failed"
    return "provider_unobservable"


def _condition_failed(
    handoff: Mapping[str, Any], criteria: list[ObservationCriterion]
) -> bool:
    """Return whether the handoff lost a condition that failed validation."""

    if handoff.get("tool_call_condition"):
        return False
    note = handoff.get("condition_omitted_reason") or ""
    return note.startswith(_CONDITION_FAILED) or (
        _population(criteria) == "condition_failed"
    )


def condition_class(
    handoff: Mapping[str, Any],
    criteria: list[ObservationCriterion],
    failure_call: FailureCall | None,
    contract: ObservationContract,
    operations: tuple[str, ...],
) -> str:
    """Return the tool-call condition Stage 5 now publishes for the handoff."""

    safe = handoff.get("safe_observable_outcome") or {}
    if (
        not _condition_failed(handoff, criteria)
        or safe.get("claim_level") == "reply"
        or failure_call_criterion(failure_call, contract, operations) is None
    ):
        return UNCHANGED
    return DERIVED if failure_call.kind == "missing_call" else INCORRECT


def assess_handoff(
    handoff: Mapping[str, Any],
    contract: ObservationContract,
    operations: tuple[str, ...],
) -> dict[str, Any]:
    """Return the before and after dispositions of one handoff."""

    assessment = (handoff.get("observation") or {}).get("assessment") or {}
    before = assessment.get("disposition")
    criteria = _criteria(handoff)
    raw_call = handoff.get("semantic_failure_call")
    failure_call = FailureCall.model_validate(raw_call) if raw_call else None
    proxies = _proxy_operations(handoff, operations)
    # The kind only words the added criterion; it never decides observability.
    proxy_call = (
        failure_call
        if failure_call is not None
        else (
            FailureCall(kind="incorrect_call", operation_name=proxies[0])
            if proxies
            else None
        )
    )
    status = handoff.get("tool_call_condition_status") or {}
    condition = condition_class(handoff, criteria, failure_call, contract, operations)
    condition_proxy = (
        condition == UNCHANGED
        and failure_call is None
        and _condition_failed(handoff, criteria)
        and (handoff.get("safe_observable_outcome") or {}).get("claim_level") != "reply"
        and bool(proxies)
        and failure_call_criterion(proxy_call, contract, operations) is not None
    )
    row = {
        "scenario_id": handoff.get("scenario_id"),
        "before": before,
        "before_reason": assessment.get("reason"),
        "failure_call": raw_call,
        "proxy_operations": proxies,
        "after": before,
        "after_proxy": before,
        "condition_status": status.get("status"),
        "criterion": handoff.get("semantic_failure_criterion"),
        "condition": condition,
        "condition_proxy": condition_proxy,
    }
    if before != ANALYTICAL:
        return row
    row["population"] = _population(criteria)
    row["after"] = _after(criteria, failure_call, contract, operations)
    row["after_proxy"] = _after(criteria, proxy_call, contract, operations)
    return row


def sweep_directory(output_dir: Path) -> dict[str, Any]:
    """Assess every handoff of one ``generate`` output directory."""

    profile = ExecutionTargetProfile.model_validate(
        json.loads((output_dir / "execution-target-profile.json").read_text())
    )
    contract = _contract(output_dir)
    operations = recorded_operations(profile)
    rows = [
        assess_handoff(yaml.safe_load(path.read_text()), contract, operations)
        for path in sorted((output_dir / "scenarios").glob("*.yaml"))
    ]
    return summarize(output_dir, profile.target_id, rows)


def summarize(
    output_dir: Path, target_id: str, rows: list[dict[str, Any]]
) -> dict[str, Any]:
    """Return the counts of one directory and its analytical rows."""

    analytical = [row for row in rows if row["before"] == ANALYTICAL]

    def by_condition(name: str) -> list[str]:
        return [row["scenario_id"] for row in rows if row["condition"] == name]

    def ids(key: str) -> list[str]:
        return [row["scenario_id"] for row in analytical if row[key] != ANALYTICAL]

    return {
        "directory": str(output_dir),
        "target_id": target_id,
        "handoffs": len(rows),
        "with_failure_call": sum(bool(row["failure_call"]) for row in rows),
        "analytical_before": len(analytical),
        "analytical_after": sum(row["after"] == ANALYTICAL for row in analytical),
        "analytical_after_proxy": sum(
            row["after_proxy"] == ANALYTICAL for row in analytical
        ),
        "executable_after": ids("after"),
        "executable_after_proxy": ids("after_proxy"),
        DERIVED: by_condition(DERIVED),
        INCORRECT: by_condition(INCORRECT),
        UNCHANGED: len(by_condition(UNCHANGED)),
        "condition_proxy": [
            row["scenario_id"] for row in rows if row["condition_proxy"]
        ],
        "rows": analytical,
    }


def examples(
    summaries: list[dict[str, Any]], wanted: Sequence[str]
) -> list[dict[str, Any]]:
    """Return the status of each ``TARGET_ID:SCN-ID`` example."""

    found = []
    for item in wanted:
        target_id, _, scenario_id = item.partition(":")
        match = next(
            (
                {"example": item, **row}
                for summary in summaries
                if summary["target_id"] == target_id
                for row in summary["rows"]
                if row["scenario_id"] == scenario_id
            ),
            None,
        )
        found.append(match or {"example": item, "before": "not analytical_only"})
    return found


def report(
    summaries: list[dict[str, Any]], wanted: Sequence[str] = ()
) -> dict[str, Any]:
    """Return the sweep with its totals and named examples."""

    return {
        "directories": [
            {key: value for key, value in item.items() if key != "rows"}
            for item in summaries
        ],
        "total": {
            key: sum(item[key] for item in summaries)
            for key in (
                "handoffs",
                "with_failure_call",
                "analytical_before",
                "analytical_after",
                "analytical_after_proxy",
                UNCHANGED,
            )
        }
        | {
            key: sum(len(item[key]) for item in summaries)
            for key in (DERIVED, INCORRECT, "condition_proxy")
        },
        "examples": examples(summaries, wanted),
    }


def render(summaries: list[dict[str, Any]], wanted: Sequence[str] = ()) -> str:
    """Render the sweep as Markdown."""

    result = report(summaries, wanted)
    lines = [
        "# Failure-call observability: offline sweep",
        "",
        "| target | directory | handoffs | with failure call | analytical "
        "before | after | after (proxy upper bound) |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for item in result["directories"]:
        lines.append(
            f"| {item['target_id']} | {item['directory']} | {item['handoffs']} | "
            f"{item['with_failure_call']} | {item['analytical_before']} | "
            f"{item['analytical_after']} | {item['analytical_after_proxy']} |"
        )
    total = result["total"]
    lines += [
        f"| total | | {total['handoffs']} | {total['with_failure_call']} | "
        f"{total['analytical_before']} | {total['analytical_after']} | "
        f"{total['analytical_after_proxy']} |",
        "",
    ]
    for summary in summaries:
        lines += [f"## {summary['target_id']}: {summary['directory']}", ""]
        for row in summary["rows"]:
            lines.append(
                f"- {row['scenario_id']} ({row['population']}): after "
                f"{row['after']}, proxy {row['after_proxy']}"
                f" [{', '.join(row['proxy_operations']) or 'no named operation'}]"
            )
        lines.append("")
    lines += [
        "## Tool-call condition after a failed condition",
        "",
        "| target | directory | derived not_called | incorrect call, no condition "
        "| unchanged | of which undecided without a failure call |",
        "| --- | --- | ---: | ---: | ---: | ---: |",
    ]
    for item in result["directories"]:
        lines.append(
            f"| {item['target_id']} | {item['directory']} | {len(item[DERIVED])} | "
            f"{len(item[INCORRECT])} | {item[UNCHANGED]} | "
            f"{len(item['condition_proxy'])} |"
        )
    lines += [
        f"| total | | {total[DERIVED]} | {total[INCORRECT]} | {total[UNCHANGED]} | "
        f"{total['condition_proxy']} |",
        "",
    ]
    if result["examples"]:
        lines += ["## Named examples", ""]
        for row in result["examples"]:
            lines.append(
                f"- {row['example']}: before {row['before']}"
                + (
                    f", after {row['after']}, proxy {row['after_proxy']} "
                    f"({row['population']}; named operations: "
                    f"{', '.join(row['proxy_operations']) or 'none'}; saved "
                    f"condition: {row['condition_status']})"
                    if "after" in row
                    else ""
                )
            )
        lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("output_dirs", nargs="+", type=Path)
    parser.add_argument(
        "--example",
        action="append",
        default=[],
        metavar="TARGET_ID:SCN-ID",
        help="report the status of this scenario, from the first directory of "
        "that target (repeatable)",
    )
    parser.add_argument("--json", action="store_true", help="print JSON")
    args = parser.parse_args(argv)
    for item in args.example:
        if ":" not in item:
            parser.error(f"--example takes TARGET_ID:SCN-ID, got {item!r}")
    summaries = [sweep_directory(directory) for directory in args.output_dirs]
    if args.json:
        print(json.dumps(report(summaries, args.example), indent=2, sort_keys=True))
    else:
        print(render(summaries, args.example))
    return 0


if __name__ == "__main__":
    sys.exit(main())
