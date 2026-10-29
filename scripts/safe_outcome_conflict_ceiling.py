#!/usr/bin/env python3
"""Measure what the cross-scenario check could decide with a richer safe outcome.

Research script; it only reads recorded runs and writes one JSON report.

The Stage 5 cross-scenario check evaluates a sibling's bound
``tool_call_condition`` on the one call a safe outcome states the agent
makes, with the values it states, as an incomplete capture. ``today`` is
that outcome. Recorded safe outcomes rarely carry argument values and never
a statement that the call is the agent's complete behaviour, so this script
measures the ceiling of each:

``complete``
    The check's call evaluated as a complete capture: every ``not_called``
    and ``order`` comparison and every comparison on another operation
    becomes decidable.
``argument_values``
    Each argument B's condition reads on the safe operation is given every
    value that matters to the condition (each literal it is compared with,
    a neighbour of each numeric literal, and one value equal to none of them).
    On an incomplete capture a call with values can make a value comparison
    ``detected`` but never ``not_detected`` (another, uncaptured call may
    match), so a pair counts as decided when some assignment is ``detected``
    (``values_decide``: it depends on the values the safe call carries) or
    every assignment is.
``argument_values_complete``
    Both at once.
``stated_values``
    A proxy for the values the recorded scenario states: an argument takes a
    literal of B's condition only when that literal appears verbatim in A's
    safe outcome (statement, record or fact references); other arguments stay
    unknown. The call is evaluated as an incomplete capture.

Siblings, eligible pairs and evaluated pairs are computed by the check's own
:func:`~asago_scenario_generator.stpa.scenario_prod.stage5.cross_scenario.sibling_pairs`
over the published scenarios of a run, functional tests included, as the
check sees them: grouped by control action and process-model context, the
context rebuilt from ``target-realization.yaml``'s effective ICA enumeration
and ``control-structure.yaml``; a pair is evaluated only when the safe
outcome states its call and the failing scenario binds a condition. A
scenario the check withdrew is not published, so it is not counted. A
published condition that the current model refuses (``invalid_conditions``)
counts as unbound. ``--exclude-duplicates`` drops the scenarios
``testability.yaml`` marks duplicate.

Usage::

    uv run --frozen python scripts/safe_outcome_conflict_ceiling.py \
        --out report.json RUN_DIR [RUN_DIR ...]
"""

from __future__ import annotations

import argparse
import collections
import itertools
import json
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.models.ica_enumeration import ICAEnumeration
from asago_scenario_generator.stpa.observation_contract import SafeObservableOutcome
from asago_scenario_generator.stpa.scenario_prod.stage5 import cross_scenario
from asago_scenario_generator.stpa.scenario_prod.stage5.cross_scenario import (
    SiblingCandidate,
    ica_process_model_contexts,
)
from asago_scenario_generator.stpa.tool_call_condition import ToolCallCondition
from asago_scenario_generator.stpa.tool_call_condition_eval import (
    evaluate_condition_v2,
)

_OTHER = "\x00value-equal-to-no-literal"
_MAX_ASSIGNMENTS = 4096


def _yaml(path: Path) -> Any:
    return yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.CSafeLoader)


def load_scenarios(
    run_dir: Path, exclude_duplicates: bool
) -> tuple[list[dict[str, Any]], dict[str, dict[str, str]]]:
    """Return a run's published scenarios and each ICA's context."""
    output = run_dir / "stages" / "generate" / "output"
    structure = ControlStructure.model_validate(
        _yaml(output / "control-structure.yaml")
    )
    realization = _yaml(output / "target-realization.yaml")
    enumeration = ICAEnumeration.model_validate(
        realization["effective_view"]["effective_ica_enumeration"]
    )
    scenarios = [_yaml(path) for path in sorted((output / "scenarios").glob("*.yaml"))]
    if exclude_duplicates:
        testability = _yaml(output / "testability.yaml")
        duplicates = {
            row["scenario_id"]
            for row in testability["scenarios"]
            if row["status"] == "duplicate"
        }
        scenarios = [s for s in scenarios if s["scenario_id"] not in duplicates]
    return scenarios, ica_process_model_contexts(enumeration, structure)


def _candidate(scenario: Mapping[str, Any], invalid: list[str]) -> SiblingCandidate:
    """Return the check's view of one published scenario."""
    lineage = scenario.get("lineage") or {}
    outcome = scenario.get("safe_observable_outcome")
    raw_condition = scenario.get("tool_call_condition")
    condition = None
    if raw_condition:
        try:
            condition = ToolCallCondition.model_validate(raw_condition)
        except ValidationError:
            invalid.append(scenario["scenario_id"])
    return SiblingCandidate(
        scenario_id=scenario["scenario_id"],
        control_action_id=str(lineage.get("control_action_id")),
        ica_id=lineage.get("ica_id"),
        safe_outcome=(
            SafeObservableOutcome.model_validate(outcome) if outcome else None
        ),
        condition=condition,
    )


def sibling_pairs(
    scenarios: Sequence[Mapping[str, Any]], contexts: Mapping[str, Mapping[str, str]]
) -> tuple[
    int,
    list[tuple[Mapping[str, Any], Mapping[str, Any], dict[str, Any]]],
    list[str],
]:
    """Return the eligible pair count, the evaluated pairs and invalid conditions.

    Each evaluated pair is (safe, failing, call): the two published scenarios
    and the call the check evaluates the failing condition on.
    """
    by_id = {scenario["scenario_id"]: scenario for scenario in scenarios}
    invalid: list[str] = []
    candidates = [_candidate(scenario, invalid) for scenario in scenarios]
    siblings = cross_scenario.sibling_pairs(candidates, contexts)
    pairs = [
        (by_id[pair.safe.scenario_id], by_id[pair.failing.scenario_id], pair.call)
        for pair in siblings.pairs
        if pair.call is not None
    ]
    return len(siblings.pairs), pairs, sorted(invalid)


def _numeric_neighbours(value: Any) -> list[Any]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return []
    return [value - 1, value + 1]


def argument_candidates(
    condition: Mapping[str, Any], operation: str
) -> dict[str, list[Any]]:
    """Return each argument ``condition`` reads on ``operation`` and its values."""
    candidates: dict[str, list[Any]] = {}

    def add(argument: str, values: Iterable[Any]) -> None:
        bucket = candidates.setdefault(argument, [])
        for value in values:
            if value not in bucket:
                bucket.append(value)

    for comparison in condition["comparisons"]:
        kind = comparison["kind"]
        if kind == "value":
            sides = (comparison["left"], comparison["right"])
            for side, other in (sides, sides[::-1]):
                if side["source"] != "argument" or side["operation"] != operation:
                    continue
                values: list[Any] = []
                if other["source"] == "literal":
                    literal = other["value"]
                    elements = literal if isinstance(literal, list) else [literal]
                    for element in elements:
                        values += [element, *_numeric_neighbours(element)]
                add(side["argument"], values)
        elif kind == "not_called" and comparison["operation"] == operation:
            for item in comparison.get("where", []):
                add(item["argument"], [item["value"]])
        elif kind == "order" and comparison.get("same_argument"):
            if operation in (comparison["operation"], comparison["requires_prior"]):
                add(comparison["same_argument"], [])
    for bucket in candidates.values():
        bucket.append(_OTHER)
    return candidates


def _outcomes(
    condition: Mapping[str, Any],
    operation: str,
    candidates: Mapping[str, list[Any]],
    complete: bool,
) -> set[str]:
    names = list(candidates)
    choices = list(itertools.product(*(candidates[name] for name in names)))
    outcomes = set()
    for choice in choices[:_MAX_ASSIGNMENTS]:
        call = {"name": operation, "arguments": dict(zip(names, choice))}
        outcomes.add(evaluate_condition_v2(condition, [call], complete)[0])
    return outcomes


def _summarize(outcomes: set[str]) -> str:
    # On an incomplete capture a value comparison can be detected but never
    # ruled out (another, uncaptured call may match), so "some assignment is
    # detected" is the question that matters for a withdrawal.
    if "detected" in outcomes:
        return "detected" if outcomes == {"detected"} else "values_decide"
    return "inconclusive" if "inconclusive" in outcomes else "not_detected"


def _stated_values(
    safe_outcome: Mapping[str, Any], candidates: Mapping[str, list[Any]]
) -> dict[str, Any]:
    text = " ".join(
        [
            safe_outcome.get("statement") or "",
            *(safe_outcome.get("record_refs") or []),
            *(safe_outcome.get("fact_refs") or []),
        ]
    )
    stated = {}
    for argument, values in candidates.items():
        found = [
            value
            for value in values
            if value is not _OTHER
            and isinstance(value, (str, int, float))
            and not isinstance(value, bool)
            and str(value)
            and str(value) in text
        ]
        if len(found) == 1:
            stated[argument] = found[0]
    return stated


def measure_pair(
    safe: Mapping[str, Any], failing: Mapping[str, Any], call: Mapping[str, Any]
) -> dict[str, Any]:
    """Return every measured outcome of one ordered sibling pair.

    ``call`` is the call the check evaluates the failing condition on.
    """
    outcome = safe["safe_observable_outcome"]
    operation = outcome["operation_name"]
    condition = failing["tool_call_condition"]
    candidates = argument_candidates(condition, operation)
    stated = _stated_values(outcome, candidates)
    stated_call = {"name": operation, "arguments": stated}
    return {
        "scenario_id": failing["scenario_id"],
        "safe_scenario_id": safe["scenario_id"],
        "control_action_id": (failing.get("lineage") or {}).get("control_action_id"),
        "safe_operation_name": operation,
        "comparison_kinds": sorted(
            {comparison["kind"] for comparison in condition["comparisons"]}
        ),
        "arguments_read": sorted(candidates),
        "today": evaluate_condition_v2(condition, [call], False)[0],
        "complete": evaluate_condition_v2(condition, [call], True)[0],
        "argument_values": _summarize(
            _outcomes(condition, operation, candidates, False)
        ),
        "argument_values_complete": _summarize(
            _outcomes(condition, operation, candidates, True)
        ),
        "stated_values": stated,
        "stated_values_outcome": evaluate_condition_v2(condition, [stated_call], False)[
            0
        ],
        "stated_values_complete_outcome": evaluate_condition_v2(
            condition, [stated_call], True
        )[0],
    }


def measure_runs(run_dirs: Sequence[Path], exclude_duplicates: bool) -> dict[str, Any]:
    """Return the per-pair rows and the totals over every run."""
    rows = []
    eligible = 0
    runs_with_pairs = 0
    invalid_conditions = []
    for run_dir in run_dirs:
        scenarios, contexts = load_scenarios(run_dir, exclude_duplicates)
        run_eligible, pairs, invalid = sibling_pairs(scenarios, contexts)
        eligible += run_eligible
        runs_with_pairs += bool(pairs)
        invalid_conditions += [f"{run_dir.name}:{item}" for item in invalid]
        for safe, failing, call in pairs:
            rows.append({"run": run_dir.name, **measure_pair(safe, failing, call)})
    totals = {
        key: dict(collections.Counter(row[key] for row in rows))
        for key in (
            "today",
            "complete",
            "argument_values",
            "argument_values_complete",
            "stated_values_outcome",
            "stated_values_complete_outcome",
        )
    }
    today_inconclusive = [row for row in rows if row["today"] == "inconclusive"]
    decided_by = collections.Counter()
    for row in today_inconclusive:
        by_values = row["argument_values"] != "inconclusive"
        by_complete = row["complete"] != "inconclusive"
        by_both = row["argument_values_complete"] != "inconclusive"
        if by_values and by_complete:
            decided_by["either"] += 1
        elif by_values:
            decided_by["argument_values_only"] += 1
        elif by_complete:
            decided_by["complete_only"] += 1
        elif by_both:
            decided_by["both_together"] += 1
        else:
            decided_by["neither"] += 1
    detected = {
        key: [
            f"{row['run']}:{row['safe_scenario_id']}->{row['scenario_id']}"
            for row in rows
            if row[key] in ("detected", "values_decide")
        ]
        for key in totals
    }
    return {
        "runs": len(run_dirs),
        "runs_with_evaluated_pairs": runs_with_pairs,
        "exclude_duplicates": exclude_duplicates,
        "eligible_pairs": eligible,
        "evaluated_pairs": len(rows),
        "invalid_conditions": invalid_conditions,
        "totals": totals,
        "today_inconclusive_decided_by": dict(decided_by),
        "detected_or_value_dependent_pairs": detected,
        "pairs": rows,
    }


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("run_dirs", nargs="+", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--exclude-duplicates", action="store_true")
    args = parser.parse_args(argv)
    report = measure_runs(args.run_dirs, args.exclude_duplicates)
    args.out.write_text(json.dumps(report, indent=2, sort_keys=False) + "\n")
    summary = {key: value for key, value in report.items() if key != "pairs"}
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
