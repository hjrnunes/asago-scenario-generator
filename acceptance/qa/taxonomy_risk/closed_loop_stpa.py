#!/usr/bin/env python3
"""Independent external QA for bounded Phase 3 composition."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import unicodedata
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[3]
LINEAGE_PATH = ROOT / "tests/fixtures/phase3-lineage-audit.yaml"
RUN_DOMAIN = "asago-scenario-generator:stpa-obligation-closed-loop-run:v1"

_DRIVER = r"""
import json
import runpy

from asago_scenario_generator.models.challenge_ledger import ChallengeEligibility
from asago_scenario_generator.pipeline.closed_loop_stpa import run_closed_loop_stpa

support = runpy.run_path("tests/test_closed_loop_stpa.py")
assessment = support["_multi_assessment"]()
before = assessment.to_yaml()
obligation_id = assessment.taxonomy_correspondence[0].obligation_id
priorities = {"NOT_PROVIDED": 40, "INCORRECT": 10, "WRONG_TIMING": 30, "WRONG_DURATION": 20}
eligibility = tuple(
    ChallengeEligibility(
        obligation_id=obligation_id,
        slot_id=row.slot_id,
        priority=priorities[row.uca_type],
        rationale=f"External QA review of {row.uca_type}.",
        evidence_refs=(f"qa:{row.uca_type}",),
    )
    for row in reversed(assessment.structural_consideration)
)
invocations = []
def factory(record):
    uca_type = record.original_decision.uca_type
    invocations.append(uca_type)
    return support["_OutcomeAdapter"](uca_type)
arguments = dict(
    challenge_budget=3,
    assessment_artifact_id="external-qa-assessment",
    opted_in=True,
    controls=support["_controls"](),
    loss_analysis=support["_loss_analysis"](),
    control_structure=support["_control_structure"](),
)
first = run_closed_loop_stpa(assessment, eligibility, adapter_factory=factory, **arguments)
repeated = run_closed_loop_stpa(
    assessment,
    eligibility,
    adapter_factory=lambda record: (_ for _ in ()).throw(AssertionError("adapter retried")),
    prior_run=first,
    **arguments,
)
print(json.dumps({
    "run": json.loads(first.to_json()),
    "repeated_equal": repeated.to_yaml() == first.to_yaml(),
    "assessment_equal": assessment.to_yaml() == before,
    "invocations": invocations,
}, sort_keys=True))
"""


def _normalize(value: Any) -> Any:
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, list):
        return [_normalize(item) for item in value]
    if isinstance(value, dict):
        return {
            unicodedata.normalize("NFC", str(key)): _normalize(item)
            for key, item in value.items()
        }
    return value


def _digest(domain: str, payload: Any) -> str:
    canonical = json.dumps(
        _normalize(payload),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(domain.encode("utf-8") + b"\0" + canonical).hexdigest()


def _check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def _run_public_seam() -> dict[str, Any]:
    completed = subprocess.run(
        ["uv", "run", "python", "-c", _DRIVER],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(completed.stdout)


def _check_lineage() -> None:
    fixture = yaml.safe_load(LINEAGE_PATH.read_text(encoding="utf-8"))
    expected = {"klarna": (94, 77, 17, 16), "nhs": (27, 13, 14, 18)}
    _check(fixture["schema_version"] == "phase3-lineage-audit-v1", "lineage schema")
    for name, counts in expected.items():
        case = fixture["use_cases"][name]
        taxonomy = case["taxonomy"]
        stpa = case["stpa"]
        total, inconsistent, extra, joins = counts
        _check(taxonomy["identity_recomputed_count"] == total, f"{name} identities")
        _check(
            taxonomy["classifications"]
            == {
                "inconsistent_planning_input": inconsistent,
                "expected_extra_candidate": extra,
            },
            f"{name} classifications",
        )
        _check(
            stpa["scenario_count"] == stpa["exact_join_count"] == joins, f"{name} joins"
        )
        _check(len(stpa["records"]) == joins, f"{name} exact STPA records")
        _check(taxonomy["identity_lineage_bug_count"] == 0, f"{name} lineage bugs")
        _check(
            case["explicit_eligibility_targets"] == [], f"{name} inferred eligibility"
        )


def main() -> int:
    """Exercise the public seam and verify its output without project imports."""
    evidence = _run_public_seam()
    run = evidence["run"]
    _check(run["schema_version"] == "stpa-obligation-closed-loop-run-v1", "schema")
    payload = {key: value for key, value in run.items() if key != "semantic_digest"}
    _check(run["semantic_digest"] == _digest(RUN_DOMAIN, payload), "run digest")
    _check(run["analysis_opt_in"] is True, "opt-in was not retained")
    _check(
        evidence["invocations"] == ["INCORRECT", "WRONG_DURATION", "WRONG_TIMING"],
        "order",
    )
    _check(evidence["repeated_equal"], "exact resume changed the run")
    _check(evidence["assessment_equal"], "Phase 2 assessment changed")
    diagnostics = run["diagnostics"]
    _check(
        (
            diagnostics["eligible_targets"],
            diagnostics["selected_targets"],
            diagnostics["not_selected_budget"],
            diagnostics["attempted_targets"],
        )
        == (4, 3, 1, 3),
        "selection/attempt counts",
    )
    _check(
        {
            item["outcome"]["disposition"]
            for item in run["analyses"]
            if item["outcome"] is not None
        }
        == {"ica", "justified_na", "unresolved"},
        "typed outcomes",
    )
    _check(run["correspondence_changes"] == run["coverage_changes"] == 0, "coverage")
    _check(
        run["hybrid_generation_status"] == "not_attempted"
        and run["hybrid_admission_status"] == "not_assessed",
        "hybrid status",
    )
    _check_lineage()
    print("Closed-loop STPA external QA: 16/16 passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"Closed-loop STPA external QA: FAIL: {error}", file=sys.stderr)
        raise SystemExit(1) from error
