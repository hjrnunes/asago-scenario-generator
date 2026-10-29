"""The funnel's second denominator leaves out the LLM01/LLM07 fan-out rows."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from asago_scenario_generator.pipeline.synthesis_manifest import (
    FAN_OUT_LLM_CODES,
    FAN_OUT_RULE,
    _obligation_resolution_funnel,
)
from asago_scenario_generator.report.obligation_section import obligation_section
from asago_scenario_generator.report.run_data import load_run
from tests.helpers.generate_report_fixture import copy_run, edit_yaml, metrics


def _path(risk_id: str, llm: str | None, pattern: str) -> Any:
    """One planner mapping record: risk -> OWASP LLM code -> pattern."""
    edges = (
        []
        if llm is None
        else [
            {"source_id": risk_id, "target_id": llm, "source": "sssom"},
            {"source_id": llm, "target_id": pattern, "source": "cross-taxonomy"},
        ]
    )
    return SimpleNamespace(kind="mapping", detail=json.dumps({"path": edges}))


def _obligation(
    obligation_id: str, risk_id: str, pattern: str | None, llms: tuple[Any, ...]
) -> Any:
    evidence = [_path(risk_id, llm, pattern or "") for llm in llms]
    evidence.append(SimpleNamespace(kind="qualification", detail="ready"))
    return SimpleNamespace(
        obligation_id=obligation_id,
        risk_ref=SimpleNamespace(risk_id=risk_id),
        attack_pattern_id=pattern,
        evidence=tuple(evidence),
    )


def _row(obligation_id: str, disposition: str, stop_reason: str | None) -> Any:
    return SimpleNamespace(
        obligation_id=obligation_id,
        disposition=disposition,
        stop_reason=stop_reason,
        ica_ids=(),
    )


PLAN = SimpleNamespace(
    obligations=(
        _obligation("ob-llm07", "R-1", "AP-T15-01", ("LLM07",)),
        _obligation("ob-llm01", "R-2", "AP-T6-10", ("LLM01",)),
        _obligation("ob-llm01-addressed", "R-3", "AP-T10-01", ("LLM01",)),
        _obligation("ob-both-fan-out", "R-4", "AP-T5-05", ("LLM01", "LLM07")),
        _obligation("ob-mixed", "R-5", "AP-T6-05", ("LLM01", "LLM05")),
        _obligation("ob-llm02", "R-6", "AP-T6-08", ("LLM02",)),
        _obligation("ob-direct", "AP-T2-01", "AP-T2-01", (None,)),
        _obligation("ob-excluded", "R-7", "AP-T2-06", ("LLM01",)),
        _obligation("ob-governance", "R-8", None, ()),
    )
)
ROWS = (
    _row("ob-llm07", "proposed_not_applicable", "risk_pattern_mismatch"),
    _row("ob-llm01", "unresolved", "no_structural_route"),
    _row("ob-llm01-addressed", "addressed", "addressed"),
    _row("ob-both-fan-out", "unresolved", "risk_pattern_mismatch"),
    _row("ob-mixed", "unresolved", "no_structural_route"),
    _row("ob-llm02", "addressed", "addressed"),
    _row("ob-direct", "unresolved", "mechanism_absent"),
    _row("ob-excluded", "capability_excluded", None),
    _row("ob-governance", "governance_only", None),
)
REALIZATION = SimpleNamespace(
    records=(
        SimpleNamespace(
            obligation_id="ob-llm01-addressed", stop_reason="scenario_realized"
        ),
        SimpleNamespace(obligation_id="ob-llm02", stop_reason="scenario_realized"),
    )
)


def _funnel() -> dict[str, Any]:
    return _obligation_resolution_funnel(
        plan=PLAN,
        accounting=SimpleNamespace(rows=ROWS),
        realization=REALIZATION,
        scenario_count=2,
    )


def test_the_existing_denominator_is_unchanged() -> None:
    funnel = _funnel()

    assert funnel["applicable_and_considered"] == 7
    assert funnel["terminal_reason_total"] == 7
    assert funnel["reconciles"] is True
    assert funnel["realized_obligation_denominator"] == 2


def test_the_second_denominator_excludes_exactly_the_fan_out_rows() -> None:
    block = _funnel()["applicable_without_llm_fan_out"]

    assert block == {
        "rule": FAN_OUT_RULE,
        "fan_out_llm_codes": ["LLM01", "LLM07"],
        "applicable": 3,
        "fan_out_excluded": 4,
        "fan_out_excluded_by_attack_pattern": {
            "AP-T10-01": 1,
            "AP-T15-01": 1,
            "AP-T5-05": 1,
            "AP-T6-10": 1,
        },
        "realized_obligations": 1,
        "fan_out_realized": 1,
    }
    assert (
        block["applicable"] + block["fan_out_excluded"]
        == (_funnel()["applicable_and_considered"])
    )


def test_the_rule_names_the_codes_and_the_every_path_condition() -> None:
    assert FAN_OUT_LLM_CODES == ("LLM01", "LLM07")
    assert "every mapping path" in FAN_OUT_RULE
    assert "LLM01 or LLM07" in FAN_OUT_RULE


def test_a_row_also_reached_through_another_llm_code_stays_in() -> None:
    plan = SimpleNamespace(obligations=(PLAN.obligations[4],))
    funnel = _obligation_resolution_funnel(
        plan=plan,
        accounting=SimpleNamespace(rows=(ROWS[4],)),
        realization=SimpleNamespace(records=()),
        scenario_count=0,
    )

    assert funnel["applicable_without_llm_fan_out"]["applicable"] == 1
    assert funnel["applicable_without_llm_fan_out"]["fan_out_excluded"] == 0


def test_a_row_without_mapping_evidence_stays_in() -> None:
    plan = SimpleNamespace(
        obligations=(
            SimpleNamespace(obligation_id="ob-x", attack_pattern_id="AP-T6-10"),
        )
    )
    funnel = _obligation_resolution_funnel(
        plan=plan,
        accounting=SimpleNamespace(
            rows=(_row("ob-x", "unresolved", "no_structural_route"),)
        ),
        realization=SimpleNamespace(records=()),
        scenario_count=0,
    )

    assert funnel["applicable_without_llm_fan_out"]["applicable"] == 1


def _with_block(tmp_path: Path) -> Path:
    output = copy_run(tmp_path)
    edit_yaml(
        output / "synthesis-manifest.yaml",
        lambda manifest: manifest["obligation_resolution_funnel"].update(
            applicable_without_llm_fan_out={
                "rule": FAN_OUT_RULE,
                "fan_out_llm_codes": ["LLM01", "LLM07"],
                "applicable": 30,
                "fan_out_excluded": 65,
                "fan_out_excluded_by_attack_pattern": {"AP-T15-01": 40, "AP-T6-10": 25},
                "realized_obligations": 1,
                "fan_out_realized": 1,
            }
        ),
    )
    return output


def test_the_report_renders_both_denominators(tmp_path: Path) -> None:
    html = str(obligation_section(load_run(_with_block(tmp_path))))
    shown = metrics(html)

    assert shown["obligations.applicable_and_considered"] == 95
    assert shown["obligations.applicable_without_llm_fan_out"] == 30
    assert shown["obligations.fan_out_excluded"] == 65
    assert FAN_OUT_RULE in html
    assert "AP-T15-01 (40)" in html
    assert "AP-T6-10 (25)" in html


def test_a_manifest_without_the_block_renders_no_second_denominator(
    tmp_path: Path,
) -> None:
    html = str(obligation_section(load_run(copy_run(tmp_path))))

    assert "obligations.applicable_without_llm_fan_out" not in metrics(html)
    assert "fan-out" not in html
