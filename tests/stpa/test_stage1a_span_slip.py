"""A rule_span slip in a Stage 1a obligation must not stop the run.

A deterministic span repair has to reach every draft a later validator reads,
including the response the targeted repair adapts after another defect sent
the first attempt there.  A slip that no deterministic repair maps drops its
obligation and records the drop.
"""

from __future__ import annotations

from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysisDraft
from asago_scenario_generator.stpa.system_model.loss_analysis import (
    derive_loss_analysis,
)
from asago_scenario_generator.stpa.system_model.loss_analysis_repair import (
    DispositionRepairResponse,
)
from tests.stpa.sp1_helpers import MockLLMClient
from tests.stpa.test_stage1a_targeted_repair import (
    _USE_CASE,
    _VALID_OBLIGATION,
    _attempt_two_response,
    _disposition_repair_rows,
    _empty_gap_response,
    _occiai_cards,
    _repair_record,
    _stage1a_entries,
)

ELLIPSIS_SPAN = "no sensitive health data... in model outputs"
REPAIRED_SPAN = "no sensitive health data is included in model outputs"


def _risk_response_with_span(span: str) -> dict:
    """The seven-missing-dispositions response, SC-1/O1 quoting ``span``."""
    response = _attempt_two_response()
    response["security_constraints"][0]["obligations"] = [
        dict(_VALID_OBLIGATION) | {"rule_span": span}
    ]
    return response


def _derive(tmp_path, responses: list[dict], *, repair_rows: list[dict] | None = None):
    client = MockLLMClient()
    client.set_response_for(LossAnalysisDraft, responses)
    client.set_response_for(
        DispositionRepairResponse,
        {"risk_dispositions": repair_rows or _disposition_repair_rows()},
    )
    result = derive_loss_analysis(
        llm_client=client,
        use_case_text=_USE_CASE,
        risk_cards=_occiai_cards(),
        run_dir=tmp_path,
    )
    return result, client


def test_a_span_repair_reaches_the_response_a_later_repair_adapts(tmp_path) -> None:
    result, client = _derive(
        tmp_path, [_risk_response_with_span(ELLIPSIS_SPAN), _empty_gap_response()]
    )

    assert result.security_constraints[0].obligations[0].rule_span == REPAIRED_SPAN
    assert len(result.risk_dispositions) == 112
    assert [entry["step"] for entry in _stage1a_entries(tmp_path)] == [
        "risk_derivation",
        "risk_derivation_repair",
        "gap_analysis",
    ]
    assert len(client.calls) == 3


def test_the_repair_record_marks_a_span_repair_the_run_used_as_applied(
    tmp_path,
) -> None:
    _derive(tmp_path, [_risk_response_with_span(ELLIPSIS_SPAN), _empty_gap_response()])

    span_entries = [
        entry
        for entry in _repair_record(tmp_path)["records"]
        if entry["kind"] == "rule_span_repaired"
    ]
    assert [(e["identity"], e["outcome"]) for e in span_entries] == [
        ("SC-1/O1", "applied")
    ]
    assert span_entries[0]["applied"]["rule_span"] == REPAIRED_SPAN
    assert span_entries[0]["proposed"]["rule_span"] == ELLIPSIS_SPAN


def test_the_repair_reason_is_a_complete_sentence(tmp_path) -> None:
    _derive(tmp_path, [_risk_response_with_span(ELLIPSIS_SPAN), _empty_gap_response()])

    reason = next(
        entry["reason"]
        for entry in _repair_record(tmp_path)["records"]
        if entry["kind"] == "rule_span_repaired"
    )
    assert reason.endswith("text that is a contiguous substring of the rule.")
