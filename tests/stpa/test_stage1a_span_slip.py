"""A rule_span slip in a Stage 1a obligation must not stop the run.

A deterministic span repair has to reach every draft a later validator reads,
including the response the targeted repair adapts after another defect sent
the first attempt there.  A slip that no repair maps drops its obligation and
records the drop.
"""

from __future__ import annotations

import pytest

from asago_scenario_generator.stpa.infra.llm_helpers import StageError
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysisDraft
from asago_scenario_generator.stpa.system_model.loss_analysis import (
    derive_loss_analysis,
)
from asago_scenario_generator.stpa.system_model.loss_analysis_repair import (
    DispositionRepairResponse,
    ObligationRepairResponse,
)
from tests.stpa.sp1_helpers import MockLLMClient
from tests.helpers.stage1a_targeted_repair import (
    _USE_CASE,
    _VALID_OBLIGATION,
    _attempt_two_response,
    _complete_risk_response,
    _disposition_repair_rows,
    _empty_gap_response,
    _gap_constraint_defect_response,
    _occiai_cards,
    _repair_record,
    _stage1a_entries,
)

ELLIPSIS_SPAN = "no sensitive health data... in model outputs"
REPAIRED_SPAN = "no sensitive health data is included in model outputs"
UNMAPPABLE_SPAN = "health records are never shared"
GAP_RULE = "The neutralized system must uphold control SC-8."


def _risk_response_with_span(span: str) -> dict:
    """The seven-missing-dispositions response, SC-1/O1 quoting ``span``."""
    response = _attempt_two_response()
    response["security_constraints"][0]["obligations"] = [
        dict(_VALID_OBLIGATION) | {"rule_span": span}
    ]
    return response


def _derive(tmp_path, responses: list[dict], *, repair: dict | None = None):
    client = MockLLMClient()
    client.set_response_for(LossAnalysisDraft, responses)
    client.set_response_for(
        DispositionRepairResponse,
        {"risk_dispositions": _disposition_repair_rows()},
    )
    if repair is not None:
        client.set_response_for(ObligationRepairResponse, repair)
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


def _entry(obligation_id: str, span: str) -> dict:
    return dict(_VALID_OBLIGATION) | {
        "obligation_id": obligation_id,
        "behavior": f"behavior of {obligation_id}",
        "rule_span": span,
    }


def _risk_with_obligations(obligations: list[dict]) -> dict:
    response = _complete_risk_response()
    response["security_constraints"][0]["obligations"] = obligations
    return response


def _obligation_repair(constraint_id: str, obligations: list[dict]) -> dict:
    return {
        "constraints": [{"constraint_id": constraint_id, "obligations": obligations}]
    }


def _dropped_entries(tmp_path) -> list[dict]:
    return [
        entry
        for entry in _repair_record(tmp_path)["records"]
        if entry["kind"] == "rule_span_dropped"
    ]


def test_risk_derivation_drops_an_obligation_whose_span_stays_unmapped(
    tmp_path,
) -> None:
    kept = _entry("O2", "no sensitive health data")
    risk = _risk_with_obligations([_entry("O1", UNMAPPABLE_SPAN), kept])
    repair = _obligation_repair("SC-1", [_entry("O1", UNMAPPABLE_SPAN), kept])
    warnings: list[str] = []
    client = MockLLMClient()
    client.set_response_for(LossAnalysisDraft, [risk, _empty_gap_response()])
    client.set_response_for(ObligationRepairResponse, repair)

    result = derive_loss_analysis(
        llm_client=client,
        use_case_text=_USE_CASE,
        risk_cards=_occiai_cards(),
        run_dir=tmp_path,
        normalization_warnings=warnings,
    )

    assert [o.obligation_id for o in result.security_constraints[0].obligations] == [
        "O2"
    ]
    assert [entry["step"] for entry in _stage1a_entries(tmp_path)] == [
        "risk_derivation",
        "risk_derivation_repair",
        "gap_analysis",
    ]
    (dropped,) = _dropped_entries(tmp_path)
    assert (dropped["stage"], dropped["identity"], dropped["outcome"]) == (
        "risk_derivation",
        "SC-1/O1",
        "dropped",
    )
    assert dropped["proposed"]["rule_span"] == UNMAPPABLE_SPAN
    assert dropped["proposed"]["rule"].startswith("The system must ensure")
    assert dropped["applied"] == {"dropped_entries": ["O1"]}
    assert any(
        "risk_derivation rule_span SC-1/O1 dropped" in warning for warning in warnings
    )
    repaired_identities = [
        entry["identity"]
        for entry in _repair_record(tmp_path)["records"]
        if entry["kind"] == "repair"
    ]
    assert "SC-1/O1" not in repaired_identities


def test_a_corrected_span_that_a_repair_maps_is_kept(tmp_path) -> None:
    kept = _entry("O2", "no sensitive health data")
    risk = _risk_with_obligations([_entry("O1", UNMAPPABLE_SPAN), kept])
    repair = _obligation_repair("SC-1", [_entry("O1", ELLIPSIS_SPAN), kept])
    warnings: list[str] = []
    client = MockLLMClient()
    client.set_response_for(LossAnalysisDraft, [risk, _empty_gap_response()])
    client.set_response_for(ObligationRepairResponse, repair)

    result = derive_loss_analysis(
        llm_client=client,
        use_case_text=_USE_CASE,
        risk_cards=_occiai_cards(),
        run_dir=tmp_path,
        normalization_warnings=warnings,
    )

    obligations = result.security_constraints[0].obligations
    assert [(o.obligation_id, o.rule_span) for o in obligations] == [
        ("O1", REPAIRED_SPAN),
        ("O2", "no sensitive health data"),
    ]
    assert _dropped_entries(tmp_path) == []
    records = _repair_record(tmp_path)["records"]
    (span_entry,) = [e for e in records if e["kind"] == "rule_span_repaired"]
    assert (
        span_entry["stage"],
        span_entry["attempt"],
        span_entry["identity"],
        span_entry["outcome"],
        span_entry["raw_step"],
    ) == ("risk_derivation", "repair", "SC-1/O1", "applied", "risk_derivation_repair")
    assert span_entry["proposed"] == {"rule_span": ELLIPSIS_SPAN}
    assert span_entry["applied"] == {"rule_span": REPAIRED_SPAN, "match": "ellipsis"}
    (repair_entry,) = [e for e in records if e["kind"] == "repair"]
    assert (repair_entry["identity"], repair_entry["outcome"]) == (
        "SC-1/O1",
        "repaired",
    )
    assert (
        "risk_derivation rule_span SC-1/O1 repaired by ellipsis match: "
        f"{ELLIPSIS_SPAN!r} -> {REPAIRED_SPAN!r}"
    ) in warnings


def test_a_constraint_that_loses_its_last_obligation_is_dropped(tmp_path) -> None:
    risk = _risk_with_obligations([_entry("O1", UNMAPPABLE_SPAN)])
    repair = _obligation_repair("SC-1", [_entry("O1", UNMAPPABLE_SPAN)])
    client = MockLLMClient()
    client.set_response_for(LossAnalysisDraft, [risk, _empty_gap_response()])
    client.set_response_for(ObligationRepairResponse, repair)

    result = derive_loss_analysis(
        llm_client=client,
        use_case_text=_USE_CASE,
        risk_cards=_occiai_cards(),
        run_dir=tmp_path,
    )

    assert [c.constraint_id for c in result.security_constraints] == [
        f"SC-{number}" for number in range(2, 8)
    ]
    (dropped,) = _dropped_entries(tmp_path)
    assert dropped["applied"] == {
        "dropped_entries": ["O1"],
        "constraint_dropped": "SC-1",
    }
    assert "constraint was dropped" in dropped["reason"]


def test_gap_analysis_drops_an_obligation_whose_span_stays_unmapped(tmp_path) -> None:
    kept = _entry("O2", "must uphold control SC-8")
    gap = _gap_constraint_defect_response()
    gap["security_constraints"][0]["obligations"] = [
        _entry("O1", UNMAPPABLE_SPAN),
        kept,
    ]
    repair = _obligation_repair("SC-8", [_entry("O1", UNMAPPABLE_SPAN), kept])
    client = MockLLMClient()
    client.set_response_for(LossAnalysisDraft, [_complete_risk_response(), gap])
    client.set_response_for(ObligationRepairResponse, repair)

    result = derive_loss_analysis(
        llm_client=client,
        use_case_text=_USE_CASE,
        risk_cards=_occiai_cards(),
        run_dir=tmp_path,
    )

    gap_constraint = result.security_constraints[7]
    assert gap_constraint.constraint_id == "SC-8"
    assert [o.obligation_id for o in gap_constraint.obligations] == ["O2"]
    (dropped,) = _dropped_entries(tmp_path)
    assert (dropped["stage"], dropped["identity"]) == ("gap_analysis", "SC-8/O1")
    assert dropped["proposed"]["rule"] == GAP_RULE


def test_a_slipping_span_beside_an_unrelated_edit_still_stops(tmp_path) -> None:
    kept = _entry("O2", "no sensitive health data")
    risk = _risk_with_obligations([_entry("O1", UNMAPPABLE_SPAN), kept])
    rewritten = _entry("O1", UNMAPPABLE_SPAN) | {"behavior": "a rewritten behavior"}
    client = MockLLMClient()
    client.set_response_for(LossAnalysisDraft, [risk])
    client.set_response_for(
        ObligationRepairResponse, _obligation_repair("SC-1", [rewritten, kept])
    )

    with pytest.raises(StageError, match="repair_unrelated_field_edit"):
        derive_loss_analysis(
            llm_client=client,
            use_case_text=_USE_CASE,
            risk_cards=_occiai_cards(),
            run_dir=tmp_path,
        )
