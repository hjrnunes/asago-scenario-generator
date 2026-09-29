"""Stage 1a recovery of a risk-derivation response cut off at its token cap.

Two saved Airbnb risk-derivation responses (runs airbnb-g4 and airbnb-g10,
2026-09-29) stopped at the 8,192-token completion cap while the model
repeated rows of ``risk_dispositions``.  Their losses, hazards, and
constraints were complete and every repeated row agreed with its first copy.
These tests reproduce that shape with the neutralized fixtures of the
targeted-repair suite.  Every test uses a fake client and contacts no network.
"""

from __future__ import annotations

import json

import pytest

from acceptance.fixture_adapters import legacy_stage1a_provider_payload
from asago_scenario_generator.stpa.infra.llm import LLMResult
from asago_scenario_generator.stpa.infra.llm_helpers import StageError
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysisDraft
from asago_scenario_generator.stpa.system_model.loss_analysis import (
    STAGE1A_MAX_COMPLETION_TOKENS,
    derive_loss_analysis,
)
from asago_scenario_generator.stpa.system_model.loss_analysis_repair import (
    TRUNCATED_DISPOSITION_RECOVERY_KIND,
    DispositionRepairResponse,
    recover_truncated_risk_dispositions,
)
from tests.stpa.sp1_helpers import MockLLMClient
from tests.stpa.test_stage1a_targeted_repair import (
    _SAVED_MISSING_SEVEN,
    _USE_CASE,
    _attempt_two_response,
    _disposition_repair_rows,
    _empty_gap_response,
    _occiai_cards,
    _repair_record,
    _stage1a_entries,
)

_CAP = STAGE1A_MAX_COMPLETION_TOKENS


def _looped_text(*, repeat: int = 20) -> str:
    """A provider body cut off mid-row after repeating agreeing rows."""
    wire = legacy_stage1a_provider_payload(
        _attempt_two_response(), risk=True, preserve_gap_extras=False
    )
    rows = wire["risk_dispositions"]
    wire["risk_dispositions"] = rows + rows[:repeat]
    text = json.dumps(wire, ensure_ascii=False)
    closing = text.rfind("]")
    partial = json.dumps(rows[repeat], ensure_ascii=False)[:40]
    return text[:closing] + ", " + partial


def _result(content, *, completion_tokens: int = _CAP) -> LLMResult:
    return LLMResult(
        content=content,
        completion_tokens=completion_tokens,
        duration_ms=1,
        request_controls={"max_completion_tokens": _CAP},
    )


class _CapClient(MockLLMClient):
    """Report a completion-cap stop for undecodable string bodies."""

    def __init__(self, *, completion_tokens: int = _CAP) -> None:
        super().__init__()
        self._stop_tokens = completion_tokens

    def complete(self, *args, **kwargs) -> LLMResult:
        result = super().complete(*args, **kwargs)
        if isinstance(result.content, str):
            try:
                json.loads(result.content)
            except json.JSONDecodeError:
                return result.model_copy(
                    update={
                        "completion_tokens": self._stop_tokens,
                        "request_controls": {
                            "max_completion_tokens": kwargs.get("max_completion_tokens")
                        },
                    }
                )
        return result


def test_recovery_keeps_complete_graph_and_collapses_agreeing_rows():
    recovered = recover_truncated_risk_dispositions(_result(_looped_text()))

    assert recovered is not None
    result, recovery = recovered
    content = json.loads(result.content)
    assert len(content["risk_card_losses"]) == 7
    assert len(content["security_constraints"]) == 7
    refs = [row["risk_ref"] for row in content["risk_dispositions"]]
    assert len(refs) == len(set(refs)) == 105
    assert recovery.complete_rows == 125
    assert recovery.kept_rows == 105
    assert len(recovery.collapsed_refs) == 20
    assert set(_SAVED_MISSING_SEVEN).isdisjoint(refs)


def test_recovery_keeps_conflicting_duplicates_for_the_repair():
    wire = legacy_stage1a_provider_payload(
        _attempt_two_response(), risk=True, preserve_gap_extras=False
    )
    first = wire["risk_dispositions"][0]
    conflicting = {
        "risk_ref": first["risk_ref"],
        "disposition": "not_applicable",
        "loss_ids": [],
        "reason": "Neutralized reason.",
    }
    wire["risk_dispositions"].append(conflicting)
    text = json.dumps(wire)
    text = text[: text.rfind("]")] + ', {"risk_ref": "cut'

    result, recovery = recover_truncated_risk_dispositions(_result(text))

    rows = json.loads(result.content)["risk_dispositions"]
    assert [row["risk_ref"] for row in rows].count(first["risk_ref"]) == 2
    assert recovery.collapsed_refs == ()


@pytest.mark.parametrize(
    "text,completion_tokens",
    [
        pytest.param(_looped_text(), _CAP - 1, id="below-cap"),
        pytest.param(_looped_text()[:900], _CAP, id="cut-before-dispositions"),
        pytest.param(json.dumps({"risk_dispositions": []}), _CAP, id="decodes"),
    ],
)
def test_recovery_applies_only_to_cut_off_disposition_lists(text, completion_tokens):
    result = _result(text, completion_tokens=completion_tokens)
    assert recover_truncated_risk_dispositions(result) is None


def test_cut_off_response_reaches_the_disposition_repair(tmp_path):
    client = _CapClient()
    client.set_response_for(LossAnalysisDraft, [_looped_text(), _empty_gap_response()])
    client.set_response_for(
        DispositionRepairResponse,
        {"risk_dispositions": _disposition_repair_rows()},
    )

    result = derive_loss_analysis(
        llm_client=client,
        use_case_text=_USE_CASE,
        risk_cards=_occiai_cards(),
        run_dir=tmp_path,
    )

    assert len(result.risk_dispositions) == 112
    assert len({row.risk_ref for row in result.risk_dispositions}) == 112
    assert len(result.security_constraints) == 7
    entries = _stage1a_entries(tmp_path)
    assert [entry["step"] for entry in entries] == [
        "risk_derivation",
        "risk_derivation_repair",
        "gap_analysis",
    ]
    repair_prompt = entries[1]["user_prompt_text"]
    for risk_id in _SAVED_MISSING_SEVEN:
        assert risk_id in repair_prompt
    assert "duplicate risk_dispositions entries" not in repair_prompt
    cleanup_names = [
        item["name"] for item in entries[0].get("cleanup_transformations", [])
    ]
    assert TRUNCATED_DISPOSITION_RECOVERY_KIND in cleanup_names
    recovery_entries = [
        entry
        for entry in _repair_record(tmp_path)["records"]
        if entry["kind"] == TRUNCATED_DISPOSITION_RECOVERY_KIND
    ]
    assert len(recovery_entries) == 1
    assert recovery_entries[0]["applied"]["kept_rows"] == 105
    assert recovery_entries[0]["outcome"] == "applied"


def test_undecodable_response_below_the_cap_stays_terminal(tmp_path):
    client = _CapClient(completion_tokens=_CAP - 1)
    client.set_response_for(LossAnalysisDraft, [_looped_text(), _empty_gap_response()])

    with pytest.raises(StageError, match="never decoded as JSON"):
        derive_loss_analysis(
            llm_client=client,
            use_case_text=_USE_CASE,
            risk_cards=_occiai_cards(),
            run_dir=tmp_path,
        )
    assert [entry["step"] for entry in _stage1a_entries(tmp_path)] == [
        "risk_derivation"
    ]


def test_risk_prompts_ask_for_rows_in_supplied_order(tmp_path):
    client = MockLLMClient()
    client.set_response_for(
        LossAnalysisDraft,
        [_attempt_two_response(), _empty_gap_response()],
    )
    client.set_response_for(
        DispositionRepairResponse,
        {"risk_dispositions": _disposition_repair_rows()},
    )
    derive_loss_analysis(
        llm_client=client,
        use_case_text=_USE_CASE,
        risk_cards=_occiai_cards(),
        run_dir=tmp_path,
    )
    call = client.calls[0]
    assert "in the order the risks are supplied" in " ".join(call.system_prompt.split())
    assert "in the order the risks appear above" in " ".join(call.user_prompt.split())
