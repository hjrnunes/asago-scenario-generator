"""An ICA slot reply cut off at its completion cap is a provider contract failure.

The reply never decodes, so the call log records ``provider_contract_failure``
for the request. Accounting gives the obligations routed to that slot the same
stop reason instead of ``ica_consideration_unresolved``, which names a slot the
analysis left unresolved. A slot left unresolved on the analysis keeps its
reason, also beside a slot whose reply was lost.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from asago_scenario_generator.models.attack_pattern_chain import AttackPattern
from asago_scenario_generator.models.obligation_consideration import (
    ConsiderationDiagnostic,
    ObligationIcaConsideration,
    ObligationRoute,
)
from asago_scenario_generator.pipeline.obligation_consideration import (
    build_consideration_artifact,
    build_neutral_briefs,
    build_obligation_accounting,
)
from asago_scenario_generator.stpa.infra.llm import LLMResult
from asago_scenario_generator.stpa.obligation_aware.contracts import (
    IcaDeviationDraft,
    IcaFindingDraft,
    ObligationIcaDraft,
    SlotIcaDraft,
)
from asago_scenario_generator.stpa.obligation_aware.provider import (
    ObligationAwareLLMAdapter,
)
from asago_scenario_generator.stpa.obligation_aware.slot_filling import (
    fill_synthesis_slots,
)
from tests.helpers.calls_log import read_calls_jsonl
from tests.helpers.governance import _accounting_pins
from tests.helpers.obligation_aware import (
    _control_structure,
    _controls,
    _loss_analysis,
    provider_slot_payload,
)
from tests.helpers.obligation_factory import make_plan
from tests.helpers.projection_factory import get_test_raw_pattern
from tests.helpers.scripted_client import ScriptedClient

_FIXTURE = (
    Path(__file__).parent
    / "fixtures"
    / "ica_fill"
    / "reply-truncated-at-completion-cap.yaml"
)
_ROUTED_SLOT = "RESP-1:CA-1-1:INCORRECT"
_SECOND_SLOT = "RESP-1:CA-1-1:WRONG_TIMING"
_SLOT_ID = re.compile(r"^\s*id: (RESP-1:\S+)$", re.MULTILINE)
_DEVIATION_FIELDS = {
    _ROUTED_SLOT: "incorrect_value_or_effect",
    _SECOND_SLOT: "timing_deviation",
}


class _SlotClient(ScriptedClient):
    """Answer each single-slot request with the reply listed for its slot.

    A slot without a listed reply is answered not applicable.
    """

    def __init__(self, replies: dict[str, Any]) -> None:
        super().__init__([], max_completion_tokens=8192)
        self._replies = replies

    def complete(self, **kwargs: Any) -> LLMResult:
        self.calls.append(kwargs)
        # The prompt names its own slot first; route rows list other slots.
        match = _SLOT_ID.search(kwargs["user_prompt"])
        assert match is not None
        slot_id = match.group(1)
        reply = self._replies.get(slot_id)
        if isinstance(reply, LLMResult):
            return reply
        content = reply or {
            "filled_slots": [
                {
                    "slot_id": slot_id,
                    "is_na": True,
                    "na_rationale": "No routed concern applies.",
                    "findings": [],
                    "consideration_results": {},
                }
            ]
        }
        return LLMResult(
            content=content, prompt_tokens=1, completion_tokens=1, duration_ms=1
        )


def _truncated_reply() -> tuple[dict[str, Any], LLMResult]:
    """Serve the recorded reply that stopped at its completion cap."""
    captured = yaml.safe_load(_FIXTURE.read_text(encoding="utf-8"))
    assert captured["finish_reason"] == "length"
    assert captured["completion_tokens"] == captured["max_completion_tokens"]
    return captured, LLMResult(
        content=captured["content"],
        raw_response=captured["content"],
        prompt_tokens=1,
        completion_tokens=captured["completion_tokens"],
        finish_reason=captured["finish_reason"],
        duration_ms=1,
    )


def _unresolved_reply(
    handle: str, slot_id: str, disposition: str = "unresolved"
) -> dict[str, Any]:
    """Analyze the slot but leave the routed obligation unresolved.

    A ``proposed_not_applicable`` result beside the slot's finding breaks a
    semantic rule the reply's schema cannot express.
    """
    draft = SlotIcaDraft(
        slot_id=slot_id,
        is_na=False,
        findings=(
            IcaFindingDraft(
                deviation=IcaDeviationDraft(
                    **{
                        _DEVIATION_FIELDS[slot_id]: (
                            "the request is checked against outdated rules"
                        )
                    }
                ),
                hazardous_context="the unreviewed request reaches the process",
                loss_consequence="the protected operation is harmed",
                related_hazard_ids=("H-1",),
                related_constraint_ids=("SC-1",),
            ),
        ),
        consideration_results=(
            ObligationIcaDraft(
                obligation_handle=handle,
                disposition=disposition,
                rationale="The supplied context cannot show whether this applies.",
            ),
        ),
    )
    return {"filled_slots": [provider_slot_payload(draft)]}


def _routed_fill(tmp_path: Path, replies: dict[str, Any], *slot_ids: str):
    """Fill the small structure's slots with one obligation routed to *slot_ids*."""
    plan = make_plan()
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    briefs = build_neutral_briefs(plan, (pattern,))
    route = ObligationRoute(
        obligation_id=briefs[0].obligation_id,
        disposition="targeted",
        slot_ids=slot_ids,
        hazard_ids=("H-1",),
        constraint_ids=("SC-1",),
        rationale="The validation path is structurally relevant.",
        evidence=("RESP-1", "H-1", "SC-1"),
    )
    consideration = build_consideration_artifact(
        plan=plan, briefs=briefs, initial_routes=(route,), final_routes=(route,)
    )
    filled = fill_synthesis_slots(
        ObligationAwareLLMAdapter(
            _SlotClient(replies), run_dir=tmp_path, controls=_controls()
        ),
        briefs=briefs,
        routes=(route,),
        loss_analysis=_loss_analysis(),
        control_structure=_control_structure(),
        controls=_controls(),
    )
    accounting = build_obligation_accounting(
        plan=plan,
        consideration=consideration,
        ica_considerations=filled.considerations,
        source_pins=_accounting_pins(plan),
    )
    return filled, accounting.rows[0]


def test_reply_cut_off_at_completion_cap_is_a_provider_contract_failure(
    tmp_path: Path,
) -> None:
    captured, reply = _truncated_reply()

    filled, row = _routed_fill(tmp_path, {_ROUTED_SLOT: reply}, _ROUTED_SLOT)

    entry = next(
        item
        for item in read_calls_jsonl(tmp_path)
        if item.get("error", "").startswith("JSONDecodeError")
    )
    assert entry["error"].startswith("JSONDecodeError: Unterminated string")
    assert captured["original_decode_error"].startswith("Unterminated string")
    assert entry["terminal_error_codes"] == ["provider_contract_failure"]
    assert [pair.disposition for pair in filled.considerations] == ["unresolved"]
    assert (row.disposition, row.stop_reason) == (
        "unresolved",
        "provider_contract_failure",
    )
    assert [item.code for item in row.diagnostics] == ["slot_provider_contract_failed"]
    assert "JSONDecodeError: Unterminated string" in row.diagnostics[0].detail


def test_slot_left_unresolved_by_the_analysis_keeps_its_stop_reason(
    tmp_path: Path,
) -> None:
    replies = {_ROUTED_SLOT: _unresolved_reply("R1", _ROUTED_SLOT)}

    filled, row = _routed_fill(tmp_path, replies, _ROUTED_SLOT)

    assert all(item["success"] for item in read_calls_jsonl(tmp_path))
    assert [pair.disposition for pair in filled.considerations] == ["unresolved"]
    assert (row.disposition, row.stop_reason) == (
        "unresolved",
        "ica_consideration_unresolved",
    )
    assert [item.code for item in row.diagnostics] == ["unresolved_ica_consideration"]


def test_reply_failing_semantic_validation_keeps_the_unresolved_stop(
    tmp_path: Path,
) -> None:
    """A reply that decodes and fits its schema but is judged invalid is analytic."""
    replies = {
        _ROUTED_SLOT: _unresolved_reply("R1", _ROUTED_SLOT, "proposed_not_applicable")
    }

    filled, row = _routed_fill(tmp_path, replies, _ROUTED_SLOT)

    failed = [item for item in read_calls_jsonl(tmp_path) if not item["success"]]
    assert failed
    assert {tuple(item["terminal_error_codes"]) for item in failed} == {
        ("provider_semantic_validation_failure",)
    }
    assert [pair.disposition for pair in filled.considerations] == ["unresolved"]
    assert row.stop_reason == "ica_consideration_unresolved"
    assert [item.code for item in row.diagnostics] == [
        "slot_pair_unresolved",
        "unresolved_ica_consideration",
    ]


def test_analytic_slot_beside_a_lost_reply_keeps_the_unresolved_stop(
    tmp_path: Path,
) -> None:
    _captured, reply = _truncated_reply()
    replies = {
        _ROUTED_SLOT: reply,
        _SECOND_SLOT: _unresolved_reply("R1", _SECOND_SLOT),
    }

    filled, row = _routed_fill(tmp_path, replies, _ROUTED_SLOT, _SECOND_SLOT)

    assert sorted(pair.slot_id for pair in filled.considerations) == [
        _ROUTED_SLOT,
        _SECOND_SLOT,
    ]
    assert row.stop_reason == "ica_consideration_unresolved"
    assert [item.code for item in row.diagnostics] == [
        "slot_provider_contract_failed",
        "unresolved_ica_consideration",
    ]


@pytest.mark.parametrize(
    ("verification_code", "stop_reason"),
    [
        ("ica_hazard_contradictory", "ica_hazard_contradictory"),
        ("slot_pair_unresolved", "ica_consideration_unresolved"),
    ],
)
def test_lost_reply_beside_another_unresolved_pair_yields_to_it(
    verification_code: str, stop_reason: str
) -> None:
    """A verification stop or an analytic slot outranks the lost reply."""
    plan = make_plan()
    briefs = build_neutral_briefs(
        plan, (AttackPattern.model_validate(get_test_raw_pattern()),)
    )
    route = ObligationRoute(
        obligation_id=briefs[0].obligation_id,
        disposition="targeted",
        slot_ids=(_ROUTED_SLOT, _SECOND_SLOT),
        hazard_ids=("H-1",),
        constraint_ids=("SC-1",),
        evidence=("route",),
    )
    consideration = build_consideration_artifact(
        plan=plan, briefs=briefs, initial_routes=(route,), final_routes=(route,)
    )

    def pair(slot_id: str, code: str) -> ObligationIcaConsideration:
        return ObligationIcaConsideration(
            route_id=route.route_id,
            obligation_id=route.obligation_id,
            slot_id=slot_id,
            disposition="unresolved",
            evidence=("slot-analysis-validation",),
            rationale="The slot stayed unresolved.",
            diagnostics=(
                ConsiderationDiagnostic(
                    code=code,
                    detail="The slot stayed unresolved.",
                    obligation_ids=(route.obligation_id,),
                    refs=(route.route_id, slot_id),
                ),
            ),
        )

    row = build_obligation_accounting(
        plan=plan,
        consideration=consideration,
        ica_considerations=(
            pair(_ROUTED_SLOT, "slot_provider_contract_failed"),
            pair(_SECOND_SLOT, verification_code),
        ),
        source_pins=_accounting_pins(plan),
    ).rows[0]

    assert (row.disposition, row.stop_reason) == ("unresolved", stop_reason)
