"""An ICA slot that was never analyzed stops at its own reason.

A reply cut off at its completion cap never decodes, so the call log records
``provider_contract_failure`` for the request. A request its prompt budget
rejects is never sent. Accounting gives the obligations routed to such a slot
``provider_contract_failure`` or ``prompt_budget_exceeded`` instead of
``ica_consideration_unresolved``, which names a slot the analysis left
unresolved. A slot left unresolved on the analysis keeps its reason, also
beside a slot that was never analyzed.
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
from asago_scenario_generator.stpa.infra.prompt_preflight import PromptBudget
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


def _routed_fill(
    tmp_path: Path,
    replies: dict[str, Any],
    *slot_ids: str,
    prompt_budget: PromptBudget | None = None,
):
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
            _SlotClient(replies),
            run_dir=tmp_path,
            controls=_controls(),
            prompt_budget=prompt_budget,
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


def test_slot_request_rejected_by_its_prompt_budget_stops_at_the_budget(
    tmp_path: Path,
) -> None:
    """A request its budget rejects is never sent, so no analysis ran."""
    budget = PromptBudget(
        context_window=8192 + 64, maximum_completion_tokens=8192, safety_margin=0
    )

    filled, row = _routed_fill(tmp_path, {}, _ROUTED_SLOT, prompt_budget=budget)

    entries = read_calls_jsonl(tmp_path)
    assert entries and not any(item["success"] for item in entries)
    assert all(
        item["error"].startswith("PromptBudgetExceeded: prompt_budget_exceeded")
        for item in entries
    )
    assert [pair.disposition for pair in filled.considerations] == ["unresolved"]
    assert [item.code for item in filled.considerations[0].diagnostics] == [
        "slot_prompt_budget_exceeded"
    ]
    assert (row.disposition, row.stop_reason) == (
        "unresolved",
        "prompt_budget_exceeded",
    )
    assert [item.code for item in row.diagnostics] == ["slot_prompt_budget_exceeded"]
    assert "rendered prompt uses" in row.diagnostics[0].detail


def test_budget_rejection_inside_the_provider_call_is_classified_by_its_cause() -> None:
    """A rejection the provider call reports reaches slot filling as the cause."""
    from asago_scenario_generator.stpa.infra.prompt_preflight import (
        PromptBudgetExceeded,
    )
    from asago_scenario_generator.stpa.obligation_aware.slot_filling import (
        _unresolved_diagnostic_code,
        _unresolved_pair_code,
    )

    budget = PromptBudgetExceeded(
        input_tokens=10,
        usable_input_tokens=5,
        context_window=15,
        maximum_completion_tokens=5,
        safety_margin=0,
    )
    wrapped = ValueError(str(budget))
    wrapped.__cause__ = budget

    for error in (budget, wrapped):
        assert _unresolved_pair_code(error) == "slot_prompt_budget_exceeded"
        assert _unresolved_diagnostic_code(error) == "prompt_budget_exceeded"
    assert _unresolved_pair_code(ValueError("other")) == "slot_pair_unresolved"


@pytest.mark.parametrize(
    ("codes", "stop_reason"),
    [
        (("slot_prompt_budget_exceeded",), "prompt_budget_exceeded"),
        (
            ("slot_prompt_budget_exceeded", "slot_provider_contract_failed"),
            "prompt_budget_exceeded",
        ),
        (
            ("slot_prompt_budget_exceeded", "slot_pair_unresolved"),
            "ica_consideration_unresolved",
        ),
        (
            ("slot_prompt_budget_exceeded", "ica_hazard_contradictory"),
            "ica_hazard_contradictory",
        ),
    ],
    ids=["budget", "budget-and-lost-reply", "beside-analytic", "beside-verification"],
)
def test_budget_rejected_slot_yields_to_an_analytic_or_verification_stop(
    codes: tuple[str, ...], stop_reason: str
) -> None:
    """A budget rejection comes before a lost reply; analysis outranks both."""
    plan = make_plan()
    briefs = build_neutral_briefs(
        plan, (AttackPattern.model_validate(get_test_raw_pattern()),)
    )
    slots = (_ROUTED_SLOT, _SECOND_SLOT)
    route = ObligationRoute(
        obligation_id=briefs[0].obligation_id,
        disposition="targeted",
        slot_ids=slots[: len(codes)],
        hazard_ids=("H-1",),
        constraint_ids=("SC-1",),
        evidence=("route",),
    )
    consideration = build_consideration_artifact(
        plan=plan, briefs=briefs, initial_routes=(route,), final_routes=(route,)
    )
    pairs = tuple(
        ObligationIcaConsideration(
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
        for slot_id, code in zip(slots, codes)
    )

    row = build_obligation_accounting(
        plan=plan,
        consideration=consideration,
        ica_considerations=pairs,
        source_pins=_accounting_pins(plan),
    ).rows[0]

    assert (row.disposition, row.stop_reason) == ("unresolved", stop_reason)
