"""A governance route runs through the slot filler, accounting, and realization."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from asago_scenario_generator.models.attack_pattern_chain import AttackPattern
from asago_scenario_generator.models.obligation_consideration import ObligationRoute
from asago_scenario_generator.pipeline.obligation_consideration import (
    build_consideration_artifact,
    build_governance_briefs,
    build_neutral_obligation_briefs,
    build_obligation_accounting,
)
from asago_scenario_generator.pipeline.scenario_realization import (
    build_scenario_realization_assessment,
)
from asago_scenario_generator.pipeline.synthesis_defaults import _findings_by_ica
from asago_scenario_generator.pipeline.synthesis_manifest import (
    _obligation_resolution_funnel,
)
from asago_scenario_generator.stpa.infra.llm import LLMResult
from asago_scenario_generator.stpa.models.loss_analysis import RiskDisposition
from asago_scenario_generator.stpa.models.scenario_context import (
    ScenarioGenerationContext,
)
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
from asago_scenario_generator.stpa.threat_enum.slot_creation import create_slots
from tests.helpers.obligation_factory import make_plan
from tests.helpers.projection_factory import get_test_raw_pattern
from tests.stpa.helpers import (
    make_minimal_control_structure,
    make_minimal_loss_analysis,
)
from tests.helpers.governance import _accounting_pins, _controls, _governance_scenario

_SLOT_ID = "RESP-1:CA-1-1:INCORRECT"


class _Client:
    """Answer each slot request with a recorded-style structured response."""

    model = "governance-end-to-end"

    def __init__(self, routed_draft, slot_ids):
        self.routed_draft = routed_draft
        self.slot_ids = tuple(slot_ids)
        self.prompts: list[str] = []

    def _draft_for(self, slot_id):
        if slot_id == self.routed_draft.slot_id:
            return self.routed_draft
        return SlotIcaDraft(
            slot_id=slot_id, is_na=True, na_rationale="No risk bears on this slot."
        )

    def complete(self, **kwargs):
        prompt = kwargs["user_prompt"]
        self.prompts.append(prompt)
        drafts = [
            self._draft_for(slot_id).model_dump(mode="json")
            for slot_id in self.slot_ids
            if slot_id in prompt
        ]
        return LLMResult(
            content={"filled_slots": drafts},
            prompt_tokens=1,
            completion_tokens=1,
            duration_ms=1,
            system_prompt=kwargs["system_prompt"],
            user_prompt=kwargs["user_prompt"],
        )


def _world():
    """Return a plan with one pattern row and one cited governance risk."""
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    mappings = [
        {
            "source_id": "risk-a",
            "target_id": pattern.id,
            "relation": "exact_match",
            "confidence": 1.0,
        }
    ]
    plan = make_plan(risk_ids=("risk-a", "risk-b"), mappings=mappings)
    loss = make_minimal_loss_analysis().model_copy(
        update={
            "risk_dispositions": [
                RiskDisposition(
                    risk_ref="risk-b", disposition="cited", loss_ids=["L-1"]
                )
            ]
        }
    )
    governance_brief = build_governance_briefs(plan, ("risk-b",))[0]
    pattern_brief = build_neutral_obligation_briefs(plan, (pattern,))[0]
    return plan, loss, make_minimal_control_structure(), pattern_brief, governance_brief


def _draft(*, finds: bool) -> SlotIcaDraft:
    handle = "R1"  # the slot prompt names its only routed obligation R1
    if not finds:
        return SlotIcaDraft(
            slot_id=_SLOT_ID,
            is_na=True,
            na_rationale="The slot cannot express the risk.",
            consideration_results=(
                ObligationIcaDraft(
                    obligation_handle=handle,
                    disposition="unresolved",
                    rationale="the slot gives no basis for the risk",
                ),
            ),
        )
    return SlotIcaDraft(
        slot_id=_SLOT_ID,
        is_na=False,
        findings=(
            IcaFindingDraft(
                deviation=IcaDeviationDraft(
                    incorrect_value_or_effect="the action carries a stale value"
                ),
                hazardous_context="the stale value reaches the process",
                loss_consequence="the protected operation is harmed",
                related_hazard_ids=("H-1",),
                related_constraint_ids=("SC-1",),
            ),
        ),
        consideration_results=(
            ObligationIcaDraft(
                obligation_handle=handle,
                disposition="finding",
                finding_indexes=(0,),
                rationale="the finding expresses the governance risk",
            ),
        ),
    )


def _governance_route(brief, *slot_ids: str) -> ObligationRoute:
    return ObligationRoute(
        obligation_id=brief.obligation_id,
        disposition="targeted",
        slot_ids=slot_ids,
        hazard_ids=("H-1",),
        constraint_ids=("SC-1",),
        rationale="The control action could bring about the reviewed risk.",
        evidence=("governance: reviewed risk",),
    )


def _pattern_route_declined(brief) -> ObligationRoute:
    return ObligationRoute(
        obligation_id=brief.obligation_id,
        disposition="unresolved",
        rationale="No slot fits the pattern.",
        evidence=("e",),
    )


def _run(tmp_path, *, finds: bool):
    plan, loss, structure, pattern_brief, governance_brief = _world()
    assert _SLOT_ID in {slot.slot_id for slot in create_slots(structure)}
    pattern_route = _pattern_route_declined(pattern_brief)
    route = _governance_route(governance_brief, _SLOT_ID)
    client = _Client(
        _draft(finds=finds),
        [slot.slot_id for slot in create_slots(structure)],
    )
    adapter = ObligationAwareLLMAdapter(client, run_dir=tmp_path, controls=_controls())

    filled = fill_synthesis_slots(
        adapter,
        briefs=(pattern_brief, governance_brief),
        routes=(pattern_route, route),
        loss_analysis=loss,
        control_structure=structure,
        controls=_controls(),
    ).result
    consideration = build_consideration_artifact(
        plan=plan,
        briefs=(pattern_brief,),
        initial_routes=(pattern_route,),
        final_routes=(pattern_route,),
    )
    accounting = build_obligation_accounting(
        plan=plan,
        consideration=consideration,
        ica_considerations=filled.considerations,
        source_pins=_accounting_pins(plan),
        governance_routes=(route,),
    )
    return SimpleNamespace(
        plan=plan,
        client=client,
        filled=filled,
        accounting=accounting,
        governance_brief=governance_brief,
        briefs=(pattern_brief, governance_brief),
    )


def _scenario_for(world: Any, ica_id: str) -> Any:
    template = _governance_scenario()
    considerations = _findings_by_ica(world.briefs, world.filled.considerations)
    context = template.scenario_context
    rebuilt = ScenarioGenerationContext.create(
        source_pins=context.source_pins,
        scenario_identity=context.scenario_identity,
        ica=context.ica,
        target_control_path=context.target_control_path,
        losses=context.losses,
        hazards=context.hazards,
        constraints=context.constraints,
        obligation_considerations=tuple(considerations[ica_id]),
    )
    return template.model_copy(update={"scenario_context": rebuilt})


def _realize(world: Any, scenarios: tuple[Any, ...]) -> Any:
    return build_scenario_realization_assessment(
        accounting=world.accounting,
        ica_considerations=world.filled.considerations,
        ica_enumeration=world.filled.ica_enumeration,
        scenario_specs=scenarios,
    )


def _funnel(world: Any, realization: Any) -> dict[str, Any]:
    return _obligation_resolution_funnel(
        plan=world.plan,
        accounting=world.accounting,
        realization=realization,
        scenario_count=len(realization.records),
    )


def _governance_row(world: Any) -> Any:
    return next(
        row
        for row in world.accounting.rows
        if row.obligation_id == world.governance_brief.obligation_id
    )


def test_a_governance_finding_is_credited_and_realized(tmp_path) -> None:
    world = _run(tmp_path, finds=True)

    (pair,) = (
        item
        for item in world.filled.considerations
        if item.obligation_id == world.governance_brief.obligation_id
    )
    assert pair.disposition == "finding"
    (ica_id,) = pair.ica_ids
    assert any("risk-b" in prompt for prompt in world.client.prompts)

    row = _governance_row(world)
    assert row.disposition == "governance_only"
    assert row.ica_ids == (ica_id,)
    assert row.stop_reason is None
    assert world.accounting.summary.governance_credited == 1

    realization = _realize(world, (_scenario_for(world, ica_id),))
    assert realization.summary.realized == 1
    funnel = _funnel(world, realization)
    assert funnel["governance_credited"] == 1
    assert funnel["governance_realized"] == 1
    assert "governance_routed_no_finding" not in funnel
    assert funnel["reconciles"] is True


def test_a_governance_route_that_finds_nothing_is_recorded_and_not_credited(
    tmp_path,
) -> None:
    world = _run(tmp_path, finds=False)

    row = _governance_row(world)
    assert row.stop_reason == "governance_routed_no_finding"
    assert row.route_refs != ()
    assert row.ica_ids == ()
    assert world.accounting.summary.governance_credited == 0
    assert world.accounting.summary.governance_routed_no_finding == 1

    realization = _realize(world, ())
    assert realization.summary.realized == 0
    funnel = _funnel(world, realization)
    assert funnel["governance_routed_no_finding"] == 1
    assert "governance_credited" not in funnel
    assert funnel["reconciles"] is True
