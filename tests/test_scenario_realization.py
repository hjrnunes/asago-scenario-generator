"""Public seam tests for scenario realization after ICA accounting."""

from __future__ import annotations

from asago_scenario_generator.models.artifact_pin import ArtifactPin
from asago_scenario_generator.models.obligation_accounting import (
    ObligationAccounting,
    ObligationAccountingRow,
    derive_obligation_accounting_summary,
)
from asago_scenario_generator.models.obligation_consideration import (
    ObligationIcaConsideration,
)
from asago_scenario_generator.models.scenario_realization import (
    ScenarioRealizationAssessment,
)
from asago_scenario_generator.pipeline.scenario_realization import (
    build_scenario_realization_assessment,
)
from asago_scenario_generator.stpa.models.causal_factor import CausalFactor
from asago_scenario_generator.stpa.models.ica_enumeration import (
    ICA,
    ICAEnumeration,
    ICASlot,
    UCAType,
)
from asago_scenario_generator.stpa.models.scenario_context import (
    DescribedControlAction,
    DescribedElement,
    ScenarioConstraint,
    ScenarioControlPath,
    ScenarioGenerationContext,
    ScenarioHazard,
    ScenarioICAContext,
    ScenarioIdentity,
    ScenarioLoss,
    ScenarioObligationConsideration,
    ScenarioSourcePin,
)
from asago_scenario_generator.stpa.models.scenario_spec import (
    AttackerBDI,
    DefenderBDI,
    DefenderBelief,
    DefenderDesire,
    DefenderIntention,
    ScenarioSpec,
    ThreatSource,
)


_OBLIGATION_ID = f"ob:v1:{'1' * 64}"
_SLOT_ID = "RESP-1:CA-1-1:INCORRECT"
_ICA_ID = f"{_SLOT_ID}:1"


def _pin(artifact_id: str, schema_version: str, marker: str) -> ArtifactPin:
    return ArtifactPin(
        artifact_id=artifact_id,
        schema_version=schema_version,
        semantic_digest=marker * 64,
    )


def _accounting() -> ObligationAccounting:
    row = ObligationAccountingRow(
        obligation_id=_OBLIGATION_ID,
        disposition="addressed",
        slot_ids=(_SLOT_ID,),
        ica_ids=(_ICA_ID,),
        exec_candidate_ids=("EXEC:RESP-1:CA-1-1:INCORRECT",),
        hazard_ids=("H-1",),
        constraint_ids=("SC-1",),
        route_refs=("route-1",),
        evidence=("pair-1",),
    )
    rows = (row,)
    return ObligationAccounting(
        source_pins=(
            _pin("taxonomy-obligation-plan", "taxonomy-obligation-plan-v1", "1"),
            _pin("stpa-loss-analysis", "stpa-loss-analysis-v1", "2"),
            _pin("stpa-control-structure", "stpa-control-structure-v1", "3"),
            _pin("ica-enumeration", "ica-enumeration-v1", "4"),
        ),
        rows=rows,
        summary=derive_obligation_accounting_summary(rows),
    )


def _pair() -> ObligationIcaConsideration:
    return ObligationIcaConsideration(
        route_id="route-1",
        obligation_id=_OBLIGATION_ID,
        slot_id=_SLOT_ID,
        disposition="finding",
        ica_ids=(_ICA_ID,),
        exec_candidate_ids=("EXEC:RESP-1:CA-1-1:INCORRECT",),
        hazard_ids=("H-1",),
        constraint_ids=("SC-1",),
        evidence=("The selected ICA responds to the obligation concern.",),
    )


def _enumeration() -> ICAEnumeration:
    return ICAEnumeration(
        slots=[
            ICASlot(
                slot_id=_SLOT_ID,
                responsibility="RESP-1",
                control_action="CA-1-1",
                uca_type=UCAType.incorrect,
                is_na=False,
                icas=[
                    ICA(
                        ica_id=_ICA_ID,
                        ica_text="The controller authorizes an unbounded action batch.",
                        hazardous_context="A single request expands into bulk actions.",
                        loss_scenario="Unauthorized bulk actions are executed.",
                        related_hazards=["H-1"],
                        related_constraints=["SC-1"],
                    )
                ],
            )
        ]
    )


def _context(
    *, include_obligation: bool = True, scenario_id: str = "SCN-001"
) -> ScenarioGenerationContext:
    considerations = (
        (
            ScenarioObligationConsideration(
                obligation_id=_OBLIGATION_ID,
                attack_pattern_id="AP-BULK",
                attack_pattern_name="Automated mass-action abuse",
                concise_concern="One request triggers an unsafe bulk operation.",
                disposition="finding",
                rationale="The selected ICA exposes the same bulk-action concern.",
                finding_ica_id=_ICA_ID,
            ),
        )
        if include_obligation
        else ()
    )
    return ScenarioGenerationContext.create(
        source_pins=(
            ScenarioSourcePin(
                source_kind="structural_threat", semantic_digest="a" * 64
            ),
            ScenarioSourcePin(source_kind="control_path", semantic_digest="b" * 64),
            ScenarioSourcePin(
                source_kind="loss_relationships", semantic_digest="c" * 64
            ),
        ),
        scenario_identity=ScenarioIdentity(
            scenario_id=scenario_id, ica_slot_id=_SLOT_ID, ica_id=_ICA_ID
        ),
        ica=ScenarioICAContext(
            ica_id=_ICA_ID,
            slot_id=_SLOT_ID,
            uca_type=UCAType.incorrect,
            uca_type_definition="The action is provided with an unsafe effect.",
            exact_ica_text="The controller authorizes an unbounded action batch.",
            unsafe_action="The controller authorizes an unbounded action batch.",
            hazardous_context="A single request expands into bulk actions.",
            loss_consequence="Unauthorized bulk actions are executed.",
        ),
        target_control_path=ScenarioControlPath(
            controller=DescribedElement(
                element_id="RESP-1", description="Authorize payment actions"
            ),
            responsibility=DescribedElement(
                element_id="RESP-1", description="Authorize payment actions"
            ),
            control_action=DescribedControlAction(
                action_id="CA-1-1",
                description="Authorize a bounded payment-action batch",
                target_id="CP-1",
            ),
            controlled_process=DescribedElement(
                element_id="CP-1", description="Payment orchestration"
            ),
            process_model_parts=(
                DescribedElement(
                    element_id="PM-1-1", description="Current action-batch size"
                ),
            ),
            feedback=(
                DescribedElement(
                    element_id="FB-1-1", description="Completed action count"
                ),
            ),
        ),
        losses=(ScenarioLoss(loss_id="L-1", description="Unauthorized bulk payments"),),
        hazards=(
            ScenarioHazard(
                hazard_id="H-1",
                description="The agent authorizes an unbounded batch",
                related_loss_ids=("L-1",),
            ),
        ),
        constraints=(
            ScenarioConstraint(
                constraint_id="SC-1",
                description="Enforce the reviewed action-batch limit",
                related_hazard_ids=("H-1",),
            ),
        ),
        obligation_considerations=considerations,
    )


def _scenario(
    *, include_obligation: bool = True, scenario_id: str = "SCN-001"
) -> ScenarioSpec:
    return ScenarioSpec(
        scenario_id=scenario_id,
        threat_source=ThreatSource(
            ica_slot_id=_SLOT_ID, provenance="structural", ica_id=_ICA_ID
        ),
        target_controller="RESP-1",
        target_control_action="CA-1-1",
        ica_type=UCAType.incorrect,
        defender_bdi=DefenderBDI(
            beliefs=[
                DefenderBelief(
                    pm_id="PM-1-1",
                    content="Current action-batch size",
                    vulnerability="The count can be stale.",
                )
            ],
            desires=[
                DefenderDesire(
                    resp_id="RESP-1", content="Authorize bounded payment actions"
                )
            ],
            intentions=[
                DefenderIntention(
                    ca_id="CA-1-1", content="Authorize a bounded action batch"
                )
            ],
        ),
        attacker_bdi=AttackerBDI(
            beliefs=["The batch count can be stale."],
            desires=["Cause an unbounded action batch."],
            intentions=["Delay FB-1-1 before CA-1-1."],
        ),
        loss_scenario="Unauthorized bulk actions are executed.",
        causal_factors=[
            CausalFactor(
                kind="FEEDBACK_DELAY",
                source_id="FB-1-1",
                description="The completed-action count arrives too late.",
            )
        ],
        unsafe_outcome_hazard_refs=[item.hazard_id for item in _context().hazards],
        unsafe_outcome_constraint_refs=[
            item.constraint_id for item in _context().constraints
        ],
        scenario_context=_context(
            include_obligation=include_obligation, scenario_id=scenario_id
        ),
    )


def test_exact_obligation_context_produces_realized_record() -> None:
    result = build_scenario_realization_assessment(
        accounting=_accounting(),
        ica_considerations=(_pair(),),
        ica_enumeration=_enumeration(),
        scenario_specs=(_scenario(),),
        requested_ica_ids=(_ICA_ID,),
    )

    assert isinstance(result, ScenarioRealizationAssessment)
    assert result.summary.model_dump() == {
        "total": 1,
        "realized": 1,
        "unresolved": 0,
        "not_requested": 0,
    }
    assert result.records[0].status == "realized"
    assert result.records[0].scenario_ids == ("SCN-001",)
    assert result.records[0].context_digests == (
        _scenario().scenario_context.context_digest,
    )


def test_one_ica_with_family_siblings_maps_to_every_scenario() -> None:
    siblings = (_scenario(), _scenario(scenario_id="SCN-002"))
    result = build_scenario_realization_assessment(
        accounting=_accounting(),
        ica_considerations=(_pair(),),
        ica_enumeration=_enumeration(),
        scenario_specs=siblings,
        requested_ica_ids=(_ICA_ID,),
    )

    assert result.summary.realized == 1
    assert result.records[0].scenario_ids == ("SCN-001", "SCN-002")
    assert result.records[0].context_digests == tuple(
        item.scenario_context.context_digest for item in siblings
    )


def test_scenario_without_exact_obligation_context_is_unresolved() -> None:
    result = build_scenario_realization_assessment(
        accounting=_accounting(),
        ica_considerations=(_pair(),),
        ica_enumeration=_enumeration(),
        scenario_specs=(_scenario(include_obligation=False),),
        requested_ica_ids=(_ICA_ID,),
    )

    assert result.records[0].status == "unresolved"
    assert result.records[0].scenario_ids == ()


def test_unselected_ica_is_not_requested_not_unresolved() -> None:
    result = build_scenario_realization_assessment(
        accounting=_accounting(),
        ica_considerations=(_pair(),),
        ica_enumeration=_enumeration(),
        scenario_specs=(),
        requested_ica_ids=(),
    )

    assert result.records[0].status == "not_requested"
    assert result.summary.not_requested == 1


def test_partial_finding_for_unresolved_obligation_is_trace_only() -> None:
    unresolved_row = ObligationAccountingRow(
        obligation_id=_OBLIGATION_ID,
        disposition="unresolved",
        slot_ids=(_SLOT_ID,),
        route_refs=("route-1", "route-2"),
        evidence=("One routed slot produced a finding and another stayed unresolved.",),
    )
    accounting = ObligationAccounting(
        source_pins=_accounting().source_pins,
        rows=(unresolved_row,),
        summary=derive_obligation_accounting_summary((unresolved_row,)),
    )
    unresolved_pair = ObligationIcaConsideration(
        route_id="route-2",
        obligation_id=_OBLIGATION_ID,
        slot_id=_SLOT_ID,
        disposition="unresolved",
        evidence=("The second routed analysis could not resolve applicability.",),
    )

    result = build_scenario_realization_assessment(
        accounting=accounting,
        ica_considerations=(_pair(), unresolved_pair),
        ica_enumeration=_enumeration(),
        scenario_specs=(_scenario(),),
    )

    assert result.records == ()
    assert result.summary.model_dump() == {
        "total": 0,
        "realized": 0,
        "unresolved": 0,
        "not_requested": 0,
    }
