"""Shared test builders moved out of test modules."""

from __future__ import annotations

from typing import Any

from asago_scenario_generator.models.obligation_accounting import (
    ObligationAccounting,
    ObligationAccountingRow,
    derive_obligation_accounting_summary,
)
from asago_scenario_generator.models.obligation_consideration import (
    ObligationIcaConsideration,
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

from asago_scenario_generator.models.artifact_pin import ArtifactPin
from asago_scenario_generator.models.obligation_plan import (
    TaxonomyObligation,
    TaxonomyObligationPlan,
    derive_obligation_summary,
)

from asago_scenario_generator.pipeline.governance_rows import select_governance_risks
from asago_scenario_generator.pipeline.obligation_consideration import (
    build_governance_briefs,
)
from asago_scenario_generator.stpa.obligation_aware.contracts import AnalysisControls
from tests.stpa.helpers import (
    make_minimal_control_structure,
    make_minimal_loss_analysis,
)
from tests.helpers.obligation_factory import make_plan
from asago_scenario_generator.stpa.models.loss_analysis import RiskDisposition

from asago_scenario_generator.models.attack_pattern_chain import AttackPattern
from tests.helpers.projection_factory import get_test_raw_pattern


def _pattern() -> AttackPattern:
    return AttackPattern.model_validate(get_test_raw_pattern())


def _setup(*risk_ids: str):
    mappings = [
        {
            "source_id": "risk-a",
            "target_id": _pattern().id,
            "relation": "exact_match",
            "confidence": 1.0,
        }
    ]
    plan = make_plan(risk_ids=("risk-a", *risk_ids), mappings=mappings)
    loss_analysis = make_minimal_loss_analysis().model_copy(
        update={
            "risk_dispositions": [
                RiskDisposition(risk_ref=risk_id, disposition="cited", loss_ids=["L-1"])
                for risk_id in risk_ids
            ]
        }
    )
    selection = select_governance_risks(plan, loss_analysis)
    briefs = build_governance_briefs(plan, selection.risk_ids)
    return briefs, selection, loss_analysis, make_minimal_control_structure()


def _controls(batch: int = 8) -> AnalysisControls:
    return AnalysisControls(
        model_profile="test",
        model_name="fake",
        deadline_seconds=10.0,
        temperature=0.0,
        max_batch_size=batch,
    )


def _plan_with_non_stpa_rows():
    """Build one exact Phase 1 plan containing all accounting scopes."""
    plan = make_plan()
    source_row = plan.obligations[0]
    excluded_payload = source_row.model_dump(mode="json")
    excluded_payload.update(
        obligation_id="ob:v1:" + "c" * 64,
        scope_disposition="capability_excluded",
        qualification_disposition="not_attempted",
        candidate_records=[],
        evidence=[
            {
                "kind": "scope",
                "detail": "required capability was explicitly excluded",
            }
        ],
    )
    excluded = TaxonomyObligation.model_validate(excluded_payload)
    governance = TaxonomyObligation.model_validate(
        {
            "obligation_id": "ob:v1:" + "b" * 64,
            "risk_ref": {
                "risk_id": "governance-risk",
                "risk_name": "Governance risk",
            },
            "taxonomy_chain": [],
            "attack_pattern_id": None,
            "attack_pattern_semantic_digest": None,
            "scope_disposition": "governance_only",
            "qualification_disposition": "not_attempted",
            "candidate_records": [],
            "evidence": [
                {
                    "kind": "governance",
                    "detail": "reviewed governance-only obligation",
                }
            ],
        }
    )
    rows = (source_row, excluded, governance)
    unchecked = TaxonomyObligationPlan.model_validate(
        {
            "schema_version": plan.schema_version,
            "semantic_digest": "0" * 64,
            "capability_snapshot_digest": plan.capability_snapshot_digest,
            "catalog_pins": plan.catalog_pins,
            "mapping_pins": plan.mapping_pins,
            "qualification_facts_digest": plan.qualification_facts_digest,
            "obligations": rows,
            "summary": derive_obligation_summary(rows),
        }
    )
    return TaxonomyObligationPlan.model_validate(
        {
            **unchecked.model_dump(mode="json"),
            "semantic_digest": unchecked.compute_semantic_digest(),
        }
    )


def _accounting_pins(plan: TaxonomyObligationPlan) -> tuple[ArtifactPin, ...]:
    """Return the four stable authorities required by accounting."""
    return (
        ArtifactPin(
            artifact_id="taxonomy-obligation-plan",
            schema_version="taxonomy-obligation-plan-v1",
            semantic_digest=plan.semantic_digest,
        ),
        ArtifactPin(
            artifact_id="stpa-loss-analysis",
            schema_version="stpa-loss-analysis-v1",
            semantic_digest="2" * 64,
        ),
        ArtifactPin(
            artifact_id="stpa-control-structure",
            schema_version="stpa-control-structure-v1",
            semantic_digest="3" * 64,
        ),
        ArtifactPin(
            artifact_id="ica-enumeration",
            schema_version="ica-enumeration-v1",
            semantic_digest="4" * 64,
        ),
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


def _governance_scenario() -> Any:
    base = _context()
    context = ScenarioGenerationContext.create(
        source_pins=base.source_pins,
        scenario_identity=base.scenario_identity,
        ica=base.ica,
        target_control_path=base.target_control_path,
        losses=base.losses,
        hazards=base.hazards,
        constraints=base.constraints,
        obligation_considerations=(
            ScenarioObligationConsideration(
                obligation_id=_OBLIGATION_ID,
                kind="governance",
                risk_id="risk-governance",
                risk_name="Governance risk",
                concise_concern="A reviewed risk with no catalogued attack pattern.",
                disposition="finding",
                rationale="The selected ICA expresses the reviewed risk.",
                finding_ica_id=_ICA_ID,
            ),
        ),
    )
    return _scenario().model_copy(update={"scenario_context": context})
