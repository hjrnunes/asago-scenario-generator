"""Shared test builders moved out of test modules."""

from __future__ import annotations

from asago_scenario_generator.stpa.models.causal_factor import (
    CausalFactor,
    CausalFactorKind,
)
from asago_scenario_generator.stpa.models.enriched_threat_set import StructuralThreat
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.models.scenario_spec import (
    AttackerBDI,
    DefenderBDI,
    DefenderBelief,
    DefenderDesire,
    DefenderIntention,
    ScenarioSpec,
    ThreatSource,
)
from asago_scenario_generator.stpa.models.control_structure import (
    ControlStructure,
    ControlledProcess,
    ElementRef,
    ReferenceType,
)
from asago_scenario_generator.stpa.scenario_prod.context import (
    build_scenario_generation_context,
)
from tests.stpa.helpers import make_minimal_loss_analysis
from asago_scenario_generator.stpa.models.semantic_conditions import (
    DelayCondition,
    SemanticBindingPlaceholder,
)
from asago_scenario_generator.stpa.models.execution_classification import (
    ExecutionActionKind,
    ExecutionDeliveryClass,
    RequestedEnvironmentBasis,
    SemanticExecutionContract,
    SemanticExecutionDelivery,
)
from tests.stpa.helpers import make_minimal_control_structure


def _control_structure() -> ControlStructure:
    base = make_minimal_control_structure()
    action = (
        base.responsibilities[0]
        .control_actions[0]
        .model_copy(
            update={
                "target": ElementRef(
                    type=ReferenceType.controlled_process,
                    id="CP-1",
                )
            }
        )
    )
    responsibility = base.responsibilities[0].model_copy(
        update={"control_actions": [action]}
    )
    return base.model_copy(
        update={
            "responsibilities": [responsibility],
            "controlled_processes": [
                ControlledProcess(cp_id="CP-1", description="Process")
            ],
        }
    )


def _spec(
    *,
    ica_type: UCAType = UCAType.wrong_timing,
    unsafe_outcome_condition=None,
) -> ScenarioSpec:
    control_structure = _control_structure()
    slot = f"RESP-1:CA-1-1:{ica_type.value}"
    threat = StructuralThreat(
        ica_slot_id=slot,
        provenance="structural",
        ica_id=f"{slot}:1",
        ica_text="Unsafe control action",
        hazardous_context="Context",
        loss_scenario="Loss scenario",
        related_hazards=["H-1"],
        related_constraints=["SC-1"],
    )
    context = build_scenario_generation_context(
        threat,
        control_structure,
        make_minimal_loss_analysis(),
        scenario_id="SCN-001",
    )
    return ScenarioSpec(
        scenario_id="SCN-001",
        threat_source=ThreatSource(
            ica_slot_id=threat.ica_slot_id,
            provenance=threat.provenance,
            ica_id=threat.ica_id,
        ),
        target_controller="RESP-1",
        target_control_action="CA-1-1",
        ica_type=ica_type,
        defender_bdi=DefenderBDI(
            beliefs=[DefenderBelief(pm_id="PM-1-1", content="State", vulnerability="")],
            desires=[DefenderDesire(resp_id="RESP-1", content="Controller")],
            intentions=[DefenderIntention(ca_id="CA-1-1", content="Action")],
        ),
        attacker_bdi=AttackerBDI(
            beliefs=["belief"], desires=["desire"], intentions=["intent"]
        ),
        loss_scenario="Loss scenario",
        causal_factors=[
            CausalFactor(
                kind=CausalFactorKind.feedback_delay,
                source_id="FB-1-1",
                description="Feedback is delayed.",
            )
        ],
        unsafe_outcome_condition=unsafe_outcome_condition
        or DelayCondition(
            reference_ref="FB-1-1",
            delay_ms=SemanticBindingPlaceholder(
                binding_ref="SEM-1",
                value_type="integer",
                description="Maximum supported feedback delay.",
                minimum=0,
            ),
        ),
        unsafe_outcome_semantic_proposition=(
            "The response exhibits the unsafe semantic behavior."
        ),
        unsafe_outcome_hazard_refs=[item.hazard_id for item in context.hazards],
        unsafe_outcome_constraint_refs=[
            item.constraint_id for item in context.constraints
        ],
        scenario_context=context,
        execution_contract=SemanticExecutionContract(
            requested_environment_basis=RequestedEnvironmentBasis.target_agnostic,
            delivery=SemanticExecutionDelivery(
                delivery_class=ExecutionDeliveryClass.direct_prompt,
                factor_id="CF-1",
                source_role="direct_user_input",
            ),
            action_kind=ExecutionActionKind.model_output,
        ),
    )
