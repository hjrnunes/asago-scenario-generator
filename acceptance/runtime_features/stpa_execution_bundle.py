"""Acceptance handlers for the execution-projection preparation seam.

The presentation opt-in step also lives here: Stage 6 presentation rendering
prepares the projection that these handlers exercise.
"""

from __future__ import annotations

from typing import Any

from runtime_shared import World

from asago_scenario_generator.stpa.models.causal_factor import (
    CausalFactor,
    CausalFactorKind,
)
from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlStructure,
    ControlledProcess,
    ElementRef,
    FeedbackChannel,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
)
from asago_scenario_generator.stpa.models.enriched_threat_set import StructuralThreat
from asago_scenario_generator.stpa.models.execution_projection_v2 import (
    ExecutionRunIdentity,
)
from asago_scenario_generator.stpa.models.execution_classification import (
    AttackerInfluence,
    ExecutionActionKind,
    ExecutionDeliveryClass,
    ExecutionResourceKind,
    ExecutionResourcePurpose,
    ExecutionResourceRequirement,
    ExecutionSurface,
    SemanticExecutionContract,
    SemanticExecutionDelivery,
)
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossAnalysis,
    LossProvenance,
    SecurityConstraint,
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
from asago_scenario_generator.stpa.models.semantic_conditions import (
    ActionValueCondition,
    SemanticBindingPlaceholder,
)
from asago_scenario_generator.stpa.scenario_prod.execution_projection import (
    ExecutionProjectionPreparationError,
    prepare_execution_projection,
)
from asago_scenario_generator.stpa.scenario_prod.context import (
    build_scenario_generation_context,
)


FEATURE_ID = "stpa_execution_bundle"

# Structured omission-evidence constants mirroring the committed projection-v3
# kit: the authored trigger interpretation, one exact observation quotation,
# and the prepared direct-prompt text the carrier's delivery attests.


def _control_structure() -> ControlStructure:
    return ControlStructure(
        controlled_processes=[
            ControlledProcess(cp_id="CP-1", description="Controlled process")
        ],
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="Controller",
                process_model_parts=[
                    ProcessModelPart(pm_id="PM-1-1", description="Authorization state")
                ],
                control_actions=[
                    ControlAction(
                        ca_id="CA-1-1",
                        description="Authorize action",
                        target=ElementRef(
                            type=ReferenceType.controlled_process,
                            id="CP-1",
                        ),
                    )
                ],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-1-1",
                        description="Authorization feedback",
                        updates="PM-1-1",
                        source=ElementRef(
                            type=ReferenceType.controlled_process,
                            id="CP-1",
                        ),
                    )
                ],
            )
        ],
    )


def _loss_analysis() -> LossAnalysis:
    return LossAnalysis(
        risk_card_losses=[
            Loss(
                loss_id="L-1",
                description="Loss",
                provenance=LossProvenance.risk_card,
                source_risk_cards=["risk-1"],
            )
        ],
        use_case_losses=[],
        hazards=[Hazard(hazard_id="H-1", description="Hazard", related_losses=["L-1"])],
        security_constraints=[
            SecurityConstraint(
                constraint_id="SC-1",
                rule="Validate before action",
                applies_when=[],
                related_hazards=["H-1"],
            )
        ],
    )


def _spec(
    *, placeholder: bool, with_outcome: bool = True, scenario_id: str = "SCN-001"
) -> ScenarioSpec:
    control_structure = _control_structure()
    threat = StructuralThreat(
        ica_slot_id="RESP-1:CA-1-1:INCORRECT",
        provenance="structural",
        ica_id="RESP-1:CA-1-1:INCORRECT:1",
        ica_text="The action carries an incorrect value",
        hazardous_context="Authorization state is stale",
        loss_scenario="An unauthorized action is accepted",
        related_hazards=["H-1"],
        related_constraints=["SC-1"],
    )
    context = build_scenario_generation_context(
        threat,
        control_structure,
        _loss_analysis(),
        scenario_id=scenario_id,
    )
    condition = (
        ActionValueCondition(
            control_action_id="CA-1-1",
            property="authorization_state",
            operator="equals",
            expected=SemanticBindingPlaceholder(
                binding_ref="SEM-1",
                value_type="string",
                description="The authorized state in this deployment.",
            ),
        )
        if placeholder
        else ActionValueCondition(
            control_action_id="CA-1-1",
            property="semantic_proposition",
            operator="equals",
            expected=True,
        )
    )
    target_action_requirement = ExecutionResourceRequirement(
        requirement_id="REQ-target-action",
        purpose=ExecutionResourcePurpose.target_action,
        factor_id="CF-1",
        owner_ref="CA-1-1",
        acceptable_resource_kinds=(
            ExecutionResourceKind.integration,
            ExecutionResourceKind.tool,
        ),
        role_id="target_control_action",
        operation="CA-1-1",
        required_surfaces=(ExecutionSurface.tool_call,),
        required_attacker_influence=AttackerInfluence.none,
        late_bindable=True,
        evidence_refs=("CF-1",),
    )
    spec = ScenarioSpec(
        scenario_id=scenario_id,
        threat_source=ThreatSource(
            ica_slot_id=threat.ica_slot_id,
            provenance=threat.provenance,
            ica_id=threat.ica_id,
        ),
        target_controller="RESP-1",
        target_control_action="CA-1-1",
        ica_type=UCAType.incorrect,
        defender_bdi=DefenderBDI(
            beliefs=[DefenderBelief(pm_id="PM-1-1", content="State", vulnerability="")],
            desires=[DefenderDesire(resp_id="RESP-1", content="Controller")],
            intentions=[DefenderIntention(ca_id="CA-1-1", content="Action")],
        ),
        attacker_bdi=AttackerBDI(
            beliefs=["The state may be stale"],
            desires=["Induce the selected action"],
            intentions=["Rely on PM-1-1 before CA-1-1"],
        ),
        loss_scenario=threat.loss_scenario,
        causal_factors=[
            CausalFactor(
                kind=CausalFactorKind.process_model_flaw,
                source_id="PM-1-1",
                description="The authorization state can be stale.",
            )
        ],
        unsafe_outcome_condition=condition,
        unsafe_outcome_hazard_refs=["H-1"],
        unsafe_outcome_constraint_refs=["SC-1"],
        unsafe_outcome_semantic_proposition=(
            None
            if placeholder
            else "The model response exhibits the selected unsafe behavior."
        ),
        scenario_context=context,
        execution_contract=SemanticExecutionContract(
            requested_environment_basis=None,
            delivery=SemanticExecutionDelivery(
                delivery_class=ExecutionDeliveryClass.direct_prompt,
                factor_id="CF-1",
                source_role="direct_user_input",
            ),
            action_kind=(
                ExecutionActionKind.tool_call
                if placeholder
                else ExecutionActionKind.model_output
            ),
            resource_requirements=(target_action_requirement,) if placeholder else (),
        ),
    )
    if not with_outcome:
        # Keep an otherwise valid contextual fixture so preparation, rather
        # than model construction, reports the intentionally missing field.
        return spec.model_copy(update={"unsafe_outcome_condition": None})
    return spec


def _state(world: World) -> dict[str, Any]:
    state = getattr(world, "stpa_bundle_state", None)
    if state is None:
        state = {}
        world.stpa_bundle_state = state
    return state


def _h_seams_available(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    state = _state(world)
    state["control_structure"] = _control_structure()
    state["run_identity"] = ExecutionRunIdentity(run_id="acceptance-run-1")
    state["stage6_calls"] = 0
    state["stage6_writes"] = 0
    return True, ""


def _h_given_projection(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del examples
    state = _state(world)
    state["placeholder"] = "placeholder" in text.lower()
    state["spec"] = _spec(placeholder=state["placeholder"])
    return True, ""


def _h_prepare(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    state = _state(world)
    try:
        state["validated"] = prepare_execution_projection(
            state["spec"],
            state["control_structure"],
            state["run_identity"],
        )
    except ExecutionProjectionPreparationError as exc:
        state["prepare_error"] = str(exc)
        state["validated"] = None
    return True, ""


def _h_enable_presentation(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    world.render_presentation = True
    return True, ""


def register(api: object) -> None:
    """Register the producer/bundle acceptance steps."""
    api.register(
        r"optional model-authored scenario presentation is enabled",
        _h_enable_presentation,
    )
    api.register(
        r"the v2 execution projection and bundle seams are available",
        _h_seams_available,
    )
    api.register(
        r"a validated (literal|placeholder) INCORRECT action_value projection",
        _h_given_projection,
    )
    api.register(r"^the producer prepares the execution projection$", _h_prepare)
