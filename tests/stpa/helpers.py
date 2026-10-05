"""Shared test fixture builders for STPA boundary schemas.

These factory functions create minimal valid instances of the boundary
schema models for use across multiple test modules. Each builder uses
sensible defaults so tests only need to specify the fields they vary.
"""

from __future__ import annotations

from asago_scenario_generator.stpa.models.execution_classification import (
    ExecutionActionKind,
    ExecutionDeliveryClass,
    RequestedEnvironmentBasis,
    SemanticExecutionContract,
    SemanticExecutionDelivery,
)
from asago_scenario_generator.stpa.models.scenario_envelope import GherkinSpec
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
    ControlAction,
    ControlStructure,
    ElementRef,
    FeedbackChannel,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
)
from asago_scenario_generator.stpa.models.ica_enumeration import (
    ICA,
    ICASlot,
    UCAType,
)
from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossAnalysis,
    LossProvenance,
    SecurityConstraint,
)


def make_minimal_loss_analysis() -> LossAnalysis:
    """Build a minimal valid LossAnalysis with one loss, hazard, and constraint."""
    return LossAnalysis(
        risk_card_losses=[],
        use_case_losses=[
            Loss(
                loss_id="L-1",
                description="Loss",
                provenance=LossProvenance.use_case,
            )
        ],
        hazards=[Hazard(hazard_id="H-1", description="Hazard", related_losses=["L-1"])],
        security_constraints=[
            SecurityConstraint(
                constraint_id="SC-1",
                rule="Constraint",
                related_hazards=["H-1"],
            )
        ],
    )


def make_minimal_control_structure() -> ControlStructure:
    """Build a minimal valid ControlStructure with one responsibility."""
    return ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="Controller",
                process_model_parts=[
                    ProcessModelPart(pm_id="PM-1-1", description="State"),
                ],
                control_actions=[
                    ControlAction(ca_id="CA-1-1", description="Action"),
                ],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-1-1",
                        description="Feedback",
                        updates="PM-1-1",
                        source=ElementRef(
                            type=ReferenceType.responsibility, id="RESP-1"
                        ),
                    )
                ],
            )
        ],
    )


def make_ica(
    ica_id: str = "RESP-1:CA-1-1:NOT_PROVIDED:1",
    related_hazards: list[str] | None = None,
    related_constraints: list[str] | None = None,
) -> ICA:
    """Build a minimal valid ICA with default hazard and constraint references."""
    return ICA(
        ica_id=ica_id,
        ica_text="Unsafe control action",
        hazardous_context="Context",
        loss_scenario="Scenario",
        related_hazards=related_hazards or ["H-1"],
        related_constraints=related_constraints or ["SC-1"],
    )


def make_ica_slot(
    slot_id: str = "RESP-1:CA-1-1:NOT_PROVIDED",
    is_na: bool = False,
    icas: list[ICA] | None = None,
    na_justification: str | None = None,
    uca_type: UCAType = UCAType.not_provided,
) -> ICASlot:
    """Build a minimal valid ICASlot with default responsibility and control action."""
    return ICASlot(
        slot_id=slot_id,
        responsibility="RESP-1",
        coordination_link=None,
        control_action="CA-1-1",
        uca_type=uca_type,
        is_na=is_na,
        icas=icas if icas is not None else ([] if is_na else [make_ica()]),
        na_justification=na_justification,
    )


def make_scenario_spec(scenario_id: str = "SCN-001") -> ScenarioSpec:
    """Build a minimal valid ScenarioSpec for one not-provided control action."""
    return ScenarioSpec(
        scenario_id=scenario_id,
        threat_source=ThreatSource(
            ica_slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
            provenance="structural",
        ),
        target_controller="RESP-1",
        target_control_action="CA-1-1",
        ica_type=UCAType.not_provided,
        defender_bdi=DefenderBDI(
            beliefs=[
                DefenderBelief(pm_id="PM-1-1", content="Belief", vulnerability="Vuln")
            ],
            desires=[DefenderDesire(resp_id="RESP-1", content="Desire")],
            intentions=[DefenderIntention(ca_id="CA-1-1", content="Intention")],
        ),
        attacker_bdi=AttackerBDI(beliefs=["b"], desires=["d"], intentions=["i"]),
        loss_scenario="Scenario",
    )


def make_gherkin_spec() -> GherkinSpec:
    """Build a minimal valid GherkinSpec."""
    return GherkinSpec(
        feature="Test",
        scenario="Test",
        given=["Given PM-1-1 is valid"],
        when=["When x"],
        then_expected=["Then should reject"],
        then_actual=["But approves"],
    )


def make_direct_execution_contract() -> SemanticExecutionContract:
    """Build a target-agnostic direct-prompt execution contract."""
    return SemanticExecutionContract(
        requested_environment_basis=RequestedEnvironmentBasis.target_agnostic,
        delivery=SemanticExecutionDelivery(
            delivery_class=ExecutionDeliveryClass.direct_prompt,
            factor_id="CF-1",
            source_role="direct_user_input",
        ),
        action_kind=ExecutionActionKind.model_output,
    )
