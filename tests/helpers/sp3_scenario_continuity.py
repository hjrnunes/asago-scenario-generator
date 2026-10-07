"""Shared test builders moved out of test modules."""

from __future__ import annotations

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
from asago_scenario_generator.stpa.models.causal_factor import (
    CausalFactor,
    CausalFactorKind,
)
from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossAnalysis,
    LossProvenance,
    SecurityConstraint,
)
from asago_scenario_generator.stpa.models.scenario_context import ReachableCapability
from asago_scenario_generator.stpa.models.scenario_spec import (
    AttackerBDI,
    DefenderBDI,
    DefenderBelief,
    DefenderDesire,
    DefenderIntention,
    ScenarioSpec,
    ThreatSource,
)
from asago_scenario_generator.stpa.scenario_prod.context import (
    build_scenario_generation_context,
)


def _control_structure() -> ControlStructure:
    return ControlStructure(
        controlled_processes=[
            ControlledProcess(
                cp_id="CP-1", description="Klarna payment orchestration service"
            )
        ],
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="Authorize bounded payment actions",
                security_constraint_refs=["SC-MASS"],
                process_model_parts=[
                    ProcessModelPart(
                        pm_id="PM-1-1", description="Recent payment-action count"
                    )
                ],
                control_actions=[
                    ControlAction(
                        ca_id="CA-1-1",
                        description="Authorize a bounded batch of payment actions",
                        target=ElementRef(
                            type=ReferenceType.controlled_process, id="CP-1"
                        ),
                    )
                ],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-1-1",
                        description="Payment-action count feedback",
                        updates="PM-1-1",
                        source=ElementRef(
                            type=ReferenceType.controlled_process, id="CP-1"
                        ),
                    )
                ],
            )
        ],
    )


def _loss_analysis() -> LossAnalysis:
    return LossAnalysis(
        risk_card_losses=[],
        use_case_losses=[
            Loss(
                loss_id="L-MASS",
                description="Customers suffer unauthorized bulk payment actions",
                provenance=LossProvenance.use_case,
            ),
            Loss(
                loss_id="L-PII",
                description="Customer PII is disclosed",
                provenance=LossProvenance.use_case,
            ),
        ],
        hazards=[
            Hazard(
                hazard_id="H-MASS",
                description="The agent authorizes an unbounded action batch",
                related_losses=["L-MASS"],
            ),
            Hazard(
                hazard_id="H-PII",
                description="The agent exposes unmasked customer PII",
                related_losses=["L-PII"],
            ),
        ],
        security_constraints=[
            SecurityConstraint(
                constraint_id="SC-PII",
                rule="Mask customer PII before disclosure",
                related_hazards=["H-PII"],
            ),
            SecurityConstraint(
                constraint_id="SC-MASS",
                rule="Enforce reviewed batch limits before authorization",
                related_hazards=["H-MASS"],
            ),
        ],
    )


def _threat(*, constraint_id: str = "SC-MASS") -> StructuralThreat:
    return StructuralThreat(
        ica_slot_id="RESP-1:CA-1-1:INCORRECT",
        ica_id="RESP-1:CA-1-1:INCORRECT:1",
        ica_text=(
            "The payment controller authorizes an unbounded batch of payment "
            "actions when the reviewed mass-action limit is exceeded."
        ),
        hazardous_context="A compromised workflow requests bulk payment actions.",
        loss_scenario="Unauthorized mass payment actions are executed.",
        related_hazards=["H-MASS"],
        related_constraints=[constraint_id],
    )


def _context():
    return build_scenario_generation_context(
        _threat(),
        _control_structure(),
        _loss_analysis(),
        scenario_id="SCN-001",
        reachable_capabilities=(
            ReachableCapability(
                capability_id="CAP-PAYMENT",
                description="Submit a payment action",
                evidence="CA-1-1 targets CP-1",
                access_path=("RESP-1", "CA-1-1", "CP-1"),
            ),
        ),
    )


def _contextual_spec() -> ScenarioSpec:
    context = _context()
    return ScenarioSpec(
        scenario_id="SCN-001",
        threat_source=ThreatSource(
            ica_slot_id=context.scenario_identity.ica_slot_id,
            provenance="structural",
            ica_id=context.ica.ica_id,
        ),
        target_controller="RESP-1",
        target_control_action="CA-1-1",
        ica_type=context.ica.uca_type,
        defender_bdi=DefenderBDI(
            beliefs=[
                DefenderBelief(
                    pm_id="PM-1-1",
                    content="Recent payment-action count",
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
                    ca_id="CA-1-1",
                    content="Authorize a bounded batch of payment actions",
                )
            ],
        ),
        attacker_bdi=AttackerBDI(
            beliefs=["The action count can be stale"],
            desires=["Induce the selected ICA"],
            intentions=["Delay FB-1-1"],
        ),
        loss_scenario=context.ica.loss_consequence,
        causal_factors=[
            CausalFactor(
                kind=CausalFactorKind.feedback_delay,
                source_id="FB-1-1",
                description="The count feedback arrives after authorization.",
            )
        ],
        unsafe_outcome_semantic_proposition=(
            "The response authorizes an unsafe action prohibited by policy."
        ),
        unsafe_outcome_hazard_refs=[item.hazard_id for item in context.hazards],
        unsafe_outcome_constraint_refs=[
            item.constraint_id for item in context.constraints
        ],
        scenario_context=context,
    )
