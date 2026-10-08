"""Control-structure, capability-profile, and loss-analysis builders that test modules share."""

from __future__ import annotations

from asago_scenario_generator.models.risk_card import RiskCard
from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    EntryPoint,
    ToolInventoryEntry,
)
from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossAnalysis,
    LossProvenance,
    SecurityConstraint,
)
from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlledProcess,
    ControlStructure,
    ElementRef,
    FeedbackChannel,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
)


def make_capability_profile(
    kc_subcodes: list[str] | None = None,
) -> CapabilityProfile:
    """Build a valid CapabilityProfile for template rendering tests."""
    return CapabilityProfile(
        zones_active=["input", "reasoning", "tool_execution"],
        entry_points=[
            EntryPoint(name="User chat", direction="input", controllability="direct"),
        ],
        confidence="medium",
        kc_subcodes=kc_subcodes or ["KC1.1", "KC5.1", "KC6.1.1"],
        tool_inventory=[
            ToolInventoryEntry(name="tool1", description="A tool"),
        ],
    )


def make_cs(
    include_resp2: bool = False,
) -> ControlStructure:
    cps = [ControlledProcess(cp_id="CP-1", description="Interface")]
    resp1 = Responsibility(
        resp_id="RESP-1",
        description="R1",
        process_model_parts=[
            ProcessModelPart(pm_id="PM-1-1", description="State"),
        ],
        control_actions=[
            ControlAction(
                ca_id="CA-1-1",
                description="Action",
                target=ElementRef(type=ReferenceType.controlled_process, id="CP-1"),
            ),
        ],
        feedback_channels=[
            FeedbackChannel(
                fb_id="FB-1-1",
                description="Feedback",
                updates="PM-1-1",
                source=ElementRef(type=ReferenceType.controlled_process, id="CP-1"),
            ),
        ],
    )
    responsibilities = [resp1]
    if include_resp2:
        responsibilities.append(
            Responsibility(
                resp_id="RESP-2",
                description="R2",
                process_model_parts=[
                    ProcessModelPart(pm_id="PM-2-1", description="State2")
                ],
                control_actions=[
                    ControlAction(
                        ca_id="CA-2-1",
                        description="Action2",
                        target=ElementRef(
                            type=ReferenceType.controlled_process, id="CP-1"
                        ),
                    ),
                ],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-2-1",
                        description="Feedback2",
                        updates="PM-2-1",
                        source=ElementRef(
                            type=ReferenceType.controlled_process, id="CP-1"
                        ),
                    ),
                ],
            )
        )
    return ControlStructure(responsibilities=responsibilities, controlled_processes=cps)


def make_risk_cards(ids: tuple[str, ...] = ("atlas-001",)) -> list[RiskCard]:
    """Build one high-grounding risk card per id."""
    return [
        RiskCard(
            risk_id=risk_id,
            risk_name=risk_id,
            risk_description=f"Risk {risk_id}",
            taxonomy="test",
            confidence=0.9,
            grounding_confidence="high",
        )
        for risk_id in ids
    ]


def make_loss_analysis() -> LossAnalysis:
    """Return one risk-card loss, one hazard, and one constraint (L-1, H-1, SC-1)."""
    return LossAnalysis(
        risk_card_losses=[
            Loss(
                loss_id="L-1",
                description="Loss",
                provenance=LossProvenance.risk_card,
                source_risk_cards=["r1"],
            ),
        ],
        use_case_losses=[],
        hazards=[Hazard(hazard_id="H-1", description="Hazard", related_losses=["L-1"])],
        security_constraints=[
            SecurityConstraint(
                constraint_id="SC-1",
                rule="Must validate",
                related_hazards=["H-1"],
            ),
        ],
    )
