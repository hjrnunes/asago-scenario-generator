"""Unit tests for SP2 Stage 3 Phase 2 — LLM slot-filling."""

from __future__ import annotations


from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlStructure,
    CoordinationLink,
    CoordinationMechanism,
    ElementRef,
    FeedbackChannel,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
    ControlledProcess,
)
from asago_scenario_generator.stpa.models.ica_enumeration import (
    ICA,
    ICAEnumeration,
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


def _make_test_control_structure() -> ControlStructure:
    """Build a control structure with 2 responsibilities, 2 CAs each, 1 coordination link."""
    cps = [
        ControlledProcess(cp_id="CP-1", description="P1"),
        ControlledProcess(cp_id="CP-2", description="P2"),
    ]
    resp1 = Responsibility(
        resp_id="RESP-1",
        description="R1",
        responsibility_constraints=[
            {"rc_id": "RC-1-1", "description": "Must validate"}
        ],
        process_model_parts=[ProcessModelPart(pm_id="PM-1-1", description="State")],
        control_actions=[
            ControlAction(
                ca_id=f"CA-1-{j + 1}",
                description=f"Action {j + 1}",
                target=ElementRef(
                    type=ReferenceType.controlled_process, id=f"CP-{j + 1}"
                ),
            )
            for j in range(2)
        ],
        feedback_channels=[
            FeedbackChannel(
                fb_id="FB-1-1",
                description="F",
                updates="PM-1-1",
                source=ElementRef(type=ReferenceType.controlled_process, id="CP-1"),
            )
        ],
    )
    resp2 = Responsibility(
        resp_id="RESP-2",
        description="R2",
        process_model_parts=[ProcessModelPart(pm_id="PM-2-1", description="State")],
        control_actions=[
            ControlAction(
                ca_id=f"CA-2-{j + 1}",
                description=f"Action {j + 1}",
                target=ElementRef(
                    type=ReferenceType.controlled_process, id=f"CP-{j + 1}"
                ),
            )
            for j in range(2)
        ],
        feedback_channels=[
            FeedbackChannel(
                fb_id="FB-2-1",
                description="F",
                updates="PM-2-1",
                source=ElementRef(type=ReferenceType.controlled_process, id="CP-2"),
            )
        ],
    )
    link = CoordinationLink(
        link_id="CL-1",
        source="RESP-1",
        target="RESP-2",
        shared_pm="PM-1-1",
        coordination_mechanism=CoordinationMechanism(
            cm_id="CM-1", description="Mechanism", payload="data"
        ),
        description="Link",
    )
    return ControlStructure(
        responsibilities=[resp1, resp2],
        controlled_processes=cps,
        coordination_links=[link],
    )


def _make_test_loss_analysis() -> LossAnalysis:
    """Build a loss analysis with hazard H-1 and constraint SC-1."""
    return LossAnalysis(
        risk_card_losses=[
            Loss(
                loss_id="L-1",
                description="Loss",
                provenance=LossProvenance.risk_card,
                source_risk_cards=["atlas-001"],
            )
        ],
        use_case_losses=[],
        hazards=[
            Hazard(hazard_id="H-1", description="Hazard", related_losses=["L-1"]),
        ],
        security_constraints=[
            SecurityConstraint(
                constraint_id="SC-1", rule="Constraint", related_hazards=["H-1"]
            ),
        ],
    )


# ---------------------------------------------------------------------------
# One LLM call per responsibility (SP2-FILL-01)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# System prompt defines four ICA types (SP2-FILL-02)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# User prompt includes control structure, tech context, slots (SP2-FILL-03)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Filled non-N/A slot has concrete ICA text (SP2-FILL-04)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Filled N/A slot has na_justification (SP2-FILL-05)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# ICA loss_scenario present (SP2-FILL-12)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Calls are stateless (SP2-FILL-08)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Parallelizable (SP2-FILL-09)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Calls logged to calls.jsonl (SP2-FILL-11)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# ICAs reference valid hazard IDs (SP2-FILL-06, SP2-FILL-07)
# ---------------------------------------------------------------------------


class TestHazardIDValidation:
    """ICAs reference valid hazard IDs from the loss analysis."""

    def test_valid_hazard_ids_validate(self):
        cs = _make_test_control_structure()
        la = _make_test_loss_analysis()
        ica_enum = ICAEnumeration(
            slots=[
                ICASlot(
                    slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
                    responsibility="RESP-1",
                    control_action="CA-1-1",
                    uca_type=UCAType.not_provided,
                    is_na=False,
                    icas=[
                        ICA(
                            ica_id="RESP-1:CA-1-1:NOT_PROVIDED:1",
                            ica_text="UCA",
                            hazardous_context="Ctx",
                            loss_scenario="Scenario",
                            related_hazards=["H-1"],
                            related_constraints=["SC-1"],
                        )
                    ],
                ),
            ]
        )
        # Should not raise
        ica_enum.validate_against(la, cs)

    def test_invalid_hazard_ids_rejected(self):
        cs = _make_test_control_structure()
        la = _make_test_loss_analysis()
        ica_enum = ICAEnumeration(
            slots=[
                ICASlot(
                    slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
                    responsibility="RESP-1",
                    control_action="CA-1-1",
                    uca_type=UCAType.not_provided,
                    is_na=False,
                    icas=[
                        ICA(
                            ica_id="RESP-1:CA-1-1:NOT_PROVIDED:1",
                            ica_text="UCA",
                            hazardous_context="Ctx",
                            loss_scenario="Scenario",
                            related_hazards=["H-99"],
                            related_constraints=["SC-1"],
                        )
                    ],
                ),
            ]
        )
        try:
            ica_enum.validate_against(la, cs)
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "related_hazards" in str(e) or "H-99" in str(e)


# ---------------------------------------------------------------------------
# Mutation hardening: _collect_filled_slots type check
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Single-responsibility fill entry point
# ---------------------------------------------------------------------------


def _make_ica() -> ICA:
    return ICA(
        ica_id="RESP-1:CA-1-1:NOT_PROVIDED:1",
        ica_text="The agent fails to validate input",
        hazardous_context="Context",
        loss_scenario="Scenario",
        related_hazards=[],
        related_constraints=[],
    )
