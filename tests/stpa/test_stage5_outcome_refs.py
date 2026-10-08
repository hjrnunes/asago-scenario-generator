"""Without a scenario context, Stage 5 assembly takes the outcome refs from the threat."""

from __future__ import annotations

from asago_scenario_generator.stpa.models.causal_factor import CausalFactorKind
from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlledProcess,
    ControlStructure,
    ElementRef,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
)
from asago_scenario_generator.stpa.models.enriched_threat_set import StructuralThreat
from asago_scenario_generator.stpa.models.scenario_spec import AttackerBDI
from asago_scenario_generator.stpa.scenario_prod.stage5.assemble import (
    assemble_scenario_spec,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.defender import (
    populate_defender_bdi,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.wire import (
    BDIGenerationResult,
    CausalFactorDeclaration,
    UnsafeOutcomeDeclaration,
)


def _control_structure() -> ControlStructure:
    return ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="Authorize payment operations",
                process_model_parts=[
                    ProcessModelPart(pm_id="PM-1-1", description="User intent state")
                ],
                control_actions=[
                    ControlAction(
                        ca_id="CA-1-1",
                        description="Select tool for request",
                        target=ElementRef(
                            type=ReferenceType.controlled_process, id="CP-1"
                        ),
                    )
                ],
            )
        ],
        controlled_processes=[ControlledProcess(cp_id="CP-1", description="Interface")],
    )


def _threat() -> StructuralThreat:
    return StructuralThreat(
        ica_slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
        provenance="structural",
        ica_id="RESP-1:CA-1-1:NOT_PROVIDED:1",
        ica_text="The agent fails to select a tool for a request.",
        hazardous_context="A user requests a refund but the agent fails.",
        loss_scenario="The user believes a refund is being processed.",
        related_hazards=["H-1"],
        related_constraints=["SC-1"],
    )


def _result(unsafe_outcome: UnsafeOutcomeDeclaration | None) -> BDIGenerationResult:
    return BDIGenerationResult(
        defender_vulnerabilities={"PM-1-1": "Intent can be stale."},
        causal_factors=[
            CausalFactorDeclaration(
                kind=CausalFactorKind.process_model_flaw,
                source_id="PM-1-1",
                evidence="The selected process-model state can be stale.",
            )
        ],
        attacker_bdi=AttackerBDI(beliefs=["b"], desires=["d"], intentions=["i"]),
        unsafe_outcome=unsafe_outcome,
    )


def _refs(unsafe_outcome: UnsafeOutcomeDeclaration | None) -> tuple[list, list]:
    structure = _control_structure()
    spec = assemble_scenario_spec(
        populate_defender_bdi(structure, "RESP-1"),
        _result(unsafe_outcome),
        _threat(),
        structure,
    )
    return spec.unsafe_outcome_hazard_refs, spec.unsafe_outcome_constraint_refs


def test_absent_unsafe_outcome_falls_back_to_the_threat_refs() -> None:
    assert _refs(None) == (["H-1"], ["SC-1"])
