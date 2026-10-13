"""Stage 5 takes the outcome refs from the scenario context's selected lineage."""

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
from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossAnalysis,
    LossProvenance,
    SecurityConstraint,
)
from asago_scenario_generator.stpa.scenario_prod.context import (
    build_scenario_generation_context,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.sources import (
    _causal_source_choices,
)
from tests.helpers.stage5_assembly import stage5_assembly
from tests.helpers.stage5_compile import compile_draft, draft_payload, factor, handle_of


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


def _loss_analysis() -> LossAnalysis:
    return LossAnalysis(
        risk_card_losses=[],
        use_case_losses=[
            Loss(
                loss_id="L-1",
                description="The user is misled about a refund",
                provenance=LossProvenance.use_case,
            )
        ],
        hazards=[
            Hazard(
                hazard_id="H-1",
                description="The agent omits a required tool call",
                related_losses=["L-1"],
            ),
            Hazard(
                hazard_id="H-2",
                description="An unrelated hazard outside the threat",
                related_losses=["L-1"],
            ),
        ],
        security_constraints=[
            SecurityConstraint(
                constraint_id="SC-1",
                rule="Select the tool the request requires",
                related_hazards=["H-1"],
            ),
            SecurityConstraint(
                constraint_id="SC-2",
                rule="An unrelated constraint outside the threat",
                related_hazards=["H-2"],
            ),
        ],
    )


def _refs() -> tuple[list, list]:
    structure = _control_structure()
    context = build_scenario_generation_context(
        _threat(), structure, _loss_analysis(), scenario_id="SCN-001"
    )
    handle = handle_of(
        _causal_source_choices(context), CausalFactorKind.process_model_flaw, "PM-1-1"
    )
    spec = compile_draft(
        draft_payload(
            [factor(handle, "The selected process-model state can be stale.")]
        ),
        context,
        stage5_assembly(context, _threat(), structure),
    )
    return spec.unsafe_outcome_hazard_refs, spec.unsafe_outcome_constraint_refs


def test_outcome_refs_are_the_scenario_context_lineage() -> None:
    assert _refs() == (["H-1"], ["SC-1"])
