"""Scenario-continuity regressions for the corrected SP3 public seams."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlStructure,
    ControlledProcess,
    CoordinationLink,
    CoordinationMechanism,
    ElementRef,
    FeedbackChannel,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
)
from asago_scenario_generator.stpa.models.enriched_threat_set import (
    CoverageAnalysis,
    EnrichedThreatSet,
    StructuralThreat,
)
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
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
from asago_scenario_generator.stpa.models.scenario_context import (
    ReachableCapability,
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
)
from asago_scenario_generator.stpa.scenario_prod._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.scenario_prod.bdi_generation import (
    BDIGenerationResult,
    CausalFactorDeclaration,
    UnsafeOutcomeDeclaration,
    assemble_scenario_spec,
    build_context_bdi_prompts,
    generate_bdi_for_context,
    populate_defender_bdi,
)
from asago_scenario_generator.stpa.scenario_prod.assembly import (
    assemble_candidate_envelope,
)
from asago_scenario_generator.stpa.scenario_prod.context import (
    build_scenario_generation_context,
    render_scenario_generation_context,
)
from asago_scenario_generator.stpa.scenario_prod.gherkin import (
    build_gherkin_prompts,
    find_security_constraint,
    generate_gherkin,
)
from asago_scenario_generator.stpa.scenario_prod.run import run_sp3
from asago_scenario_generator.stpa.scenario_prod.validators import (
    validate_active_access_grounding,
)
from asago_scenario_generator.stpa.scenario_prod.attack_tree import (
    build_attack_tree_prompts,
)
from asago_scenario_generator.stpa.scenario_prod.narrative import (
    build_narrative_prompts,
)
from tests.stpa.sp1_helpers import MockLLMClient


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
                description="Mask customer PII before disclosure",
                related_hazards=["H-PII"],
            ),
            SecurityConstraint(
                constraint_id="SC-MASS",
                description="Enforce reviewed batch limits before authorization",
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


def _coordination_control_structure() -> ControlStructure:
    """Build two exact endpoint responsibilities joined by one CL/CM path."""
    source = (
        _control_structure()
        .responsibilities[0]
        .model_copy(update={"resp_id": "RESP-1"})
    )
    target = Responsibility(
        resp_id="RESP-2",
        description="Verify the action against shared policy state",
        process_model_parts=[
            ProcessModelPart(pm_id="PM-2-1", description="Shared policy state")
        ],
        control_actions=[
            ControlAction(
                ca_id="CA-2-1",
                description="Verify the selected payment action",
                target=ElementRef(type=ReferenceType.controlled_process, id="CP-2"),
            )
        ],
        feedback_channels=[
            FeedbackChannel(
                fb_id="FB-2-1",
                description="Policy verification feedback",
                updates="PM-2-1",
                source=ElementRef(type=ReferenceType.controlled_process, id="CP-2"),
            )
        ],
    )
    return ControlStructure(
        responsibilities=[source, target],
        controlled_processes=[
            ControlledProcess(cp_id="CP-1", description="Payment service"),
            ControlledProcess(cp_id="CP-2", description="Policy verification service"),
        ],
        coordination_links=[
            CoordinationLink(
                link_id="CL-1",
                source="RESP-1",
                target="RESP-2",
                shared_pm="PM-1-1",
                coordination_mechanism=CoordinationMechanism(
                    cm_id="CM-1",
                    description="Synchronize payment policy state",
                    payload="policy_state",
                ),
                description="Payment authorization and policy verification coordinate",
            )
        ],
    )


def _coordination_threat() -> StructuralThreat:
    return StructuralThreat(
        ica_slot_id="CL-1:CM-1:INCORRECT",
        ica_id="CL-1:CM-1:INCORRECT:1",
        ica_text="The coordination mechanism transmits an incorrect policy state.",
        hazardous_context="A manipulated policy state reaches payment authorization.",
        loss_scenario="An unauthorized payment is approved.",
        related_hazards=["H-MASS"],
        related_constraints=["SC-MASS"],
    )


def test_context_supports_exact_coordination_link_path() -> None:
    context = build_scenario_generation_context(
        _coordination_threat(),
        _coordination_control_structure(),
        _loss_analysis(),
        scenario_id="SCN-CL-001",
    )

    path = context.target_control_path
    assert path.controller.element_id == "CL-1"
    assert path.control_action.action_id == "CM-1"
    assert path.coordination_path is not None
    assert path.coordination_path.link_id == "CL-1"
    assert path.coordination_path.source.element_id == "RESP-1"
    assert path.coordination_path.target.element_id == "RESP-2"
    assert path.coordination_path.shared_process_model.element_id == "PM-1-1"
    assert path.coordination_path.coordination_mechanism.element_id == "CM-1"
    assert "CL-1" in render_scenario_generation_context(context)

    _system, prompt = build_context_bdi_prompts(context, TemplateLoader(PROMPTS_DIR))
    assert "coordination" in prompt.lower()
    assert "CM-1" in prompt
    assert "Synchronize payment policy state" in prompt


def test_context_stage5_offers_only_compiler_owned_causal_source_handles() -> None:
    """Coordination IDs stay context, while causal sources use local handles."""
    context = build_scenario_generation_context(
        _coordination_threat(),
        _coordination_control_structure(),
        _loss_analysis(),
        scenario_id="SCN-CL-001",
    )

    _system, prompt = build_context_bdi_prompts(context, TemplateLoader(PROMPTS_DIR))
    choices = prompt.split("## Allowed Causal-Factor Sources", 1)[1].split(
        "## Your Task", 1
    )[0]

    assert "source_handle: cause_1" in choices
    assert "kind: PROCESS_MODEL_FLAW" in choices
    assert "source_id: PM-1-1" in choices
    assert "source_id: CL-1" not in choices
    assert "source_id: CM-1" not in choices
    assert "source_id: RESP-1" not in choices
    assert "source_id: CP-1" not in choices


def test_context_stage5_compiles_local_handles_to_exact_structural_sources(
    tmp_path,
) -> None:
    """Provider prose chooses local handles; deterministic code owns exact IDs."""
    context = _context()
    client = MockLLMClient()
    client.set_response_queue(
        [
            {
                "defender_vulnerabilities": [
                    {
                        "belief_handle": "belief_1",
                        "vulnerability": "The batch count can remain stale.",
                    }
                ],
                "attacker_bdi": {
                    "beliefs": ["The controller can act on a stale batch count."],
                    "desires": ["Induce the selected unsafe action."],
                    "intentions": [
                        {
                            "description": "Keep the batch count stale.",
                            "source_handles": ["cause_1"],
                        }
                    ],
                },
                "causal_factors": [
                    {
                        "source_handle": "cause_1",
                        "evidence": "The selected process-model state stays stale.",
                        "temporal_condition": None,
                        "evidence_status": "structural_failure",
                        "capability_refs": [],
                        "access_refs": [],
                        "bounded_assumption": None,
                    }
                ],
                "unsafe_outcome": {
                    "condition": {
                        "type": "action_value",
                        "control_action_id": "CA-1-1",
                        "property": "authorization_state",
                        "operator": "equals",
                        "expected": "approved",
                    },
                    "semantic_binding_required": False,
                },
            }
        ]
    )

    result, error = generate_bdi_for_context(client, context, tmp_path)

    assert error is None
    assert result is not None
    assert result.causal_factors[0].kind is CausalFactorKind.process_model_flaw
    assert result.causal_factors[0].source_id == "PM-1-1"
    assert result.defender_vulnerabilities == {
        "PM-1-1": "The batch count can remain stale."
    }
    assert "PM-1-1" in result.attacker_bdi.intentions[0]
    assert "cause_1" not in result.model_dump_json()


def test_context_stage5_preserves_explicit_assumption_when_status_is_mislabeled(
    tmp_path,
) -> None:
    """An explicit assumption is not discarded because its status was mislabeled."""
    context = _context()
    client = MockLLMClient()
    client.set_response_queue(
        [
            {
                "defender_vulnerabilities": [
                    {
                        "belief_handle": "belief_1",
                        "vulnerability": "The batch count may remain stale.",
                    }
                ],
                "attacker_bdi": {
                    "beliefs": ["The controller may act on a stale batch count."],
                    "desires": ["Induce the selected unsafe action."],
                    "intentions": [
                        {
                            "description": "Rely on a delayed state update.",
                            "source_handles": ["cause_1"],
                        }
                    ],
                },
                "causal_factors": [
                    {
                        "source_handle": "cause_1",
                        "evidence": "The process model may remain stale.",
                        "temporal_condition": None,
                        "evidence_status": "structural_failure",
                        "capability_refs": [],
                        "access_refs": [],
                        "bounded_assumption": "Assume the update arrives late.",
                    }
                ],
                "unsafe_outcome": {
                    "condition": {
                        "type": "action_value",
                        "control_action_id": "CA-1-1",
                        "property": "authorization_state",
                        "operator": "equals",
                        "expected": "approved",
                    },
                    "semantic_binding_required": False,
                },
            }
        ]
    )

    result, error = generate_bdi_for_context(client, context, tmp_path)

    assert error is None
    assert result is not None
    factor = result.causal_factors[0]
    assert factor.evidence_status == "bounded_assumption"
    assert factor.bounded_assumption == "Assume the update arrives late."


def test_context_stage5_intentions_must_reference_a_declared_factor(tmp_path) -> None:
    """An intention cannot cite context that was omitted from causal evidence."""
    context = _context()
    client = MockLLMClient()
    client.set_response_queue(
        [
            {
                "defender_vulnerabilities": [
                    {
                        "belief_handle": "belief_1",
                        "vulnerability": "The batch count can remain stale.",
                    }
                ],
                "attacker_bdi": {
                    "beliefs": ["The controller can act on stale state."],
                    "desires": ["Induce the selected unsafe action."],
                    "intentions": [
                        {
                            "description": "Exploit unrelated feedback timing.",
                            "source_handles": ["cause_2"],
                        }
                    ],
                },
                "causal_factors": [
                    {
                        "source_handle": "cause_1",
                        "evidence": "The selected process-model state stays stale.",
                        "temporal_condition": None,
                        "evidence_status": "structural_failure",
                        "capability_refs": [],
                        "access_refs": [],
                        "bounded_assumption": None,
                    }
                ],
                "unsafe_outcome": {
                    "condition": {
                        "type": "action_value",
                        "control_action_id": "CA-1-1",
                        "property": "authorization_state",
                        "operator": "equals",
                        "expected": "approved",
                    },
                    "semantic_binding_required": False,
                },
            }
        ]
    )

    result, error = generate_bdi_for_context(client, context, tmp_path)

    assert result is None
    assert error is not None
    assert "intention source handles must have declared causal factors" in error


def test_context_stage5_requires_one_vulnerability_for_every_selected_belief(
    tmp_path,
) -> None:
    """The provider cannot omit a selected defender belief from its response."""
    context = build_scenario_generation_context(
        _coordination_threat(),
        _coordination_control_structure(),
        _loss_analysis(),
        scenario_id="SCN-CL-001",
    )
    client = MockLLMClient()
    invalid_response = {
        "defender_vulnerabilities": [
            {
                "belief_handle": "belief_1",
                "vulnerability": "The selected state may remain stale.",
            }
        ],
        "attacker_bdi": {
            "beliefs": ["The selected state may remain stale."],
            "desires": ["Induce the selected unsafe action."],
            "intentions": [
                {
                    "description": "Rely on the stale state.",
                    "source_handles": ["cause_1"],
                }
            ],
        },
        "causal_factors": [
            {
                "source_handle": "cause_1",
                "evidence": "The selected state remains stale.",
                "temporal_condition": None,
                "evidence_status": "structural_failure",
            }
        ],
        "unsafe_outcome": {
            "condition": {
                "type": "action_value",
                "control_action_id": "CM-1",
                "property": "authorization_state",
                "operator": "equals",
                "expected": "approved",
            },
            "semantic_binding_required": False,
        },
    }
    client.set_response_queue([invalid_response, invalid_response])

    result, error = generate_bdi_for_context(client, context, tmp_path)

    assert result is None
    assert error is not None
    assert "defender_vulnerabilities" in error


def test_context_rejects_unknown_coordination_link() -> None:
    threat = _coordination_threat().model_copy(
        update={"ica_slot_id": "CL-404:CM-1:INCORRECT"}
    )

    with pytest.raises(ValueError, match="coordination link"):
        build_scenario_generation_context(
            threat,
            _coordination_control_structure(),
            _loss_analysis(),
            scenario_id="SCN-CL-001",
        )


def test_context_rejects_coordination_slot_with_wrong_mechanism() -> None:
    threat = _coordination_threat().model_copy(
        update={"ica_slot_id": "CL-1:CM-404:INCORRECT"}
    )

    with pytest.raises(ValueError, match="coordination mechanism"):
        build_scenario_generation_context(
            threat,
            _coordination_control_structure(),
            _loss_analysis(),
            scenario_id="SCN-CL-001",
        )


def test_context_rejects_dangling_coordination_endpoint() -> None:
    control_structure = _coordination_control_structure()
    bad_link = control_structure.coordination_links[0].model_copy(
        update={"target": "RESP-404"}
    )
    unchecked_structure = ControlStructure.model_construct(
        responsibilities=control_structure.responsibilities,
        controlled_processes=control_structure.controlled_processes,
        coordination_links=[bad_link],
    )

    with pytest.raises(ValueError, match="responsibility"):
        build_scenario_generation_context(
            _coordination_threat(),
            unchecked_structure,
            _loss_analysis(),
            scenario_id="SCN-CL-001",
        )


def test_coordination_bdi_and_spec_validate_against_exact_link() -> None:
    control_structure = _coordination_control_structure()
    threat = _coordination_threat()
    context = build_scenario_generation_context(
        threat,
        control_structure,
        _loss_analysis(),
        scenario_id="SCN-001",
    )

    defender_bdi = populate_defender_bdi(control_structure, "CL-1")
    result = BDIGenerationResult(
        defender_vulnerabilities={
            item.pm_id: "The shared state can be stale."
            for item in control_structure.responsibilities[0].process_model_parts
        },
        attacker_bdi=AttackerBDI(
            beliefs=["The coordination state can be manipulated."],
            desires=["Induce the selected coordination ICA."],
            intentions=["Manipulate PM-1-1 before CM-1 is used."],
        ),
        causal_factors=[
            CausalFactorDeclaration(
                kind=CausalFactorKind.process_model_flaw,
                source_id="PM-1-1",
                evidence="The shared policy state can be stale when synchronized.",
            )
        ],
    )

    spec = assemble_scenario_spec(
        defender_bdi,
        result,
        threat,
        control_structure,
        scenario_context=context,
    )

    assert spec.target_controller == "CL-1"
    assert spec.target_control_action == "CM-1"
    spec.validate_against(control_structure)


def test_coordination_candidate_envelope_preserves_cl_cm_identity() -> None:
    control_structure = _coordination_control_structure()
    envelope = assemble_candidate_envelope(
        control_structure,
        controller_id="CL-1",
        control_action_id="CM-1",
        uca_type=UCAType.incorrect,
        causal_factors=[
            CausalFactor(
                kind=CausalFactorKind.process_model_flaw,
                source_id="PM-1-1",
                description="The shared policy state can be stale.",
            )
        ],
        derive_temporal_vector=True,
    )

    assert envelope.candidate_id == "EXEC:CL-1:CM-1:INCORRECT"
    assert envelope.control_action_description == "Synchronize payment policy state"


def test_run_sp3_realizes_coordination_slot_without_relabeled_identity(
    tmp_path,
) -> None:
    control_structure = _coordination_control_structure()
    threat = _coordination_threat()
    enriched = EnrichedThreatSet(
        structural_threats=[threat],
        coverage_analysis=CoverageAnalysis(
            structural_coverage={"total_slots": 1, "non_na": 1, "na": 0},
            structural_consideration={"total_slots": 1, "considered": 1},
            na_quality={},
        ),
    )
    client = MockLLMClient()
    client.set_response_queue(
        [
            BDIGenerationResult(
                defender_vulnerabilities={
                    "PM-1-1": "The shared state can be stale.",
                    "PM-2-1": "The verification state can be stale.",
                },
                attacker_bdi=AttackerBDI(
                    beliefs=["The coordination state can be manipulated."],
                    desires=["Induce the coordination ICA."],
                    intentions=["Rely on stale PM-1-1 before CM-1 is used."],
                ),
                causal_factors=[
                    CausalFactorDeclaration(
                        kind=CausalFactorKind.process_model_flaw,
                        source_id="PM-1-1",
                        evidence="The shared policy state can be stale when synchronized.",
                    )
                ],
                unsafe_outcome=UnsafeOutcomeDeclaration(
                    condition=ActionValueCondition(
                        control_action_id="CM-1",
                        property="authorization_state",
                        operator="equals",
                        expected="approved",
                    ),
                    semantic_binding_required=False,
                ),
            ),
            "Step 1: The path begins with the shared policy state.\n"
            "Step 2: PM-1-1 becomes stale before synchronization.\n"
            "Step 3: The coordination mechanism carries the changed state.\n"
            "Step 4: The receiver acts on the changed state.\n"
            "Step 5: The incorrect coordination action occurs.\n"
            "Step 6: The hazard follows.\n"
            "Step 7: The loss follows.\n",
            json.dumps(
                {
                    "root": "Induce ICA INCORRECT on CM-1",
                    "branches": [
                        {"category": "controller_side", "children": []},
                        {"category": "path_side", "children": []},
                    ],
                    "leaves": ["PM-1-1 is stale", "CM-1 carries it"],
                }
            ),
            "feature: Coordination scenario\n"
            "scenario: Coordination scenario\n"
            "given:\n"
            "  - Given PM-1-1 is current\n"
            "when:\n"
            "  - When PM-1-1 is stale during synchronization\n"
            "then_expected:\n"
            "  - Then the system should reject the changed state\n"
            "then_actual:\n"
            "  - But the system performs INCORRECT on CM-1\n"
            "  - And loss L-MASS is realized\n",
        ]
    )

    result = run_sp3(
        llm_client=client,
        enriched_threat_set=enriched,
        control_structure=control_structure,
        loss_analysis=_loss_analysis(),
        run_dir=tmp_path,
    )

    assert len(result.scenario_envelopes) == 1
    assert result.scenario_envelopes[0].scenario_spec.target_controller == "CL-1"
    assert result.scenario_envelopes[0].scenario_spec.target_control_action == "CM-1"


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
        scenario_context=context,
    )


def test_stage5_context_preserves_mass_action_meaning_and_excludes_unrelated_pii() -> (
    None
):
    context = _context()
    _, prompt = build_context_bdi_prompts(context, TemplateLoader(PROMPTS_DIR))

    assert context.ica.exact_ica_text == _threat().ica_text
    assert [item.hazard_id for item in context.hazards] == ["H-MASS"]
    assert [item.constraint_id for item in context.constraints] == ["SC-MASS"]
    assert "unbounded batch" in prompt
    assert "SC-MASS" in prompt
    assert "CAP-PAYMENT" in prompt
    assert "SC-PII" not in prompt
    assert "Mask customer PII" not in prompt


@pytest.mark.parametrize("causal_factors", [None, []])
def test_successful_stage5_response_requires_explicit_nonempty_causal_factors(
    causal_factors,
) -> None:
    payload = {
        "defender_vulnerabilities": {"PM-1-1": "count feedback can be stale"},
        "attacker_bdi": AttackerBDI(
            beliefs=["The action count can be stale"],
            desires=["Induce the selected ICA"],
            intentions=["Manipulate FB-1-1"],
        ).model_dump(mode="json"),
    }
    if causal_factors is not None:
        payload["causal_factors"] = causal_factors

    with pytest.raises(ValidationError, match="causal_factors"):
        BDIGenerationResult.model_validate(payload)


def test_stage5_response_cannot_replace_authoritative_scenario_context() -> None:
    with pytest.raises(ValidationError, match="ica_text"):
        BDIGenerationResult.model_validate(
            {
                "defender_vulnerabilities": {"PM-1-1": "stale feedback"},
                "attacker_bdi": {
                    "beliefs": ["stale feedback"],
                    "desires": ["induce ICA"],
                    "intentions": ["manipulate FB-1-1"],
                },
                "causal_factors": [
                    {
                        "kind": "feedback_delay",
                        "source_id": "FB-1-1",
                        "evidence": "The feedback update arrives after authorization.",
                    }
                ],
                "ica_text": "Replace the mass-action ICA with a PII masking bypass",
            }
        )


def test_gherkin_uses_exact_nhs_style_integrity_constraint_not_first_global() -> None:
    context = _context()
    from asago_scenario_generator.stpa.models.scenario_spec import ScenarioSpec

    spec = ScenarioSpec.model_construct(scenario_context=context)

    constraint = find_security_constraint(spec, _loss_analysis())

    assert constraint.constraint_id == "SC-MASS"
    assert (
        constraint.description == "Enforce reviewed batch limits before authorization"
    )


def test_context_fails_closed_when_selected_constraint_does_not_govern_hazard() -> None:
    with pytest.raises(ValueError, match="does not govern"):
        build_scenario_generation_context(
            _threat(constraint_id="SC-PII"),
            _control_structure(),
            _loss_analysis(),
            scenario_id="SCN-001",
        )


def test_context_digest_detects_authority_tamper() -> None:
    payload = _context().model_dump(mode="json")
    payload["ica"]["exact_ica_text"] = "A different unsafe action"

    from asago_scenario_generator.stpa.models.scenario_context import (
        ScenarioGenerationContext,
    )

    with pytest.raises(ValidationError, match="context_digest"):
        ScenarioGenerationContext.model_validate(payload)


def test_context_factory_hashes_model_defaults_when_optional_collections_omitted() -> (
    None
):
    from asago_scenario_generator.stpa.models.scenario_context import (
        ScenarioGenerationContext,
    )

    payload = _context().model_dump(
        mode="python",
        exclude={
            "context_digest",
            "obligation_considerations",
            "reachable_capabilities",
            "catalog_context",
        },
    )

    rebuilt = ScenarioGenerationContext.create(**payload)

    assert rebuilt.obligation_considerations == ()
    assert rebuilt.reachable_capabilities == ()
    assert rebuilt.catalog_context == ()


def test_all_stage6_prompts_consume_the_same_exact_context() -> None:
    spec = _contextual_spec()
    loader = TemplateLoader(PROMPTS_DIR)
    constraint = find_security_constraint(spec, _loss_analysis())

    prompts = (
        build_narrative_prompts(spec, loader)[1],
        build_attack_tree_prompts(spec, _control_structure(), loader)[1],
        build_gherkin_prompts(spec, constraint, _loss_analysis(), loader)[1],
    )

    for prompt in prompts:
        assert spec.scenario_context.context_digest in prompt
        assert "unbounded batch of payment" in prompt
        assert "reviewed mass-action limit" in prompt
        assert "SC-MASS" in prompt
        assert "SC-PII" not in prompt


def test_contextual_scenario_rejects_empty_causal_factors() -> None:
    payload = _contextual_spec().model_dump(mode="json")
    payload["causal_factors"] = []

    with pytest.raises(ValidationError, match="requires causal_factors"):
        ScenarioSpec.model_validate(payload)


def test_no_capability_context_rejects_asserted_active_access() -> None:
    context = build_scenario_generation_context(
        _threat(),
        _control_structure(),
        _loss_analysis(),
        scenario_id="SCN-001",
    )
    spec = _contextual_spec().model_copy(update={"scenario_context": context})

    result = validate_active_access_grounding(
        spec,
        "The attacker injects a forged update into the feedback path.",
    )

    assert not result.passed
    assert "unsupported active access" in result.errors[0]


@pytest.mark.parametrize(
    "claim",
    (
        "Exploit the stale process-model window.",
        "Replay stale feedback before the control action.",
        "Induce the selected unsafe output from stale PM-1-1 state.",
        "Elicit a response before the delayed sanitization action.",
        "Bypass the current forbidden-pattern check because PM-1-1 is stale.",
    ),
)
def test_no_capability_context_allows_adversarial_use_of_structural_failure(
    claim: str,
) -> None:
    context = build_scenario_generation_context(
        _threat(),
        _control_structure(),
        _loss_analysis(),
        scenario_id="SCN-001",
    )
    spec = _contextual_spec().model_copy(update={"scenario_context": context})

    result = validate_active_access_grounding(spec, claim)

    assert result.passed


def test_reachable_capability_context_allows_active_access_description() -> None:
    result = validate_active_access_grounding(
        _contextual_spec(),
        "The attacker injects a request through the supplied payment access path.",
    )

    assert result.passed


def test_bounded_assumption_requires_and_accepts_explicit_label() -> None:
    context = build_scenario_generation_context(
        _threat(),
        _control_structure(),
        _loss_analysis(),
        scenario_id="SCN-001",
    )
    spec = _contextual_spec().model_copy(
        update={
            "scenario_context": context,
            "causal_factors": [
                CausalFactor(
                    kind=CausalFactorKind.process_model_flaw,
                    source_id="PM-1-1",
                    description="The state may be stale.",
                    evidence_status="bounded_assumption",
                    bounded_assumption="Assume a forged update can reach the state.",
                )
            ],
        }
    )

    labelled = validate_active_access_grounding(
        spec,
        "Assumption: an adversary injects a forged update.",
    )
    unlabelled = validate_active_access_grounding(
        spec,
        "An adversary injects a forged update.",
    )

    assert labelled.passed
    assert not unlabelled.passed


def test_stage5_rejects_causal_factor_from_unselected_control_path() -> None:
    selected = _control_structure()
    unrelated = Responsibility(
        resp_id="RESP-2",
        description="Mask PII",
        process_model_parts=[
            ProcessModelPart(pm_id="PM-2-1", description="PII classification state")
        ],
        control_actions=[
            ControlAction(
                ca_id="CA-2-1",
                description="Mask PII",
                target=ElementRef(type=ReferenceType.controlled_process, id="CP-1"),
            )
        ],
    )
    control_structure = ControlStructure(
        responsibilities=[*selected.responsibilities, unrelated],
        controlled_processes=selected.controlled_processes,
    )
    context = build_scenario_generation_context(
        _threat(),
        control_structure,
        _loss_analysis(),
        scenario_id="SCN-001",
    )
    result = BDIGenerationResult(
        defender_vulnerabilities={"PM-1-1": "stale count"},
        attacker_bdi=AttackerBDI(
            beliefs=["PII state is reachable"],
            desires=["change the selected concern"],
            intentions=["manipulate PM-2-1"],
        ),
        causal_factors=[
            CausalFactorDeclaration(
                kind=CausalFactorKind.process_model_flaw,
                source_id="PM-2-1",
                evidence="Unrelated PII classification evidence",
            )
        ],
    )

    with pytest.raises(ValueError, match="outside the selected scenario control path"):
        assemble_scenario_spec(
            populate_defender_bdi(control_structure, "RESP-1"),
            result,
            _threat(),
            control_structure,
            scenario_context=context,
        )


def test_gherkin_fails_without_call_when_exact_constraint_authority_changed(
    tmp_path,
) -> None:
    loss_analysis = _loss_analysis()
    changed = loss_analysis.model_copy(
        update={
            "security_constraints": [
                loss_analysis.security_constraints[0],
                loss_analysis.security_constraints[1].model_copy(
                    update={"description": "A changed constraint"}
                ),
            ]
        }
    )
    client = MockLLMClient()

    result, raw, error = generate_gherkin(
        client,
        _contextual_spec(),
        changed,
        tmp_path,
    )

    assert result is None
    assert raw is None
    assert (
        error
        == "ScenarioContextError: scenario governing constraint changed after context capture"
    )
    assert client.call_count == 0
