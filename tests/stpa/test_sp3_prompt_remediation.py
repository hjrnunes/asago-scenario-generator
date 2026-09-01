"""Focused tests for SP3 feedback guidance and mechanism context."""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    EntryPoint,
    ToolInventoryEntry,
)
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
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
from asago_scenario_generator.stpa.models.scenario_spec import (
    AttackerBDI,
    DefenderBDI,
    DefenderBelief,
    DefenderDesire,
    DefenderIntention,
    ScenarioSpec,
    ThreatSource,
)
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.scenario_prod.bdi_generation import (
    BDIGenerationResult,
    CausalFactorDeclaration,
    generate_bdi,
    populate_defender_bdi,
)
from asago_scenario_generator.stpa.models.causal_factor import CausalFactorKind
from asago_scenario_generator.stpa.scenario_prod.narrative import (
    build_narrative_prompts,
)
from tests.stpa.sp1_helpers import MockLLMClient


PROMPTS_DIR = (
    Path(__file__).parents[2]
    / "src/asago_scenario_generator/stpa/scenario_prod/prompts"
)
STAGE3_PROMPTS_DIR = (
    Path(__file__).parents[2] / "src/asago_scenario_generator/stpa/threat_enum/prompts"
)

BRIDGE = (
    "FB-* denotes a logical information dependency that updates a process-model belief"
)
SURFACES = (
    "prompt/context input",
    "retrieved content",
    "tool result",
    "memory state",
    "agent message",
    "model output",
)
NEGATIVE_MECHANISMS = (
    "packet interception",
    "MITM",
    "network delay",
    "traffic blocking",
    "network-signal spoofing",
    "communication-link severing",
    "credential theft",
    "account takeover",
    "session hijacking/fixation",
    "generic flooding/DoS",
)


def _profile() -> CapabilityProfile:
    """Build a profile whose context contains every positive mechanism."""
    return CapabilityProfile(
        zones_active=["input", "tool_execution", "memory", "inter_agent"],
        entry_points=[
            EntryPoint(name="chat", direction="input", controllability="direct"),
        ],
        confidence="medium",
        kc_subcodes=["KC1.1", "KC6.3.3", "KC4.3", "KC2.3"],
        tool_inventory=[
            ToolInventoryEntry(name="search", description="retrieves documents"),
        ],
    )


def _control_structure() -> ControlStructure:
    """Build the smallest control structure needed by Stage 5."""
    return ControlStructure(
        controlled_processes=[
            ControlledProcess(cp_id="CP-1", description="Agent interface"),
        ],
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="Coordinate the agent",
                process_model_parts=[
                    ProcessModelPart(pm_id="PM-1-1", description="Retrieved state"),
                ],
                control_actions=[
                    ControlAction(
                        ca_id="CA-1-1",
                        description="Select a tool",
                        target=ElementRef(
                            type=ReferenceType.controlled_process,
                            id="CP-1",
                        ),
                    ),
                ],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-1-1",
                        description="Retrieved feedback",
                        updates="PM-1-1",
                        source=ElementRef(
                            type=ReferenceType.controlled_process,
                            id="CP-1",
                        ),
                    ),
                ],
            ),
        ],
    )


def _threat() -> StructuralThreat:
    """Build a structural threat for the BDI prompt."""
    return StructuralThreat(
        ica_slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
        provenance="structural",
        ica_id="RESP-1:CA-1-1:NOT_PROVIDED:1",
        ica_text="The agent does not select a tool.",
        hazardous_context="The request remains unresolved.",
        loss_scenario="The user receives no service.",
        related_hazards=["H-1"],
        related_constraints=["SC-1"],
    )


def _scenario_spec() -> ScenarioSpec:
    """Build a minimal scenario for the narrative prompt."""
    return ScenarioSpec(
        scenario_id="SCN-001",
        threat_source=ThreatSource(
            ica_slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
            provenance="structural",
            ica_id="RESP-1:CA-1-1:NOT_PROVIDED:1",
        ),
        target_controller="RESP-1",
        target_control_action="CA-1-1",
        ica_type=UCAType.not_provided,
        defender_bdi=DefenderBDI(
            beliefs=[
                DefenderBelief(
                    pm_id="PM-1-1",
                    content="Retrieved state",
                    vulnerability="retrieval can be poisoned",
                ),
            ],
            desires=[DefenderDesire(resp_id="RESP-1", content="Coordinate the agent")],
            intentions=[DefenderIntention(ca_id="CA-1-1", content="Select a tool")],
        ),
        attacker_bdi=AttackerBDI(
            beliefs=["The retrieved state is exploitable"],
            desires=["Induce NOT_PROVIDED"],
            intentions=["Poison PM-1-1 via FB-1-1"],
        ),
        loss_scenario="The user receives no service.",
    )


def _bdi_client() -> MockLLMClient:
    """Return a client with one valid Stage 5 response."""
    client = MockLLMClient()
    client.set_response_for(
        BDIGenerationResult,
        BDIGenerationResult(
            defender_vulnerabilities={"PM-1-1": "retrieval poisoning"},
            causal_factors=[
                CausalFactorDeclaration(
                    kind=CausalFactorKind.feedback_delay,
                    source_id="FB-1-1",
                    evidence="The selected feedback can arrive too late.",
                )
            ],
            attacker_bdi=AttackerBDI(
                beliefs=["The retrieved state is exploitable"],
                desires=["Induce NOT_PROVIDED"],
                intentions=["Poison PM-1-1 via FB-1-1"],
            ),
        ),
    )
    return client


def test_stage3_prompt_defines_feedback_bridge_and_negative_rule():
    prompt = TemplateLoader(STAGE3_PROMPTS_DIR).render_prompt("stage3_system.j2")

    assert BRIDGE in prompt
    assert "not evidence of a network socket" in prompt
    assert "declared AI surface" in prompt
    assert all(surface in prompt for surface in SURFACES)
    assert "Do not invent packet interception" in prompt
    assert all(mechanism in prompt for mechanism in NEGATIVE_MECHANISMS)


def test_stage5_prompt_defines_feedback_bridge_and_negative_rule():
    prompt = TemplateLoader(PROMPTS_DIR).render_prompt("stage5_system.j2")

    assert BRIDGE in prompt
    assert "supplied technology-context mechanisms" in prompt
    assert "declared AI surfaces" in prompt
    assert "Do not invent packet interception" in prompt
    assert all(mechanism in prompt for mechanism in NEGATIVE_MECHANISMS)


def test_stage6_narrative_prompt_uses_ai_surface_realizations():
    prompt = TemplateLoader(PROMPTS_DIR).render_prompt("stage6a_narrative_system.j2")

    assert BRIDGE in prompt
    assert "changes a declared AI surface" in prompt
    assert "prompt/context injection" in prompt
    assert "retrieved-content poisoning" in prompt
    assert "tool-result fabrication" in prompt
    assert "memory poisoning" in prompt
    assert "agent-message tampering" in prompt
    assert "model-output manipulation" in prompt
    assert "poisons a feedback channel" not in prompt


def test_stage6_tree_prompt_uses_evidence_gated_causal_leaves():
    prompt = TemplateLoader(PROMPTS_DIR).render_prompt("stage6b_tree_system.j2")

    leaves = (
        "Process-model state is stale or inaccurate [PM-*]",
        "Feedback is missing, late, stale, or inaccurate [FB-*]",
        "Evidence-backed active change (only with exact capability/access evidence)",
    )
    ungrounded_leaves = (
        "Inject instructions through prompt/context input [FB-*]",
        "Poison retrieved content [FB-*]",
        "Fabricate a tool result [FB-*]",
        "Poison memory state [FB-*]",
    )

    assert all(leaf in prompt for leaf in leaves)
    assert all(leaf not in prompt for leaf in ungrounded_leaves)
    assert (
        "infrastructure leaf only when it cites an explicitly "
        "attacker-accessible architecture element"
    ) in prompt


def test_stage5_prompt_includes_context_when_profile_is_supplied():
    client = _bdi_client()
    with TemporaryDirectory() as tmpdir:
        generate_bdi(
            client,
            populate_defender_bdi(_control_structure(), "RESP-1"),
            _threat(),
            _control_structure(),
            Path(tmpdir),
            capability_profile=_profile(),
        )

    user_prompt = client.calls[0].user_prompt
    assert "Technology Context" in user_prompt
    assert "prompt injection" in user_prompt
    assert "retrieval poisoning" in user_prompt
    assert "tool result fabrication" in user_prompt
    assert "memory poisoning" in user_prompt
    assert "agent impersonation" in user_prompt


def test_stage5_prompt_omits_context_without_profile():
    client = _bdi_client()
    cs = _control_structure()
    with TemporaryDirectory() as tmpdir:
        generate_bdi(
            client,
            populate_defender_bdi(cs, "RESP-1"),
            _threat(),
            cs,
            Path(tmpdir),
        )

    assert "Technology Context" not in client.calls[0].user_prompt


def test_stage6_narrative_prompt_propagates_context():
    loader = TemplateLoader(PROMPTS_DIR)
    _, user_prompt = build_narrative_prompts(
        _scenario_spec(),
        loader,
        capability_profile=_profile(),
    )

    assert "Technology Context" in user_prompt
    assert "prompt injection" in user_prompt
    assert "retrieval poisoning" in user_prompt


def test_stage6_narrative_prompt_omits_context_without_profile():
    loader = TemplateLoader(PROMPTS_DIR)
    _, user_prompt = build_narrative_prompts(_scenario_spec(), loader)

    assert "Technology Context" not in user_prompt
