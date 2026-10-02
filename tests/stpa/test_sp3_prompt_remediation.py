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
)
from asago_scenario_generator.stpa.scenario_prod.bdi_generation import (
    BDIGenerationResult,
    CausalFactorDeclaration,
    build_context_bdi_prompts,
    generate_bdi,
    populate_defender_bdi,
)
from asago_scenario_generator.stpa.models.causal_factor import CausalFactorKind
from tests.stpa.sp1_helpers import MockLLMClient

from .test_sp3_scenario_continuity import _context


PROMPTS_DIR = (
    Path(__file__).parents[2]
    / "src/asago_scenario_generator/stpa/scenario_prod/prompts"
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


def test_stage5_prompt_defines_feedback_bridge_and_negative_rule():
    prompt = TemplateLoader(PROMPTS_DIR).render_prompt("stage5_system.j2")

    assert BRIDGE in prompt
    assert "supplied technology-context mechanisms" in prompt
    assert "declared AI surfaces" in prompt
    assert "Do not invent packet interception" in prompt
    assert all(mechanism in prompt for mechanism in NEGATIVE_MECHANISMS)


def test_contextual_stage5_defines_loss_scenario_and_bdi() -> None:
    prompt, _ = build_context_bdi_prompts(_context(), TemplateLoader(PROMPTS_DIR))

    assert "STPA (System-Theoretic Process Analysis)" in prompt
    assert "A **loss scenario** is the causal explanation" in prompt
    assert "BDI means Belief–Desire–Intention" in prompt


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
