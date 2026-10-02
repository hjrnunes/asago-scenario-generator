"""Property tests for SP3 technology-context prompt propagation.

When a capability profile is supplied, the Stage 5 user prompt contains the
deterministic technology-context block.  When it is not supplied, that
section is absent.
"""

from __future__ import annotations

from hypothesis import given, settings, strategies as st

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
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.models.scenario_spec import (
    AttackerBDI,
    DefenderBDI,
    DefenderBelief,
    DefenderDesire,
    DefenderIntention,
    ScenarioSpec,
    ThreatSource,
)
from asago_scenario_generator.stpa.scenario_prod._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.scenario_prod.bdi_generation import (
    build_bdi_prompts,
    populate_defender_bdi,
)
from asago_scenario_generator.stpa.threat_enum.technology_context import (
    build_technology_context,
    context_for,
)


_HEADING = "## Technology Context"
_KC_POOL = (
    "KC1.1",
    "KC2.3",
    "KC4.3",
    "KC5.1",
    "KC6.2.1",
    "KC6.3.3",
    "KCX-HITL",
)
_LOADER = TemplateLoader(PROMPTS_DIR)


def _control_structure() -> ControlStructure:
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


def _user_prompt(profile: CapabilityProfile | None) -> str:
    """Build the Stage 5 user prompt for one profile."""
    cs = _control_structure()
    _, stage5 = build_bdi_prompts(
        populate_defender_bdi(cs, "RESP-1"),
        _threat(),
        cs,
        "RESP-1",
        _LOADER,
        capability_profile=profile,
    )
    return stage5


@st.composite
def profiles(draw: st.DrawFn) -> CapabilityProfile:
    """Build a valid capability profile over a range of KC combinations."""
    codes = draw(st.lists(st.sampled_from(_KC_POOL), min_size=1, unique=True))
    if "KC1.1" not in codes:
        codes = ["KC1.1", *codes]
    tools = None
    if any(code.startswith(("KC5.", "KC6.")) for code in codes):
        tools = [ToolInventoryEntry(name="search", description="retrieves documents")]
    return CapabilityProfile(
        zones_active=["input", "reasoning"],
        entry_points=[
            EntryPoint(name="chat", direction="input", controllability="direct"),
        ],
        confidence="medium",
        kc_subcodes=codes,
        tool_inventory=tools,
    )


class TestContextPropagationProperty:
    """Presence and absence of technology context stay aligned."""

    @given(profile=profiles())
    @settings(max_examples=40, deadline=None)
    def test_profile_reaches_the_prompt(self, profile: CapabilityProfile):
        """A supplied profile appears verbatim in the Stage 5 prompt."""
        expected = build_technology_context(profile)
        stage5 = _user_prompt(profile)
        assert _HEADING in stage5
        assert expected in stage5
        assert context_for(profile) == expected

    def test_missing_profile_omits_the_section(self):
        """No profile means no technology-context section in the prompt."""
        stage5 = _user_prompt(None)
        assert _HEADING not in stage5
        assert context_for(None) is None
