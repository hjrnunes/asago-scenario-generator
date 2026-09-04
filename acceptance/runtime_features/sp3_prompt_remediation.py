"""Acceptance handlers for SP3 prompt remediation features."""

from __future__ import annotations

import json
import re

from runtime_shared import (
    Path,
    TemplateLoader,
    World,
    _make_sp3_cs,
    _make_sp3_causal_factors,
    _make_sp3_ets,
    _make_sp3_loss_analysis,
    _make_sp3_scenario_spec,
    _make_sp3_threat,
    _setup_sp3_mock_client,
    tempfile,
)

from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    EntryPoint,
    ToolInventoryEntry,
)
from asago_scenario_generator.stpa.models.scenario_context import (
    ReachableCapability,
)
from asago_scenario_generator.stpa.scenario_prod.bdi_generation import (
    build_context_bdi_prompts,
)
from asago_scenario_generator.stpa.scenario_prod.context import (
    build_scenario_generation_context,
)
from asago_scenario_generator.stpa.scenario_prod.narrative import (
    build_narrative_prompts,
    generate_narrative,
)


_BRIDGE = (
    "FB-* denotes a logical information dependency that updates a process-model belief"
)
_SURFACES = (
    "prompt/context input",
    "retrieved content",
    "tool result",
    "memory state",
    "agent message",
    "model output",
)
_LEAVES = (
    "Process-model state is stale or inaccurate [PM-*]",
    "Feedback is missing, late, stale, or inaccurate [FB-*]",
    "Evidence-backed active change (only with exact capability/access evidence)",
)
_OLD_LEAVES = (
    "Delay/block feedback [FB-*]",
    "Forge feedback [FB-*]",
    "Action intercepted/modified in transit",
)
_BANNED = (
    "packet interception",
    "man-in-the-middle",
    "network delay",
    "traffic blocking",
    "network-signal spoofing",
    "communication-link severing",
    "credential theft",
    "account takeover",
    "session hijack",
    "session fixation",
    "flooding",
    "denial of service",
    "packet injection",
)


def _table_values(world: World, heading: str, fallback: tuple[str, ...]) -> list[str]:
    """Read the first column of a step table, tolerating parser shapes."""
    rows = getattr(world, "current_data_table", None) or []
    values: list[str] = []
    for row in rows:
        if isinstance(row, dict):
            value = row.get(heading)
        elif row:
            value = row[0]
        else:
            value = None
        if value is not None:
            values.append(str(value).strip())
    if values and values[0].lower() == heading.lower():
        values = values[1:]
    return values or list(fallback)


def _prompt_for_stage(stage: str) -> str:
    """Render a system prompt for one of the three SP3 stages."""
    if stage == "Stage 3 ICA":
        from asago_scenario_generator.stpa.threat_enum._constants import PROMPTS_DIR

        return TemplateLoader(PROMPTS_DIR).render_prompt("stage3_system.j2")
    from asago_scenario_generator.stpa.scenario_prod._constants import PROMPTS_DIR

    name = {
        "Stage 5 BDI": "stage5_system.j2",
        "Stage 6 narrative": "stage6a_narrative_system.j2",
    }[stage]
    return TemplateLoader(PROMPTS_DIR).render_prompt(name)


def _reachable_capabilities() -> tuple[ReachableCapability, ...]:
    """Build only capabilities proven reachable from the selected control path."""
    return tuple(
        ReachableCapability(
            capability_id=capability_id,
            description=description,
            evidence="The selected input path reaches this declared capability.",
            access_path=("RESP-1", "CA-1-1", "CP-1"),
        )
        for capability_id, description in (
            ("CAP-PROMPT", "prompt injection"),
            ("CAP-TOOL-RESULT", "tool result fabrication"),
            ("CAP-MEMORY", "memory poisoning"),
            ("CAP-AGENT", "agent impersonation"),
            ("CAP-RETRIEVAL", "retrieval poisoning"),
        )
    )


def _profile() -> CapabilityProfile:
    """Build the legacy profile used by the focused prompt-guidance fixtures."""
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


def _scenario_context():
    """Build the exact authority context used throughout one acceptance scenario."""
    return build_scenario_generation_context(
        _make_sp3_threat(),
        _make_sp3_cs(),
        _make_sp3_loss_analysis(),
        scenario_id="SCN-001",
        reachable_capabilities=_reachable_capabilities(),
    )


def _scenario_spec_with_context(context):
    """Attach the exact context to the legacy ScenarioSpec fixture."""
    base = _make_sp3_scenario_spec()
    values = base.model_dump(mode="json", exclude={"scenario_context"})
    values["loss_scenario"] = context.ica.loss_consequence
    values["causal_factors"] = [
        {
            "kind": factor.kind,
            "source_id": factor.source_id,
            "description": factor.evidence,
            "declared_timing": factor.timing,
        }
        for factor in _make_sp3_causal_factors()
    ]
    values["unsafe_outcome_hazard_refs"] = [item.hazard_id for item in context.hazards]
    values["unsafe_outcome_constraint_refs"] = [
        item.constraint_id for item in context.constraints
    ]
    values["scenario_context"] = context
    return type(base).model_validate(values)


def _call_value(call: object, name: str) -> str:
    """Read a prompt from either mock-client call representation."""
    if isinstance(call, dict):
        return str(call.get(name, ""))
    return str(getattr(call, name, ""))


def _logged_calls(world: World) -> list[dict]:
    """Read call metadata written by the SP3 run."""
    path = getattr(world, "sp3_run_dir", None)
    calls_path = path / "calls.jsonl" if path is not None else None
    if calls_path is None or not calls_path.exists():
        return []
    return [
        json.loads(line)
        for line in calls_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _tree_text(tree: object) -> str:
    """Flatten an attack tree for focused mechanism assertions."""
    return json.dumps(tree, sort_keys=True).lower()


def _h_fcb_render_prompt(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle rendering a Stage 3, Stage 5, or Stage 6 system prompt."""
    match = re.search(r"the (Stage \d+ (?:ICA|BDI|narrative)) system prompt", text)
    if not match:
        return False, f"Could not identify stage in: {text}"
    world.sp3_prompt = _prompt_for_stage(match.group(1))
    return True, ""


def _h_fcb_templates(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle the prompt-template availability precondition."""
    world.sp3_mode = "narrative"
    return True, ""


def _h_fcb_bridge(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Check that a rendered prompt defines the logical FB bridge."""
    prompt = getattr(world, "sp3_prompt", "")
    if _BRIDGE not in prompt:
        return False, "Prompt does not define the FB logical information dependency"
    return True, ""


def _h_fcb_not_transport(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Check that the bridge does not imply an attacker transport."""
    prompt = getattr(world, "sp3_prompt", "").lower()
    if "not evidence" not in prompt or "attacker-accessible transport" not in prompt:
        return False, "Prompt does not reject transport inference"
    return True, ""


def _h_fcb_surfaces(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Check every declared AI surface in the table."""
    prompt = getattr(world, "sp3_prompt", "")
    for surface in _table_values(world, "surface", _SURFACES):
        if surface not in prompt:
            return False, f"Prompt does not name AI surface {surface!r}"
    return True, ""


def _h_fcb_surface(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Check one declared AI surface captured from the step wording."""
    match = re.search(r"the prompt includes the declared AI surface (.+)$", text)
    if match is None:
        return False, f"Could not identify AI surface in: {text}"
    surface = match.group(1).strip()
    if surface not in getattr(world, "sp3_prompt", ""):
        return False, f"Prompt does not name AI surface {surface!r}"
    return True, ""


def _h_fcb_forbidden(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Check every narrow negative mechanism in the table."""
    prompt = getattr(world, "sp3_prompt", "").lower()
    aliases = {
        "man-in-the-middle access": "mitm",
        "session hijacking or fixation": "session hijacking/fixation",
        "session hijack": "session hijacking/fixation",
        "session fixation": "session hijacking/fixation",
        "generic flooding or denial of service": "generic flooding/dos",
    }
    for mechanism in _table_values(world, "mechanism", _BANNED):
        expected = aliases.get(mechanism.lower(), mechanism.lower())
        if expected not in prompt:
            return False, f"Prompt does not prohibit {mechanism!r}"
    return True, ""


def _h_fcb_forbidden_mechanism(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Check one forbidden mechanism captured from the step wording."""
    match = re.search(
        r"the prompt forbids inventing mechanism (.+) without explicit",
        text,
    )
    if match is None:
        return False, f"Could not identify mechanism in: {text}"
    mechanism = match.group(1).strip()
    aliases = {
        "man-in-the-middle access": "mitm",
        "session hijacking or fixation": "session hijacking/fixation",
        "session hijack": "session hijacking/fixation",
        "session fixation": "session hijacking/fixation",
        "generic flooding or denial of service": "generic flooding/dos",
    }
    expected = aliases.get(mechanism.lower(), mechanism.lower())
    if expected not in getattr(world, "sp3_prompt", "").lower():
        return False, f"Prompt does not prohibit {mechanism!r}"
    return True, ""


def _h_fcb_architecture(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Record the logical or transport architecture used by later steps."""
    world.sp3_profile = _profile()
    world.sp3_transport_accessible = (
        "through transport" in text or "explicitly declared attacker-accessible" in text
    )
    world.sp3_transport = "webhook-1" if world.sp3_transport_accessible else ""
    return True, ""


def _h_fcb_tool_architecture(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Record a logical tool-result feedback architecture."""
    world.sp3_profile = _profile()
    world.sp3_transport_accessible = False
    world.sp3_transport = ""
    return True, ""


def _h_fcb_llm(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Configure a deterministic narrative response."""
    if getattr(world, "sp3_mode", "") == "tree":
        return _h_aat_llm(world, text, examples)
    from tests.stpa.sp1_helpers import MockLLMClient

    client = MockLLMClient()
    if getattr(world, "sp3_transport_accessible", False):
        response = (
            "Step 1: PM-1-1 starts correct.\n"
            "Step 2: The attacker intercepts transport webhook-1; the architecture "
            "evidence declares it attacker-accessible.\n"
            "Step 3: PM-1-1 diverges from reality.\n"
            "Step 4: The defender acts on the false belief.\n"
            "Step 5: The ICA occurs on CA-1-1.\n"
            "Step 6: The hazard is realized.\n"
            "Step 7: The loss follows.\n"
        )
    else:
        response = (
            "Step 1: PM-1-1 starts correct.\n"
            "Step 2: The attacker poisons retrieved content through FB-1-1.\n"
            "Step 3: PM-1-1 diverges from reality.\n"
            "Step 4: The defender acts on the false belief.\n"
            "Step 5: The ICA occurs on CA-1-1.\n"
            "Step 6: The hazard is realized.\n"
            "Step 7: The loss follows.\n"
        )
    client.set_response_for(None, response)
    world.sp3_llm_client = client
    return True, ""


def _h_fcb_narrative(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Run the narrative prompt against the deterministic mock."""
    if not hasattr(world, "sp3_llm_client"):
        _h_fcb_llm(world, text, examples)
    spec = _make_sp3_scenario_spec()
    world.sp3_narrative, world.sp3_error = generate_narrative(
        world.sp3_llm_client,
        spec,
        Path(tempfile.mkdtemp()),
        capability_profile=getattr(world, "sp3_profile", None),
    )
    return True, ""


def _h_fcb_retrieved(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Check the logical-only narrative realization."""
    narrative = getattr(world, "sp3_narrative", "") or ""
    if (
        "poison" not in narrative.lower()
        or "retrieved content" not in narrative.lower()
    ):
        return False, "Narrative does not poison retrieved content"
    return True, ""


def _h_fcb_no_infra(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Reject infrastructure and session mechanisms in a logical-only narrative."""
    narrative = (getattr(world, "sp3_narrative", "") or "").lower()
    for mechanism in _BANNED:
        if mechanism in narrative:
            return False, f"Narrative invents {mechanism}"
    return True, ""


def _h_fcb_transport_evidence(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Check that an allowed transport is tied to its architecture evidence."""
    narrative = (getattr(world, "sp3_narrative", "") or "").lower()
    if "webhook-1" not in narrative or "architecture evidence" not in narrative:
        return False, "Narrative does not cite webhook-1 architecture evidence"
    return True, ""


def _h_aat_render_prompt(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Render the Stage 6 attack tree system prompt."""
    from asago_scenario_generator.stpa.scenario_prod._constants import PROMPTS_DIR

    world.sp3_prompt = TemplateLoader(PROMPTS_DIR).render_prompt(
        "stage6b_tree_system.j2"
    )
    return True, ""


def _h_existing_tree_call(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Give the exact legacy tree step its production handler priority."""
    from runtime_features.sp3 import _h_sp3_tree_call

    return _h_sp3_tree_call(world, text, examples)


def _h_aat_available(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle the attack-tree prompt availability precondition."""
    world.sp3_mode = "tree"
    return True, ""


def _h_aat_leaves(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Check all evidence-gated causal leaves from the hard template."""
    prompt = getattr(world, "sp3_prompt", "")
    for leaf in _table_values(world, "leaf", _LEAVES):
        if leaf not in prompt:
            return False, f"Missing evidence-gated causal leaf {leaf!r}"
    return True, ""


def _h_aat_leaf(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Check one evidence-gated causal leaf captured from the step wording."""
    match = re.search(r"evidence-gated causal leaf (.+)$", text)
    if match is None:
        return False, f"Could not identify evidence-gated causal leaf in: {text}"
    leaf = match.group(1).strip()
    if leaf not in getattr(world, "sp3_prompt", ""):
        return False, f"Missing evidence-gated causal leaf {leaf!r}"
    return True, ""


def _h_aat_old_leaves(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Check that old infrastructure leaves are not mandatory."""
    prompt = getattr(world, "sp3_prompt", "")
    for leaf in _table_values(world, "leaf", _OLD_LEAVES):
        if leaf in prompt:
            return False, f"Mandatory infrastructure leaf remains: {leaf!r}"
    return True, ""


def _h_aat_old_leaf(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Check one former infrastructure leaf captured from the step wording."""
    match = re.search(r"mandatory infrastructure leaf (.+)$", text)
    if match is None:
        return False, f"Could not identify infrastructure leaf in: {text}"
    leaf = match.group(1).strip()
    if leaf in getattr(world, "sp3_prompt", ""):
        return False, f"Mandatory infrastructure leaf remains: {leaf!r}"
    return True, ""


def _h_aat_permission(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Check the explicit architecture-evidence exception."""
    prompt = getattr(world, "sp3_prompt", "").lower()
    required = "explicitly attacker-accessible architecture element"
    if required not in prompt:
        return False, "Infrastructure exception lacks explicit architecture evidence"
    return True, ""


def _h_aat_llm(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Configure a deterministic attack-tree response."""
    from tests.stpa.sp1_helpers import MockLLMClient

    client = MockLLMClient()
    if getattr(world, "sp3_transport_accessible", False):
        tree = {
            "root": "Induce ICA NOT_PROVIDED on CA-1-1",
            "branches": [
                {
                    "category": "controller_side",
                    "label": "Corrupt PM-1-1 via FB-1-1",
                    "children": [],
                },
                {
                    "category": "path_side",
                    "label": "Infrastructure transport interception via webhook-1",
                    "details": (
                        "Architecture evidence: webhook-1 is explicitly "
                        "attacker-accessible"
                    ),
                    "children": [],
                },
            ],
            "leaves": [
                "Fabricate a tool result via FB-1-1",
                "Infrastructure transport interception via webhook-1",
            ],
        }
    else:
        tree = {
            "root": "Induce ICA NOT_PROVIDED on CA-1-1",
            "branches": [
                {
                    "category": "controller_side",
                    "label": "Fabricate a tool result via FB-1-1",
                    "children": [],
                },
                {"category": "path_side", "label": "Tool execution", "children": []},
            ],
            "leaves": ["Fabricate a tool result via FB-1-1", "Tool execution"],
        }
    client.set_response_for(None, json.dumps(tree))
    world.sp3_llm_client = client
    return True, ""


def _h_aat_tree(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Run the attack-tree prompt against the deterministic mock."""
    from asago_scenario_generator.stpa.scenario_prod.attack_tree import (
        generate_attack_tree,
    )

    if not hasattr(world, "sp3_llm_client"):
        _h_aat_llm(world, text, examples)
    world.sp3_attack_tree, world.sp3_error = generate_attack_tree(
        world.sp3_llm_client,
        _make_sp3_scenario_spec(),
        _make_sp3_cs(),
        Path(tempfile.mkdtemp()),
    )
    return True, ""


def _h_aat_tool_result(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Check that the logical-only tree uses tool-result fabrication."""
    tree = _tree_text(getattr(world, "sp3_attack_tree", {}))
    if "fabricat" not in tree or "tool result" not in tree:
        return False, "Tree does not fabricate a tool result"
    return True, ""


def _h_aat_no_infra(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Check that the logical-only tree has no infrastructure leaf."""
    tree = _tree_text(getattr(world, "sp3_attack_tree", {}))
    for mechanism in ("network", "packet", "session", "interception", "webhook"):
        if mechanism in tree:
            return False, f"Tree invents infrastructure mechanism {mechanism}"
    return True, ""


def _h_aat_transport_evidence(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Check that an infrastructure leaf cites webhook-1."""
    tree = _tree_text(getattr(world, "sp3_attack_tree", {}))
    if "webhook-1" not in tree or "architecture evidence" not in tree:
        return False, "Tree does not cite webhook-1 architecture evidence"
    return True, ""


def _h_mcp_modules(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle the prompt assembly importability precondition."""
    return True, ""


def _h_mcp_profile(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Create the proven reachable capabilities used by the scenarios."""
    world.sp3_reachable_capabilities = _reachable_capabilities()
    return True, ""


def _h_mcp_kc(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Check that every capability carries explicit reachability evidence."""
    capabilities = getattr(world, "sp3_reachable_capabilities", ())
    if not capabilities or any(not item.evidence for item in capabilities):
        return False, "Reachable capability evidence is incomplete"
    return True, ""


def _h_mcp_context(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Build the exact immutable context once for prompt comparisons."""
    world.sp3_context = _scenario_context()
    return True, ""


def _h_mcp_prompt(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Build the requested Stage 5 or Stage 6 prompt from one exact context."""
    from asago_scenario_generator.stpa.scenario_prod._constants import PROMPTS_DIR

    loader = TemplateLoader(PROMPTS_DIR)
    stage = re.search(r"the (Stage \d+ (?:BDI|narrative)) user prompt", text)
    if not stage:
        return False, f"Could not identify prompt stage in: {text}"
    context = world.sp3_context
    world.sp3_prompt_stage = stage.group(1)
    if world.sp3_prompt_stage == "Stage 5 BDI":
        _system, user = build_context_bdi_prompts(context, loader)
    else:
        spec = _scenario_spec_with_context(context)
        _system, user = build_narrative_prompts(
            spec,
            loader,
        )
        world.sp3_scenario_spec = spec
    world.sp3_user_prompt = user
    return True, ""


def _h_mcp_complete(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Check the exact full or purpose-built context for the selected stage."""
    prompt = getattr(world, "sp3_user_prompt", "")
    if getattr(world, "sp3_prompt_stage", None) == "Stage 5 BDI":
        return _check_actionable_stage5_context(prompt, world.sp3_context)
    return _check_actionable_stage6_context(prompt, world.sp3_context)


def _check_actionable_stage5_context(prompt: str, context: object) -> tuple[bool, str]:
    """Require useful semantic facts while excluding integrity-only material."""
    required = (
        context.ica.exact_ica_text,
        context.ica.uca_type_definition,
        context.target_control_path.control_action.action_id,
        context.target_control_path.control_action.description,
        *(item.description for item in context.losses),
        *(item.description for item in context.hazards),
        *(item.description for item in context.constraints),
        *(item.capability_id for item in context.reachable_capabilities),
        *(item.description for item in context.reachable_capabilities),
        *(item.evidence for item in context.reachable_capabilities),
    )
    if any(value not in prompt for value in required):
        return False, "Stage 5 prompt lacks actionable scenario meaning"
    if context.context_digest in prompt or "source_pins:" in prompt:
        return False, "Stage 5 prompt contains integrity-only bookkeeping"
    return True, ""


def _check_actionable_stage6_context(prompt: str, context: object) -> tuple[bool, str]:
    """Require selected scenario meaning while excluding integrity metadata."""
    required = (
        "unsafe_control_action:",
        "selected_control_path:",
        "causal_factors:",
        context.ica.exact_ica_text,
        context.ica.uca_type_definition,
        context.target_control_path.control_action.action_id,
        context.target_control_path.control_action.description,
        *(item.loss_id for item in context.losses),
        *(item.description for item in context.losses),
        *(item.hazard_id for item in context.hazards),
        *(item.description for item in context.hazards),
        *(item.constraint_id for item in context.constraints),
        *(item.description for item in context.constraints),
        *(item.capability_id for item in context.reachable_capabilities),
        *(item.description for item in context.reachable_capabilities),
        *(item.evidence for item in context.reachable_capabilities),
    )
    if any(value not in prompt for value in required):
        return False, "Stage 6 prompt lacks actionable scenario evidence"
    if context.context_digest in prompt or "source_pins:" in prompt:
        return False, "Stage 6 prompt contains integrity-only bookkeeping"
    return True, ""


def _h_mcp_mechanisms(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Check positive mechanisms listed in the acceptance table."""
    prompt = getattr(world, "sp3_user_prompt", "").lower()
    fallback = (
        "prompt injection",
        "tool result fabrication",
        "memory poisoning",
        "agent impersonation",
        "retrieval poisoning",
    )
    for mechanism in _table_values(world, "mechanism", fallback):
        if mechanism.lower() not in prompt:
            return False, f"User prompt lacks positive mechanism {mechanism!r}"
    return True, ""


def _h_mcp_mechanism(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Check one positive mechanism captured from the step wording."""
    match = re.search(r"contains? (?:positive )?mechanism (.+)$", text)
    if match is None:
        return False, f"Could not identify positive mechanism in: {text}"
    mechanism = match.group(1).strip().lower()
    if mechanism not in getattr(world, "sp3_user_prompt", "").lower():
        return False, f"User prompt lacks positive mechanism {mechanism!r}"
    return True, ""


def _h_mcp_recording_llm(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Prepare the full-run recording mock."""
    world.sp3_llm_client = _setup_sp3_mock_client(1)
    return True, ""


def _h_mcp_run(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Run SP3 with the exact prebuilt context."""
    from asago_scenario_generator.stpa.scenario_prod.run import run_sp3

    world.sp3_run_dir = Path(tempfile.mkdtemp())
    context = world.sp3_context
    world.sp3_result = run_sp3(
        llm_client=world.sp3_llm_client,
        enriched_threat_set=_make_sp3_ets(),
        control_structure=_make_sp3_cs(),
        loss_analysis=_make_sp3_loss_analysis(),
        run_dir=world.sp3_run_dir,
        scenario_contexts={context.ica.ica_id: context},
    )
    return True, ""


def _h_mcp_stage5_requests(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Check every Stage 5 request for useful facts without bookkeeping."""
    calls = [call for call in _logged_calls(world) if call.get("stage") == "stage_5"]
    if not calls:
        return False, "A Stage 5 request lacks the deterministic context"
    for call in calls:
        passed, reason = _check_actionable_stage5_context(
            call.get("user_prompt_text", ""), world.sp3_context
        )
        if not passed:
            return False, reason
    return True, ""


def _h_mcp_stage6_requests(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Check every Stage 6 request for actionable evidence, not bookkeeping."""
    calls = [
        call
        for call in _logged_calls(world)
        if call.get("stage") == "stage_6" and call.get("step") == "narrative"
    ]
    if not calls:
        return False, "No Stage 6 narrative request was recorded"
    for call in calls:
        prompt = call.get("user_prompt_text", "")
        passed, reason = _check_actionable_stage6_context(prompt, world.sp3_context)
        if not passed:
            return False, reason
    return True, ""


FEATURE_ID = "sp3_prompt_remediation"


def register(api: object) -> None:
    """Register prompt-remediation handlers under the SP3 feature tag."""
    api.set_feature(None)
    api.set_feature("sp3")
    api.register_first(
        "the SP3 prompt templates are available",
        _h_fcb_templates,
        source_order=23999,
    )
    api.register_first(
        "the Stage (?:3 ICA|5 BDI|6 narrative) system prompt is rendered",
        _h_fcb_render_prompt,
        source_order=24000,
    )
    api.register_first(
        "the prompt defines an FB identifier as a logical information dependency.*",
        _h_fcb_bridge,
        source_order=24001,
    )
    api.register_first(
        "the prompt states that an FB identifier is not evidence.*",
        _h_fcb_not_transport,
        source_order=24002,
    )
    api.register_first(
        "the prompt directs logical feedback updates through each of these AI surfaces:",
        _h_fcb_surfaces,
        source_order=24003,
    )
    api.register_first(
        "the prompt includes the declared AI surface .+$",
        _h_fcb_surface,
        source_order=24003,
    )
    api.register_first(
        "the prompt forbids inventing any of these mechanisms.*",
        _h_fcb_forbidden,
        source_order=24004,
    )
    api.register_first(
        "the prompt forbids inventing mechanism .+ without explicit "
        "attacker-accessible architecture evidence$",
        _h_fcb_forbidden_mechanism,
        source_order=24004,
    )
    api.register_first(
        "an architecture where FB-1-1 updates PM-1-1 from retrieved content",
        _h_fcb_architecture,
        source_order=24005,
    )
    api.register_first(
        "an architecture where FB-1-1 updates PM-1-1 from a tool result",
        _h_fcb_tool_architecture,
        source_order=24006,
    )
    api.register_first(
        "an architecture where FB-1-1 updates PM-1-1 through transport webhook-1",
        _h_fcb_architecture,
        source_order=24007,
    )
    api.register_first(
        "the architecture declares no attacker-accessible transport or session surface",
        _h_fcb_architecture,
        source_order=24008,
    )
    api.register_first(
        "transport webhook-1 is explicitly declared attacker-accessible",
        _h_fcb_architecture,
        source_order=24009,
    )
    api.register_first(
        "a deterministic instruction-following LLM",
        _h_fcb_llm,
        source_order=24010,
    )
    api.register_first(
        "SP3 generates the attack narrative$",
        _h_fcb_narrative,
        source_order=24011,
    )
    api.register_first(
        "SP3 generates the attack narrative through transport interception",
        _h_fcb_narrative,
        source_order=24012,
    )
    api.register_first(
        "the narrative realizes the FB-1-1 manipulation by poisoning retrieved content",
        _h_fcb_retrieved,
        source_order=24013,
    )
    api.register_first(
        "the narrative does not invent an infrastructure or session mechanism",
        _h_fcb_no_infra,
        source_order=24014,
    )
    api.register_first(
        "the narrative identifies webhook-1 as the architecture evidence for interception",
        _h_fcb_transport_evidence,
        source_order=24015,
    )
    api.register_first(
        "the attack tree LLM call is executed",
        _h_existing_tree_call,
        source_order=24016,
    )
    api.register_first(
        "the SP3 attack tree prompt is available",
        _h_aat_available,
        source_order=24017,
    )
    api.register_first(
        "the Stage 6 attack tree system prompt is rendered",
        _h_aat_render_prompt,
        source_order=24018,
    )
    api.register_first(
        "the hard template contains each evidence-gated causal leaf:",
        _h_aat_leaves,
        source_order=24019,
    )
    api.register_first(
        "the hard template contains evidence-gated causal leaf .+$",
        _h_aat_leaf,
        source_order=24019,
    )
    api.register_first(
        "the hard template does not contain any mandatory infrastructure leaf:",
        _h_aat_old_leaves,
        source_order=24020,
    )
    api.register_first(
        "the hard template does not contain mandatory infrastructure leaf .+$",
        _h_aat_old_leaf,
        source_order=24020,
    )
    api.register_first(
        "the prompt permits an infrastructure leaf only with explicit attacker-accessible architecture evidence",
        _h_aat_permission,
        source_order=24021,
    )
    api.register_first(
        "SP3 generates the attack tree$",
        _h_aat_tree,
        source_order=24022,
    )
    api.register_first(
        "SP3 generates an attack tree with a transport-interception leaf",
        _h_aat_tree,
        source_order=24023,
    )
    api.register_first(
        "the tree realizes FB-1-1 by fabricating the tool result",
        _h_aat_tool_result,
        source_order=24024,
    )
    api.register_first(
        "the tree contains no invented infrastructure or session leaf",
        _h_aat_no_infra,
        source_order=24025,
    )
    api.register_first(
        "that leaf identifies webhook-1 as the architecture evidence",
        _h_aat_transport_evidence,
        source_order=24026,
    )
    api.register_first(
        "the SP3 prompt assembly modules are importable",
        _h_mcp_modules,
        source_order=24027,
    )
    api.register_first(
        "exact reachable capabilities for the selected control path",
        _h_mcp_profile,
        source_order=24028,
    )
    api.register_first(
        "each reachable capability has explicit access evidence",
        _h_mcp_kc,
        source_order=24029,
    )
    api.register_first(
        "the exact scenario generation context is built from selected authority",
        _h_mcp_context,
        source_order=24030,
    )
    api.register_first(
        "the Stage (?:5 BDI|6 narrative) user prompt is built with the exact scenario context",
        _h_mcp_prompt,
        source_order=24031,
    )
    api.register_first(
        "the user prompt contains the stage-appropriate scenario context",
        _h_mcp_complete,
        source_order=24032,
    )
    api.register_first(
        "the user prompt reachable capabilities contain each mechanism:",
        _h_mcp_mechanisms,
        source_order=24033,
    )
    api.register_first(
        "the user prompt reachable capabilities contain mechanism .+$",
        _h_mcp_mechanism,
        source_order=24033,
    )
    api.register_first(
        "a recording LLM that returns valid Stage 5 and Stage 6 results",
        _h_mcp_recording_llm,
        source_order=24034,
    )
    api.register_first(
        "SP3 runs with the exact scenario context",
        _h_mcp_run,
        source_order=24035,
    )
    api.register_first(
        "every Stage 5 BDI request contains the actionable scenario context",
        _h_mcp_stage5_requests,
        source_order=24036,
    )
    api.register_first(
        "every Stage 6 narrative request contains the actionable scenario "
        "evidence without integrity bookkeeping",
        _h_mcp_stage6_requests,
        source_order=24037,
    )
    api.set_feature(None)


__all__ = ["FEATURE_ID", "register"]
