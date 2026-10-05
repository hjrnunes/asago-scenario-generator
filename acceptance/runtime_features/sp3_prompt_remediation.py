"""Acceptance handlers for SP3 prompt remediation features."""

from __future__ import annotations

import json
import re

from runtime_shared import (
    Path,
    TemplateLoader,
    World,
    _make_sp3_cs,
    _make_sp3_ets,
    _make_sp3_loss_analysis,
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
from asago_scenario_generator.stpa.scenario_prod._constants import PROMPTS_DIR


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
    """Build the Stage 5 prompt from one exact context."""
    loader = TemplateLoader(PROMPTS_DIR)
    _system, user = build_context_bdi_prompts(world.sp3_context, loader)
    world.sp3_user_prompt = user
    return True, ""


def _h_mcp_complete(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Check the Stage 5 prompt for the exact purpose-built context."""
    prompt = getattr(world, "sp3_user_prompt", "")
    return _check_actionable_stage5_context(prompt, world.sp3_context)


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


FEATURE_ID = "sp3_prompt_remediation"


def register(api: object) -> None:
    """Register prompt-remediation handlers under the SP3 feature tag."""
    api.set_feature(None)
    api.set_feature("sp3")
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
        "the Stage 5 BDI user prompt is built with the exact scenario context",
        _h_mcp_prompt,
        source_order=24031,
    )
    api.register_first(
        "the user prompt contains the stage-appropriate scenario context",
        _h_mcp_complete,
        source_order=24032,
    )
    api.register_first(
        "the user prompt reachable capabilities contain mechanism .+$",
        _h_mcp_mechanism,
        source_order=24033,
    )
    api.register_first(
        "a recording LLM that returns valid Stage 5 results",
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
    api.set_feature(None)


__all__ = ["FEATURE_ID", "register"]
