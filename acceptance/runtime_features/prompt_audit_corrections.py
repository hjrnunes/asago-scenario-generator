"""Acceptance handlers for the prompt-quality audit correction contract."""

from __future__ import annotations

import json
import re
import tempfile
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from runtime_bootstrap import PROJECT_ROOT
from runtime_shared import (
    World,
    _make_sp3_cs,
    _make_sp3_loss_analysis,
    _make_sp3_threat,
)

from asago_scenario_generator.models.obligation_consideration import (
    ObligationSemanticAssessment,
)
from asago_scenario_generator.pipeline.risk_pattern_crosswalk import (
    resolve_risk_pattern_mapping_strength,
)
from asago_scenario_generator.stpa.infra.llm import LLMResult
from asago_scenario_generator.stpa.infra.llm_helpers import safe_llm_call
from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.scenario_prod.context import (
    build_scenario_generation_context,
)
from asago_scenario_generator.stpa.scenario_prod.execution_classification import (
    classify_scenario_execution,
)
from asago_scenario_generator.stpa.system_model.critic import RevisionDelta
from asago_scenario_generator.stpa.infra.manifest import STPARunManifest


FEATURE_ID = "prompt_audit_corrections"

_ROOT = Path(PROJECT_ROOT)
_SYSTEM_PROMPTS = _ROOT / "src/asago_scenario_generator/stpa/system_model/prompts"
_OBLIGATION_PROMPTS = (
    _ROOT / "src/asago_scenario_generator/stpa/obligation_aware/prompt_templates"
)


def _state(world: World) -> dict[str, Any]:
    """Return per-scenario state for this feature."""
    state = getattr(world, "prompt_audit_state", None)
    if state is None:
        state = {}
        world.prompt_audit_state = state
    return state


def _read(paths: tuple[Path, ...]) -> str:
    """Read prompt sources as one deterministic inspection corpus."""
    return "\n".join(path.read_text(encoding="utf-8") for path in paths)


def _h_stage1_inspected(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Inspect the shared loss method card and both Stage 1 prompt families."""
    del text, examples
    paths = (
        _SYSTEM_PROMPTS / "_loss_analysis_method.j2",
        _SYSTEM_PROMPTS / "stage1a_risk_system.j2",
        _SYSTEM_PROMPTS / "stage1a_gap_system.j2",
        _SYSTEM_PROMPTS / "stage1a_gap_user.j2",
    )
    missing_paths = [str(path) for path in paths if not path.is_file()]
    if missing_paths:
        return False, f"Stage 1 prompt sources are missing: {missing_paths}"
    _state(world)["stage1_text"] = _read(paths)
    return True, ""


def _h_stage1_provenance(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Check distinct risk-card and use-case loss shapes."""
    del text, examples
    corpus = _state(world).get("stage1_text", "")
    required = (
        "source_risk_cards",
        "provenance: risk_card",
        "provenance: use_case",
        "empty `source_risk_cards`",
        "Do NOT duplicate",
    )
    missing = [item for item in required if item.lower() not in corpus.lower()]
    return not missing, f"Stage 1 provenance guidance is missing: {missing}"


def _h_stage1_hazard(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Check system-level hazard semantics and failure rejection guidance."""
    del text, examples
    corpus = _state(world).get("stage1_text", "")
    required = (
        "system-level state or condition",
        "the failure is not itself the hazard",
        "component failure itself as the hazard",
        "Reject a generic catalog statement",
        "resulting system-level",
    )
    missing = [item for item in required if item.lower() not in corpus.lower()]
    return not missing, f"Stage 1 hazard guidance is missing: {missing}"


def _h_stage2_inspected(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Inspect the bounded revision prompts and manifest model."""
    del text, examples
    paths = (
        _SYSTEM_PROMPTS / "revision_system.j2",
        _SYSTEM_PROMPTS / "revision_user.j2",
    )
    missing_paths = [str(path) for path in paths if not path.is_file()]
    if missing_paths:
        return False, f"Stage 2 prompt sources are missing: {missing_paths}"
    state = _state(world)
    state["stage2_text"] = _read(paths)
    state["revision_model"] = RevisionDelta
    state["manifest_model"] = STPARunManifest
    return True, ""


def _h_stage2_strict(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Check the additive closed delta contract."""
    del text, examples
    state = _state(world)
    corpus = state.get("stage2_text", "")
    model = state.get("revision_model")
    expected_fields = {
        "new_responsibilities",
        "new_controlled_processes",
        "new_coordination_links",
        "modified_responsibilities",
        "dismissed_gaps",
    }
    actual_fields = set(model.model_fields) if model is not None else set()
    missing = [
        item
        for item in (
            "RevisionDelta with only new and modified elements",
            "Do NOT restate the entire control structure",
        )
        if item.lower() not in corpus.lower()
    ]
    if actual_fields != expected_fields:
        return (
            False,
            f"RevisionDelta fields are {sorted(actual_fields)!r}, "
            f"expected {sorted(expected_fields)!r}",
        )
    if model.model_config.get("extra") != "forbid":
        return False, "RevisionDelta does not forbid unknown fields"
    if missing:
        return False, f"strict revision wording is missing: {missing}"
    return True, ""


def _h_stage2_dismiss(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Check that every critic gap has an explicit add-or-dismiss branch."""
    del text, examples
    corpus = _state(world).get("stage2_text", "")
    required = (
        "You may DISMISS",
        "dismiss it with a one-sentence justification in dismissed_gaps",
    )
    missing = [item for item in required if item.lower() not in corpus.lower()]
    return not missing, f"revision gap decision guidance is missing: {missing}"


def _h_stage2_manifest(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Check operator-visible revision and post-revision diagnostics."""
    del text, examples
    model = _state(world).get("manifest_model")
    fields = set(model.model_fields) if model is not None else set()
    required = {
        "revised",
        "post_revision_warnings",
        "stage_errors",
        "stage_warnings",
        "stage_summary",
    }
    missing = sorted(required - fields)
    return not missing, f"run manifest is missing revision fields: {missing}"


def _h_inter_responsibility_context(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Build a route context whose typed action target is another responsibility."""
    del text, examples
    structure_payload = _make_sp3_cs(include_resp2=True).model_dump(mode="json")
    action = structure_payload["responsibilities"][0]["control_actions"][0]
    action["target"] = {"type": "responsibility", "id": "RESP-2"}
    action["effect_kind"] = "agent_message"
    action["temporality"] = "instantaneous"
    structure = ControlStructure.model_validate(structure_payload)
    context = build_scenario_generation_context(
        _make_sp3_threat(),
        structure,
        _make_sp3_loss_analysis(),
        scenario_id="SCN-001",
    )
    target_action = context.target_control_path.control_action
    if target_action.target_id != "RESP-2":
        return False, "the real control-structure target did not reach the context"
    if target_action.effect_kind.value != "agent_message":
        return False, "the typed agent-message effect did not reach the context"
    world.route_context = context
    return True, ""


def _h_ica_concise(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Check the compiled provider deviation remains one concise sentence."""
    del text, examples
    state = _state(world)
    synthesis_state = getattr(world, "synthesis_prompt_state", {})
    ica = state.get("compiled_ica") or synthesis_state.get("compiled_ica")
    if ica is None:
        return False, "the captured ICA was not compiled"
    value = " ".join(ica.ica_text.split())
    if not value:
        return False, "compiled ICA text is empty"
    sentence_count = len(re.findall(r"[^.!?]+[.!?](?:\s|$)", value))
    if sentence_count > 1:
        return False, f"compiled ICA has {sentence_count} sentences"
    if len(value) > 500:
        return False, "compiled ICA exceeds the concise presentation limit"
    return True, ""


def _h_ica_category(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Check the provider schema cannot replace the slot's UCA category."""
    del text, examples
    state = _state(world)
    synthesis_state = getattr(world, "synthesis_prompt_state", {})
    response_format = state.get("ica_provider_schema") or synthesis_state.get(
        "ica_provider_schema"
    )
    if response_format is None:
        return False, "the captured ICA provider schema is missing"
    definitions = response_format.model_json_schema().get("$defs", {})
    finding = definitions.get("_SlotProviderFindingDraft", {}).get("properties", {})
    forbidden = {"uca_type", "uca_category", "category"}.intersection(finding)
    if forbidden:
        return False, f"provider schema exposes category fields: {sorted(forbidden)}"
    if finding.get("deviation", {}).get("type") != "string":
        return False, "provider schema does not expose one plain deviation string"
    prompt = state.get("ica_system_prompt") or synthesis_state.get(
        "ica_system_prompt", ""
    )
    phrase = "compiler owns the slot's exact UCA type"
    return (
        phrase in prompt,
        "ICA prompt does not leave category ownership to the slot",
    )


def _h_rejected_response(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Run one deterministic provider response through the shared call logger."""
    del text, examples

    class Expected(BaseModel):
        required: str

    class Provider:
        model = "acceptance-provider"

        def complete(self, **kwargs: Any) -> LLMResult:
            return LLMResult(
                content={"wrong": "shape"},
                prompt_tokens=1,
                completion_tokens=1,
                duration_ms=1,
                system_prompt=kwargs["system_prompt"],
                user_prompt=kwargs["user_prompt"],
            )

    run_dir = Path(tempfile.mkdtemp(prefix="prompt-audit-rejection-"))
    safe_llm_call(
        llm_client=Provider(),
        system_prompt="Return JSON.",
        user_prompt="Return the required field.",
        response_format=Expected,
        run_dir=run_dir,
        stage="stage_5",
        step="bdi_generation",
        slot_id="RESP-1:CA-1-1:INCORRECT",
        scenario_id="SCN-001",
    )
    path = run_dir / "calls.jsonl"
    if not path.is_file():
        return False, "rejected provider response did not create calls.jsonl"
    _state(world)["rejection"] = json.loads(
        path.read_text(encoding="utf-8").splitlines()[0]
    )
    return True, ""


def _h_rejection_lifecycle(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Check provider receipt versus semantic-validation state."""
    del text, examples
    entry = _state(world).get("rejection")
    if entry is None:
        return False, "rejection record is missing"
    expected = {
        "success": False,
        "provider_response_received": True,
        "semantic_validation_passed": False,
    }
    actual = {key: entry.get(key) for key in expected}
    return actual == expected, f"unexpected rejection lifecycle: {actual!r}"


def _h_rejection_identity(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Check exact stage, step, slot, and scenario call identity."""
    del examples
    match = re.search(
        r'stage "([^"]+)", step "([^"]+)", slot "([^"]+)", and scenario "([^"]+)"',
        text,
    )
    if match is None:
        return False, f"could not parse call identity: {text}"
    entry = _state(world).get("rejection")
    if entry is None:
        return False, "rejection record is missing"
    expected = match.groups()
    actual = (
        entry.get("stage"),
        entry.get("step"),
        entry.get("slot_id"),
        entry.get("scenario_id"),
    )
    return actual == expected, f"call identity is {actual!r}, expected {expected!r}"


def _h_rejection_code(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Check stable terminal provider-contract classification."""
    del examples
    match = re.search(r'terminal error code "([^"]+)"', text)
    if match is None:
        return False, f"could not parse terminal error code: {text}"
    entry = _state(world).get("rejection")
    if entry is None:
        return False, "rejection record is missing"
    expected = [match.group(1)]
    actual = entry.get("terminal_error_codes")
    return (
        actual == expected,
        f"terminal error codes are {actual!r}, expected {expected!r}",
    )


def _h_stage6_views(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Check Stage 6 prompt views are render-only and omit bookkeeping."""
    del text, examples
    stage6 = getattr(world, "stpa_stage6", None)
    if not stage6:
        return False, "Stage 6 prompts were not rendered"
    forbidden = ("semantic_digest", "source_pins", "provider_call", "raw_mapping")
    required = (
        "renders the already validated causal scenario",
        "Do not invent any causal factor, temporal assertion, or scenario step",
    )
    for call in ("narrative", "tree", "gherkin"):
        prompts = stage6.get(call)
        if prompts is None:
            return False, f"{call} prompts were not rendered"
        system, user = prompts
        joined = f"{system}\n{user}"
        missing = [item for item in required if item not in system]
        leaked = [item for item in forbidden if item in joined]
        if missing or leaked:
            return False, f"{call} prompt missing={missing!r}, leaked={leaked!r}"
    return True, ""


def _h_crosswalk_inspected(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Inspect the deterministic crosswalk and obligation routing prompt."""
    del text, examples
    paths = (
        _ROOT / "src/asago_scenario_generator/pipeline/risk_pattern_crosswalk.py",
        _ROOT / "src/asago_scenario_generator/stpa/obligation_aware/prompts.py",
        _OBLIGATION_PROMPTS / "structural_routing_system.j2",
    )
    missing_paths = [str(path) for path in paths if not path.is_file()]
    if missing_paths:
        return False, f"crosswalk prompt sources are missing: {missing_paths}"
    _state(world)["crosswalk_text"] = _read(paths)
    return True, ""


def _h_crosswalk_all_relations(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Check that later weak mapping edges cannot be hidden by an exact edge."""
    del text, examples
    corpus = _state(world).get("crosswalk_text", "")
    expected = {
        "exact_then_category_expansion": resolve_risk_pattern_mapping_strength(
            (("exact", "direct"),)
        ),
        "related_category_expansion": resolve_risk_pattern_mapping_strength(
            (("exact", "related"),)
        ),
    }
    missing = [
        phrase
        for phrase in (
            "Every edge in every path contributes",
            "retaining the weakest supplied provenance",
        )
        if phrase.lower() not in corpus.lower()
    ]
    if missing:
        return False, f"crosswalk provenance guidance is missing: {missing}"
    actual = {key: value for key, value in expected.items()}
    return (
        actual["exact_then_category_expansion"] == "exact_then_category_expansion"
        and actual["related_category_expansion"] == "related_category_expansion",
        f"crosswalk labels are {actual!r}",
    )


def _h_crosswalk_independent(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Check mechanism plausibility and risk alignment are separate fields."""
    del text, examples
    state = _state(world)
    fields = set(ObligationSemanticAssessment.model_fields)
    corpus = state.get("crosswalk_text", "")
    required_fields = {"mechanism_assessment", "risk_alignment"}
    required_phrases = ("risk_alignment=mismatch", "not proof")
    missing = sorted(required_fields - fields) + [
        phrase for phrase in required_phrases if phrase.lower() not in corpus.lower()
    ]
    return not missing, f"crosswalk independence evidence is missing: {missing}"


def _h_crosswalk_advisory(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Check weak or mismatched mapping remains a hypothesis."""
    del text, examples
    corpus = _state(world).get("crosswalk_text", "").lower()
    required = ("hypothesis", "do not prescribe an attack sequence")
    missing = [phrase for phrase in required if phrase not in corpus]
    return not missing, f"crosswalk advisory boundary is missing: {missing}"


def _h_projection_classification(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Recompute readiness from the typed projection, not a heuristic label."""
    del text, examples
    state = getattr(world, "stpa_bundle_state", {})
    validated = state.get("validated")
    if validated is None:
        return False, "no validated execution projection exists"
    projection = validated.projection
    expected = classify_scenario_execution(
        projection.execution_contract,
        projection.unsafe_outcome,
        None,
    )
    actual = projection.execution_classification
    actual_data = actual.model_dump(mode="json", exclude={"classification_digest"})
    expected_data = expected.model_dump(mode="json", exclude={"classification_digest"})
    if actual_data != expected_data:
        return False, "projection classification differs from deterministic derivation"
    _state(world)["classification"] = actual
    return True, ""


def _h_projection_target_agnostic(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Check resource-free model behavior is target agnostic and concrete."""
    del text, examples
    classification = _state(world).get("classification")
    if classification is None:
        return False, "projection classification was not captured"
    actual = (
        classification.environment_basis.value,
        classification.binding_completeness.value,
        classification.profile_fit.value,
    )
    expected = ("target_agnostic", "concrete", "not_required")
    return actual == expected, f"classification dimensions are {actual!r}"


def _h_no_attack_zone(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Check readiness has no attack-zone input or output field."""
    del text, examples
    state = getattr(world, "stpa_bundle_state", {})
    validated = state.get("validated")
    if validated is None:
        return False, "no validated execution projection exists"
    payload = json.dumps(validated.projection.model_dump(mode="json"), sort_keys=True)
    if "attack_zone" in payload.lower() or "attack-zone" in payload.lower():
        return False, "attack-zone heuristic leaked into the execution projection"
    return bool(
        validated.projection.execution_contract
    ), "execution contract is missing"


def register(api: object) -> None:
    """Register prompt-quality audit correction steps."""
    api.register(
        r"^the Stage 1 loss-analysis prompt set is inspected$", _h_stage1_inspected
    )
    api.register(
        r"^Stage 1 separates risk-card and use-case loss provenance$",
        _h_stage1_provenance,
    )
    api.register(
        r"^Stage 1 defines a hazard as a system-level condition$",
        _h_stage1_hazard,
    )
    api.register(
        r"^Stage 1 rejects a component failure as the hazard itself$",
        _h_stage1_hazard,
    )
    api.register(
        r"^the Stage 2 revision prompt and manifest contract are inspected$",
        _h_stage2_inspected,
    )
    api.register(
        r"^Stage 2 revision accepts only new and modified elements$",
        _h_stage2_strict,
    )
    api.register(
        r"^Stage 2 revision provides an add-or-dismiss decision for each gap$",
        _h_stage2_dismiss,
    )
    api.register(
        r"^the run manifest exposes revision outcome and post-revision errors$",
        _h_stage2_manifest,
    )
    api.register(
        r"^a corrected inter-responsibility Stage 5 route context is available$",
        _h_inter_responsibility_context,
    )
    api.register(
        r"^the compiled ICA has one concise deviation sentence$",
        _h_ica_concise,
    )
    api.register(
        r"^the ICA provider contract leaves UCA category selection to the slot$",
        _h_ica_category,
    )
    api.register(
        r"^an offline provider returns a rejected structured response$",
        _h_rejected_response,
    )
    api.register(r"^the rejected provider response is logged$", _h_rejected_response)
    api.register(
        r"^the rejection record has provider receipt and failed semantic validation$",
        _h_rejection_lifecycle,
    )
    api.register(
        r'^the rejection record retains stage "[^"]+", step "[^"]+", slot "[^"]+", and scenario "[^"]+"$',
        _h_rejection_identity,
    )
    api.register(
        r'^the rejection record has terminal error code "[^"]+"$',
        _h_rejection_code,
    )
    api.register(
        r"^Stage 6 prompt views are render-only and evidence-grounded$",
        _h_stage6_views,
    )
    api.register(
        r"^the taxonomy crosswalk and obligation prompt contracts are inspected$",
        _h_crosswalk_inspected,
    )
    api.register(
        r"^crosswalk strength is derived from every relation in a path$",
        _h_crosswalk_all_relations,
    )
    api.register(
        r"^mechanism plausibility and reviewed-risk alignment are independent$",
        _h_crosswalk_independent,
    )
    api.register(
        r"^a weak or mismatched mapping remains an obligation hypothesis$",
        _h_crosswalk_advisory,
    )
    api.register(
        r"^projection readiness uses the deterministic execution classification$",
        _h_projection_classification,
    )
    api.register(
        r"^the classification is target-agnostic for this resource-free model action$",
        _h_projection_target_agnostic,
    )
    api.register(
        r"^readiness has no attack-zone heuristic input$",
        _h_no_attack_zone,
    )


__all__ = ["FEATURE_ID", "register"]
