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
    _feature_state,
    World,
)

from asago_scenario_generator.models.obligation_consideration import (
    ObligationSemanticAssessment,
)
from asago_scenario_generator.pipeline.risk_pattern_crosswalk import (
    resolve_risk_pattern_mapping_strength,
)
from asago_scenario_generator.stpa.infra.llm import LLMResult
from asago_scenario_generator.stpa.infra.llm_helpers import (
    CorrectionPolicy,
    call_with_policy,
)
from asago_scenario_generator.stpa.system_model.critic import RevisionDelta
from asago_scenario_generator.stpa.infra.manifest import STPARunManifest
from registry import StepTable

step = StepTable()


FEATURE_ID = "prompt_audit_corrections"

_ROOT = Path(PROJECT_ROOT)
_SYSTEM_PROMPTS = _ROOT / "src/asago_scenario_generator/stpa/system_model/prompts"
_OBLIGATION_PROMPTS = (
    _ROOT / "src/asago_scenario_generator/stpa/obligation_aware/prompt_templates"
)


def _state(world: World) -> dict[str, Any]:
    return _feature_state(world, "prompt_audit_state")


def _read(paths: tuple[Path, ...]) -> str:
    """Read prompt sources as one deterministic inspection corpus."""
    return "\n".join(path.read_text(encoding="utf-8") for path in paths)


@step(r"^the Stage 1 loss-analysis prompt set is inspected$")
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


@step(r"^Stage 1 separates risk-card and use-case loss provenance$")
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


@step(r"^Stage 1 defines a hazard as a system-level condition$")
@step(r"^Stage 1 rejects a component failure as the hazard itself$")
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


@step(r"^the Stage 2 revision prompt and manifest contract are inspected$")
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


@step(r"^Stage 2 revision accepts only new and modified elements$")
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


@step(r"^Stage 2 revision provides an add-or-dismiss decision for each gap$")
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


@step(r"^the run manifest exposes revision outcome and post-revision errors$")
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


@step(r"^the compiled ICA has one concise deviation sentence$")
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


@step(r"^the ICA provider contract leaves UCA category selection to the slot$")
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


@step(r"^an offline provider returns a rejected structured response$")
@step(r"^the rejected provider response is logged$")
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
    call_with_policy(
        llm_client=Provider(),
        system_prompt="Return JSON.",
        user_prompt="Return the required field.",
        response_format=Expected,
        run_dir=run_dir,
        stage="stage_5",
        step="bdi_generation",
        slot_id="RESP-1:CA-1-1:INCORRECT",
        scenario_id="SCN-001",
        policy=CorrectionPolicy(),
    )
    path = run_dir / "calls.jsonl"
    if not path.is_file():
        return False, "rejected provider response did not create calls.jsonl"
    _state(world)["rejection"] = json.loads(
        path.read_text(encoding="utf-8").splitlines()[0]
    )
    return True, ""


@step(r"^the rejection record has provider receipt and failed semantic validation$")
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


@step(
    r'^the rejection record retains stage "[^"]+", step "[^"]+", slot "[^"]+", and scenario "[^"]+"$'
)
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


@step(r'^the rejection record has terminal error code "[^"]+"$')
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


@step(r"^the taxonomy crosswalk and obligation prompt contracts are inspected$")
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


@step(r"^crosswalk strength is derived from every relation in a path$")
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


@step(r"^mechanism plausibility and reviewed-risk alignment are independent$")
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


@step(r"^a weak or mismatched mapping remains an obligation hypothesis$")
def _h_crosswalk_advisory(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Check weak or mismatched mapping remains a hypothesis."""
    del text, examples
    corpus = _state(world).get("crosswalk_text", "").lower()
    required = ("hypothesis", "do not prescribe an attack sequence")
    missing = [phrase for phrase in required if phrase not in corpus]
    return not missing, f"crosswalk advisory boundary is missing: {missing}"


register = step.register


__all__ = ["FEATURE_ID", "register"]
