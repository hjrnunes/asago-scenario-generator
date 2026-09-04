"""Stage 6 Call C — Gherkin behavior specification.

One LLM call per scenario produces a structured Gherkin spec (YAML)
with the should/but structure mapping to control structure state transitions.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml

from asago_scenario_generator.stpa.infra.llm import LLMClient
from asago_scenario_generator.stpa.infra.llm_helpers import safe_llm_call_raw
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.models.loss_analysis import (
    LossAnalysis,
    SecurityConstraint,
)
from asago_scenario_generator.stpa.models.scenario_envelope import GherkinSpec
from asago_scenario_generator.stpa.models.scenario_spec import ScenarioSpec

from ._constants import PROMPTS_DIR
from .context import render_stage6_scenario_view

__all__ = [
    "generate_gherkin",
    "build_gherkin_prompts",
    "apply_gherkin_identity_scaffold",
    "build_gherkin_identity_scaffold",
    "find_security_constraint",
    "parse_gherkin_spec",
    "GHERKIN_MAX_COMPLETION_TOKENS",
]

GHERKIN_MAX_COMPLETION_TOKENS = 384

# Matches markdown code fences: ```yaml ... ``` or ``` ... ```
_CODE_FENCE_RE = re.compile(
    r"```(?:[a-zA-Z]+)?\s*\n(.*?)\n\s*```",
    re.DOTALL,
)
_STRUCTURAL_REFERENCE_RE = re.compile(r"\b(?:PM|FB|CA|CM|CL|RESP)-\d+(?:-\d+)?\b")


def _selected_process_model(scenario_spec: ScenarioSpec) -> Any | None:
    """Resolve the selected process-model element or a historical fallback."""
    context = scenario_spec.scenario_context
    path = context.target_control_path if context is not None else None
    process_model = _path_process_model(path)
    if process_model is not None:
        return process_model
    process_model_ids = _scenario_process_model_ids(scenario_spec)
    if process_model_ids:
        return process_model_ids[0], "the selected process-model state"
    return None


def _path_process_model(path: Any | None) -> Any | None:
    """Select the exact coordination or direct-path process-model element."""
    if path is None:
        return None
    if path.coordination_path is not None:
        return path.coordination_path.shared_process_model
    if path.process_model_parts:
        return path.process_model_parts[0]
    return None


def _scaffold_given(process_model: Any | None) -> list[str]:
    """Render the deterministic selected process-model Given clause."""
    if process_model is None:
        return ["Given the selected process-model state is supplied"]
    pm_id, pm_description = _described_element_values(process_model)
    return [f"Given {pm_id} ({pm_description}) is the selected process-model state"]


def _scaffold_actual(
    scenario_spec: ScenarioSpec,
    loss_analysis: LossAnalysis | None,
) -> list[str]:
    """Render exact unsafe meaning, accepted condition, and selected loss."""
    context = scenario_spec.scenario_context
    action_id = scenario_spec.target_control_action
    ica_type = scenario_spec.ica_type.value
    exact_ica_text = (
        context.ica.exact_ica_text
        if context is not None
        else f"{ica_type} on {action_id}"
    )
    actual = [
        (
            f"But the system exhibits {ica_type} for the selected unsafe action "
            f"{action_id}: {exact_ica_text}"
        )
    ]
    condition = _semantic_condition_text(scenario_spec.unsafe_outcome_condition)
    if condition:
        actual.append(condition)
    loss_id = _selected_loss_id(scenario_spec, loss_analysis)
    if loss_id is not None:
        actual.append(f"And loss {loss_id} is realized")
    return actual


def build_gherkin_identity_scaffold(
    scenario_spec: ScenarioSpec,
    security_constraint: SecurityConstraint | None,
    loss_analysis: LossAnalysis | None = None,
) -> GherkinSpec:
    """Build the deterministic identity-bearing portion of one Gherkin spec.

    Stage 6 renders an accepted Stage 5 scenario; it is not allowed to select
    a nearby action or invent a new unsafe meaning.  This scaffold therefore
    owns all identity-bearing clauses (selected process-model state, exact
    action/UCA, governing constraint, accepted condition, and loss).  Provider
    prose is overlaid only by :func:`apply_gherkin_identity_scaffold` after it
    has been bounded and filtered against this identity set.
    """
    action_id = scenario_spec.target_control_action
    ica_type = scenario_spec.ica_type.value

    return GherkinSpec(
        feature=f"STPA {ica_type} rendering",
        scenario=f"{scenario_spec.scenario_id}: {ica_type} on {action_id}",
        given=_scaffold_given(_selected_process_model(scenario_spec)),
        when=[f"When the selected control path reaches {action_id}"],
        then_expected=[_expected_constraint_text(security_constraint)],
        then_actual=_scaffold_actual(scenario_spec, loss_analysis),
    )


def apply_gherkin_identity_scaffold(
    provider_spec: GherkinSpec,
    scenario_spec: ScenarioSpec,
    security_constraint: SecurityConstraint | None,
    loss_analysis: LossAnalysis | None = None,
) -> GherkinSpec:
    """Overlay bounded provider prose onto deterministic Gherkin identities.

    The provider may make the trigger readable, and may add one short
    process-model context sentence.  It cannot replace the selected action,
    UCA category, PM identity, expected constraint, unsafe condition, or loss.
    Structural references outside the accepted scenario are dropped rather
    than copied into the published feature.
    """
    scaffold = build_gherkin_identity_scaffold(
        scenario_spec, security_constraint, loss_analysis
    )
    allowed_refs = _gherkin_allowed_references(scenario_spec, loss_analysis)
    provider_given = _safe_provider_steps(provider_spec.given, allowed_refs, limit=2)
    provider_when = _safe_provider_steps(provider_spec.when, allowed_refs, limit=1)

    return scaffold.model_copy(
        update={
            "feature": _provider_feature(provider_spec, scaffold, allowed_refs),
            "given": _merge_gherkin_given(scaffold, provider_given),
            # The trigger is the one prose slot the provider may render.  The
            # exact selected action remains in the deterministic ``But`` clause.
            "when": provider_when[:1] or scaffold.when,
        }
    )


def _provider_feature(
    provider_spec: GherkinSpec,
    scaffold: GherkinSpec,
    allowed_refs: set[str],
) -> str:
    """Use bounded provider feature prose or retain the deterministic title."""
    return _safe_provider_text(provider_spec.feature, allowed_refs) or scaffold.feature


def _matching_gherkin_given(
    scaffold: GherkinSpec,
    provider_given: list[str],
) -> str | None:
    """Find provider Given prose that preserves the scaffold identity set."""
    scaffold_refs = set(_STRUCTURAL_REFERENCE_RE.findall(scaffold.given[0]))
    return next(
        (
            item
            for item in provider_given
            if set(_STRUCTURAL_REFERENCE_RE.findall(item)) == scaffold_refs
        ),
        None,
    )


def _provider_given_extras(
    scaffold: GherkinSpec,
    provider_given: list[str],
    matching: str | None,
) -> list[str]:
    """Keep provider context prose that carries no competing identity."""
    scaffold_refs = set(_STRUCTURAL_REFERENCE_RE.findall(scaffold.given[0]))
    return [
        item
        for item in provider_given
        if item != matching
        and not (
            scaffold_refs
            and scaffold_refs & set(_STRUCTURAL_REFERENCE_RE.findall(item))
        )
    ]


def _merge_gherkin_given(
    scaffold: GherkinSpec,
    provider_given: list[str],
) -> list[str]:
    """Keep one identity-bearing Given plus at most one provider extra."""
    matching = _matching_gherkin_given(scaffold, provider_given)
    identity_given = [matching] if matching else scaffold.given
    extras = _provider_given_extras(scaffold, provider_given, matching)
    return identity_given + extras[:1]


def _described_element_values(element: Any) -> tuple[str, str]:
    """Read an exact context element or a legacy ``(id, description)`` pair."""
    if isinstance(element, tuple):
        return str(element[0]), str(element[1])
    return str(element.element_id), str(element.description)


def _scenario_process_model_ids(scenario_spec: ScenarioSpec) -> tuple[str, ...]:
    """Find deterministic PM identities retained in a historical spec."""
    return tuple(
        dict.fromkeys(
            belief.pm_id
            for belief in scenario_spec.defender_bdi.beliefs
            if belief.pm_id
        )
    )


def _expected_constraint_text(
    security_constraint: SecurityConstraint | None,
) -> str:
    """Render the one exact expected security constraint."""
    if security_constraint is None:
        return "Then the system should satisfy the selected security constraint"
    return (
        f"Then the system should satisfy {security_constraint.constraint_id}: "
        f"{security_constraint.description}"
    )


def _render_action_presence_condition(payload: dict[str, Any]) -> str:
    """Render the literal action-presence unsafe condition."""
    return f"And {payload['control_action_id']} is not provided when required"


def _render_action_value_condition(payload: dict[str, Any]) -> str:
    """Render an action-property comparison condition."""
    return _comparison_text(
        payload["control_action_id"],
        payload["property"],
        payload["operator"],
        payload["expected"],
    )


def _render_state_value_condition(payload: dict[str, Any]) -> str:
    """Render a process-state property comparison condition."""
    return _comparison_text(
        payload["subject_ref"],
        payload["property"],
        payload["operator"],
        payload["expected"],
    )


def _render_ordering_condition(payload: dict[str, Any]) -> str:
    """Render the selected action ordering condition."""
    return (
        f"And the selected action is {payload['relation']} "
        f"{payload['reference_step_id']}"
    )


def _render_absence_condition(payload: dict[str, Any]) -> str:
    """Render the exact absence-until condition."""
    return (
        f"And {payload['reference_ref']} remains absent until "
        f"{payload['until_step_id']}"
    )


def _render_timing_condition(payload: dict[str, Any]) -> str:
    """Render accepted timing semantics without inventing deployment values."""
    return "And the accepted unsafe timing condition is observed: " + json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _render_generic_condition(_payload: dict[str, Any]) -> str:
    """Render a bounded marker for an unknown accepted condition type."""
    return "And the accepted unsafe outcome condition is observed"


_CONDITION_RENDERERS = {
    "action_presence": _render_action_presence_condition,
    "action_value": _render_action_value_condition,
    "state_value": _render_state_value_condition,
    "ordering": _render_ordering_condition,
    "absence": _render_absence_condition,
    "delay": _render_timing_condition,
    "duration": _render_timing_condition,
    "window": _render_timing_condition,
}


def _semantic_condition_text(condition: Any) -> str | None:
    """Render an accepted semantic condition without adding new semantics."""
    if condition is None:
        return None
    payload = condition.model_dump(mode="json")
    renderer = _CONDITION_RENDERERS.get(payload.get("type"), _render_generic_condition)
    return renderer(payload)


def _comparison_text(
    subject: str,
    property_name: str,
    operator: str,
    expected: Any,
) -> str:
    """Render one literal or typed-placeholder comparison from the condition."""
    value = json.dumps(expected, ensure_ascii=False, sort_keys=True)
    return f"And {subject}.{property_name} is {operator} {value}"


def _selected_loss_id(
    scenario_spec: ScenarioSpec,
    loss_analysis: LossAnalysis | None,
) -> str | None:
    """Choose the first exact context/analysis loss without inventing one."""
    context = scenario_spec.scenario_context
    if context is not None and context.losses:
        return context.losses[0].loss_id
    if loss_analysis is None:
        return None
    losses = loss_analysis.risk_card_losses + loss_analysis.use_case_losses
    return losses[0].loss_id if losses else None


def _gherkin_allowed_references(
    scenario_spec: ScenarioSpec,
    loss_analysis: LossAnalysis | None,
) -> set[str]:
    """Return exact structural and consequence references safe for prose."""
    context = scenario_spec.scenario_context
    if context is not None:
        return _context_allowed_references(scenario_spec.target_control_action, context)
    return _historical_allowed_references(scenario_spec, loss_analysis)


def _context_allowed_references(
    action_id: str,
    context: Any,
) -> set[str]:
    """Return identities retained by the exact selected context path."""
    path = context.target_control_path
    allowed: set[str] = {action_id, path.control_action.action_id}
    process_model = _path_process_model(path)
    if process_model is not None:
        allowed.add(_described_element_values(process_model)[0])
    allowed.update(item.element_id for item in path.feedback)
    allowed.update(item.loss_id for item in context.losses)
    allowed.update(item.hazard_id for item in context.hazards)
    allowed.update(item.constraint_id for item in context.constraints)
    return allowed


def _historical_allowed_references(
    scenario_spec: ScenarioSpec,
    loss_analysis: LossAnalysis | None,
) -> set[str]:
    """Return identities available to legacy specs without a context graph."""
    allowed = {
        scenario_spec.target_control_action,
        *_scenario_process_model_ids(scenario_spec),
    }
    if loss_analysis is not None:
        allowed.update(_extract_valid_loss_ids(loss_analysis))
        allowed.update(_extract_valid_hazard_ids(loss_analysis))
    return allowed


def _safe_provider_text(value: Any, allowed_refs: set[str], limit: int = 160) -> str:
    """Bound provider prose and reject prose containing another identity."""
    if not isinstance(value, str):
        return ""
    text = " ".join(value.split())
    if not text or len(text) > limit:
        text = text[:limit].rstrip()
    references = set(_STRUCTURAL_REFERENCE_RE.findall(text))
    if references - allowed_refs:
        return ""
    return text


def _safe_provider_steps(
    values: Any,
    allowed_refs: set[str],
    *,
    limit: int,
) -> list[str]:
    """Keep at most *limit* short provider steps with accepted identities."""
    if not isinstance(values, list):
        return []
    result: list[str] = []
    for value in values:
        text = _safe_provider_text(value, allowed_refs)
        if text:
            result.append(text)
        if len(result) >= limit:
            break
    return result


def _resolve_gherkin_constraint(
    scenario_spec: ScenarioSpec,
    loss_analysis: LossAnalysis,
) -> tuple[SecurityConstraint | None, str | None]:
    """Resolve the governing constraint while keeping context errors local."""
    try:
        return find_security_constraint(scenario_spec, loss_analysis), None
    except ValueError as exc:
        return None, f"ScenarioContextError: {exc}"


def _result_raw_text(result: Any) -> str | None:
    """Coerce a failed structured result into bounded raw text for callers."""
    raw_text = getattr(result, "content", None)
    if raw_text is None:
        return None
    return raw_text if isinstance(raw_text, str) else str(raw_text)


def _finish_gherkin_response(
    text: str | None,
    result: Any,
    error: str | None,
    scenario_spec: ScenarioSpec,
    security_constraint: SecurityConstraint | None,
    loss_analysis: LossAnalysis,
) -> tuple[GherkinSpec | None, str | None, str | None]:
    """Parse, scaffold, and return one Gherkin response consistently."""
    if error is not None:
        return None, _result_raw_text(result), error
    raw_text = text or ""
    spec = parse_gherkin_spec(raw_text)
    if spec is None:
        return None, raw_text, "Failed to parse Gherkin YAML from LLM response"
    return (
        apply_gherkin_identity_scaffold(
            spec,
            scenario_spec,
            security_constraint,
            loss_analysis,
        ),
        raw_text,
        None,
    )


def generate_gherkin(
    llm_client: LLMClient,
    scenario_spec: ScenarioSpec,
    loss_analysis: LossAnalysis,
    run_dir: Path,
    loader: TemplateLoader | None = None,
    stage: str = "stage_6",
    step: str = "gherkin",
    temperature: float = 0.4,
) -> tuple[GherkinSpec | None, str | None, str | None]:
    """Execute the Gherkin LLM call.

    Args:
        llm_client: LLM client for making the completion call.
        scenario_spec: The scenario specification.
        loss_analysis: The loss analysis for security constraint lookup
            and valid Loss/Hazard ID extraction.
        run_dir: Directory for call logging.
        loader: Template loader (default: SP3 prompts directory).
        stage: Pipeline stage label.
        step: Sub-step label.
        temperature: LLM temperature.

    Returns:
        A tuple of (gherkin_spec or None, raw_text or None, error_message or None).
    """
    if loader is None:
        loader = TemplateLoader(PROMPTS_DIR)

    security_constraint, constraint_error = _resolve_gherkin_constraint(
        scenario_spec, loss_analysis
    )
    if constraint_error is not None:
        return None, None, constraint_error
    system_prompt, user_prompt = build_gherkin_prompts(
        scenario_spec, security_constraint, loss_analysis, loader
    )

    text, _result, error = safe_llm_call_raw(
        llm_client=llm_client,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        run_dir=run_dir,
        stage=stage,
        step=step,
        slot_id=scenario_spec.threat_source.ica_slot_id,
        scenario_id=scenario_spec.scenario_id,
        temperature=temperature,
        max_completion_tokens=GHERKIN_MAX_COMPLETION_TOKENS,
        raw_result_validator=_require_parseable_gherkin,
    )
    return _finish_gherkin_response(
        text,
        _result,
        error,
        scenario_spec,
        security_constraint,
        loss_analysis,
    )


def _require_parseable_gherkin(content: Any) -> None:
    """Classify malformed provider text while retaining its response evidence."""
    if parse_gherkin_spec(content) is None:
        raise ValueError("Failed to parse Gherkin YAML from LLM response")


def parse_gherkin_spec(content: str) -> GherkinSpec | None:
    """Parse LLM response content into a :class:`GherkinSpec`.

    Strips markdown code fences before parsing YAML. Handles responses
    that contain a YAML block embedded in prose.

    Args:
        content: The LLM response text.

    Returns:
        A :class:`GherkinSpec` or None if parsing fails.
    """
    if not isinstance(content, str):
        return None
    cleaned = _strip_code_fences(content)
    return _parse_gherkin_yaml(cleaned)


def _strip_code_fences(text: str) -> str:
    """Extract content from markdown code fences if present."""
    match = _CODE_FENCE_RE.search(text)
    if match:
        return match.group(1).strip()
    return text


def _parse_gherkin_yaml(text: str) -> GherkinSpec | None:
    """Try parsing text as YAML into a :class:`GherkinSpec`."""
    try:
        parsed = yaml.safe_load(text)
        if not isinstance(parsed, dict):
            return None
        _normalize_gherkin_headings(parsed)
        return GherkinSpec.model_validate(parsed)
    except Exception:  # noqa: BLE001
        return None


def _normalize_gherkin_headings(parsed: dict[object, object]) -> None:
    """Remove renderer-owned keywords from model-authored title fields."""
    for field, keyword in (("feature", "Feature"), ("scenario", "Scenario")):
        value = parsed.get(field)
        if isinstance(value, str):
            normalized, replacements = re.subn(
                rf"^(?:\s*{keyword}\s*:\s*)+",
                "",
                value,
                flags=re.IGNORECASE,
            )
            if replacements:
                parsed[field] = normalized.strip()


def find_security_constraint(
    scenario_spec: ScenarioSpec,
    loss_analysis: LossAnalysis,
) -> SecurityConstraint | None:
    """Resolve the one exact governing constraint from the retained context."""
    context = scenario_spec.scenario_context
    if context is None:
        return None
    if len(context.constraints) != 1:
        raise ValueError("scenario context has ambiguous governing constraints")
    selected = context.constraints[0]
    hazard_ids = {item.hazard_id for item in context.hazards}
    if not set(selected.related_hazard_ids) & hazard_ids:
        raise ValueError("scenario constraint does not govern its selected hazard")
    matches = [
        item
        for item in loss_analysis.security_constraints
        if item.constraint_id == selected.constraint_id
    ]
    if len(matches) != 1:
        raise ValueError("scenario governing constraint is missing from loss analysis")
    resolved = matches[0]
    if (
        resolved.description != selected.description
        or tuple(resolved.related_hazards) != selected.related_hazard_ids
    ):
        raise ValueError("scenario governing constraint changed after context capture")
    return resolved


def _extract_valid_loss_ids(loss_analysis: LossAnalysis) -> list[str]:
    """Extract all valid Loss IDs from a loss analysis."""
    return [
        loss.loss_id
        for loss in loss_analysis.risk_card_losses + loss_analysis.use_case_losses
    ]


def _extract_valid_hazard_ids(loss_analysis: LossAnalysis) -> list[str]:
    """Extract all valid Hazard IDs from a loss analysis."""
    return [hazard.hazard_id for hazard in loss_analysis.hazards]


def _identity_scaffold_yaml(
    scenario_spec: ScenarioSpec,
    security_constraint: SecurityConstraint | None,
    loss_analysis: LossAnalysis,
) -> str:
    """Serialize the deterministic Gherkin identity scaffold for prompting."""
    return yaml.safe_dump(
        build_gherkin_identity_scaffold(
            scenario_spec,
            security_constraint,
            loss_analysis,
        ).model_dump(mode="json"),
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
    )


def _gherkin_prompt_values(
    scenario_spec: ScenarioSpec,
    security_constraint: SecurityConstraint | None,
    loss_analysis: LossAnalysis,
) -> dict[str, Any]:
    """Collect closed prompt-view values without exposing source bookkeeping."""
    ica_text, valid_loss_ids, valid_hazard_ids = _context_prompt_values(
        scenario_spec, loss_analysis
    )
    return {
        "scenario_spec_yaml": render_stage6_scenario_view(scenario_spec),
        "security_constraint": _constraint_prompt_text(security_constraint),
        "ica_type": scenario_spec.ica_type.value,
        "control_action": scenario_spec.target_control_action,
        "ica_text": ica_text,
        "valid_loss_ids": ", ".join(valid_loss_ids),
        "valid_hazard_ids": ", ".join(valid_hazard_ids),
        "identity_scaffold_yaml": _identity_scaffold_yaml(
            scenario_spec,
            security_constraint,
            loss_analysis,
        ),
    }


def _constraint_prompt_text(security_constraint: SecurityConstraint | None) -> str:
    """Render the governing constraint value supplied to the provider."""
    if security_constraint is None:
        return "No security constraint found."
    return f"{security_constraint.constraint_id}: {security_constraint.description}"


def _context_prompt_values(
    scenario_spec: ScenarioSpec,
    loss_analysis: LossAnalysis,
) -> tuple[str, list[str], list[str]]:
    """Resolve exact ICA, loss, and hazard values for contextual prompting."""
    context = scenario_spec.scenario_context
    if context is None:
        return (
            f"ICA type: {scenario_spec.ica_type.value} on {scenario_spec.target_control_action}",
            _extract_valid_loss_ids(loss_analysis),
            _extract_valid_hazard_ids(loss_analysis),
        )
    return (
        context.ica.exact_ica_text,
        [item.loss_id for item in context.losses],
        [item.hazard_id for item in context.hazards],
    )


def build_gherkin_prompts(
    scenario_spec: ScenarioSpec,
    security_constraint: SecurityConstraint | None,
    loss_analysis: LossAnalysis,
    loader: TemplateLoader,
    projection_alignment: str | None = None,
) -> tuple[str, str]:
    """Build the system and user prompts for the Gherkin call.

    Args:
        scenario_spec: The scenario specification.
        security_constraint: The security constraint for the should clause.
        loss_analysis: The loss analysis for valid Loss/Hazard ID extraction.
        loader: Template loader.
        projection_alignment: Optional rendered STPA projection alignment
            table shared by every Stage 6 prompt.  When ``None`` no table
            is included (backward compatible default).

    Returns:
        A tuple of (system_prompt, user_prompt).
    """
    system_prompt = loader.render_prompt(
        "stage6c_gherkin_system.j2",
        projection_alignment=projection_alignment,
    )
    prompt_values = _gherkin_prompt_values(
        scenario_spec,
        security_constraint,
        loss_analysis,
    )
    user_prompt = loader.render_prompt(
        "stage6c_gherkin_user.j2",
        **prompt_values,
        projection_alignment=projection_alignment,
    )

    return system_prompt, user_prompt
