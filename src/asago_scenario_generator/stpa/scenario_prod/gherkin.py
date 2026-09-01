"""Stage 6 Call C — Gherkin behavior specification.

One LLM call per scenario produces a structured Gherkin spec (YAML)
with the should/but structure mapping to control structure state transitions.
"""

from __future__ import annotations

import re
import yaml
from pathlib import Path

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
from .context import render_scenario_generation_context

__all__ = [
    "generate_gherkin",
    "build_gherkin_prompts",
    "find_security_constraint",
    "parse_gherkin_spec",
]

# Matches markdown code fences: ```yaml ... ``` or ``` ... ```
_CODE_FENCE_RE = re.compile(
    r"```(?:[a-zA-Z]+)?\s*\n(.*?)\n\s*```",
    re.DOTALL,
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

    try:
        security_constraint = find_security_constraint(scenario_spec, loss_analysis)
    except ValueError as exc:
        return None, None, f"ScenarioContextError: {exc}"
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
        temperature=temperature,
    )

    if error is not None:
        return None, None, error

    raw_text = text or ""
    spec = parse_gherkin_spec(raw_text)
    if spec is None:
        return None, raw_text, "Failed to parse Gherkin YAML from LLM response"
    return spec, raw_text, None


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
    context = scenario_spec.scenario_context
    scenario_spec_yaml = yaml.dump(
        scenario_spec.model_dump(
            mode="json", exclude_none=True, exclude={"scenario_context"}
        ),
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
    )

    constraint_text = (
        f"{security_constraint.constraint_id}: {security_constraint.description}"
        if security_constraint
        else "No security constraint found."
    )

    ica_text = (
        context.ica.exact_ica_text
        if context is not None
        else f"ICA type: {scenario_spec.ica_type.value} on {scenario_spec.target_control_action}"
    )

    valid_loss_ids = (
        [item.loss_id for item in context.losses]
        if context is not None
        else _extract_valid_loss_ids(loss_analysis)
    )
    valid_hazard_ids = (
        [item.hazard_id for item in context.hazards]
        if context is not None
        else _extract_valid_hazard_ids(loss_analysis)
    )

    system_prompt = loader.render_prompt(
        "stage6c_gherkin_system.j2",
        projection_alignment=projection_alignment,
    )
    user_prompt = loader.render_prompt(
        "stage6c_gherkin_user.j2",
        scenario_spec_yaml=scenario_spec_yaml,
        scenario_context_yaml=(
            render_scenario_generation_context(context) if context is not None else None
        ),
        security_constraint=constraint_text,
        ica_type=scenario_spec.ica_type.value,
        control_action=scenario_spec.target_control_action,
        ica_text=ica_text,
        valid_loss_ids=", ".join(valid_loss_ids),
        valid_hazard_ids=", ".join(valid_hazard_ids),
        projection_alignment=projection_alignment,
    )

    return system_prompt, user_prompt
