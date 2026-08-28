"""Stage 6 Call B — Attack tree.

One LLM call per scenario produces a YAML-serializable attack tree
using the STPA two-level causal taxonomy with 3 branch categories:
controller_side, path_side, coordination_gap.
"""

from __future__ import annotations

import json
import re
import yaml
from pathlib import Path

from asago_scenario_generator.stpa.infra.llm import LLMClient
from asago_scenario_generator.stpa.infra.llm_helpers import safe_llm_call_raw
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.models.scenario_spec import ScenarioSpec

from ._constants import PROMPTS_DIR

__all__ = ["generate_attack_tree", "build_attack_tree_prompts", "parse_attack_tree"]

# Matches markdown code fences: ```json ... ``` or ```yaml ... ``` or ``` ... ```
_CODE_FENCE_RE = re.compile(
    r"```(?:[a-zA-Z]+)?\s*\n(.*?)\n\s*```",
    re.DOTALL,
)


def generate_attack_tree(
    llm_client: LLMClient,
    scenario_spec: ScenarioSpec,
    control_structure: ControlStructure,
    run_dir: Path,
    loader: TemplateLoader | None = None,
    stage: str = "stage_6",
    step: str = "attack_tree",
    temperature: float = 0.4,
) -> tuple[dict | None, str | None]:
    """Execute the attack tree LLM call.

    Args:
        llm_client: LLM client for making the completion call.
        scenario_spec: The scenario specification.
        control_structure: The full control structure.
        run_dir: Directory for call logging.
        loader: Template loader (default: SP3 prompts directory).
        stage: Pipeline stage label.
        step: Sub-step label.
        temperature: LLM temperature.

    Returns:
        A tuple of (attack_tree_dict or None, error_message or None).
    """
    if loader is None:
        loader = TemplateLoader(PROMPTS_DIR)

    system_prompt, user_prompt = build_attack_tree_prompts(
        scenario_spec, control_structure, loader
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
        return None, error

    tree = parse_attack_tree(text)
    if tree is None:
        return None, "Failed to parse attack tree from LLM response"
    return tree, None


def parse_attack_tree(content) -> dict | None:
    """Parse LLM response content into an attack tree dict.

    Handles dicts, JSON strings, and YAML strings. Strips markdown
    code fences (```json ... ``` or ```yaml ... ```) before parsing.

    Args:
        content: The LLM response content (string or dict).

    Returns:
        A dict with ``root``, ``branches``, and ``leaves`` keys, or None.
    """
    if isinstance(content, dict):
        return content
    if not isinstance(content, str):
        return None
    return _parse_tree_text(_strip_code_fences(content))


def _strip_code_fences(text: str) -> str:
    """Extract content from markdown code fences.

    If the text contains a fenced block (```json ... ``` or ```yaml ... ```
    or ``` ... ```), return the inner content. Otherwise return the
    original text unchanged.
    """
    match = _CODE_FENCE_RE.search(text)
    if match:
        return match.group(1).strip()
    return text


def _parse_tree_text(text: str) -> dict | None:
    """Try parsing text as JSON then YAML, returning a dict or None."""
    for parser in (_parse_json_dict, _parse_yaml_dict):
        result = parser(text)
        if result is not None:
            return result
    return None


def _parse_json_dict(text: str) -> dict | None:
    """Parse text as JSON, returning a dict or None."""
    try:
        result = json.loads(text)
        return result if isinstance(result, dict) else None
    except (json.JSONDecodeError, ValueError):
        return None


def _parse_yaml_dict(text: str) -> dict | None:
    """Parse text as YAML, returning a dict or None."""
    try:
        parsed = yaml.safe_load(text)
        return parsed if isinstance(parsed, dict) else None
    except yaml.YAMLError:
        return None


def build_attack_tree_prompts(
    scenario_spec: ScenarioSpec,
    control_structure: ControlStructure,
    loader: TemplateLoader,
    projection_alignment: str | None = None,
) -> tuple[str, str]:
    """Build the system and user prompts for the attack tree call.

    Args:
        scenario_spec: The scenario specification.
        control_structure: The full control structure.
        loader: Template loader.
        projection_alignment: Optional rendered STPA projection alignment
            table shared by every Stage 6 prompt.  When ``None`` no table
            is included (backward compatible default).

    Returns:
        A tuple of (system_prompt, user_prompt).
    """
    scenario_spec_yaml = yaml.dump(
        scenario_spec.model_dump(mode="json", exclude_none=True),
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
    )
    control_structure_yaml = yaml.dump(
        control_structure.model_dump(mode="json", exclude_none=True),
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
    )

    system_prompt = loader.render_prompt(
        "stage6b_tree_system.j2",
        projection_alignment=projection_alignment,
    )
    user_prompt = loader.render_prompt(
        "stage6b_tree_user.j2",
        scenario_spec_yaml=scenario_spec_yaml,
        control_structure_yaml=control_structure_yaml,
        ica_type=scenario_spec.ica_type.value,
        control_action=scenario_spec.target_control_action,
        projection_alignment=projection_alignment,
    )

    return system_prompt, user_prompt
