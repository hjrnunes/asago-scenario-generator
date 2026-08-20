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


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-20T20:28:12Z","module_hash":"25043bcb65dcaac9eff51c4fbebc8605723674adb943bbfa2ec8859cb6b9086d","functions":[{"id":"func/generate_attack_tree","name":"generate_attack_tree","line":32,"end_line":80,"hash":"9861913674ad7602c79cf4545b3b51e5fc2e255335c2bfc90c0f10a8241de875"},{"id":"func/parse_attack_tree","name":"parse_attack_tree","line":83,"end_line":99,"hash":"c208bb813fe0ce27f551feb829085d1002480cbaab0477106c7529ead4b6d94c"},{"id":"func/_strip_code_fences","name":"_strip_code_fences","line":102,"end_line":112,"hash":"7bd3488f08e00dd9ab7ddeabd5b02b54ea3657f726d507408b9735a474f2ebc9"},{"id":"func/_parse_tree_text","name":"_parse_tree_text","line":115,"end_line":121,"hash":"a67cf9f4c0333751a8cae8ebda47d1211540b21b113a9cf980c5fa043a371fac"},{"id":"func/_parse_json_dict","name":"_parse_json_dict","line":124,"end_line":130,"hash":"0ef24dc5b9cf2795a974c04be991415f00a3763ddd7f16c7bb800038e73dde2e"},{"id":"func/_parse_yaml_dict","name":"_parse_yaml_dict","line":133,"end_line":139,"hash":"63b9d92874cf433196af7624aab0847e4e6842bb464711fb6ada80c5e1188b96"},{"id":"func/build_attack_tree_prompts","name":"build_attack_tree_prompts","line":142,"end_line":187,"hash":"4e67cb9c1146c6af49e6498a49be37c34873e0be886c2ef6c4350db99ed3ed89"}]}
# mutate4py-manifest-end
