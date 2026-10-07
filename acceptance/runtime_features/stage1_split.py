"""Acceptance step handlers for the stage1_split feature group."""

from __future__ import annotations

from runtime_shared import (
    Path,
    World,
    re,
)
from asago_scenario_generator.stpa.system_model import PROMPTS_DIR
from registry import StepTable

step = StepTable()


@step("the prompts directory does not contain")
def _h_stage1_prompts_not_contains(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the prompts directory does not contain `X.j2`.

    Also verifies (case-sensitive) that the template name is a recognized
    retired template, so that Gherkin value mutations that change the
    example cell to a nonsense name — which is also absent — are killed
    rather than silently surviving.
    """
    _KNOWN_RETIRED_TEMPLATES = frozenset(
        {
            "stage1a_system.j2",
            "stage1a_user.j2",
            "stage2_call2_system.j2",
            "stage2_call2_user.j2",
        }
    )
    m = re.search(r"does not contain `([^`]+)`", text)
    if not m:
        return False, f"Could not parse template name from: {text}"
    tmpl = m.group(1)
    path = PROMPTS_DIR / tmpl
    if path.exists():
        return False, f"Template {tmpl} exists in prompts directory (expected absent)"
    if tmpl not in _KNOWN_RETIRED_TEMPLATES:
        return False, f"Template name '{tmpl}' is not a recognized retired template"
    return True, ""


@step("the prompts directory contains")
def _h_stage1_prompts_contains(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the prompts directory contains `X.j2`.

    Uses a case-sensitive directory listing to kill Gherkin value
    mutations that change the template name casing. On macOS,
    path.exists() is case-insensitive, so we must explicitly verify
    the filename matches exactly.
    """
    m = re.search(r"contains `([^`]+)`", text)
    if not m:
        return False, f"Could not parse template name from: {text}"
    tmpl = m.group(1)
    path = PROMPTS_DIR / tmpl
    if not path.exists():
        return False, f"Template {tmpl} not found in prompts directory"
    # Case-sensitive check: verify the actual filename matches exactly.
    # macOS APFS is case-insensitive but case-preserving, so iterdir()
    # returns the real on-disk spelling.
    actual_names = {f.name for f in PROMPTS_DIR.iterdir() if f.is_file()}
    if tmpl not in actual_names:
        return False, f"Template '{tmpl}' not found (case mismatch)"
    return True, ""


@step("the `Stage1Profile` model does not declare")
def _h_stage1_model_no_declare(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    m = re.search(r"does not declare `([^`]+)`", text)
    if not m:
        return False, f"Could not parse field name from: {text}"
    field_name = m.group(1)
    profile_model_path = (
        next(
            p
            for p in Path(__file__).resolve().parents
            if (p / "pyproject.toml").is_file()
        )
        / "src"
        / "asago_scenario_generator"
        / "models"
        / "capability_profile.py"
    )
    src = profile_model_path.read_text(encoding="utf-8")
    # Extract the Stage1Profile class body
    match = re.search(
        r"class Stage1Profile\(BaseModel\):(.*?)(?=\nclass |\Z)",
        src,
        re.DOTALL,
    )
    if not match:
        return False, "Could not locate Stage1Profile class definition"
    class_body = match.group(1)
    decl_pattern = rf"^\s*{re.escape(field_name)}\s*:\s*bool\s*=\s*Field"
    found = bool(re.search(decl_pattern, class_body, re.MULTILINE))
    if found:
        return False, f"Stage1Profile declares '{field_name}' as a bool Field"
    return True, ""


_PROMPT_TEMPLATE_CHECK = re.compile(
    r"template `([^`]+\.j2)` (contains|does not contain)(?: the text)? `([^`]+)`"
)


@step("the prompt template .* (?:contains|does not contain)")
def _h_prompt_template_contains(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    m = _PROMPT_TEMPLATE_CHECK.search(text)
    if not m:
        return False, f"Could not parse from: {text}"
    tmpl_name, verb, needle = m.groups()
    path = PROMPTS_DIR / tmpl_name
    if not path.exists():
        return False, f"Template {tmpl_name} not found"
    present = needle in path.read_text(encoding="utf-8")
    if verb == "contains" and not present:
        return False, f"Template {tmpl_name} does not contain '{needle}'"
    if verb != "contains" and present:
        return False, f"Template {tmpl_name} contains '{needle}' (expected absent)"
    return True, ""


FEATURE_ID = "stage1_split"


register = step.register


__all__ = ["FEATURE_ID", "register"]
