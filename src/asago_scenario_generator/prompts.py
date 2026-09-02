"""Jinja2 prompt template loader for asago-scenario-generator LLM prompts."""

from __future__ import annotations

import hashlib
from pathlib import Path

import jinja2

_PROMPTS_DIR = Path(__file__).resolve().parent / "data" / "prompts"

_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(str(_PROMPTS_DIR)),
    keep_trailing_newline=True,
    undefined=jinja2.StrictUndefined,
)


def render_prompt(template_name: str, **kwargs: object) -> str:
    """Render a Jinja2 prompt template with the given variables.

    Args:
        template_name: Filename of the template (e.g. ``"filter_system.j2"``).
        **kwargs: Template variables.

    Returns:
        The rendered prompt string.
    """
    template = _env.get_template(template_name)
    return template.render(**kwargs)


def hash_prompt_templates() -> dict[str, str]:
    """Return SHA-256 hashes for every ``.j2`` file in the prompts directory.

    Returns:
        Dict mapping template filename to its hex digest.
    """
    hashes: dict[str, str] = {}
    for path in sorted(_PROMPTS_DIR.glob("*.j2")):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        hashes[path.name] = digest
    return hashes
