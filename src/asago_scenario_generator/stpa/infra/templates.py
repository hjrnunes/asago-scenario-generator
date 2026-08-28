"""Parameterized Jinja2 template loader for the STPA pipeline — clean copy.

Unlike the existing ``asago_scenario_generator.prompts`` module which hardcodes the
prompts directory, this loader accepts a ``Path`` so each STPA sub-project
can pass its own ``prompts/`` directory.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import jinja2


class TemplateLoader:
    """Jinja2 template loader bound to a specific prompts directory.

    Args:
        prompts_dir: Directory containing ``.j2`` template files.
    """

    def __init__(self, prompts_dir: Path) -> None:
        self.prompts_dir = Path(prompts_dir).resolve()
        self._env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(str(self.prompts_dir)),
            keep_trailing_newline=True,
            undefined=jinja2.StrictUndefined,
        )

    def render_prompt(self, template_name: str, **kwargs: object) -> str:
        """Render a Jinja2 template with the given variables.

        Args:
            template_name: Filename of the template (e.g. ``"call0_system.j2"``).
            **kwargs: Template variables.

        Returns:
            The rendered prompt string.
        """
        template = self._env.get_template(template_name)
        return template.render(**kwargs)

    def hash_prompt_templates(self) -> dict[str, str]:
        """Return SHA-256 hashes for every ``.j2`` file in the prompts directory.

        Returns:
            Dict mapping template filename to its 64-character hex digest.
        """
        hashes: dict[str, str] = {}
        for path in sorted(self.prompts_dir.glob("*.j2")):
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            hashes[path.name] = digest
        return hashes


def hash_prompt_templates(prompts_dir: Path) -> dict[str, str]:
    """Return SHA-256 hashes for every ``.j2`` file in *prompts_dir*.

    Args:
        prompts_dir: Directory containing ``.j2`` template files.

    Returns:
        Dict mapping template filename to its 64-character hex digest.
    """
    return TemplateLoader(prompts_dir).hash_prompt_templates()
