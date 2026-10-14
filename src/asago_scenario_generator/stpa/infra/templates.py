"""Parameterized Jinja2 template loader for the STPA pipeline — clean copy.

The loader accepts a ``Path`` so each STPA sub-project can pass its own
``prompts/`` directory.
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
        """Return SHA-256 hashes for every ``.j2`` file under the prompts directory.

        Templates in subfolders count too, so a change to any template a
        prompt can include or render shows in the recorded hashes.

        Returns:
            Dict mapping each template's ``/``-separated path from the prompts
            directory (``a.j2``, ``prose/b.j2``) to its 64-character hex digest,
            in path order.
        """
        paths = {
            path.relative_to(self.prompts_dir).as_posix(): path
            for path in self.prompts_dir.rglob("*.j2")
            if path.is_file()
        }
        return {
            name: hashlib.sha256(paths[name].read_bytes()).hexdigest()
            for name in sorted(paths)
        }


def hash_prompt_templates(prompts_dir: Path) -> dict[str, str]:
    """Return SHA-256 hashes for every ``.j2`` file under *prompts_dir*.

    Args:
        prompts_dir: Directory containing ``.j2`` template files.

    Returns:
        Dict mapping each template's path from *prompts_dir* to its digest.
    """
    return TemplateLoader(prompts_dir).hash_prompt_templates()
