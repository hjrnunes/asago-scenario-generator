"""Tests for STPA infra template loader (InfraTemplates-01 through InfraTemplates-04)."""

from __future__ import annotations

import hashlib

import jinja2
import pytest

from asago_scenario_generator.stpa.infra.templates import (
    TemplateLoader,
    hash_prompt_templates,
)


class TestInfraTemplates:
    """Parameterized Jinja2 template loader."""

    def test_templates_01_accepts_custom_prompts_dir(self, tmp_path):
        """InfraTemplates-01: loader accepts a custom prompts directory."""
        prompts_dir = tmp_path / "prompts"
        prompts_dir.mkdir()
        (prompts_dir / "test.j2").write_text("Hello {{ name }}!")
        loader = TemplateLoader(prompts_dir)
        rendered = loader.render_prompt("test.j2", name="World")
        assert "World" in rendered

    def test_templates_02_hash_returns_sha256_hashes(self, tmp_path):
        """InfraTemplates-02: hash_prompt_templates returns SHA-256 hashes."""
        prompts_dir = tmp_path / "prompts"
        prompts_dir.mkdir()
        (prompts_dir / "a.j2").write_text("template A")
        (prompts_dir / "b.j2").write_text("template B")
        hashes = hash_prompt_templates(prompts_dir)
        assert "a.j2" in hashes
        assert "b.j2" in hashes
        assert len(hashes["a.j2"]) == 64
        assert len(hashes["b.j2"]) == 64
        # Verify the hash is correct
        expected = hashlib.sha256((prompts_dir / "a.j2").read_bytes()).hexdigest()
        assert hashes["a.j2"] == expected

    def test_templates_03_undefined_variable_raises(self, tmp_path):
        """InfraTemplates-03: undefined template variable raises error."""
        prompts_dir = tmp_path / "prompts"
        prompts_dir.mkdir()
        (prompts_dir / "test.j2").write_text("Hello {{ name }}!")
        loader = TemplateLoader(prompts_dir)
        with pytest.raises(jinja2.exceptions.UndefinedError):
            loader.render_prompt("test.j2")

    def test_templates_04_independent_of_existing_pipeline(self, tmp_path):
        """InfraTemplates-04: loader does not reference the existing pipeline prompts."""
        prompts_dir = tmp_path / "stpa_prompts"
        prompts_dir.mkdir()
        (prompts_dir / "test.j2").write_text("{{ msg }}")
        loader = TemplateLoader(prompts_dir)
        # The loader's prompts_dir should be the one we passed, not the
        # existing pipeline's data/prompts directory
        assert loader.prompts_dir == prompts_dir.resolve()
        assert "data" not in str(loader.prompts_dir) or "stpa_prompts" in str(
            loader.prompts_dir
        )
        # Should be able to render our template
        result = loader.render_prompt("test.j2", msg="ok")
        assert result == "ok"

    def test_templates_05_keeps_trailing_newline(self, tmp_path):
        """InfraTemplates-05: loader preserves trailing newline in templates."""
        prompts_dir = tmp_path / "prompts"
        prompts_dir.mkdir()
        (prompts_dir / "test.j2").write_text("Hello {{ name }}!\n")
        loader = TemplateLoader(prompts_dir)
        rendered = loader.render_prompt("test.j2", name="World")
        assert rendered == "Hello World!\n"
