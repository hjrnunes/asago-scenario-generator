"""Tests for entry point identification in stage1b_system.j2 — revised for KC-driven approach.

The old 5-category entry point checklist was replaced with a KC-driven
approach. These tests verify the new structure: KC taxonomy drives entry
point identification, the rigid checklist is absent, and KC-based examples
are present.
"""

from __future__ import annotations

from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR


def _load_template_text() -> str:
    """Load the raw text of stage1b_system.j2."""
    path = PROMPTS_DIR / "stage1b_system.j2"
    return path.read_text(encoding="utf-8")


class TestEntryPointIdentification:
    """Verify the revised stage1b_system.j2 entry point section."""

    def test_template_contains_entry_point_section(self):
        """The template contains an Entry Points section."""
        text = _load_template_text()
        assert "## Entry Points" in text

    def test_template_does_not_contain_checklist(self):
        """The template does not contain the old entry point category checklist."""
        text = _load_template_text()
        assert "Entry point category checklist" not in text
        assert "User input surfaces" not in text

    def test_template_uses_kc_driven_examples(self):
        """The template uses KC codes to illustrate entry point identification."""
        text = _load_template_text()
        assert "KC6.3.3" in text  # RAG example
        assert "KC6.1.2" in text  # API example
        assert "KC4.3" in text  # cross-session memory example
        assert "KC2.3" in text  # multi-agent example

    def test_template_preserves_dual_listing_note(self):
        """The template notes a component can appear in both inventories."""
        text = _load_template_text()
        assert "both" in text.lower()
        assert "tool_inventory" in text
        assert "entry_points" in text

    def test_template_does_not_contain_old_categories(self):
        """None of the old 5-category names are present."""
        text = _load_template_text()
        for old_category in (
            "RAG/retrieval data sources",
            "Tool execution results",
            "External data feeds",
            "Admin/config interfaces",
        ):
            assert old_category not in text, (
                f"Old category still present: {old_category}"
            )

    def test_template_does_not_have_schneider_zones_section(self):
        """The template does not have the old Schneider zones section."""
        text = _load_template_text()
        assert "## Schneider zones" not in text

    def test_template_does_not_have_emphasis_section(self):
        """The template does not have the old Emphasis section."""
        text = _load_template_text()
        assert "## Emphasis" not in text

    def test_template_has_rules_section(self):
        """The template has a Rules section with grounding instructions."""
        text = _load_template_text()
        assert "## Rules" in text
        assert "Grounding" in text
