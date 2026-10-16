"""Tests for SP1 KC sub-code display in serialized YAML.

Covers the KCDisp scenarios from the Gherkin feature file
sp1_kc_subcode_display.feature.
"""

from __future__ import annotations

import yaml

from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    build_kc_subcodes_display,
    inject_kc_subcodes_display,
    KC_SUBCODE_NAMES,
    KCX_SUBCODES,
)
from asago_scenario_generator.stpa.infra.yaml_io import write_yaml, read_yaml


def _make_profile(kc_subcodes: list[str]) -> CapabilityProfile:
    """Build a minimal valid CapabilityProfile with the given kc_subcodes."""
    return CapabilityProfile(
        zones_active=["input", "reasoning", "tool_execution"],
        entry_points=[{"name": "user prompt", "direction": "input"}],
        confidence="high",
        kc_subcodes=kc_subcodes,
        tool_inventory=[{"name": "search", "description": "Search tool"}],
    )


class TestBuildKcSubcodesDisplay:
    """Unit tests for the build_kc_subcodes_display helper."""

    def test_owasp_codes_map_to_kc_subcode_names(self):
        """OWASP KC codes map to their descriptions from KC_SUBCODE_NAMES."""
        result = build_kc_subcodes_display(["KC1.1", "KC5.1"])
        assert result["KC1.1"] == KC_SUBCODE_NAMES["KC1.1"]
        assert result["KC5.1"] == KC_SUBCODE_NAMES["KC5.1"]

    def test_kcx_extension_codes_map_to_kcx_subcodes(self):
        """KCX extension codes map to their descriptions from KCX_SUBCODES."""
        result = build_kc_subcodes_display(["KCX-PRIV"])
        assert result["KCX-PRIV"] == KCX_SUBCODES["KCX-PRIV"]
        assert "privilege" in result["KCX-PRIV"].lower()

    def test_unknown_codes_fall_back_to_code_string(self):
        """Unknown codes fall back to the code string itself."""
        result = build_kc_subcodes_display(["KCX-UNKNOWN"])
        assert result["KCX-UNKNOWN"] == "KCX-UNKNOWN"

    def test_mixed_codes_all_present(self):
        """A mix of OWASP, KCX, and unknown codes all appear in the dict."""
        result = build_kc_subcodes_display(["KC1.1", "KCX-PRIV", "KCX-UNKNOWN"])
        assert set(result.keys()) == {"KC1.1", "KCX-PRIV", "KCX-UNKNOWN"}

    def test_empty_list_returns_empty_dict(self):
        """An empty kc_subcodes list produces an empty display dict."""
        assert build_kc_subcodes_display([]) == {}

    def test_inject_without_kc_subcodes_is_noop(self):
        """A dict without kc_subcodes gets no display field."""
        assert inject_kc_subcodes_display({"zones_active": []}) == {"zones_active": []}


class TestStpaWriteYamlInjection:
    """write_yaml with the injection hook adds the display field to the YAML."""

    def test_written_yaml_carries_display_and_reloads_without_it(self, tmp_path):
        profile = _make_profile(["KC1.1", "KCX-PRIV", "KC5.1"])
        path = write_yaml(
            profile,
            tmp_path / "capability-profile.yaml",
            post_process=inject_kc_subcodes_display,
        )
        data = yaml.safe_load(path.read_text(encoding="utf-8"))

        assert "kc_subcodes_display" in data
        display = data["kc_subcodes_display"]
        assert isinstance(display, dict)
        assert display["KC1.1"] == "Large Language Model (LLM)"
        assert display["KC5.1"] == "Flexible libraries / SDK"
        assert "privilege" in display["KCX-PRIV"].lower()

        assert "kc_subcodes" in data
        assert data["kc_subcodes"] == ["KC1.1", "KC5.1", "KCX-PRIV"]

        loaded = read_yaml(path, CapabilityProfile)
        assert set(loaded.kc_subcodes) == {"KC1.1", "KCX-PRIV", "KC5.1"}
