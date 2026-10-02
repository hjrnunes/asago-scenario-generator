"""Tests for SP1 KC sub-code display in serialized YAML.

Covers KCDisp-01 through KCDisp-06 from the Gherkin feature file
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


class TestStpaWriteYamlInjection:
    """KCDisp-01 through KCDisp-06: STPA write_yaml path injects display."""

    def test_kcdisp_01_yaml_contains_kc_subcodes_display(self, tmp_path):
        """KCDisp-01: capability-profile.yaml contains kc_subcodes_display field."""
        profile = _make_profile(["KC1.1", "KCX-PRIV", "KC5.1"])
        path = write_yaml(
            profile,
            tmp_path / "capability-profile.yaml",
            post_process=inject_kc_subcodes_display,
        )
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert "kc_subcodes_display" in data

    def test_kcdisp_01_kc_subcodes_display_is_dict(self, tmp_path):
        """KCDisp-01: kc_subcodes_display is a dict."""
        profile = _make_profile(["KC1.1", "KCX-PRIV", "KC5.1"])
        path = write_yaml(
            profile,
            tmp_path / "capability-profile.yaml",
            post_process=inject_kc_subcodes_display,
        )
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert isinstance(data["kc_subcodes_display"], dict)

    def test_kcdisp_02_owasp_codes_mapped(self, tmp_path):
        """KCDisp-02: OWASP KC codes map to their descriptions."""
        profile = _make_profile(["KC1.1", "KCX-PRIV", "KC5.1"])
        path = write_yaml(
            profile,
            tmp_path / "capability-profile.yaml",
            post_process=inject_kc_subcodes_display,
        )
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        display = data["kc_subcodes_display"]
        assert display["KC1.1"] == "Large Language Model (LLM)"
        assert display["KC5.1"] == "Flexible libraries / SDK"

    def test_kcdisp_03_kcx_codes_mapped(self, tmp_path):
        """KCDisp-03: KCX extension codes map to their descriptions."""
        profile = _make_profile(["KC1.1", "KCX-PRIV", "KC5.1"])
        path = write_yaml(
            profile,
            tmp_path / "capability-profile.yaml",
            post_process=inject_kc_subcodes_display,
        )
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        display = data["kc_subcodes_display"]
        assert "privilege" in display["KCX-PRIV"].lower()

    def test_kcdisp_04_unknown_code_fallback(self, tmp_path):
        """KCDisp-04: unknown codes fall back to the code string itself."""
        profile = _make_profile(["KC1.1", "KCX-UNKNOWN"])
        path = write_yaml(
            profile,
            tmp_path / "capability-profile.yaml",
            post_process=inject_kc_subcodes_display,
        )
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        display = data["kc_subcodes_display"]
        assert display["KCX-UNKNOWN"] == "KCX-UNKNOWN"

    def test_kcdisp_05_kc_subcodes_unchanged(self, tmp_path):
        """KCDisp-05: kc_subcodes list[str] field is unchanged after serialization."""
        profile = _make_profile(["KC1.1", "KCX-PRIV", "KC5.1"])
        path = write_yaml(
            profile,
            tmp_path / "capability-profile.yaml",
            post_process=inject_kc_subcodes_display,
        )
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert "kc_subcodes" in data
        assert data["kc_subcodes"] == ["KC1.1", "KC5.1", "KCX-PRIV"]

    def test_kcdisp_06_reload_ignores_display_field(self, tmp_path):
        """KCDisp-06: reloading the YAML as CapabilityProfile ignores the extra display field."""
        profile = _make_profile(["KC1.1", "KCX-PRIV", "KC5.1"])
        path = write_yaml(
            profile,
            tmp_path / "capability-profile.yaml",
            post_process=inject_kc_subcodes_display,
        )
        loaded = read_yaml(path, CapabilityProfile)
        assert set(loaded.kc_subcodes) == {"KC1.1", "KCX-PRIV", "KC5.1"}
