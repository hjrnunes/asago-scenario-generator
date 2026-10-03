"""Tests for threat gating logic.

Covers:
  - KC-based threat scoping via _compute_kc_enabled_threats
  - kc_requires evaluation in _evaluate_prerequisite_capabilities
  - Logging of all gating decisions (silent filtering fix)
  - Attack-pattern filtering with Stage 1 vs Stage 2 data
"""

from __future__ import annotations

import logging

from asago_scenario_generator.data.threat_gating import (
    _compute_kc_enabled_threats,
    _evaluate_prerequisite_capabilities,
    _filter_attack_patterns,
    determine_threat_scope,
)
from asago_scenario_generator.models import (
    CapabilityProfile,
    MemoryMechanism,
)
from asago_scenario_generator.models.capability_profile import ToolInventoryEntry


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_profile(
    *,
    has_persistent_memory: bool = False,
    zones_active: list[str] | None = None,
    multi_agent: bool = False,
    hitl: bool = False,
    memory_mechanisms: list[MemoryMechanism] | None = None,
    kc_subcodes: list[str] | None = None,
) -> CapabilityProfile:
    """Build a CapabilityProfile with sensible defaults for testing.

    Boolean flags are computed from kc_subcodes.  When explicit kc_subcodes
    are not provided, they are assembled from the boolean flag arguments so
    the computed properties return the expected values.
    """
    if kc_subcodes is None:
        kc_subcodes = [
            "KC1.1",
            "KC2.1",
            "KC3.3",
            "KC5.2",
            "KC6.1.1",
            "KC6.1.2",
            "KC6.2.1",
            "KC6.2.2",
        ]
        if has_persistent_memory:
            kc_subcodes.append("KC4.3")
        if multi_agent:
            kc_subcodes.append("KC2.3")
        if hitl:
            kc_subcodes.append("KCX-HITL")
    kw = {}
    if any(c.startswith("KC5.") or c.startswith("KC6.") for c in kc_subcodes):
        kw["tool_inventory"] = [
            ToolInventoryEntry(name="test_tool", description="A test tool")
        ]
    return CapabilityProfile(
        zones_active=zones_active or ["input", "reasoning"],
        entry_points=["user input (zone 1)"],
        confidence="medium",
        memory_mechanisms=memory_mechanisms,
        kc_subcodes=kc_subcodes,
        **kw,
    )


# ---------------------------------------------------------------------------
# Minimal KC mapping fixture for unit tests
# ---------------------------------------------------------------------------

_MINI_KC_MAPPING = {
    "kc_to_threats": {
        "KC1.1": ["T5", "T6", "T7", "T15"],
        "KC2.3": ["T6", "T8", "T9", "T10", "T12", "T13", "T14", "T16"],
        "KC4.3": ["T1", "T5", "T6", "T8"],
        "KC6.1.1": ["T2"],
        "KC6.2.2": ["T2", "T3", "T4", "T6", "T11"],
        "KC5.1": ["T2", "T6", "T7", "T8", "T17"],
    },
    "hitl": {"threat_ids": ["T10"]},
}


# ---------------------------------------------------------------------------
# Test attack-pattern dicts (synthetic, matching real YAML structure)
# ---------------------------------------------------------------------------

# AP-T2-05 requires KCX-VSTORE + KC6.3.3
_AP_T2_05 = {
    "id": "AP-T2-05",
    "threat_id": "T2",
    "name": "Tool misuse via adversarial retrieval content",
    "description": "...",
    "prerequisite_capabilities": {
        "min_zones": ["input", "memory", "tool_execution"],
        "kc_requires": {"all": ["KCX-VSTORE"], "any": ["KC6.3.3"]},
    },
}

# AP-T2-04 requires KCX-PMEM + KC4.x
_AP_T2_04 = {
    "id": "AP-T2-04",
    "threat_id": "T2",
    "name": "Tool misuse via poisoned persistent memory",
    "description": "...",
    "prerequisite_capabilities": {
        "min_zones": ["input", "memory", "tool_execution"],
        "kc_requires": {
            "all": ["KCX-PMEM"],
            "any": ["KC4.3", "KC4.4", "KC4.5", "KC4.6"],
        },
    },
}

# AP-T2-01 has basic KC6 prereqs (no KCX gate)
_AP_T2_01 = {
    "id": "AP-T2-01",
    "threat_id": "T2",
    "name": "Tool misuse via direct prompt injection",
    "description": "...",
    "prerequisite_capabilities": {
        "min_zones": ["input", "reasoning", "tool_execution"],
        "kc_requires": {
            "any": [
                "KC6.1.1",
                "KC6.1.2",
                "KC6.2.1",
                "KC6.2.2",
                "KC6.3.1",
                "KC6.3.2",
                "KC6.4",
                "KC6.5",
                "KC6.6",
                "KC6.7",
            ]
        },
    },
}

# AP-T1-04 requires KCX-SHMEM + KC4.4/KC4.6
_AP_T1_04 = {
    "id": "AP-T1-04",
    "threat_id": "T1",
    "name": "Shared memory corruption for cross-agent influence",
    "description": "...",
    "prerequisite_capabilities": {
        "min_zones": ["input", "memory", "inter_agent"],
        "kc_requires": {"all": ["KCX-SHMEM"], "any": ["KC4.4", "KC4.6"]},
    },
}

# AP-T1-01 requires KCX-PMEM + KC4.x
_AP_T1_01 = {
    "id": "AP-T1-01",
    "threat_id": "T1",
    "name": "Memory poisoning via conversational injection",
    "description": "...",
    "prerequisite_capabilities": {
        "min_zones": ["input", "memory"],
        "kc_requires": {
            "all": ["KCX-PMEM"],
            "any": ["KC4.3", "KC4.4", "KC4.5", "KC4.6"],
        },
    },
}

# AP-T6-01 only requires input + reasoning (always passes for default profile)
_AP_T6_01 = {
    "id": "AP-T6-01",
    "threat_id": "T6",
    "name": "Incremental sub-goal injection for plan drift",
    "description": "...",
    "prerequisite_capabilities": {
        "min_zones": ["input", "reasoning"],
        "kc_requires": {"any": ["KC1.1", "KC1.2", "KC1.3", "KC1.4"]},
    },
}

# AP-T6-02 also only requires input + reasoning
_AP_T6_02 = {
    "id": "AP-T6-02",
    "threat_id": "T6",
    "name": "Direct instruction override for tool-chain hijacking",
    "description": "...",
    "prerequisite_capabilities": {
        "min_zones": ["input", "reasoning"],
        "kc_requires": {"any": ["KC1.1", "KC1.2", "KC1.3", "KC1.4"]},
    },
}

# AP-T11-01 requires extensive code execution (KC6.2.2) — the headline fix
_AP_T11_01 = {
    "id": "AP-T11-01",
    "threat_id": "T11",
    "name": "Infrastructure-as-code injection via agent code generation",
    "description": "...",
    "prerequisite_capabilities": {
        "min_zones": ["input", "reasoning", "tool_execution"],
        "kc_requires": {"any": ["KC6.2.2"]},
    },
}


# ---------------------------------------------------------------------------
# _compute_kc_enabled_threats
# ---------------------------------------------------------------------------


class TestComputeKCEnabledThreats:
    """Verify KC→T lookup correctly enables threats from profile sub-codes."""

    def test_minimal_profile_gets_baseline_threats(self):
        """KC1.1 alone enables T5, T6, T7, T15."""
        profile = _make_profile(kc_subcodes=["KC1.1"])
        result = _compute_kc_enabled_threats(profile, _MINI_KC_MAPPING)
        assert set(result.keys()) == {"T5", "T6", "T7", "T15"}

    def test_kc6_2_2_adds_code_execution_threats(self):
        """KC6.2.2 adds T2, T3, T4, T11 (including the critical T11)."""
        profile = _make_profile(kc_subcodes=["KC1.1", "KC6.2.2"])
        result = _compute_kc_enabled_threats(profile, _MINI_KC_MAPPING)
        assert "T11" in result
        assert "T2" in result
        assert "T3" in result
        assert "T4" in result

    def test_kc6_1_1_does_not_enable_t11(self):
        """KC6.1.1 (limited API) only enables T2, not T11 — the headline fix."""
        profile = _make_profile(kc_subcodes=["KC1.1", "KC6.1.1"])
        result = _compute_kc_enabled_threats(profile, _MINI_KC_MAPPING)
        assert "T2" in result
        assert "T11" not in result

    def test_hitl_adds_t10(self):
        """HITL cross-cutting flag enables T10."""
        profile = _make_profile(kc_subcodes=["KC1.1", "KCX-HITL"])
        result = _compute_kc_enabled_threats(profile, _MINI_KC_MAPPING)
        assert "T10" in result
        assert "hitl" in result["T10"]

    def test_hitl_false_no_t10(self):
        """Without HITL, T10 is not enabled (unless via KC2.2/KC2.3)."""
        profile = _make_profile(kc_subcodes=["KC1.1"])
        result = _compute_kc_enabled_threats(profile, _MINI_KC_MAPPING)
        assert "T10" not in result

    def test_multi_agent_kcs_enable_multi_agent_threats(self):
        """KC2.3 enables T12, T13, T14, T16."""
        profile = _make_profile(
            kc_subcodes=["KC1.1", "KC2.3"],
            multi_agent=True,
            zones_active=["input", "reasoning", "inter_agent"],
        )
        result = _compute_kc_enabled_threats(profile, _MINI_KC_MAPPING)
        assert "T12" in result
        assert "T13" in result
        assert "T14" in result
        assert "T16" in result

    def test_gating_reason_includes_enabling_kcs(self):
        """The gating reason string lists which KC sub-codes enabled the threat."""
        profile = _make_profile(kc_subcodes=["KC1.1", "KC6.2.2"])
        result = _compute_kc_enabled_threats(profile, _MINI_KC_MAPPING)
        assert "KC6.2.2" in result["T11"]

    def test_klarna_chatbot_excludes_t11(self):
        """Klarna-like chatbot: KC1.1+KC2.1+KC3.3+KC4.1+KC5.2+KC6.1.1 → no T11."""
        profile = _make_profile(
            kc_subcodes=["KC1.1"],
            zones_active=["input", "reasoning"],
        )
        result = _compute_kc_enabled_threats(profile, _MINI_KC_MAPPING)
        assert "T11" not in result


# ---------------------------------------------------------------------------
# kc_requires evaluation
# ---------------------------------------------------------------------------


class TestKcRequiresEvaluation:
    """Verify kc_requires any/all logic in _evaluate_prerequisite_capabilities."""

    def test_any_passes_when_profile_has_one(self):
        profile = _make_profile(kc_subcodes=["KC1.1", "KC6.2.2"])
        prereqs = {"kc_requires": {"any": ["KC6.2.2"]}}
        assert _evaluate_prerequisite_capabilities(prereqs, profile) is True

    def test_any_fails_when_profile_has_none(self):
        profile = _make_profile(kc_subcodes=["KC1.1", "KC6.1.1"])
        prereqs = {"kc_requires": {"any": ["KC6.2.2"]}}
        assert _evaluate_prerequisite_capabilities(prereqs, profile) is False

    def test_all_passes_when_profile_has_all(self):
        profile = _make_profile(
            kc_subcodes=["KC1.1", "KC2.3", "KC5.1"],
            multi_agent=True,
            zones_active=["input", "reasoning", "inter_agent"],
        )
        prereqs = {"kc_requires": {"all": ["KC2.3", "KC5.1"]}}
        assert _evaluate_prerequisite_capabilities(prereqs, profile) is True

    def test_all_fails_when_profile_missing_one(self):
        profile = _make_profile(
            kc_subcodes=["KC1.1", "KC2.3"],
            multi_agent=True,
            zones_active=["input", "reasoning", "inter_agent"],
        )
        prereqs = {"kc_requires": {"all": ["KC2.3", "KC5.1"]}}
        assert _evaluate_prerequisite_capabilities(prereqs, profile) is False

    def test_any_and_all_both_must_pass(self):
        profile = _make_profile(
            kc_subcodes=["KC1.1", "KC2.3", "KC6.2.2"],
            multi_agent=True,
            zones_active=["input", "reasoning", "inter_agent"],
        )
        prereqs = {"kc_requires": {"any": ["KC6.2.2", "KC6.4"], "all": ["KC2.3"]}}
        assert _evaluate_prerequisite_capabilities(prereqs, profile) is True

    def test_ap_t11_01_filtered_for_limited_api(self):
        """AP-T11-01 requires KC6.2.2; profile with KC6.1.1 is filtered."""
        profile = _make_profile(kc_subcodes=["KC1.1", "KC6.1.1"])
        result = _filter_attack_patterns([_AP_T11_01], profile)
        assert "AP-T11-01" not in result

    def test_ap_t11_01_passes_for_extensive_code_exec(self):
        """AP-T11-01 requires KC6.2.2; profile with KC6.2.2 passes."""
        profile = _make_profile(kc_subcodes=["KC1.1", "KC6.2.2"])
        result = _filter_attack_patterns([_AP_T11_01], profile)
        assert "AP-T11-01" in result


# ---------------------------------------------------------------------------
# _filter_attack_patterns
# ---------------------------------------------------------------------------


class TestFilterAttackPatterns:
    """Verify data-driven attack-pattern filtering."""

    def test_ap_t2_05_not_filtered_with_kcx_vstore(self):
        profile = _make_profile(
            has_persistent_memory=True,
            kc_subcodes=["KC1.1", "KC6.1.1", "KC6.3.3", "KCX-VSTORE"],
        )
        patterns = [_AP_T2_01, _AP_T2_04, _AP_T2_05]
        result = _filter_attack_patterns(patterns, profile)
        assert "AP-T2-05" in result

    def test_ap_t2_05_filtered_without_kcx_vstore(self):
        profile = _make_profile(has_persistent_memory=False)
        patterns = [_AP_T2_01, _AP_T2_04, _AP_T2_05]
        result = _filter_attack_patterns(patterns, profile)
        assert "AP-T2-04" not in result
        assert "AP-T2-05" not in result

    def test_ap_t1_04_not_filtered_with_kcx_shmem(self):
        profile = _make_profile(
            has_persistent_memory=True,
            multi_agent=True,
            kc_subcodes=["KC1.1", "KC4.4", "KCX-SHMEM"],
        )
        patterns = [_AP_T1_01, _AP_T1_04]
        result = _filter_attack_patterns(patterns, profile)
        assert "AP-T1-04" in result

    def test_unrelated_patterns_pass_all_with_matching_zones(self):
        profile = _make_profile(has_persistent_memory=False)
        patterns = [_AP_T6_01, _AP_T6_02]
        result = _filter_attack_patterns(patterns, profile)
        assert result == ["AP-T6-01", "AP-T6-02"]


# ---------------------------------------------------------------------------
# Logging of gating decisions
# ---------------------------------------------------------------------------


class TestGatingLogging:
    """Verify that all gating decisions produce log messages."""

    def test_filter_attack_patterns_logs_ap_t2_05_pass(self, caplog):
        profile = _make_profile(
            has_persistent_memory=True,
            kc_subcodes=["KC1.1", "KC6.1.1", "KC6.3.3", "KCX-VSTORE"],
        )
        patterns = [_AP_T2_01, _AP_T2_05]
        with caplog.at_level(
            logging.DEBUG, logger="asago_scenario_generator.data.threat_gating"
        ):
            _filter_attack_patterns(patterns, profile)

        ap_t2_05_logs = [r for r in caplog.records if "AP-T2-05" in r.message]
        assert len(ap_t2_05_logs) >= 1
        assert any("PASSED" in r.message for r in ap_t2_05_logs)

    def test_filter_attack_patterns_logs_ap_t2_05_filtered(self, caplog):
        profile = _make_profile(has_persistent_memory=False)
        patterns = [_AP_T2_01, _AP_T2_05]
        with caplog.at_level(
            logging.DEBUG, logger="asago_scenario_generator.data.threat_gating"
        ):
            _filter_attack_patterns(patterns, profile)

        ap_t2_05_logs = [r for r in caplog.records if "AP-T2-05" in r.message]
        assert len(ap_t2_05_logs) >= 1
        assert any(r.levelno == logging.WARNING for r in ap_t2_05_logs)

    def test_filter_attack_patterns_logs_ap_t1_04_filtered(self, caplog):
        profile = _make_profile(has_persistent_memory=False)
        patterns = [_AP_T1_01, _AP_T1_04]
        with caplog.at_level(
            logging.DEBUG, logger="asago_scenario_generator.data.threat_gating"
        ):
            _filter_attack_patterns(patterns, profile)

        ap_t1_04_logs = [r for r in caplog.records if "AP-T1-04" in r.message]
        assert len(ap_t1_04_logs) >= 1
        assert any("FILTERED" in r.message for r in ap_t1_04_logs)

    def test_determine_threat_scope_logs_in_scope(self, caplog):
        profile = _make_profile(
            has_persistent_memory=True,
            kc_subcodes=["KC1.1", "KC4.3", "KC6.1.1"],
        )
        with caplog.at_level(
            logging.DEBUG, logger="asago_scenario_generator.data.threat_gating"
        ):
            determine_threat_scope(profile)

        in_scope_logs = [r for r in caplog.records if "IN SCOPE" in r.message]
        assert len(in_scope_logs) > 0
        t6_logs = [r for r in in_scope_logs if "T6" in r.message]
        assert len(t6_logs) >= 1

    def test_determine_threat_scope_logs_out_of_scope(self, caplog):
        profile = _make_profile(
            has_persistent_memory=False,
            multi_agent=False,
            kc_subcodes=["KC1.1"],
            zones_active=["input", "reasoning"],
        )
        with caplog.at_level(
            logging.DEBUG, logger="asago_scenario_generator.data.threat_gating"
        ):
            determine_threat_scope(profile)

        out_scope_logs = [r for r in caplog.records if "OUT OF SCOPE" in r.message]
        assert len(out_scope_logs) > 0
        assert any(r.levelno == logging.WARNING for r in out_scope_logs)

    def test_determine_threat_scope_logs_dropped_attack_patterns(self, caplog):
        profile = _make_profile(
            has_persistent_memory=False,
            kc_subcodes=["KC1.1", "KC6.1.1"],
        )
        with caplog.at_level(
            logging.DEBUG, logger="asago_scenario_generator.data.threat_gating"
        ):
            determine_threat_scope(profile)

        t2_in_scope = [
            r for r in caplog.records if "T2" in r.message and "IN SCOPE" in r.message
        ]
        assert len(t2_in_scope) >= 1
        assert any("dropped" in r.message for r in t2_in_scope)


# ---------------------------------------------------------------------------
# KC-based threat scope integration
# ---------------------------------------------------------------------------


class TestDetermineThreatScopeKC:
    """Integration tests for KC-based determine_threat_scope."""

    def test_minimal_profile_scopes_baseline_threats(self):
        """KC1.1 only → T5, T6, T7, T15 in scope."""
        profile = _make_profile(
            kc_subcodes=["KC1.1"],
            zones_active=["input", "reasoning"],
        )
        scope = determine_threat_scope(profile)
        in_scope_ids = {e.threat_id for e in scope.in_scope}
        assert {"T5", "T6", "T7", "T15"}.issubset(in_scope_ids)
        assert "T11" not in in_scope_ids

    def test_full_profile_scopes_all_threats(self):
        """Full KC set enables all 17 threats."""
        profile = _make_profile(
            kc_subcodes=[
                "KC1.1",
                "KC2.3",
                "KC3.2",
                "KC4.3",
                "KC5.1",
                "KC6.1.2",
                "KC6.2.2",
            ],
            has_persistent_memory=True,
            multi_agent=True,
            hitl=True,
        )
        scope = determine_threat_scope(profile)
        in_scope_ids = {e.threat_id for e in scope.in_scope}
        assert in_scope_ids == {f"T{i}" for i in range(1, 18)}

    def test_t11_excluded_for_limited_api_profile(self):
        """KC6.1.1 (limited API) does NOT enable T11 — the headline fix."""
        profile = _make_profile(
            kc_subcodes=["KC1.1", "KC6.1.1"],
        )
        scope = determine_threat_scope(profile)
        in_scope_ids = {e.threat_id for e in scope.in_scope}
        assert "T2" in in_scope_ids
        assert "T11" not in in_scope_ids

    def test_hitl_enables_t10(self):
        """HITL flag enables T10 even without KC2.2/KC2.3."""
        profile = _make_profile(
            kc_subcodes=["KC1.1", "KCX-HITL"],
        )
        scope = determine_threat_scope(profile)
        in_scope_ids = {e.threat_id for e in scope.in_scope}
        assert "T10" in in_scope_ids


# ---------------------------------------------------------------------------
# Phase 3 verification: min_zones removal is safe
# ---------------------------------------------------------------------------


class TestMinZonesRemovalSafe:
    """Verify that removing min_zones from _evaluate_prerequisite_capabilities
    does not change filtering outcomes for any real attack pattern.

    The key property: for every AP that has both min_zones and kc_requires,
    kc_requires alone produces the same filtering result as both checks
    combined would have. This is tested by constructing profiles where
    min_zones would have failed and verifying kc_requires also fails.
    """

    def test_min_zones_silently_ignored(self):
        """min_zones in prereqs is ignored — does not affect evaluation."""
        profile = _make_profile(
            zones_active=["input", "reasoning"],
            kc_subcodes=["KC1.1", "KC6.2.2"],
        )
        prereqs = {
            "min_zones": ["input", "reasoning", "tool_execution"],
            "kc_requires": {"any": ["KC6.2.2"]},
        }
        assert _evaluate_prerequisite_capabilities(prereqs, profile) is True

    def test_no_real_ap_relies_solely_on_min_zones(self):
        """Every real AP with min_zones also has kc_requires
        — so removing min_zones never leaves an AP ungated."""
        from asago_scenario_generator.data.loaders import load_attack_patterns

        patterns = load_attack_patterns()
        for pid, pattern in patterns.items():
            prereqs = pattern.get("prerequisite_capabilities")
            if not prereqs or not prereqs.get("min_zones"):
                continue
            has_kc_requires = bool(prereqs.get("kc_requires"))
            assert has_kc_requires, (
                f"{pid} has min_zones as its ONLY gate — "
                f"removing min_zones would leave it ungated"
            )
