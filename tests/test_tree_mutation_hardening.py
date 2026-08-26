"""Mutation hardening tests for tree.py.

Targets surviving mutants identified by mutate4py on the attack-tree
generation helpers in ``src/asago_scenario_generator/pipeline/generate/tree.py``.
Tests use ``SimpleNamespace`` stand-ins so private functions can be exercised
without the full pydantic construction cost and validator friction, while
still driving the exact branch conditions (None vs non-None, boundary
comparisons, and/or logic) that the surviving mutants flip.
"""

from __future__ import annotations

import logging
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from asago_scenario_generator.models.attack_tree import GateType
from asago_scenario_generator.models.scenario import (
    ActorAccessProvenance,
    ActorProfile,
)
from asago_scenario_generator.pipeline.generate.tree import (
    _access_provenance_block_text,
    _actor_section_text,
    _architecture_section_text,
    _build_tree_skeleton,
    _call_attack_tree_once,
    _collect_threat_ids_from_tree,
    _compile_tree_response,
    _constrain_zone_to_technique,
    _ensure_accessible_pinned_entry,
    _entry_points_for_template,
    _external_integrations_for,
    _format_skeleton_yaml,
    _humanized_projection_value,
    _match_zone_for_technique,
    _resolve_action_ids_node,
    _resolve_initial_ingress_action,
    _resolve_integration_interaction_action,
    _resolve_tool_invocation_action,
    _resolve_tool_invocation_integration,
    _semantic_draft_flow,
    _skeleton_and_section,
    _technique_count_for,
    _tool_inventory_for,
    _validate_and_postprocess_tree,
    _validate_mandatory_leaves,
    _warn_dominant_threat_id_crossref,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mk_node(
    *,
    threat_id: str | None = None,
    children: list | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(threat_id=threat_id, children=children)


def _mk_tree(root: SimpleNamespace) -> SimpleNamespace:
    return SimpleNamespace(root=root)


def _mk_step(
    *,
    action: str = "",
    effect: str = "",
    zone: str = "input",
) -> SimpleNamespace:
    return SimpleNamespace(action=action, effect=effect, zone=zone)


def _mk_narrative(
    *,
    steps: list[SimpleNamespace] | None = None,
    zone_sequence: list[str] | None = None,
    entry_point: str = "user prompts",
) -> SimpleNamespace:
    if steps is None:
        steps = [_mk_step()]
    if zone_sequence is None:
        zone_sequence = ["input"]
    return SimpleNamespace(
        steps=steps,
        zone_sequence=zone_sequence,
        entry_point=entry_point,
    )


def _mk_profile(
    *,
    zones_active: list[str] | None = None,
    entry_points: list | None = None,
    tool_inventory: list | None = None,
    external_integrations: list | None = None,
    entry_point_name_to_id: dict[str, str] | None = None,
    tool_name_to_id: dict[str, str] | None = None,
    integration_name_to_id: dict[str, str] | None = None,
    resolve_entry_point_map: dict[str, object] | None = None,
    resolve_tool_map: dict[str, object] | None = None,
    resolve_integration_map: dict[str, object] | None = None,
) -> SimpleNamespace:
    """Minimal CapabilityProfile stand-in for tree.py helpers."""
    if zones_active is None:
        zones_active = ["input", "reasoning"]
    if entry_points is None:
        entry_points = []
    if tool_inventory is None:
        tool_inventory = []
    if external_integrations is None:
        external_integrations = []
    if entry_point_name_to_id is None:
        entry_point_name_to_id = {}
    if tool_name_to_id is None:
        tool_name_to_id = {}
    if integration_name_to_id is None:
        integration_name_to_id = {}
    if resolve_entry_point_map is None:
        resolve_entry_point_map = {}
    if resolve_tool_map is None:
        resolve_tool_map = {}
    if resolve_integration_map is None:
        resolve_integration_map = {}

    return SimpleNamespace(
        zones_active=zones_active,
        entry_points=entry_points,
        tool_inventory=tool_inventory,
        external_integrations=external_integrations,
        entry_point_name_to_id=lambda: entry_point_name_to_id,
        tool_name_to_id=lambda: tool_name_to_id,
        integration_name_to_id=lambda: integration_name_to_id,
        resolve_entry_point=lambda eid: resolve_entry_point_map.get(eid),
        resolve_tool=lambda tid: resolve_tool_map.get(tid),
        resolve_integration=lambda iid: resolve_integration_map.get(iid),
    )


def _mk_action(
    kind: str = "initial_ingress",
    **kw,
) -> SimpleNamespace:
    return SimpleNamespace(kind=kind, **kw)


# ---------------------------------------------------------------------------
# 1. _warn_dominant_threat_id_crossref
# ---------------------------------------------------------------------------


class TestWarnDominantThreatIdCrossref:
    """Kill mutants in the dominant threat_id cross-ref warning."""

    def test_warns_when_dominant_differs_from_parent(self, caplog):
        """ratio > 0.5 and dominant_id != parent → warning emitted."""
        # 3 nodes, 2 tagged T2, parent is T1 → ratio 2/3 > 0.5, T2 != T1
        root = _mk_node(
            threat_id="T2",
            children=[
                _mk_node(threat_id="T2"),
                _mk_node(threat_id="T1"),
            ],
        )
        tree = _mk_tree(root)
        with caplog.at_level(logging.WARNING):
            _warn_dominant_threat_id_crossref(tree, "T1", "AP-T1-01")
        assert any("T2" in r.message and "T1" in r.message for r in caplog.records)

    def test_no_warn_when_dominant_equals_parent(self, caplog):
        """ratio > 0.5 but dominant_id == parent → no warning.

        Kills ``dominant_id != parent_threat_id -> ==``: the mutant would
        warn here (== becomes True).
        """
        root = _mk_node(
            threat_id="T1",
            children=[
                _mk_node(threat_id="T1"),
                _mk_node(threat_id="T2"),
            ],
        )
        tree = _mk_tree(root)
        with caplog.at_level(logging.WARNING):
            _warn_dominant_threat_id_crossref(tree, "T1", "AP-T1-01")
        assert not caplog.records

    def test_no_warn_when_ratio_exactly_half(self, caplog):
        """ratio == 0.5 → no warning (boundary: > not >=).

        Kills ``ratio > 0.5 -> >= 0.5``: the mutant would warn here.
        """
        # 2 nodes, 1 tagged T2 → ratio 1/2 = 0.5, T2 != T1
        root = _mk_node(
            threat_id="T2",
            children=[_mk_node(threat_id="T1")],
        )
        tree = _mk_tree(root)
        with caplog.at_level(logging.WARNING):
            _warn_dominant_threat_id_crossref(tree, "T1", "AP-T1-01")
        assert not caplog.records

    def test_no_warn_when_ratio_le_half_and_dominant_differs(self, caplog):
        """ratio <= 0.5 and dominant_id != parent → no warning (and logic).

        Kills ``ratio > 0.5 and ... -> or ...``: the mutant would warn here
        because dominant_id != parent is True even though ratio <= 0.5.
        """
        # 4 nodes: T2, T1, T3, T4 → dominant T2 count 1, ratio 1/4 = 0.25
        root = _mk_node(
            threat_id="T2",
            children=[
                _mk_node(threat_id="T1"),
                _mk_node(threat_id="T3"),
                _mk_node(threat_id="T4"),
            ],
        )
        tree = _mk_tree(root)
        with caplog.at_level(logging.WARNING):
            _warn_dominant_threat_id_crossref(tree, "T1", "AP-T1-01")
        assert not caplog.records

    def test_no_warn_when_all_threat_ids_none(self, caplog):
        """All threat_ids None → early return, no crash.

        Kills ``tid is not None -> is None``: the mutant would collect only
        None values, then Counter(None...) and crash or behave differently.
        """
        root = _mk_node(
            threat_id=None,
            children=[_mk_node(threat_id=None)],
        )
        tree = _mk_tree(root)
        with caplog.at_level(logging.WARNING):
            _warn_dominant_threat_id_crossref(tree, "T1", "AP-T1-01")
        assert not caplog.records

    def test_mixed_null_and_non_null_ids(self, caplog):
        """Mix of None and non-None threat_ids → only non-None counted.

        Kills ``tid is not None -> is None``: the mutant would collect only
        the None values, making non_null_ids contain None entries, which
        changes the Counter and ratio computation.
        """
        # 3 nodes: T2, None, None → non_null_ids = [T2], ratio = 1.0
        root = _mk_node(
            threat_id="T2",
            children=[
                _mk_node(threat_id=None),
                _mk_node(threat_id=None),
            ],
        )
        tree = _mk_tree(root)
        with caplog.at_level(logging.WARNING):
            _warn_dominant_threat_id_crossref(tree, "T1", "AP-T1-01")
        # T2 is dominant with ratio 1.0 > 0.5 and T2 != T1 → should warn
        assert any("T2" in r.message for r in caplog.records)

    def test_most_common_gets_dominant_not_second(self, caplog):
        """most_common(1)[0] returns the most common, not second.

        Kills ``1 -> 0`` in most_common(1): if 0, most_common(0) returns []
        and [0] raises IndexError.
        Kills ``0 -> 1`` in [0] index: if [1], gets second most common.
        """
        # T2 appears 3 times, T1 appears 1 time → dominant is T2
        root = _mk_node(
            threat_id="T2",
            children=[
                _mk_node(threat_id="T2"),
                _mk_node(threat_id="T2"),
                _mk_node(threat_id="T1"),
            ],
        )
        tree = _mk_tree(root)
        with caplog.at_level(logging.WARNING):
            _warn_dominant_threat_id_crossref(tree, "T1", "AP-T1-01")
        # Should warn about T2 (the dominant), not T1
        assert any("T2" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# 2. _match_zone_for_technique
# ---------------------------------------------------------------------------


class TestMatchZoneForTechnique:
    """Kill mutants in the zone-matching helper."""

    def test_matches_by_technique_id(self):
        """tid_lower in haystack → returns that step's zone.

        Kills ``tid_lower in haystack -> not in``.
        """
        narrative = _mk_narrative(
            steps=[
                _mk_step(action="some other action", effect="no match", zone="reasoning"),
                _mk_step(action="uses AML.T0054 here", effect="done", zone="input"),
            ]
        )
        result = _match_zone_for_technique(narrative, "AML.T0054", "LLM Jailbreak", "fallback")
        assert result == "input"

    def test_matches_by_technique_name(self):
        """tname_lower in haystack → returns that step's zone.

        Kills ``tname_lower in haystack -> not in``.
        """
        narrative = _mk_narrative(
            steps=[
                _mk_step(action="perform LLM Jailbreak", effect="success", zone="reasoning"),
            ]
        )
        result = _match_zone_for_technique(narrative, "AML.T0054", "LLM Jailbreak", "fallback")
        assert result == "reasoning"

    def test_or_logic_tid_only_match(self):
        """Only tid matches (not tname) → still returns zone (or logic).

        Kills ``or -> and``: with `and`, both tid and tname must match.
        """
        narrative = _mk_narrative(
            steps=[
                _mk_step(action="uses AML.T0054", effect="no name here", zone="input"),
            ]
        )
        result = _match_zone_for_technique(narrative, "AML.T0054", "LLM Jailbreak", "fallback")
        assert result == "input"

    def test_or_logic_tname_only_match(self):
        """Only tname matches (not tid) → still returns zone (or logic).

        Kills ``or -> and``: with `and`, both must match.
        """
        narrative = _mk_narrative(
            steps=[
                _mk_step(action="perform jailbreak", effect="LLM Jailbreak effect", zone="reasoning"),
            ]
        )
        result = _match_zone_for_technique(narrative, "AML.T0054", "LLM Jailbreak", "fallback")
        assert result == "reasoning"

    def test_fallback_when_no_match(self):
        """No match → returns fallback zone."""
        narrative = _mk_narrative(
            steps=[_mk_step(action="unrelated", effect="unrelated", zone="input")]
        )
        result = _match_zone_for_technique(narrative, "AML.T0054", "LLM Jailbreak", "fallback_zone")
        assert result == "fallback_zone"


# ---------------------------------------------------------------------------
# 3. _constrain_zone_to_technique
# ---------------------------------------------------------------------------


class TestConstrainZoneToTechnique:
    """Kill mutants in the zone-constraint helper."""

    def test_invalid_zone_replaced_by_min(self):
        """Zone not in valid_zones → returns min(valid_zones).

        Kills ``valid_zones is not None -> is None``: mutant skips the
        check and returns the invalid zone.
        Kills ``and -> or``: mutant always returns min even for valid zones.
        """
        # AML.T0054 valid zones: {"input", "reasoning"}
        result = _constrain_zone_to_technique("tool_execution", "AML.T0054")
        assert result == "input"  # min of {"input", "reasoning"}

    def test_valid_zone_kept(self):
        """Zone in valid_zones → returns zone unchanged.

        Kills ``zone not in valid_zones -> in valid_zones``: mutant would
        return min(valid_zones) for a valid zone.
        Kills ``and -> or``: mutant would always return min.
        """
        result = _constrain_zone_to_technique("reasoning", "AML.T0054")
        assert result == "reasoning"

    def test_no_constraint_returns_zone(self):
        """Technique with no zone constraint → returns zone unchanged.

        Kills ``valid_zones is not None -> is None``: when valid_zones is
        None, original returns zone; mutant would check `zone not in None`
        and crash.
        """
        # AML.T0010 has no entry in TECHNIQUE_ZONE_CONSTRAINTS
        result = _constrain_zone_to_technique("memory", "AML.T0010")
        assert result == "memory"


# ---------------------------------------------------------------------------
# 4. _architecture_section_text
# ---------------------------------------------------------------------------


class TestArchitectureSectionText:
    """Kill mutants in the architecture section builder."""

    def test_none_profile_returns_empty(self):
        """profile is None → empty string.

        Kills ``profile is None -> is not None``: mutant would try to access
        profile.entry_points and crash.
        """
        assert _architecture_section_text(None) == ""

    def test_non_none_profile_returns_section(self):
        """profile is not None → non-empty section with zones and entry points.

        Kills ``profile is None -> is not None``: mutant would return "" for
        a non-None profile.
        """
        ep = SimpleNamespace(name="user prompts")
        profile = SimpleNamespace(
            zones_active=["input", "reasoning"],
            entry_points=[ep],
        )
        result = _architecture_section_text(profile)
        assert "Target System Architecture" in result
        assert "input" in result
        assert "user prompts" in result


# ---------------------------------------------------------------------------
# 5. _actor_section_text
# ---------------------------------------------------------------------------


class TestActorSectionText:
    """Kill mutants in the actor section builder."""

    def test_none_actor_returns_empty(self):
        """actor_profile is None → empty string.

        Kills ``actor_profile is None -> is not None``: mutant would crash.
        """
        assert _actor_section_text(None) == ""

    def test_non_none_actor_returns_section(self):
        """actor_profile is not None → non-empty section.

        Kills ``actor_profile is None -> is not None``: mutant returns "".
        """
        actor = SimpleNamespace(actor_type="cybercriminal", capability_level="advanced")
        result = _actor_section_text(actor)
        assert "Actor Profile" in result
        assert "cybercriminal" in result
        assert "advanced" in result


# ---------------------------------------------------------------------------
# 6. _access_provenance_block_text
# ---------------------------------------------------------------------------


class TestAccessProvenanceBlockText:
    """Kill mutants in the access provenance block builder."""

    def test_none_actor_returns_empty(self):
        """actor_profile is None → empty string.

        Kills ``actor_profile is None -> is not None``: mutant would crash
        accessing actor_profile.access.
        Kills ``or -> and``: `if actor_profile is None and ...` → when
        actor_profile is None, `True and (crash)` → crashes.
        """
        assert _access_provenance_block_text(None, None) == ""

    def test_none_access_returns_empty(self):
        """actor_profile.access is None → empty string.

        Kills ``actor_profile.access is None -> is not None``: mutant would
        proceed to call access_provenance_block_with_names with None access.
        """
        actor = SimpleNamespace(access=None)
        profile = _mk_profile()
        assert _access_provenance_block_text(actor, profile) == ""

    def test_none_profile_returns_empty(self):
        """profile is None but actor_profile.access is not None → empty.

        The second guard: `if profile is None: return ""`.
        """
        actor = SimpleNamespace(access=SimpleNamespace())
        assert _access_provenance_block_text(actor, None) == ""

    def test_present_access_and_profile_returns_block(self):
        actor = ActorProfile(
            actor_type="cybercriminal",
            capability_level="novice",
            beliefs=["b"],
            desires=["d"],
            intentions=["i"],
            resources=["r"],
            access=ActorAccessProvenance(
                initial_entry_point_id="ep1",
                ingress_mode="direct",
                access_class="public",
            ),
        )
        profile = SimpleNamespace(
            id_to_entry_point_name=lambda: {"ep1": "Chat"},
            id_to_integration_name=lambda: {},
            id_to_trust_boundary_name=lambda: {},
            id_to_tool_name=lambda: {},
        )
        result = _access_provenance_block_text(actor, profile)
        assert "Actor Access Provenance" in result
        assert "Chat" in result


# ---------------------------------------------------------------------------
# 7. _format_skeleton_yaml
# ---------------------------------------------------------------------------


class TestFormatSkeletonYaml:
    """Kill mutants in the skeleton YAML formatter."""

    def test_empty_skeleton_returns_empty(self):
        assert _format_skeleton_yaml([]) == ""

    def test_additional_leaves_count_uses_plus(self):
        """len(skeleton) + 2 → correct count.

        Kills ``+ -> -``: mutant would compute len(skeleton) - 2.
        """
        skeleton = [
            {"id": "n0.1", "technique_id": "AML.T0054", "technique_name": "Jailbreak", "zone": "input"},
        ]
        result = _format_skeleton_yaml(skeleton)
        # 1 + 2 = 3 additional leaves
        assert "3 additional" in result
        assert "-3 additional" not in result

    def test_additional_leaves_count_multiple_skeleton(self):
        """Verify + for a larger skeleton (3 entries → 5 additional)."""
        skeleton = [
            {"id": f"n0.{i}", "technique_id": f"AML.T005{i}", "technique_name": f"tech{i}", "zone": "input"}
            for i in range(1, 4)
        ]
        result = _format_skeleton_yaml(skeleton)
        assert "5 additional" in result


# ---------------------------------------------------------------------------
# 8. _validate_mandatory_leaves
# ---------------------------------------------------------------------------


class TestValidateMandatoryLeaves:
    """Kill mutants in the mandatory-leaf validator."""

    def test_empty_skeleton_no_warn(self, caplog):
        tree = SimpleNamespace(collect_technique_ids=lambda: [])
        with caplog.at_level(logging.WARNING):
            _validate_mandatory_leaves(tree, [], "seed-1")
        assert not caplog.records

    def test_missing_technique_warns(self, caplog):
        """technique_id not in tree → warning.

        Kills ``not in -> in``: mutant would NOT warn here.
        """
        tree = SimpleNamespace(collect_technique_ids=lambda: ["AML.T0010"])
        skeleton = [{"technique_id": "AML.T0054", "technique_name": "Jailbreak"}]
        with caplog.at_level(logging.WARNING):
            _validate_mandatory_leaves(tree, skeleton, "seed-1")
        assert any("AML.T0054" in r.message for r in caplog.records)

    def test_present_technique_no_warn(self, caplog):
        """technique_id in tree → no warning.

        Kills ``not in -> in``: mutant WOULD warn here (in becomes True).
        """
        tree = SimpleNamespace(collect_technique_ids=lambda: ["AML.T0054", "AML.T0010"])
        skeleton = [{"technique_id": "AML.T0054", "technique_name": "Jailbreak"}]
        with caplog.at_level(logging.WARNING):
            _validate_mandatory_leaves(tree, skeleton, "seed-1")
        assert not caplog.records


# ---------------------------------------------------------------------------
# 9. _build_tree_skeleton
# ---------------------------------------------------------------------------


class TestBuildTreeSkeleton:
    """Kill mutants in the tree skeleton builder."""

    def test_empty_pinned_ids_returns_empty(self):
        narrative = _mk_narrative()
        result = _build_tree_skeleton(narrative, [], [])
        assert result == []

    def test_fallback_zone_is_first_active_zone(self):
        """active_sequence[0] is used as fallback.

        Kills ``0 -> 1`` in active_sequence[0]: mutant would use [1] and
        crash or get the wrong zone.
        """
        # Technique that doesn't match any step → uses fallback
        # Only one active zone so [0] works but [1] would IndexError
        narrative = _mk_narrative(
            steps=[_mk_step(action="unrelated", effect="unrelated", zone="input")],
            zone_sequence=["input"],
        )
        result = _build_tree_skeleton(narrative, ["AML.T0054"], ["Jailbreak"])
        assert len(result) == 1
        assert result[0]["zone"] == "input"

    def test_matched_zone_from_narrative_step(self):
        """Technique matching a step gets that step's zone."""
        narrative = _mk_narrative(
            steps=[
                _mk_step(action="uses AML.T0054", effect="done", zone="reasoning"),
            ],
            zone_sequence=["input", "reasoning"],
        )
        result = _build_tree_skeleton(narrative, ["AML.T0054"], ["LLM Jailbreak"])
        assert result[0]["zone"] == "reasoning"

    def test_skeleton_ids_start_at_n0_1(self):
        """IDs are n0.1, n0.2, etc."""
        narrative = _mk_narrative(
            steps=[_mk_step(action="AML.T0054 AML.T0010", effect="x", zone="input")],
            zone_sequence=["input"],
        )
        result = _build_tree_skeleton(
            narrative, ["AML.T0054", "AML.T0010"], ["Jailbreak", "Supply Chain"]
        )
        assert result[0]["id"] == "n0.1"
        assert result[1]["id"] == "n0.2"

    def test_outside_zone_dropped_from_fallback(self):
        """'outside' zone is not used as fallback (active_narrative_zones drops it)."""
        narrative = _mk_narrative(
            steps=[_mk_step(action="unrelated", effect="unrelated", zone="input")],
            zone_sequence=["outside", "input"],
        )
        result = _build_tree_skeleton(narrative, ["AML.T0054"], ["Jailbreak"])
        # Fallback should be "input" (first active), not "outside"
        assert result[0]["zone"] == "input"


# ---------------------------------------------------------------------------
# 10. _ensure_accessible_pinned_entry
# ---------------------------------------------------------------------------


class TestEnsureAccessiblePinnedEntry:
    """Kill mutants in the accessible-pinned-entry guard."""

    def test_none_profile_returns_silently(self):
        """profile is None → return without checking.

        Kills ``profile is None -> is not None``: mutant would proceed.
        Kills ``or -> and``: `if profile is None and len(...) != 1` →
        when profile is None, `True and (len check)` → if len == 1, False,
        so mutant proceeds and crashes accessing profile.zones_active.
        """
        ep = SimpleNamespace(name="test")
        # Should not raise
        _ensure_accessible_pinned_entry(None, [ep], "ep-1")

    def test_wrong_entry_point_count_returns_silently(self):
        """len(entry_points) != 1 → return.

        Kills ``len(entry_points) != 1 -> == 1``: mutant would return when
        len == 1 instead.
        """
        profile = _mk_profile()
        # Two entry points → len != 1 → should return silently
        _ensure_accessible_pinned_entry(profile, [SimpleNamespace(), SimpleNamespace()], "ep-1")

    def test_accessible_entry_no_raise(self):
        """Accessible entry point with len == 1 → no raise.

        Kills ``profile is None -> is not None`` and
        ``len(entry_points) != 1 -> == 1``: both mutants would skip the
        check, but since the entry is accessible, no raise either way.
        We need the inaccessible test to kill these.
        """
        from asago_scenario_generator.models.capability_profile import EntryPoint

        ep = EntryPoint(name="user prompts", direction="input", controllability="direct")
        profile = _mk_profile(zones_active=["input", "reasoning"])
        # Should not raise — entry is accessible
        _ensure_accessible_pinned_entry(profile, [ep], "ep-1")

    def test_inaccessible_entry_raises(self):
        """Inaccessible entry point with len == 1 → raises GenerationError.

        Kills ``profile is None -> is not None``: mutant returns silently
        instead of raising.
        Kills ``len(entry_points) != 1 -> == 1``: mutant returns silently.
        Kills ``0 -> 1`` in entry_points[0]: mutant uses [1] → IndexError
        instead of GenerationError.
        """
        from asago_scenario_generator.pipeline.generate.assembly import GenerationError
        from asago_scenario_generator.models.capability_profile import EntryPoint

        # Output-only entry point → not attacker-accessible
        ep = EntryPoint(name="system log", direction="output")
        profile = _mk_profile(zones_active=["input", "reasoning"])
        with pytest.raises(GenerationError, match="not an attacker-accessible"):
            _ensure_accessible_pinned_entry(profile, [ep], "ep-1")

    def test_empty_entry_points_returns_silently(self):
        """len(entry_points) == 0 → return (len != 1).

        Kills ``1 -> 0`` in ``len(entry_points) != 1``: mutant checks
        ``len != 0`` → 0 != 0 is False, so mutant would proceed and crash
        on entry_points[0].
        """
        profile = _mk_profile()
        _ensure_accessible_pinned_entry(profile, [], "ep-1")


# ---------------------------------------------------------------------------
# 11. _skeleton_and_section
# ---------------------------------------------------------------------------


class TestSkeletonAndSection:
    """Kill mutants in the skeleton-and-section combiner."""

    def test_both_none_returns_empty(self):
        """Both pinned lists None → empty skeleton, empty section."""
        narrative = _mk_narrative()
        skeleton, section = _skeleton_and_section(narrative, None, None)
        assert skeleton == []
        assert section == ""

    def test_only_ids_not_names_returns_empty(self):
        """pinned_technique_ids set but names None → empty (and logic).

        Kills ``and -> or``: mutant would proceed with names=None and crash
        in zip().
        """
        narrative = _mk_narrative()
        skeleton, section = _skeleton_and_section(narrative, ["AML.T0054"], None)
        assert skeleton == []
        assert section == ""

    def test_only_names_not_ids_returns_empty(self):
        """pinned_technique_names set but ids None → empty (and logic).

        Kills ``and -> or``: mutant would proceed with ids=None and crash.
        """
        narrative = _mk_narrative()
        skeleton, section = _skeleton_and_section(narrative, None, ["Jailbreak"])
        assert skeleton == []
        assert section == ""

    def test_both_set_builds_skeleton(self):
        """Both set → skeleton built and section formatted."""
        narrative = _mk_narrative(
            steps=[_mk_step(action="AML.T0054", effect="done", zone="input")],
            zone_sequence=["input"],
        )
        skeleton, section = _skeleton_and_section(
            narrative, ["AML.T0054"], ["LLM Jailbreak"]
        )
        assert len(skeleton) == 1
        assert "Mandatory Leaf Nodes" in section


# ---------------------------------------------------------------------------
# 12. _humanized_projection_value
# ---------------------------------------------------------------------------


class TestHumanizedProjectionValue:
    """Kill mutants in the projection humanizer."""

    def test_both_none_returns_none(self):
        assert _humanized_projection_value(None, None) is None

    def test_projection_none_returns_none(self):
        """projection_context is None → returns None (not humanized).

        Kills ``projection_context is not None -> is None``: mutant would
        try to humanize None.
        """
        profile = _mk_profile()
        assert _humanized_projection_value(None, profile) is None

    def test_profile_none_returns_projection_unchanged(self):
        """profile is None → returns projection_context unchanged.

        Kills ``profile is not None -> is None``: mutant would try to
        humanize with None profile and crash.
        Kills ``and -> or``: `if projection_context is not None or profile
        is not None` → True when projection is not None, so mutant tries to
        humanize with None profile → crash.
        """
        ctx = {"selected_steps": []}
        result = _humanized_projection_value(ctx, None)
        assert result is ctx

    def test_both_not_none_humanizes(self):
        """Both not None → humanized (differs from input).

        Kills ``projection_context is not None -> is None``: mutant returns
        input unchanged.
        Kills ``profile is not None -> is None``: mutant returns input.
        """
        # Use a real CapabilityProfile for humanize_projection_context
        from asago_scenario_generator.models.capability_profile import (
            CapabilityProfile,
            ToolInventoryEntry,
        )

        profile = CapabilityProfile(
            zones_active=["input", "reasoning"],
            entry_points=["user prompts"],
            confidence="high",
            kc_subcodes=["KC1.1"],
        )
        ctx = {"selected_steps": [], "canonical_ingress": {}}
        result = _humanized_projection_value(ctx, profile)
        # humanize_projection_context returns a new dict (not the same object)
        assert result is not ctx


# ---------------------------------------------------------------------------
# 13. _entry_points_for_template
# ---------------------------------------------------------------------------


class TestEntryPointsForTemplate:
    """Kill mutants in the entry-points-for-template helper."""

    def test_none_profile_returns_empty(self):
        """profile is None → empty list.

        Kills ``or [] -> and []``: `(None if None else None) and []` → None
        and [] → None (falsy). Actually `None and []` → None. But then
        `if pinned_entry_point_id is None: return None` → returns None not [].
        Hmm, let's just check it returns a list/None.
        """
        result = _entry_points_for_template(None, None)
        assert result == [] or result is None

    def test_no_pinned_id_returns_all_entry_points(self):
        """pinned_entry_point_id is None → returns all entry points.

        Kills ``pinned_entry_point_id is None -> is not None``: mutant would
        NOT return early and would filter by None ID → empty list.
        Kills ``or [] -> and []``: mutant returns [] instead of entry_points.
        """
        from asago_scenario_generator.models.capability_profile import EntryPoint

        ep1 = EntryPoint(name="user prompts", direction="input", controllability="direct")
        ep2 = EntryPoint(name="api calls", direction="input", controllability="direct")
        profile = _mk_profile(entry_points=[ep1, ep2])
        result = _entry_points_for_template(profile, None)
        assert result == [ep1, ep2]

    def test_pinned_id_filters_entry_points(self):
        """pinned_entry_point_id set → returns only matching entry point."""
        from asago_scenario_generator.models.capability_profile import EntryPoint

        ep1 = EntryPoint(name="user prompts", direction="input", controllability="direct")
        ep2 = EntryPoint(name="api calls", direction="input", controllability="direct")
        profile = _mk_profile(entry_points=[ep1, ep2])
        result = _entry_points_for_template(profile, ep2.entry_point_id)
        assert result == [ep2]

    def test_or_not_and_returns_entry_points(self):
        """`(profile.entry_points if profile else None) or []` → entry_points.

        Kills ``or [] -> and []``: with `and`, when entry_points is truthy,
        `entry_points and []` → [] (empty list).
        """
        from asago_scenario_generator.models.capability_profile import EntryPoint

        ep = EntryPoint(name="user prompts", direction="input", controllability="direct")
        profile = _mk_profile(entry_points=[ep])
        result = _entry_points_for_template(profile, None)
        assert len(result) == 1


# ---------------------------------------------------------------------------
# 14. _technique_count_for
# ---------------------------------------------------------------------------


class TestTechniqueCountFor:
    """Kill mutants in the technique-count helper."""

    def test_empty_list_returns_zero(self):
        """Empty list → 0 (not 1).

        Kills ``0 -> 1``: mutant returns 1.
        """
        assert _technique_count_for([]) == 0

    def test_none_returns_zero(self):
        """None → 0 (not 1).

        Kills ``0 -> 1``: mutant returns 1.
        """
        assert _technique_count_for(None) == 0

    def test_non_empty_returns_len(self):
        assert _technique_count_for(["AML.T0054", "AML.T0010"]) == 2


# ---------------------------------------------------------------------------
# 15. _tool_inventory_for
# ---------------------------------------------------------------------------


class TestToolInventoryFor:
    """Kill mutants in the tool-inventory helper."""

    def test_none_profile_returns_empty(self):
        """profile is None → [].

        Kills ``or [] -> and []``: `(None if None else None) and []` → None.
        """
        result = _tool_inventory_for(None)
        assert result == []

    def test_none_inventory_returns_empty(self):
        """profile.tool_inventory is None → [].

        Kills ``or [] -> and []``: `None and []` → None, but `None or []` → [].
        """
        profile = _mk_profile(tool_inventory=None)
        # SimpleNamespace doesn't have tool_inventory=None by default...
        # Actually our _mk_profile sets tool_inventory=[] by default.
        # Let's override:
        profile.tool_inventory = None
        result = _tool_inventory_for(profile)
        assert result == []

    def test_non_empty_inventory_returned(self):
        """profile.tool_inventory is not None → returns inventory.

        Kills ``or [] -> and []``: `inventory and []` → [] (empty).
        """
        tool = SimpleNamespace(name="db_query")
        profile = _mk_profile(tool_inventory=[tool])
        result = _tool_inventory_for(profile)
        assert result == [tool]


# ---------------------------------------------------------------------------
# 16. _external_integrations_for
# ---------------------------------------------------------------------------


class TestExternalIntegrationsFor:
    """Kill mutants in the external-integrations helper."""

    def test_none_profile_returns_empty(self):
        result = _external_integrations_for(None)
        assert result == []

    def test_none_integrations_returns_empty(self):
        profile = _mk_profile(external_integrations=[])
        profile.external_integrations = None
        result = _external_integrations_for(profile)
        assert result == []

    def test_non_empty_integrations_returned(self):
        """Kills ``or [] -> and []``: `integrations and []` → []."""
        integ = SimpleNamespace(name="CRM")
        profile = _mk_profile(external_integrations=[integ])
        result = _external_integrations_for(profile)
        assert result == [integ]


# ---------------------------------------------------------------------------
# 17. _resolve_initial_ingress_action
# ---------------------------------------------------------------------------


class TestResolveInitialIngressAction:
    """Kill mutants in the initial-ingress action resolver."""

    def test_resolves_name_to_id(self):
        """resolved_id is not None → action.entry_point_id updated.

        Kills ``resolved_id is not None -> is None``: mutant would NOT
        update the action.
        """
        action = _mk_action("initial_ingress", entry_point_id="user prompts")
        node = SimpleNamespace(id="n1.1")
        profile = _mk_profile(
            entry_point_name_to_id={"user prompts": "ep:v1:resolved"},
            resolve_entry_point_map={"ep:v1:resolved": SimpleNamespace(name="user prompts")},
        )
        violations: list[str] = []
        _resolve_initial_ingress_action(node, action, profile, violations)
        assert action.entry_point_id == "ep:v1:resolved"
        assert violations == []

    def test_already_hex_id_not_reassigned(self):
        """Already a hex ID → resolve returns same, no change needed."""
        action = _mk_action("initial_ingress", entry_point_id="ep:v1:already")
        node = SimpleNamespace(id="n1.1")
        profile = _mk_profile(
            resolve_entry_point_map={"ep:v1:already": SimpleNamespace(name="test")},
        )
        violations: list[str] = []
        _resolve_initial_ingress_action(node, action, profile, violations)
        assert action.entry_point_id == "ep:v1:already"
        assert violations == []

    def test_unresolved_entry_point_adds_violation(self):
        """ep is None → violation added.

        Kills ``ep is None -> is not None``: mutant would NOT add a violation
        for an unresolved entry point, and WOULD add one for a resolved one.
        """
        action = _mk_action("initial_ingress", entry_point_id="unknown_ep")
        node = SimpleNamespace(id="n1.1")
        profile = _mk_profile(
            entry_point_name_to_id={},
            resolve_entry_point_map={},
        )
        violations: list[str] = []
        _resolve_initial_ingress_action(node, action, profile, violations)
        assert len(violations) == 1
        assert "unresolved-entry-point-id" in violations[0]

    def test_resolved_entry_point_no_violation(self):
        """ep is not None → no violation.

        Kills ``ep is None -> is not None``: mutant WOULD add a violation
        for a resolved entry point.
        """
        action = _mk_action("initial_ingress", entry_point_id="user prompts")
        node = SimpleNamespace(id="n1.1")
        profile = _mk_profile(
            entry_point_name_to_id={"user prompts": "ep:v1:resolved"},
            resolve_entry_point_map={"ep:v1:resolved": SimpleNamespace(name="user prompts")},
        )
        violations: list[str] = []
        _resolve_initial_ingress_action(node, action, profile, violations)
        assert violations == []


# ---------------------------------------------------------------------------
# 18. _resolve_tool_invocation_integration
# ---------------------------------------------------------------------------


class TestResolveToolInvocationIntegration:
    """Kill mutants in the tool-invocation integration resolver."""

    def test_none_integration_id_skips(self):
        """integration_id is None → skip resolution.

        Kills ``action.integration_id is not None -> is None``: mutant would
        try to resolve None and crash or behave differently.
        """
        action = _mk_action("tool_invocation", tool_id="db_query", integration_id=None)
        node = SimpleNamespace(id="n1.1")
        profile = _mk_profile()
        violations: list[str] = []
        _resolve_tool_invocation_integration(node, action, profile, violations)
        assert violations == []

    def test_resolves_integration_name_to_id(self):
        """resolved_int is not None → action.integration_id updated.

        Kills ``resolved_int is not None -> is None``: mutant would NOT
        update.
        """
        action = _mk_action("tool_invocation", tool_id="db_query", integration_id="CRM")
        node = SimpleNamespace(id="n1.1")
        profile = _mk_profile(
            integration_name_to_id={"CRM": "int:v1:resolved"},
            resolve_integration_map={"int:v1:resolved": SimpleNamespace(name="CRM")},
        )
        violations: list[str] = []
        _resolve_tool_invocation_integration(node, action, profile, violations)
        assert action.integration_id == "int:v1:resolved"
        assert violations == []

    def test_unresolved_integration_adds_violation(self):
        """integ is None → violation added.

        Kills ``integ is None -> is not None``: mutant would NOT add a
        violation for unresolved integration.
        """
        action = _mk_action("tool_invocation", tool_id="db_query", integration_id="unknown_int")
        node = SimpleNamespace(id="n1.1")
        profile = _mk_profile(
            integration_name_to_id={},
            resolve_integration_map={},
        )
        violations: list[str] = []
        _resolve_tool_invocation_integration(node, action, profile, violations)
        assert len(violations) == 1
        assert "unresolved-integration-id" in violations[0]

    def test_resolved_integration_no_violation(self):
        """integ is not None → no violation.

        Kills ``integ is None -> is not None``: mutant WOULD add a violation.
        """
        action = _mk_action("tool_invocation", tool_id="db_query", integration_id="CRM")
        node = SimpleNamespace(id="n1.1")
        profile = _mk_profile(
            integration_name_to_id={"CRM": "int:v1:resolved"},
            resolve_integration_map={"int:v1:resolved": SimpleNamespace(name="CRM")},
        )
        violations: list[str] = []
        _resolve_tool_invocation_integration(node, action, profile, violations)
        assert violations == []


# ---------------------------------------------------------------------------
# 19. _resolve_tool_invocation_action
# ---------------------------------------------------------------------------


class TestResolveToolInvocationAction:
    """Kill mutants in the tool-invocation action resolver."""

    def test_resolves_tool_name_to_id(self):
        """resolved_tool is not None → action.tool_id updated.

        Kills ``resolved_tool is not None -> is None``: mutant would NOT
        update.
        """
        action = _mk_action("tool_invocation", tool_id="db_query", integration_id=None)
        node = SimpleNamespace(id="n1.1")
        profile = _mk_profile(
            tool_name_to_id={"db_query": "tool:v1:resolved"},
            resolve_tool_map={"tool:v1:resolved": SimpleNamespace(name="db_query")},
        )
        violations: list[str] = []
        _resolve_tool_invocation_action(node, action, profile, violations)
        assert action.tool_id == "tool:v1:resolved"

    def test_unresolved_tool_adds_violation(self):
        """tool is None → violation added.

        Kills ``tool is None -> is not None``: mutant would NOT add a
        violation for unresolved tool.
        """
        action = _mk_action("tool_invocation", tool_id="unknown_tool", integration_id=None)
        node = SimpleNamespace(id="n1.1")
        profile = _mk_profile(
            tool_name_to_id={},
            resolve_tool_map={},
        )
        violations: list[str] = []
        _resolve_tool_invocation_action(node, action, profile, violations)
        assert any("unresolved-tool-id" in v for v in violations)

    def test_resolved_tool_no_violation(self):
        """tool is not None → no violation.

        Kills ``tool is None -> is not None``: mutant WOULD add a violation.
        """
        action = _mk_action("tool_invocation", tool_id="db_query", integration_id=None)
        node = SimpleNamespace(id="n1.1")
        profile = _mk_profile(
            tool_name_to_id={"db_query": "tool:v1:resolved"},
            resolve_tool_map={"tool:v1:resolved": SimpleNamespace(name="db_query")},
        )
        violations: list[str] = []
        _resolve_tool_invocation_action(node, action, profile, violations)
        assert not any("unresolved-tool-id" in v for v in violations)


# ---------------------------------------------------------------------------
# 20. _resolve_integration_interaction_action
# ---------------------------------------------------------------------------


class TestResolveIntegrationInteractionAction:
    """Kill mutants in the integration-interaction action resolver."""

    def test_resolves_integration_name_to_id(self):
        action = _mk_action("integration_interaction", integration_id="CRM")
        node = SimpleNamespace(id="n1.1")
        profile = _mk_profile(
            integration_name_to_id={"CRM": "int:v1:resolved"},
            resolve_integration_map={"int:v1:resolved": SimpleNamespace(name="CRM")},
        )
        violations: list[str] = []
        _resolve_integration_interaction_action(node, action, profile, violations)
        assert action.integration_id == "int:v1:resolved"
        assert violations == []

    def test_unresolved_integration_adds_violation(self):
        """integ is None → violation.

        Kills ``integ is None -> is not None``: mutant would NOT add violation.
        """
        action = _mk_action("integration_interaction", integration_id="unknown")
        node = SimpleNamespace(id="n1.1")
        profile = _mk_profile(
            integration_name_to_id={},
            resolve_integration_map={},
        )
        violations: list[str] = []
        _resolve_integration_interaction_action(node, action, profile, violations)
        assert len(violations) == 1
        assert "unresolved-integration-id" in violations[0]

    def test_resolved_integration_no_violation(self):
        """integ is not None → no violation.

        Kills ``integ is None -> is not None``: mutant WOULD add violation.
        """
        action = _mk_action("integration_interaction", integration_id="CRM")
        node = SimpleNamespace(id="n1.1")
        profile = _mk_profile(
            integration_name_to_id={"CRM": "int:v1:resolved"},
            resolve_integration_map={"int:v1:resolved": SimpleNamespace(name="CRM")},
        )
        violations: list[str] = []
        _resolve_integration_interaction_action(node, action, profile, violations)
        assert violations == []


# ---------------------------------------------------------------------------
# 21. _resolve_action_ids_node
# ---------------------------------------------------------------------------


class TestResolveActionIdsNode:
    """Kill mutants in the per-node action ID resolver."""

    def test_non_leaf_node_returns(self):
        """gate != LEAF → return (no resolution).

        Kills ``node.gate != LEAF -> == LEAF``: mutant would return for LEAF
        nodes (skipping resolution) and proceed for non-LEAF (crash).
        """
        node = SimpleNamespace(
            id="n1",
            gate=GateType.AND,
            action=None,
            children=[SimpleNamespace(id="n1.1"), SimpleNamespace(id="n1.2")],
        )
        profile = _mk_profile()
        violations: list[str] = []
        _resolve_action_ids_node(node, profile, violations)
        assert violations == []

    def test_leaf_with_none_action_returns(self):
        """gate == LEAF but action is None → return.

        Kills ``node.action is None -> is not None``: mutant would proceed
        and crash accessing action.kind.
        """
        node = SimpleNamespace(
            id="n1.1",
            gate=GateType.LEAF,
            action=None,
        )
        profile = _mk_profile()
        violations: list[str] = []
        _resolve_action_ids_node(node, profile, violations)
        assert violations == []

    def test_leaf_with_initial_ingress_resolves(self):
        """gate == LEAF, action.kind == "initial_ingress" → resolves.

        Kills ``node.gate != LEAF -> == LEAF``: mutant returns for LEAF.
        Kills ``node.action is None -> is not None``: mutant returns.
        Kills ``kind == "initial_ingress" -> !=``: mutant skips this branch.
        """
        action = _mk_action("initial_ingress", entry_point_id="user prompts")
        node = SimpleNamespace(id="n1.1", gate=GateType.LEAF, action=action)
        profile = _mk_profile(
            entry_point_name_to_id={"user prompts": "ep:v1:resolved"},
            resolve_entry_point_map={"ep:v1:resolved": SimpleNamespace(name="user prompts")},
        )
        violations: list[str] = []
        _resolve_action_ids_node(node, profile, violations)
        assert action.entry_point_id == "ep:v1:resolved"
        assert violations == []

    def test_leaf_with_tool_invocation_resolves(self):
        """gate == LEAF, action.kind == "tool_invocation" → resolves.

        Kills ``kind == "tool_invocation" -> !=``: mutant skips this branch.
        """
        action = _mk_action("tool_invocation", tool_id="db_query", integration_id=None)
        node = SimpleNamespace(id="n1.1", gate=GateType.LEAF, action=action)
        profile = _mk_profile(
            tool_name_to_id={"db_query": "tool:v1:resolved"},
            resolve_tool_map={"tool:v1:resolved": SimpleNamespace(name="db_query")},
        )
        violations: list[str] = []
        _resolve_action_ids_node(node, profile, violations)
        assert action.tool_id == "tool:v1:resolved"

    def test_leaf_with_integration_interaction_resolves(self):
        """gate == LEAF, action.kind == "integration_interaction" → resolves.

        Kills ``kind == "integration_interaction" -> !=``: mutant skips.
        """
        action = _mk_action("integration_interaction", integration_id="CRM")
        node = SimpleNamespace(id="n1.1", gate=GateType.LEAF, action=action)
        profile = _mk_profile(
            integration_name_to_id={"CRM": "int:v1:resolved"},
            resolve_integration_map={"int:v1:resolved": SimpleNamespace(name="CRM")},
        )
        violations: list[str] = []
        _resolve_action_ids_node(node, profile, violations)
        assert action.integration_id == "int:v1:resolved"

    def test_leaf_with_other_kind_no_resolution(self):
        """gate == LEAF, action.kind == "ai_system_action" → no resolution.

        Kills ``kind == "initial_ingress" -> !=``: mutant would match
        ai_system_action as initial_ingress (wrong branch).
        """
        action = _mk_action("ai_system_action")
        node = SimpleNamespace(id="n1.1", gate=GateType.LEAF, action=action)
        profile = _mk_profile()
        violations: list[str] = []
        _resolve_action_ids_node(node, profile, violations)
        assert violations == []

    def test_or_logic_non_leaf_with_action_returns(self):
        """gate != LEAF and action is not None → return (or short-circuits).

        Kills ``or -> and``: `if node.gate != LEAF and node.action is None`
        → False and ... → False, so mutant would proceed and try to access
        action.kind, potentially resolving a non-LEAF node.
        """
        action = _mk_action("initial_ingress", entry_point_id="user prompts")
        node = SimpleNamespace(
            id="n1",
            gate=GateType.OR,
            action=action,  # AND/OR shouldn't have actions, but test the guard
            children=[SimpleNamespace(id="n1.1"), SimpleNamespace(id="n1.2")],
        )
        profile = _mk_profile(
            entry_point_name_to_id={"user prompts": "ep:v1:resolved"},
            resolve_entry_point_map={"ep:v1:resolved": SimpleNamespace(name="user prompts")},
        )
        violations: list[str] = []
        _resolve_action_ids_node(node, profile, violations)
        # Original returns early (gate != LEAF), action not resolved
        assert action.entry_point_id == "user prompts"
        assert violations == []


# ---------------------------------------------------------------------------
# 22. _compile_tree_response (simple path)
# ---------------------------------------------------------------------------


class TestCompileTreeResponse:
    """Kill mutants in the tree-response compiler (simple paths)."""

    def test_none_specs_and_str_content_calls_yaml_parse(self):
        """semantic_leaf_specs is None, content is str → YAML parse path.

        Kills ``is not None and not -> or not``: mutant would enter the
        if-branch when specs is None and content is not str... but content
        IS str here, so `not isinstance(content, str)` is False. With `or`:
        `None is not None or not isinstance(content, str)` → `False or False`
        → False. So this test doesn't kill the `or` mutant directly.
        But it verifies the normal YAML path works.
        """
        from asago_scenario_generator.pipeline.seeds import ScenarioSeed
        from asago_scenario_generator.models.scenario import RiskCardRef

        seed = ScenarioSeed(
            seed_id="AP-T7-01",
            threat_id="T7",
            threat_name="test",
            attack_pattern_name="test",
            attack_pattern_description="test",
            risk_card_ref=RiskCardRef(
                risk_id="r1",
                risk_name="r",
                risk_description="d",
                taxonomy="ibm-risk-atlas",
                confidence=0.5,
                grounding_confidence="high",
            ),
            owasp_llm_ids=["LLM01"],
            agentic_threat_ids=["T7"],
        )
        # Mock _parse_attack_tree_yaml to verify it's called
        with pytest.MonkeyPatch.context() as mp:
            called = False

            def fake_parse(content, s, pc):
                nonlocal called
                called = True
                return SimpleNamespace()

            mp.setattr(
                "asago_scenario_generator.pipeline.generate.tree._parse_attack_tree_yaml",
                fake_parse,
            )
            _compile_tree_response("yaml: content", None, seed, None)
            assert called

    def test_none_specs_and_non_str_content_calls_yaml_parse(self):
        """semantic_leaf_specs is None, content is not str → YAML parse.

        Kills ``is not None and not -> or not``: with `or`, the condition
        becomes `None is not None or not isinstance(content, str)` →
        `False or True` → True, so mutant enters the if-branch and tries
        to import tree_semantics, potentially crashing.
        """
        from asago_scenario_generator.pipeline.seeds import ScenarioSeed
        from asago_scenario_generator.models.scenario import RiskCardRef

        seed = ScenarioSeed(
            seed_id="AP-T7-01",
            threat_id="T7",
            threat_name="test",
            attack_pattern_name="test",
            attack_pattern_description="test",
            risk_card_ref=RiskCardRef(
                risk_id="r1",
                risk_name="r",
                risk_description="d",
                taxonomy="ibm-risk-atlas",
                confidence=0.5,
                grounding_confidence="high",
            ),
            owasp_llm_ids=["LLM01"],
            agentic_threat_ids=["T7"],
        )
        with pytest.MonkeyPatch.context() as mp:
            called = False

            def fake_parse(content, s, pc):
                nonlocal called
                called = True
                return SimpleNamespace()

            mp.setattr(
                "asago_scenario_generator.pipeline.generate.tree._parse_attack_tree_yaml",
                fake_parse,
            )
            # Pass a dict (not str) with specs=None → should still go to YAML parse
            _compile_tree_response({"key": "val"}, None, seed, None)
            assert called


# ---------------------------------------------------------------------------
# 23. _call_attack_tree_once (or/and logic in flow selection)
# ---------------------------------------------------------------------------


class TestCallAttackTreeOnce:
    """Kill mutants in the attack-tree-once flow selector."""

    def test_projection_none_profile_not_none_uses_legacy(self, monkeypatch):
        """projection_context is None, profile is not None → legacy flow.

        Kills ``and -> or`` in the flow selector: `if projection_context is
        not None or profile is not None` → `False or True` → True, so mutant
        tries semantic flow with None projection_context → crash.
        """
        from asago_scenario_generator.pipeline.seeds import ScenarioSeed
        from asago_scenario_generator.models.scenario import RiskCardRef

        seed = ScenarioSeed(
            seed_id="AP-T7-01",
            threat_id="T7",
            threat_name="test",
            attack_pattern_name="test",
            attack_pattern_description="test",
            risk_card_ref=RiskCardRef(
                risk_id="r1",
                risk_name="r",
                risk_description="d",
                taxonomy="ibm-risk-atlas",
                confidence=0.5,
                grounding_confidence="high",
            ),
            owasp_llm_ids=["LLM01"],
            agentic_threat_ids=["T7"],
        )
        narrative = _mk_narrative()

        # Mock _legacy_prompt_flow to verify it's called
        legacy_called = False

        def fake_legacy(*args, **kwargs):
            nonlocal legacy_called
            legacy_called = True
            return [], "system", "user"

        def fake_semantic(*args, **kwargs):
            return None  # should not be called

        monkeypatch.setattr(
            "asago_scenario_generator.pipeline.generate.tree._legacy_prompt_flow",
            fake_legacy,
        )
        monkeypatch.setattr(
            "asago_scenario_generator.pipeline.generate.tree._semantic_draft_flow",
            fake_semantic,
        )
        # Mock the LLM invocation and postprocessing
        monkeypatch.setattr(
            "asago_scenario_generator.pipeline.generate.tree._invoke_attack_tree",
            lambda *a, **kw: SimpleNamespace(content="yaml"),
        )
        monkeypatch.setattr(
            "asago_scenario_generator.pipeline.generate.tree._postprocess_attack_tree_response",
            lambda *a, **kw: SimpleNamespace(),
        )

        profile = _mk_profile()
        client = MagicMock()
        _call_attack_tree_once(
            seed, narrative, client, "use_case",
            profile=profile,
        )
        assert legacy_called

    def test_projection_and_profile_present_use_semantic_flow(self, monkeypatch):
        """Both optional inputs present → semantic flow, not legacy flow.

        Kills the ``profile is not None -> profile is None`` mutant in the
        ``projection_context and profile`` selector.
        """
        semantic_called = False
        legacy_called = False

        def fake_semantic(*args, **kwargs):
            nonlocal semantic_called
            semantic_called = True
            return [], object(), [], "semantic-system", "semantic-user"

        def fake_legacy(*args, **kwargs):
            nonlocal legacy_called
            legacy_called = True
            return [], "legacy-system", "legacy-user"

        monkeypatch.setattr(
            "asago_scenario_generator.pipeline.generate.tree._semantic_draft_flow",
            fake_semantic,
        )
        monkeypatch.setattr(
            "asago_scenario_generator.pipeline.generate.tree._legacy_prompt_flow",
            fake_legacy,
        )
        monkeypatch.setattr(
            "asago_scenario_generator.pipeline.generate.tree._invoke_attack_tree",
            lambda *a, **kw: SimpleNamespace(content="response"),
        )
        monkeypatch.setattr(
            "asago_scenario_generator.pipeline.generate.tree._postprocess_attack_tree_response",
            lambda *a, **kw: SimpleNamespace(),
        )

        _call_attack_tree_once(
            None,
            _mk_narrative(),
            MagicMock(),
            "use_case",
            profile=_mk_profile(),
            projection_context={"selected_steps": []},
        )
        assert semantic_called
        assert not legacy_called


class TestSemanticDraftFlowGuard:
    def test_none_projection_with_profile_returns_none(self):
        assert _semantic_draft_flow(
            None, None, "use_case", None, None, SimpleNamespace()
        ) is None

    def test_projection_with_none_profile_returns_none(self):
        assert _semantic_draft_flow(
            None, None, "use_case", None, {}, None
        ) is None


# ---------------------------------------------------------------------------
# 24. _validate_and_postprocess_tree (profile guard)
# ---------------------------------------------------------------------------


class TestValidateAndPostprocessTree:
    """Kill mutants in the validate-and-postprocess tree guard."""

    def test_none_profile_skips_action_id_resolution(self, monkeypatch):
        """profile is None → skip resolve_action_ids.

        Kills ``profile is not None -> is None``: mutant would call
        resolve_action_ids with None profile → crash.
        """
        from asago_scenario_generator.pipeline.seeds import ScenarioSeed
        from asago_scenario_generator.models.scenario import RiskCardRef

        seed = ScenarioSeed(
            seed_id="AP-T7-01",
            threat_id="T7",
            threat_name="test",
            attack_pattern_name="test",
            attack_pattern_description="test",
            risk_card_ref=RiskCardRef(
                risk_id="r1",
                risk_name="r",
                risk_description="d",
                taxonomy="ibm-risk-atlas",
                confidence=0.5,
                grounding_confidence="high",
            ),
            owasp_llm_ids=["LLM01"],
            agentic_threat_ids=["T7"],
        )
        tree = SimpleNamespace(root=SimpleNamespace())

        # Mock all the called functions
        monkeypatch.setattr(
            "asago_scenario_generator.pipeline.generate.tree._fill_tree_realizations",
            lambda *a, **kw: None,
        )
        monkeypatch.setattr(
            "asago_scenario_generator.pipeline.generate.tree._enforce_zones_attack_tree",
            lambda tree, zones: tree,
        )
        monkeypatch.setattr(
            "asago_scenario_generator.pipeline.generate.tree._validate_pinned_ingress",
            lambda *a, **kw: [],
        )
        monkeypatch.setattr(
            "asago_scenario_generator.pipeline.generate.tree._validate_mandatory_leaves",
            lambda *a, **kw: None,
        )
        monkeypatch.setattr(
            "asago_scenario_generator.pipeline.generate.tree._validate_tree_against_projection",
            lambda *a, **kw: None,
        )

        # If profile is None, resolve_action_ids should NOT be called.
        # The mutant (profile is None) WOULD call it → crash.
        result = _validate_and_postprocess_tree(
            tree, None, None, [], seed, None
        )
        assert result is tree

    def test_non_none_profile_resolves_action_ids(self, monkeypatch):
        """profile is not None → resolve_action_ids called.

        Kills ``profile is not None -> is None``: mutant would SKIP
        resolve_action_ids when profile is not None.
        """
        from asago_scenario_generator.pipeline.seeds import ScenarioSeed
        from asago_scenario_generator.models.scenario import RiskCardRef

        seed = ScenarioSeed(
            seed_id="AP-T7-01",
            threat_id="T7",
            threat_name="test",
            attack_pattern_name="test",
            attack_pattern_description="test",
            risk_card_ref=RiskCardRef(
                risk_id="r1",
                risk_name="r",
                risk_description="d",
                taxonomy="ibm-risk-atlas",
                confidence=0.5,
                grounding_confidence="high",
            ),
            owasp_llm_ids=["LLM01"],
            agentic_threat_ids=["T7"],
        )
        tree = SimpleNamespace(root=SimpleNamespace())

        resolve_called = False

        def fake_resolve_action_ids(t, p):
            nonlocal resolve_called
            resolve_called = True
            return []  # no violations

        monkeypatch.setattr(
            "asago_scenario_generator.pipeline.generate.tree.resolve_action_ids",
            fake_resolve_action_ids,
        )
        monkeypatch.setattr(
            "asago_scenario_generator.pipeline.generate.tree._fill_tree_realizations",
            lambda *a, **kw: None,
        )
        monkeypatch.setattr(
            "asago_scenario_generator.pipeline.generate.tree._enforce_zones_attack_tree",
            lambda tree, zones: tree,
        )
        monkeypatch.setattr(
            "asago_scenario_generator.pipeline.generate.tree._validate_pinned_ingress",
            lambda *a, **kw: [],
        )
        monkeypatch.setattr(
            "asago_scenario_generator.pipeline.generate.tree._validate_mandatory_leaves",
            lambda *a, **kw: None,
        )
        monkeypatch.setattr(
            "asago_scenario_generator.pipeline.generate.tree._validate_tree_against_projection",
            lambda *a, **kw: None,
        )

        profile = _mk_profile()
        _validate_and_postprocess_tree(tree, profile, None, [], seed, None)
        assert resolve_called

    def test_non_none_profile_with_violations_raises(self, monkeypatch):
        """profile is not None and resolve_action_ids returns violations → raises.

        Kills ``profile is not None -> is None``: mutant would skip
        resolve_action_ids entirely, so no ValueError.
        """
        from asago_scenario_generator.pipeline.seeds import ScenarioSeed
        from asago_scenario_generator.models.scenario import RiskCardRef

        seed = ScenarioSeed(
            seed_id="AP-T7-01",
            threat_id="T7",
            threat_name="test",
            attack_pattern_name="test",
            attack_pattern_description="test",
            risk_card_ref=RiskCardRef(
                risk_id="r1",
                risk_name="r",
                risk_description="d",
                taxonomy="ibm-risk-atlas",
                confidence=0.5,
                grounding_confidence="high",
            ),
            owasp_llm_ids=["LLM01"],
            agentic_threat_ids=["T7"],
        )
        tree = SimpleNamespace(root=SimpleNamespace())

        monkeypatch.setattr(
            "asago_scenario_generator.pipeline.generate.tree.resolve_action_ids",
            lambda t, p: ["unresolved-entry-point-id: bad"],
        )
        monkeypatch.setattr(
            "asago_scenario_generator.pipeline.generate.tree._fill_tree_realizations",
            lambda *a, **kw: None,
        )
        monkeypatch.setattr(
            "asago_scenario_generator.pipeline.generate.tree._enforce_zones_attack_tree",
            lambda tree, zones: tree,
        )
        monkeypatch.setattr(
            "asago_scenario_generator.pipeline.generate.tree._validate_pinned_ingress",
            lambda *a, **kw: [],
        )
        monkeypatch.setattr(
            "asago_scenario_generator.pipeline.generate.tree._validate_mandatory_leaves",
            lambda *a, **kw: None,
        )
        monkeypatch.setattr(
            "asago_scenario_generator.pipeline.generate.tree._validate_tree_against_projection",
            lambda *a, **kw: None,
        )

        profile = _mk_profile()
        with pytest.raises(ValueError, match="Unresolved typed action IDs"):
            _validate_and_postprocess_tree(tree, profile, None, [], seed, None)


# ---------------------------------------------------------------------------
# 25. _collect_threat_ids_from_tree (helper used by crossref)
# ---------------------------------------------------------------------------


class TestCollectThreatIdsFromTree:
    """Verify the recursive threat_id collector used by crossref."""

    def test_collects_all_ids_depth_first(self):
        root = _mk_node(
            threat_id="T1",
            children=[
                _mk_node(threat_id="T2"),
                _mk_node(
                    threat_id="T3",
                    children=[_mk_node(threat_id="T4")],
                ),
            ],
        )
        ids = _collect_threat_ids_from_tree(root)
        assert ids == ["T1", "T2", "T3", "T4"]

    def test_collects_none_ids(self):
        root = _mk_node(threat_id=None, children=[_mk_node(threat_id="T1")])
        ids = _collect_threat_ids_from_tree(root)
        assert ids == [None, "T1"]

    def test_no_children(self):
        root = _mk_node(threat_id="T1")
        assert _collect_threat_ids_from_tree(root) == ["T1"]
