"""Tests for post-generation coverage analysis.

Covers:
- Coverage gap analysis (asago-scenario-generator-n63):
  - All entry points covered (no gaps)
  - Some entry points missing
  - All entry points missing
  - Zone coverage gaps
  - Threat coverage gaps
  - Empty scenarios list
- Actor profile diversity:
  - Diverse actor types (no flag)
  - Monotone actor types (flagged)
  - Single scenario edge case
  - Missing actor profile (unknown)
  - Empty scenarios list
- Coverage report output
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from asago_scenario_generator.models.attack_tree import (
    AiSystemAction,
    AttackTree,
    AttackTreeNode,
    GateType,
)
from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    ToolInventoryEntry,
    compute_entry_point_id,
)
from asago_scenario_generator.models.scenario import (
    ActorAccessProvenance,
    ActorProfile,
    ArchitectureMatch,
    AttackComplexity,
    CallMetadata,
    CallName,
    CapabilityProfileRef,
    FacetingMetadata,
    GenerationMetadata,
    LikelihoodLevel,
    NarrativeLayer,
    NarrativeStep,
    Priority,
    PrioritySignals,
    RiskCardRef,
    ScenarioEnvelope,
    SeverityLevel,
    StructuralExposureSignal,
    TaxonomyChain,
    TechniqueMaturity,
)
from asago_scenario_generator.pipeline.candidates import (
    CandidateTriple,
    FilteredSeed,
    compute_candidate_id,
)
from asago_scenario_generator.pipeline.coverage import (
    AttackerDiversityResult,
    CoverageGaps,
    EntryPointGap,
    _normalize_entry_point,
    analyze_attacker_diversity,
    analyze_coverage_gaps,
    write_coverage_report,
)
from asago_scenario_generator.pipeline.generate import compute_scenario_id
from asago_scenario_generator.pipeline.seeds import ScenarioSeed
from asago_scenario_generator.models import ThreatSurface, ThreatSurfaceEntry
from tests.helpers.projection_factory import (
    make_behavior_spec,
    make_projection_block,
)
from tests.helpers.realization_helper import make_realizations

# ---------------------------------------------------------------------------
# Fixtures: helpers to build minimal valid objects
# ---------------------------------------------------------------------------


def _make_risk_card_ref(risk_id: str = "test-risk") -> RiskCardRef:
    return RiskCardRef(
        risk_id=risk_id,
        risk_name="Test Risk",
        risk_description="A test risk.",
        taxonomy="ibm-risk-atlas",
        confidence=0.9,
        grounding_confidence="high",
    )


def _make_envelope(
    entry_point: str = "user prompts (zone 1)",
    zone_sequence: list[str] | None = None,
    agentic_threat_ids: list[str] | None = None,
    scenario_seed: str = "AP-T1-01",
    summary: str = "The attacker exploits user prompts to inject malicious instructions.",
    step_actions: list[str] | None = None,
    actor_type: str | None = "adversarial-user",
    entry_point_id: str | None = None,
) -> ScenarioEnvelope:
    """Build a minimal valid ScenarioEnvelope for testing."""
    if zone_sequence is None:
        zone_sequence = ["input", "reasoning"]
    if agentic_threat_ids is None:
        agentic_threat_ids = ["T1"]
    if step_actions is None:
        step_actions = ["I craft a malicious prompt to inject commands."]

    steps = [
        NarrativeStep(
            step_number=i + 1,
            zone=zone_sequence[min(i, len(zone_sequence) - 1)],
            action=action,
            effect="The system processes the input.",
            projected_step_ids=(f"step.{i + 1}",),
            realizations=make_realizations(
                (f"step.{i + 1}",),
                action_kind="prepare",
                executor_role="attacker",
                boundary_position="crossing",
            ),
        )
        for i, action in enumerate(step_actions)
    ]

    narrative = NarrativeLayer(
        title="Test Scenario",
        summary=summary,
        entry_point=entry_point,
        zone_sequence=zone_sequence,
        steps=steps,
    )

    attack_tree = AttackTree(
        id="tree-AP-T1-01",
        seed_id="AP-T1-01",
        goal="Compromise the system",
        root=AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Path A",
                    gate=GateType.LEAF,
                    zone="input",
                    action=AiSystemAction(),
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Path B",
                    gate=GateType.LEAF,
                    zone="reasoning",
                    action=AiSystemAction(),
                ),
            ],
        ),
    )

    faceting = FacetingMetadata(
        risk_card=_make_risk_card_ref(),
        taxonomy_chain=TaxonomyChain(
            owasp_llm_ids=["LLM01"],
            agentic_threat_ids=agentic_threat_ids,
            scenario_seed=scenario_seed,
        ),
        capability_profile=CapabilityProfileRef(
            zones_traversed=zone_sequence,
            architecture_match=ArchitectureMatch.explicit,
            entry_point=entry_point,
        ),
        maestro_layers=[1, 2],
    )

    priority = Priority(
        composite=0.7,
        signals=PrioritySignals(
            technique_maturity=TechniqueMaturity.feasible,
            risk_impact=SeverityLevel.high,
            risk_likelihood=LikelihoodLevel.medium,
            attack_complexity=AttackComplexity.medium,
            architecture_match=ArchitectureMatch.explicit,
            structural_exposure=StructuralExposureSignal.none,
        ),
    )

    generation = GenerationMetadata(
        model="test-model",
        call_metadata=[
            CallMetadata(
                call=CallName.narrative,
                prompt_tokens=100,
                completion_tokens=200,
                duration_ms=1000,
            ),
        ],
    )

    actor_profile = None
    if actor_type is not None:
        access = ActorAccessProvenance(
            initial_entry_point_id=(
                entry_point_id
                if entry_point_id is not None
                else "ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            ),
            ingress_mode="direct",
            access_class="public",
        )
        actor_profile = ActorProfile(
            actor_type=actor_type,  # type: ignore[arg-type]
            capability_level="intermediate",
            beliefs=["The system exposes a chat API"],
            desires=["Exfiltrate sensitive data"],
            intentions=["Exploit the chat interface"],
            resources=["open-source tools"],
            access=access,
        )

    return ScenarioEnvelope(
        projection=make_projection_block(),
        scenario_id=compute_scenario_id(
            "20260101T000000_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "cand:v2:7e57c0de000000000000000000000000",
            1,
        ),
        candidate_id="cand:v2:7e57c0de000000000000000000000000",
        initial_entry_point_id=(
            entry_point_id
            if entry_point_id is not None
            else "ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ),
        generated_at=datetime.now(tz=UTC),
        generator_version="0.1.0",
        actor_profile=actor_profile,
        narrative=narrative,
        attack_tree=attack_tree,
        behavior_spec=make_behavior_spec(),
        faceting=faceting,
        priority=priority,
        generation=generation,
    )


def _make_profile(
    entry_points: list[str] | None = None,
    zones_active: list[str] | None = None,
) -> CapabilityProfile:
    if entry_points is None:
        entry_points = [
            "user prompts (zone 1)",
            "document uploads (zone 1)",
            "admin console (zone 2)",
        ]
    if zones_active is None:
        zones_active = ["input", "reasoning", "tool_execution"]
    kc = ["KC1.1"]
    if "tool_execution" in zones_active:
        kc.append("KC6.1.1")
    if "memory" in zones_active:
        kc.append("KC4.3")
    if "inter_agent" in zones_active:
        kc.append("KC2.3")
    kw = {}
    if any(c.startswith(("KC5.", "KC6.")) for c in kc):
        kw["tool_inventory"] = [
            ToolInventoryEntry(name="test_tool", description="A test tool")
        ]
    return CapabilityProfile(
        zones_active=zones_active,
        entry_points=entry_points,
        confidence="high",
        kc_subcodes=kc,
        **kw,
    )


def _make_threat_surface(
    threat_ids: list[list[str]] | None = None,
    attack_pattern_ids: list[list[str]] | None = None,
) -> ThreatSurface:
    """Build a ThreatSurface with the given threat IDs per entry.

    Args:
        threat_ids: Per-entry lists of agentic threat IDs.
        attack_pattern_ids: Per-entry lists of attack pattern IDs.
            When ``None``, defaults to ``["AP-{t}-01" for t in ids]`` for
            each entry.
    """
    if threat_ids is None:
        threat_ids = [["T1", "T2"]]
    entries = []
    for i, ids in enumerate(threat_ids):
        ap_ids = (
            attack_pattern_ids[i]
            if attack_pattern_ids is not None
            else [f"AP-{t}-01" for t in ids]
        )
        entries.append(
            ThreatSurfaceEntry(
                risk_card=_make_risk_card_ref(f"risk-{i}"),
                owasp_llm_ids=["LLM01"],
                agentic_threat_ids=ids,
                attack_pattern_ids=ap_ids,
            )
        )
    return ThreatSurface(entries=entries, governance_only=[])


# ---------------------------------------------------------------------------
# Coverage gap analysis tests (asago-scenario-generator-n63)
# ---------------------------------------------------------------------------


class TestCoverageGaps:
    """Tests for analyze_coverage_gaps."""

    def test_all_entry_points_covered(self):
        """When every entry point has at least one scenario, no gaps."""
        profile = _make_profile(
            entry_points=["ep-a (zone 1)", "ep-b (zone 2)"],
            zones_active=["input", "reasoning"],
        )
        threat_surface = _make_threat_surface([["T1"]])
        scenarios = [
            _make_envelope(entry_point="ep-a (zone 1)", agentic_threat_ids=["T1"]),
            _make_envelope(entry_point="ep-b (zone 2)", agentic_threat_ids=["T1"]),
        ]

        gaps = analyze_coverage_gaps(profile, threat_surface, scenarios)
        assert gaps.uncovered_entry_points == []
        assert not gaps.has_gaps

    def test_some_entry_points_missing(self):
        """When some entry points have no scenarios, they appear as gaps."""
        profile = _make_profile(
            entry_points=["ep-a (zone 1)", "ep-b (zone 2)", "ep-c (zone 3)"],
            zones_active=["input", "reasoning", "tool_execution"],
        )
        threat_surface = _make_threat_surface([["T1"]])
        scenarios = [
            _make_envelope(
                entry_point="ep-a (zone 1)",
                zone_sequence=["input", "reasoning", "tool_execution"],
                agentic_threat_ids=["T1"],
            ),
        ]

        gaps = analyze_coverage_gaps(profile, threat_surface, scenarios)
        uncovered_names = {ep.name for ep in gaps.uncovered_entry_points}
        assert uncovered_names == {"ep-b (zone 2)", "ep-c (zone 3)"}
        assert gaps.has_gaps

    def test_all_entry_points_missing(self):
        """No scenarios at all means every entry point is uncovered."""
        profile = _make_profile(
            entry_points=["ep-a (zone 1)", "ep-b (zone 2)"],
        )
        threat_surface = _make_threat_surface([["T1"]])
        scenarios: list[ScenarioEnvelope] = []

        gaps = analyze_coverage_gaps(profile, threat_surface, scenarios)
        uncovered_names = {ep.name for ep in gaps.uncovered_entry_points}
        assert uncovered_names == {"ep-a (zone 1)", "ep-b (zone 2)"}

    def test_all_zones_covered(self):
        """When all active zones are traversed, no zone gaps."""
        profile = _make_profile(zones_active=["input", "reasoning", "tool_execution"])
        threat_surface = _make_threat_surface([["T1"]])
        scenarios = [
            _make_envelope(
                zone_sequence=["input", "reasoning", "tool_execution"],
                agentic_threat_ids=["T1"],
            ),
        ]

        gaps = analyze_coverage_gaps(profile, threat_surface, scenarios)
        assert gaps.uncovered_zones == []

    def test_some_zones_uncovered(self):
        """Zones not traversed by any scenario appear as gaps."""
        profile = _make_profile(zones_active=["input", "reasoning", "tool_execution"])
        threat_surface = _make_threat_surface([["T1"]])
        scenarios = [
            _make_envelope(
                zone_sequence=["input", "reasoning"], agentic_threat_ids=["T1"]
            ),
        ]

        gaps = analyze_coverage_gaps(profile, threat_surface, scenarios)
        assert gaps.uncovered_zones == ["tool_execution"]

    def test_all_threats_covered(self):
        """When every in-scope threat has at least one scenario, no gaps."""
        threat_surface = _make_threat_surface([["T1", "T2"]])
        profile = _make_profile()
        scenarios = [
            _make_envelope(agentic_threat_ids=["T1", "T2"]),
        ]

        gaps = analyze_coverage_gaps(profile, threat_surface, scenarios)
        assert gaps.uncovered_threats == []

    def test_some_threats_uncovered(self):
        """Threats with no scenarios appear as gaps."""
        threat_surface = _make_threat_surface([["T1", "T2", "T3"]])
        profile = _make_profile()
        scenarios = [
            _make_envelope(agentic_threat_ids=["T1"]),
        ]

        gaps = analyze_coverage_gaps(profile, threat_surface, scenarios)
        assert set(gaps.uncovered_threats) == {"T2", "T3"}

    def test_empty_scenarios_flags_everything(self):
        """With no scenarios, all entry points, zones, threats, and APs are gaps."""
        profile = _make_profile(
            entry_points=["ep-a (zone 1)"],
            zones_active=["input", "reasoning"],
        )
        threat_surface = _make_threat_surface([["T1"]])

        gaps = analyze_coverage_gaps(profile, threat_surface, [])
        assert [ep.name for ep in gaps.uncovered_entry_points] == ["ep-a (zone 1)"]
        assert gaps.uncovered_zones == ["input", "reasoning"]
        assert gaps.uncovered_threats == ["T1"]
        assert gaps.uncovered_attack_patterns == ["AP-T1-01"]
        assert gaps.has_gaps

    def test_zones_across_multiple_scenarios(self):
        """Zone coverage is the union across all scenarios."""
        profile = _make_profile(zones_active=["input", "reasoning", "tool_execution"])
        threat_surface = _make_threat_surface([["T1"]])
        scenarios = [
            _make_envelope(zone_sequence=["input"], agentic_threat_ids=["T1"]),
            _make_envelope(
                zone_sequence=["reasoning", "tool_execution"], agentic_threat_ids=["T1"]
            ),
        ]

        gaps = analyze_coverage_gaps(profile, threat_surface, scenarios)
        assert gaps.uncovered_zones == []

    def test_threats_across_multiple_entries(self):
        """Threats from multiple threat surface entries are all checked."""
        threat_surface = _make_threat_surface([["T1"], ["T2"]])
        profile = _make_profile()
        scenarios = [
            _make_envelope(agentic_threat_ids=["T1"]),
        ]

        gaps = analyze_coverage_gaps(profile, threat_surface, scenarios)
        assert gaps.uncovered_threats == ["T2"]

    def test_to_dict(self):
        """CoverageGaps.to_dict returns a serializable dict."""
        gaps = CoverageGaps(
            uncovered_entry_points=[
                EntryPointGap(entry_point_id="ep-a-id", name="ep-a")
            ],
            uncovered_zones=["tool_execution"],
            uncovered_threats=["T5"],
            uncovered_attack_patterns=["AP-T5-01"],
        )
        d = gaps.to_dict()
        assert d["uncovered_entry_points"] == [
            {"entry_point_id": "ep-a-id", "name": "ep-a"}
        ]
        assert d["uncovered_zones"] == ["tool_execution"]
        assert d["uncovered_threats"] == ["T5"]
        assert d["uncovered_attack_patterns"] == ["AP-T5-01"]

    def test_has_gaps_false_when_empty(self):
        """No gaps means has_gaps is False."""
        gaps = CoverageGaps()
        assert not gaps.has_gaps

    def test_has_gaps_true_for_entry_points(self):
        gaps = CoverageGaps(
            uncovered_entry_points=[
                EntryPointGap(entry_point_id="ep-a-id", name="ep-a")
            ]
        )
        assert gaps.has_gaps

    def test_has_gaps_true_for_zones(self):
        gaps = CoverageGaps(uncovered_zones=["tool_execution"])
        assert gaps.has_gaps

    def test_has_gaps_true_for_threats(self):
        gaps = CoverageGaps(uncovered_threats=["T5"])
        assert gaps.has_gaps

    def test_has_gaps_true_for_attack_patterns(self):
        gaps = CoverageGaps(uncovered_attack_patterns=["AP-T5-01"])
        assert gaps.has_gaps

    # --- Per-attack-pattern coverage tests (asago-scenario-generator-4kfz) ---

    def test_all_attack_patterns_covered(self):
        """When every in-scope AP has at least one scenario, no AP gaps."""
        threat_surface = _make_threat_surface(
            [["T1"]],
            attack_pattern_ids=[["AP-T1-01", "AP-T1-02"]],
        )
        profile = _make_profile()
        scenarios = [
            _make_envelope(agentic_threat_ids=["T1"], scenario_seed="AP-T1-01"),
            _make_envelope(agentic_threat_ids=["T1"], scenario_seed="AP-T1-02"),
        ]

        gaps = analyze_coverage_gaps(profile, threat_surface, scenarios)
        assert gaps.uncovered_attack_patterns == []

    def test_some_attack_patterns_uncovered(self):
        """APs with no scenario appear as gaps even when threat is covered."""
        threat_surface = _make_threat_surface(
            [["T9"]],
            attack_pattern_ids=[["AP-T9-01", "AP-T9-03", "AP-T9-05"]],
        )
        profile = _make_profile()
        # Only AP-T9-03 produces a scenario; AP-T9-01 and AP-T9-05 have none.
        scenarios = [
            _make_envelope(agentic_threat_ids=["T9"], scenario_seed="AP-T9-03"),
        ]

        gaps = analyze_coverage_gaps(profile, threat_surface, scenarios)
        # T9 is covered at threat level (has at least one scenario)
        assert gaps.uncovered_threats == []
        # But two individual APs are uncovered
        assert gaps.uncovered_attack_patterns == ["AP-T9-01", "AP-T9-05"]

    def test_all_aps_uncovered_when_threat_fully_rejected(self):
        """When all APs for a threat are rejected, both threat and AP gaps appear."""
        threat_surface = _make_threat_surface(
            [["T8"]],
            attack_pattern_ids=[["AP-T8-01", "AP-T8-02", "AP-T8-03"]],
        )
        profile = _make_profile()
        # No scenarios at all for T8
        scenarios: list[ScenarioEnvelope] = []

        gaps = analyze_coverage_gaps(profile, threat_surface, scenarios)
        assert gaps.uncovered_threats == ["T8"]
        assert gaps.uncovered_attack_patterns == ["AP-T8-01", "AP-T8-02", "AP-T8-03"]

    def test_attack_patterns_across_multiple_entries(self):
        """AP coverage checks span all threat surface entries."""
        threat_surface = _make_threat_surface(
            [["T1"], ["T2"]],
            attack_pattern_ids=[["AP-T1-01"], ["AP-T2-01", "AP-T2-02"]],
        )
        profile = _make_profile()
        scenarios = [
            _make_envelope(agentic_threat_ids=["T1"], scenario_seed="AP-T1-01"),
            _make_envelope(agentic_threat_ids=["T2"], scenario_seed="AP-T2-01"),
        ]

        gaps = analyze_coverage_gaps(profile, threat_surface, scenarios)
        assert gaps.uncovered_threats == []
        assert gaps.uncovered_attack_patterns == ["AP-T2-02"]


# ---------------------------------------------------------------------------
# Entry point normalization tests (asago-scenario-generator-8dd)
# ---------------------------------------------------------------------------


class TestNormalizeEntryPoint:
    """Tests for _normalize_entry_point helper."""

    def test_lowercases(self):
        assert (
            _normalize_entry_point("User Prompts (Zone 1)") == "user prompts (zone 1)"
        )

    def test_strips_whitespace(self):
        assert (
            _normalize_entry_point("  user prompts (zone 1)  ")
            == "user prompts (zone 1)"
        )

    def test_collapses_internal_whitespace(self):
        assert (
            _normalize_entry_point("user  prompts   (zone 1)")
            == "user prompts (zone 1)"
        )

    def test_removes_trailing_period(self):
        assert (
            _normalize_entry_point("user prompts (zone 1).") == "user prompts (zone 1)"
        )

    def test_removes_trailing_comma(self):
        assert (
            _normalize_entry_point("user prompts (zone 1),") == "user prompts (zone 1)"
        )

    def test_removes_trailing_semicolon(self):
        assert (
            _normalize_entry_point("user prompts (zone 1);") == "user prompts (zone 1)"
        )

    def test_identity_for_already_normalized(self):
        assert (
            _normalize_entry_point("user prompts (zone 1)") == "user prompts (zone 1)"
        )


class TestCoverageGapsEntryPointMatching:
    """Tests for entry point coverage with normalized matching (asago-scenario-generator-8dd)."""

    def test_partial_entry_points_used(self):
        """Scenarios using only 3 of 5 profile entry points → 2 uncovered."""
        profile = _make_profile(
            entry_points=[
                "user prompts (zone 1)",
                "document uploads (zone 1)",
                "admin console (zone 2)",
                "API gateway (zone 3)",
                "message queue (zone 3)",
            ],
            zones_active=["input", "reasoning", "tool_execution"],
        )
        threat_surface = _make_threat_surface([["T1"]])
        scenarios = [
            _make_envelope(
                entry_point="user prompts (zone 1)",
                zone_sequence=["input", "reasoning", "tool_execution"],
                agentic_threat_ids=["T1"],
            ),
            _make_envelope(
                entry_point="admin console (zone 2)",
                zone_sequence=["input", "reasoning", "tool_execution"],
                agentic_threat_ids=["T1"],
            ),
            _make_envelope(
                entry_point="API gateway (zone 3)",
                zone_sequence=["input", "reasoning", "tool_execution"],
                agentic_threat_ids=["T1"],
            ),
        ]

        gaps = analyze_coverage_gaps(profile, threat_surface, scenarios)
        uncovered_names = {ep.name for ep in gaps.uncovered_entry_points}
        assert uncovered_names == {
            "document uploads (zone 1)",
            "message queue (zone 3)",
        }
        assert len(gaps.uncovered_entry_points) == 2
        assert gaps.has_gaps

    def test_all_entry_points_used_no_gaps(self):
        """All entry points used → 0 uncovered."""
        profile = _make_profile(
            entry_points=["ep-a (zone 1)", "ep-b (zone 2)", "ep-c (zone 3)"],
            zones_active=["input", "reasoning", "tool_execution"],
        )
        threat_surface = _make_threat_surface([["T1"]])
        scenarios = [
            _make_envelope(
                entry_point="ep-a (zone 1)",
                zone_sequence=["input", "reasoning", "tool_execution"],
                agentic_threat_ids=["T1"],
            ),
            _make_envelope(
                entry_point="ep-b (zone 2)",
                zone_sequence=["input", "reasoning", "tool_execution"],
                agentic_threat_ids=["T1"],
            ),
            _make_envelope(
                entry_point="ep-c (zone 3)",
                zone_sequence=["input", "reasoning", "tool_execution"],
                agentic_threat_ids=["T1"],
            ),
        ]

        gaps = analyze_coverage_gaps(profile, threat_surface, scenarios)
        assert gaps.uncovered_entry_points == []
        assert not gaps.has_gaps

    def test_empty_scenarios_all_uncovered(self):
        """Empty scenarios list → all entry points uncovered."""
        profile = _make_profile(
            entry_points=[
                "user prompts (zone 1)",
                "document uploads (zone 1)",
                "admin console (zone 2)",
            ],
            zones_active=["input", "reasoning"],
        )
        threat_surface = _make_threat_surface([["T1"]])
        scenarios: list[ScenarioEnvelope] = []

        gaps = analyze_coverage_gaps(profile, threat_surface, scenarios)
        uncovered_names = {ep.name for ep in gaps.uncovered_entry_points}
        assert uncovered_names == {
            "user prompts (zone 1)",
            "document uploads (zone 1)",
            "admin console (zone 2)",
        }
        assert len(gaps.uncovered_entry_points) == 3

    def test_case_insensitive_matching(self):
        """LLM-generated entry points with different casing should match."""
        profile = _make_profile(
            entry_points=["User Prompts (Zone 1)", "Admin Console (Zone 2)"],
            zones_active=["input", "reasoning"],
        )
        threat_surface = _make_threat_surface([["T1"]])
        scenarios = [
            _make_envelope(
                entry_point="user prompts (zone 1)",
                zone_sequence=["input", "reasoning"],
                agentic_threat_ids=["T1"],
            ),
            _make_envelope(
                entry_point="ADMIN CONSOLE (ZONE 2)",
                zone_sequence=["input", "reasoning"],
                agentic_threat_ids=["T1"],
            ),
        ]

        gaps = analyze_coverage_gaps(profile, threat_surface, scenarios)
        assert gaps.uncovered_entry_points == []

    def test_whitespace_normalized_matching(self):
        """Extra whitespace in LLM output should not cause false gaps."""
        profile = _make_profile(
            entry_points=["user prompts (zone 1)", "admin console (zone 2)"],
            zones_active=["input", "reasoning"],
        )
        threat_surface = _make_threat_surface([["T1"]])
        scenarios = [
            _make_envelope(
                entry_point="user  prompts  (zone  1)",
                zone_sequence=["input", "reasoning"],
                agentic_threat_ids=["T1"],
            ),
            _make_envelope(
                entry_point="  admin console (zone 2)  ",
                zone_sequence=["input", "reasoning"],
                agentic_threat_ids=["T1"],
            ),
        ]

        gaps = analyze_coverage_gaps(profile, threat_surface, scenarios)
        assert gaps.uncovered_entry_points == []

    def test_trailing_punctuation_normalized(self):
        """Trailing punctuation from LLM output should not cause false gaps."""
        profile = _make_profile(
            entry_points=["user prompts (zone 1)", "admin console (zone 2)"],
            zones_active=["input", "reasoning"],
        )
        threat_surface = _make_threat_surface([["T1"]])
        scenarios = [
            _make_envelope(
                entry_point="user prompts (zone 1).",
                zone_sequence=["input", "reasoning"],
                agentic_threat_ids=["T1"],
            ),
            _make_envelope(
                entry_point="admin console (zone 2)",
                zone_sequence=["input", "reasoning"],
                agentic_threat_ids=["T1"],
            ),
        ]

        gaps = analyze_coverage_gaps(profile, threat_surface, scenarios)
        assert gaps.uncovered_entry_points == []

    def test_uncovered_preserves_original_profile_names(self):
        """Uncovered entry points should use the original profile names, not normalized."""
        profile = _make_profile(
            entry_points=["User Prompts (Zone 1)", "Admin Console (Zone 2)"],
            zones_active=["input", "reasoning"],
        )
        threat_surface = _make_threat_surface([["T1"]])
        scenarios: list[ScenarioEnvelope] = []

        gaps = analyze_coverage_gaps(profile, threat_surface, scenarios)
        # Should preserve original casing from the profile
        uncovered_names = {ep.name for ep in gaps.uncovered_entry_points}
        assert "User Prompts (Zone 1)" in uncovered_names
        assert "Admin Console (Zone 2)" in uncovered_names


# ---------------------------------------------------------------------------
# Actor profile diversity tests
# ---------------------------------------------------------------------------


class TestAnalyzeAttackerDiversity:
    """Tests for analyze_attacker_diversity (actor_profile based)."""

    def test_empty_scenarios(self):
        result = analyze_attacker_diversity([])
        assert result.model_counts == {}
        assert result.dominant_model is None
        assert result.is_flagged is False

    def test_diverse_actor_types_no_flag(self):
        """When scenarios have varied actor types, no flag."""
        scenarios = [
            _make_envelope(actor_type="malicious-insider"),
            _make_envelope(actor_type="supply-chain-actor"),
            _make_envelope(actor_type="hacktivist"),
            _make_envelope(actor_type="cybercriminal"),
            _make_envelope(actor_type="nation-state"),
        ]

        result = analyze_attacker_diversity(scenarios)
        assert not result.is_flagged
        assert len(result.model_counts) == 5

    def test_monotone_actor_type_flagged(self):
        """When >80% of scenarios use the same actor type, flag is raised."""
        scenarios = [
            _make_envelope(actor_type="adversarial-user"),
            _make_envelope(actor_type="adversarial-user"),
            _make_envelope(actor_type="adversarial-user"),
            _make_envelope(actor_type="adversarial-user"),
            _make_envelope(actor_type="adversarial-user"),
        ]

        result = analyze_attacker_diversity(scenarios)
        assert result.is_flagged
        assert result.dominant_model == "adversarial-user"
        assert result.dominant_fraction > 0.8

    def test_exactly_at_threshold_not_flagged(self):
        """Exactly 80% (4/5) should NOT be flagged (> threshold, not >=)."""
        scenarios = [
            _make_envelope(actor_type="cybercriminal"),
            _make_envelope(actor_type="cybercriminal"),
            _make_envelope(actor_type="cybercriminal"),
            _make_envelope(actor_type="cybercriminal"),
            _make_envelope(actor_type="malicious-insider"),
        ]

        result = analyze_attacker_diversity(scenarios)
        # 4 cybercriminal + 1 malicious-insider = 4/5 = 0.8
        assert result.dominant_fraction == pytest.approx(0.8)
        assert not result.is_flagged

    def test_single_scenario_flagged(self):
        """One scenario = 100% one type, which is > 80%, so it IS flagged."""
        scenarios = [
            _make_envelope(actor_type="nation-state"),
        ]

        result = analyze_attacker_diversity(scenarios)
        assert result.dominant_fraction == 1.0
        assert result.is_flagged

    def test_no_actor_profile_classified_as_unknown(self):
        """Envelopes without actor_profile are classified as 'unknown'."""
        scenarios = [
            _make_envelope(actor_type=None),
            _make_envelope(actor_type=None),
            _make_envelope(actor_type=None),
        ]

        result = analyze_attacker_diversity(scenarios)
        assert result.dominant_model == "unknown"
        assert result.is_flagged

    def test_mixed_with_and_without_actor_profile(self):
        """Mix of envelopes with and without actor_profile."""
        scenarios = [
            _make_envelope(actor_type="cybercriminal"),
            _make_envelope(actor_type="nation-state"),
            _make_envelope(actor_type=None),
        ]

        result = analyze_attacker_diversity(scenarios)
        assert result.model_counts == {
            "cybercriminal": 1,
            "nation-state": 1,
            "unknown": 1,
        }
        assert not result.is_flagged

    def test_to_dict(self):
        result = AttackerDiversityResult(
            model_counts={"cybercriminal": 3, "malicious-insider": 1},
            dominant_model="cybercriminal",
            dominant_fraction=0.75,
            is_flagged=False,
        )
        d = result.to_dict()
        assert d["model_counts"] == {"cybercriminal": 3, "malicious-insider": 1}
        assert d["dominant_model"] == "cybercriminal"
        assert d["dominant_fraction"] == 0.75
        assert d["is_flagged"] is False


# ---------------------------------------------------------------------------
# Coverage report output tests
# ---------------------------------------------------------------------------


class TestWriteCoverageReport:
    """Tests for write_coverage_report."""

    def test_writes_json_file(self, tmp_path: Path):
        gaps = CoverageGaps(
            uncovered_entry_points=[
                EntryPointGap(entry_point_id="ep-a-id", name="ep-a")
            ],
            uncovered_zones=["tool_execution"],
            uncovered_threats=["T5"],
        )
        diversity = AttackerDiversityResult(
            model_counts={"external_attacker": 5},
            dominant_model="external_attacker",
            dominant_fraction=1.0,
            is_flagged=True,
        )

        path = write_coverage_report(gaps, tmp_path, diversity)
        assert path.exists()
        assert path.name == "coverage-gaps.json"

        data = json.loads(path.read_text())
        assert data["coverage_gaps"]["uncovered_entry_points"] == [
            {"entry_point_id": "ep-a-id", "name": "ep-a"}
        ]
        assert data["coverage_gaps"]["uncovered_zones"] == ["tool_execution"]
        assert data["coverage_gaps"]["uncovered_threats"] == ["T5"]
        assert data["attacker_diversity"]["is_flagged"] is True
        assert data["attacker_diversity"]["dominant_model"] == "external_attacker"

    def test_writes_empty_gaps(self, tmp_path: Path):
        gaps = CoverageGaps()

        path = write_coverage_report(gaps, tmp_path)
        data = json.loads(path.read_text())
        assert data["coverage_gaps"]["uncovered_entry_points"] == []
        assert data["coverage_gaps"]["uncovered_zones"] == []
        assert data["coverage_gaps"]["uncovered_threats"] == []
        assert "attacker_diversity" not in data

    def test_writes_with_attacker_diversity(self, tmp_path: Path):
        gaps = CoverageGaps()
        diversity = AttackerDiversityResult(
            model_counts={"insider": 2, "external_attacker": 3},
            dominant_model="external_attacker",
            dominant_fraction=0.6,
            is_flagged=False,
        )

        path = write_coverage_report(gaps, tmp_path, diversity)
        data = json.loads(path.read_text())
        assert data["attacker_diversity"]["dominant_model"] == "external_attacker"
        assert data["attacker_diversity"]["is_flagged"] is False


# ---------------------------------------------------------------------------
# Gap attribution tests (asago-scenario-generator-qaeh)
# ---------------------------------------------------------------------------


def _make_seed(
    seed_id: str = "AP-T1-01",
    threat_id: str = "T1",
    threat_name: str = "Prompt Injection",
    agentic_threat_ids: list[str] | None = None,
) -> ScenarioSeed:
    """Build a minimal valid ScenarioSeed for testing."""
    if agentic_threat_ids is None:
        agentic_threat_ids = [threat_id]
    return ScenarioSeed(
        seed_id=seed_id,
        threat_id=threat_id,
        threat_name=threat_name,
        attack_pattern_name=f"Attack pattern for {threat_name}",
        attack_pattern_description=f"Description of {threat_name} attack pattern.",
        risk_card_ref=_make_risk_card_ref(),
        contributing_risk_cards=[_make_risk_card_ref()],
        owasp_llm_ids=["LLM01"],
        agentic_threat_ids=agentic_threat_ids,
    )


def _make_candidate(
    seed_id: str = "AP-T1-01",
    threat_id: str = "T1",
    entry_point: str = "user prompts (zone 1)",
) -> CandidateTriple:
    """Build a minimal CandidateTriple for testing."""
    technique_ids = ("AML.T0051",)
    ep_id = compute_entry_point_id(entry_point, "input", None)
    cand_id = compute_candidate_id(seed_id, ep_id, technique_ids)
    return CandidateTriple(
        seed_id=seed_id,
        threat_id=threat_id,
        threat_name=f"Threat {threat_id}",
        attack_pattern_name=f"Attack pattern {seed_id}",
        attack_pattern_description=f"Description for {seed_id}.",
        entry_point=entry_point,
        atlas_technique_ids=technique_ids,
        atlas_technique_names=("LLM Prompt Injection",),
        atlas_technique_descriptions=("Inject instructions into LLM prompts.",),
        risk_card_ref=_make_risk_card_ref(),
        owasp_llm_ids=["LLM01"],
        direction="input",
        entry_point_id=ep_id,
        candidate_id=cand_id,
    )


def _make_filtered_seed(
    seed_id: str = "AP-T1-01",
    threat_id: str = "T1",
    pinned_entry_point: str = "user prompts (zone 1)",
) -> FilteredSeed:
    """Build a minimal FilteredSeed for testing."""
    technique_ids = ("AML.T0051",)
    ep_id = compute_entry_point_id(pinned_entry_point, "input", None)
    cand_id = compute_candidate_id(seed_id, ep_id, technique_ids)
    return FilteredSeed(
        seed_id=seed_id,
        threat_id=threat_id,
        threat_name=f"Threat {threat_id}",
        attack_pattern_name=f"Attack pattern {seed_id}",
        attack_pattern_description=f"Description for {seed_id}.",
        risk_card_ref=_make_risk_card_ref(),
        owasp_llm_ids=["LLM01"],
        agentic_threat_ids=[threat_id],
        pinned_entry_point=pinned_entry_point,
        pinned_technique_ids=technique_ids,
        pinned_technique_names=("LLM Prompt Injection",),
        entry_point_id=ep_id,
        candidate_id=cand_id,
    )


# ---------------------------------------------------------------------------
# Direct branch tests for the decomposed coverage-analysis helpers
# ---------------------------------------------------------------------------


class TestBuildEntryPointNameLookup:
    """Branch tests for _build_entry_point_name_lookup."""

    def test_includes_attacker_accessible_only(self) -> None:
        from asago_scenario_generator.models.capability_profile import EntryPoint
        from asago_scenario_generator.pipeline.coverage import (
            _build_entry_point_name_lookup,
        )

        profile = CapabilityProfile(
            zones_active=["input", "reasoning"],
            entry_points=[
                EntryPoint(
                    name="user prompts (zone 1)",
                    direction="input",
                    controllability="direct",
                ),
                EntryPoint(
                    name="logs (output)",
                    direction="output",
                    controllability="system",
                ),
            ],
            confidence="high",
            kc_subcodes=["KC1.1"],
        )
        lookup = _build_entry_point_name_lookup(
            profile, set(profile.zones_active)
        )
        assert "logs (output)" not in lookup
        assert "user prompts (zone 1)" in lookup

    def test_normalized_name_groups_entry_points(self) -> None:
        from asago_scenario_generator.pipeline.coverage import (
            _build_entry_point_name_lookup,
        )

        profile = _make_profile(entry_points=["User Prompts (Zone 1)"])
        lookup = _build_entry_point_name_lookup(profile, {"input", "reasoning"})
        assert lookup == {"user prompts (zone 1)": {profile.entry_points[0].entry_point_id}}


class TestRecordScenarioUsage:
    """Branch tests for _record_scenario_usage."""

    def test_candidate_filter_entry_point_id_credited(self) -> None:
        from asago_scenario_generator.pipeline.coverage import _record_scenario_usage

        envelope = _make_envelope(
            entry_point="user prompts (zone 1)",
            zone_sequence=["input", "reasoning"],
            agentic_threat_ids=["T1"],
        ).model_copy(
            update={"candidate_filter": {"entry_point_id": "ep:v1:direct-canonical"}}
        )
        used: set[str] = set()
        zones: set[str] = set()
        threats: set[str] = set()
        patterns: set[str] = set()
        _record_scenario_usage(envelope, {}, used, zones, threats, patterns)
        assert used == {"ep:v1:direct-canonical"}
        assert zones == {"input", "reasoning"}
        assert threats == {"T1"}
        assert patterns == {"AP-T1-01"}

    def test_narrative_fallback_unique_name_credited(self) -> None:
        from asago_scenario_generator.pipeline.coverage import _record_scenario_usage

        envelope = _make_envelope(entry_point="user prompts (zone 1)")
        lookup = {"user prompts (zone 1)": {"ep:v1:canonical"}}
        used: set[str] = set()
        _record_scenario_usage(envelope, lookup, used, set(), set(), set())
        assert used == {"ep:v1:canonical"}

    def test_ambiguous_name_not_credited(self) -> None:
        from asago_scenario_generator.pipeline.coverage import _record_scenario_usage

        envelope = _make_envelope(entry_point="ambiguous name")
        lookup = {"ambiguous name": {"ep:v1:one", "ep:v1:two"}}
        used: set[str] = set()
        _record_scenario_usage(envelope, lookup, used, set(), set(), set())
        assert used == set()

    def test_unknown_name_not_credited(self) -> None:
        from asago_scenario_generator.pipeline.coverage import _record_scenario_usage

        envelope = _make_envelope(entry_point="totally unknown name")
        used: set[str] = set()
        _record_scenario_usage(envelope, {}, used, set(), set(), set())
        assert used == set()


class TestUncoveredAttackerEntryPoints:
    def test_reports_uncovered_accessible_and_skips_inaccessible(self) -> None:
        from asago_scenario_generator.models.capability_profile import EntryPoint
        from asago_scenario_generator.pipeline.coverage import (
            _uncovered_attacker_entry_points,
        )

        profile = CapabilityProfile(
            zones_active=["input", "reasoning"],
            entry_points=[
                EntryPoint(
                    name="ep-a (zone 1)",
                    direction="input",
                    controllability="direct",
                ),
                EntryPoint(
                    name="ep-out (output)",
                    direction="output",
                    controllability="system",
                ),
            ],
            confidence="high",
            kc_subcodes=["KC1.1"],
        )
        gaps = _uncovered_attacker_entry_points(
            profile, {"input", "reasoning"}, set()
        )
        assert [g.name for g in gaps] == ["ep-a (zone 1)"]

    def test_covered_ids_not_reported(self) -> None:
        from asago_scenario_generator.pipeline.coverage import (
            _uncovered_attacker_entry_points,
        )

        profile = _make_profile(entry_points=["ep-a (zone 1)"])
        ep_id = profile.entry_points[0].entry_point_id
        assert _uncovered_attacker_entry_points(
            profile, {"input", "reasoning"}, {ep_id}
        ) == []


class TestInScopeAndUncoveredSets:
    def test_in_scope_attack_ids(self) -> None:
        from asago_scenario_generator.pipeline.coverage import _in_scope_attack_ids

        surface = _make_threat_surface(
            [["T1"], ["T2"]],
            attack_pattern_ids=[["AP-T1-01"], ["AP-T2-01", "AP-T2-02"]],
        )
        threats, patterns = _in_scope_attack_ids(surface)
        assert threats == {"T1", "T2"}
        assert patterns == {"AP-T1-01", "AP-T2-01", "AP-T2-02"}

    def test_sorted_uncovered(self) -> None:
        from asago_scenario_generator.pipeline.coverage import _sorted_uncovered

        assert _sorted_uncovered({"T2", "T1", "T3"}, {"T2"}) == ["T1", "T3"]
        assert _sorted_uncovered({"T1"}, {"T1"}) == []


class TestLogCoverageGapWarnings:
    def test_logs_all_four_categories(self, caplog) -> None:
        from asago_scenario_generator.pipeline.coverage import (
            CoverageGaps,
            _log_coverage_gap_warnings,
        )

        with caplog.at_level("WARNING", logger="asago_scenario_generator.pipeline.coverage"):
            _log_coverage_gap_warnings(
                CoverageGaps(
                    uncovered_entry_points=[EntryPointGap("ep-a", "ep-a")],
                    uncovered_zones=["input"],
                    uncovered_threats=["T1"],
                    uncovered_attack_patterns=["AP-T1-01"],
                )
            )
        assert "entry point(s)" in caplog.text
        assert "active zone(s)" in caplog.text
        assert "in-scope threat(s)" in caplog.text
        assert "attack pattern(s)" in caplog.text

    def test_no_warnings_when_covered(self, caplog) -> None:
        from asago_scenario_generator.pipeline.coverage import (
            CoverageGaps,
            _log_coverage_gap_warnings,
        )

        with caplog.at_level("WARNING", logger="asago_scenario_generator.pipeline.coverage"):
            _log_coverage_gap_warnings(CoverageGaps())
        assert caplog.text == ""


class TestActorProfileHelpers:
    def test_actor_type_of_with_and_without_profile(self) -> None:
        from asago_scenario_generator.pipeline.coverage import _actor_type_of

        assert _actor_type_of(_make_envelope(actor_type="cybercriminal")) == (
            "cybercriminal"
        )
        assert _actor_type_of(_make_envelope(actor_type=None)) == "unknown"

    def test_goal_category_of_with_and_without_parent(self) -> None:
        from asago_scenario_generator.pipeline.coverage import _goal_category_of

        envelope = _make_envelope(actor_type="cybercriminal")
        assert _goal_category_of(envelope) == "uncategorized"
        with_parent = envelope.model_copy(
            update={
                "actor_profile": envelope.actor_profile.model_copy(
                    update={"goal_category_parent": "exfiltration"}
                )
            }
        )
        assert _goal_category_of(with_parent) == "exfiltration"

    def test_count_actor_profiles(self) -> None:
        from asago_scenario_generator.pipeline.coverage import _count_actor_profiles

        scenarios = [
            _make_envelope(actor_type="cybercriminal"),
            _make_envelope(actor_type="cybercriminal"),
            _make_envelope(actor_type=None),
        ]
        models, goals = _count_actor_profiles(scenarios)
        assert models == {"cybercriminal": 2, "unknown": 1}
        assert goals == {"uncategorized": 3}


class TestReportPayloadHelpers:
    def test_coverage_plan_payload_model_dump_branch(self) -> None:
        from asago_scenario_generator.pipeline.coverage import (
            _coverage_plan_payload,
        )

        payload = _coverage_plan_payload(_make_risk_card_ref())
        assert payload["risk_id"] == "test-risk"

    def test_coverage_plan_payload_to_dict_branch(self) -> None:
        from asago_scenario_generator.pipeline.coverage import (
            _coverage_plan_payload,
        )

        class _PlainPlan:
            def to_dict(self) -> dict:
                return {"schema_version": "1"}

        assert _coverage_plan_payload(_PlainPlan()) == {"schema_version": "1"}

    def test_finalization_payload(self) -> None:
        from asago_scenario_generator.pipeline.coverage import _finalization_payload

        payload = _finalization_payload(_make_risk_card_ref())
        assert payload["risk_id"] == "test-risk"

    def test_stage_ledger_payload(self) -> None:
        from asago_scenario_generator.pipeline.coverage import _stage_ledger_payload
        from asago_scenario_generator.pipeline.coverage_planning import (
            STAGE_FILTER,
            StageLedger,
        )

        assert _stage_ledger_payload(None) is None
        assert _stage_ledger_payload(StageLedger()) is None
        ledger = StageLedger()
        ledger.record("ep-a", "c1", STAGE_FILTER, "rejected")
        assert _stage_ledger_payload(ledger)["events"][0]["candidate_id"] == "c1"

    def test_add_optional(self) -> None:
        from asago_scenario_generator.pipeline.coverage import _add_optional

        report: dict = {}
        _add_optional(report, "key", "value")
        assert report == {"key": "value"}
        _add_optional(report, "absent", None)
        assert report == {"key": "value"}

    def test_attacker_diversity_payload(self) -> None:
        from asago_scenario_generator.pipeline.coverage import (
            AttackerDiversityResult,
            _attacker_diversity_payload,
        )

        diversity = AttackerDiversityResult(
            model_counts={"cybercriminal": 1},
            goal_counts={"exfiltration": 1},
            dominant_model="cybercriminal",
            dominant_fraction=1.0,
            is_flagged=False,
        )
        assert _attacker_diversity_payload(diversity)["model_counts"] == {
            "cybercriminal": 1
        }
        assert _attacker_diversity_payload(None) is None

    def test_coverage_universe_payload(self) -> None:
        from asago_scenario_generator.pipeline.coverage import (
            _coverage_universe_payload,
        )
        from asago_scenario_generator.pipeline.coverage_planning import (
            CoverageUniverse,
        )

        universe = CoverageUniverse()
        assert _coverage_universe_payload(universe)["feasible_targets"] == []
        assert _coverage_universe_payload(None) is None

    def test_quality_gaps_payload(self) -> None:
        from asago_scenario_generator.pipeline.coverage import (
            _quality_gaps_payload,
        )
        from asago_scenario_generator.pipeline.coverage_planning import (
            CoverageGapReason,
            QualityGap,
        )

        gap = QualityGap(
            entry_point_id="ep-a",
            entry_point_name="Target A",
            reason=CoverageGapReason.NO_SEED,
        )
        payload = _quality_gaps_payload([gap])
        assert payload == [gap.to_dict()]
        assert _quality_gaps_payload([]) is None
        assert _quality_gaps_payload(None) is None

    def test_coverage_summary_payload(self) -> None:
        from asago_scenario_generator.pipeline.coverage import (
            _coverage_summary_payload,
        )
        from asago_scenario_generator.pipeline.coverage_planning import (
            CoverageSummary,
        )

        summary = CoverageSummary(
            covered_feasible=["ep-a"],
            policy_exclusions=[],
            structural_gaps=[],
            selection_limitations=[],
            runtime_generation_gaps=[],
            quarantine_admission_failures=[],
            projection_limitations=[],
        )
        assert _coverage_summary_payload(summary)["covered_feasible"] == ["ep-a"]
        assert _coverage_summary_payload(None) is None
