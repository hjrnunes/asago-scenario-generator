"""Property tests for taxonomy threat-surface derivation and scope gating.

Hypothesis-driven invariants over generated fixture inputs for
``determine_threat_surface`` / ``determine_threat_scope``:

- **Partition**: every risk card yields exactly one entry, actionable or
  governance-only; governance entries carry no resolved threat IDs.
- **Conservation**: actionable threat IDs stay within the gated in-scope
  set; attack-pattern and ASI unions match the per-threat gating output;
  the LLM ID list matches the card's SSSOM rows in first-seen order.
- **No duplicates**: every ID list in every entry is duplicate-free and
  preserves each source list's relative order (first-seen union).
- **Direct-path join**: a direct-path threat appears only when it shares
  an ATLAS technique with the card's three-hop threats.
- **KC6 ATLAS gate**: capability-gated techniques are dropped exactly
  when the profile lacks any mapping-declared KC6 sub-code.
- **Determinism**: identical inputs produce identical surfaces.
- **Persistence round trip**: the serialised surface survives the
  YAML dump/validate cycle used by ``pipeline.io`` and ``pipeline.runner``.
- **Gating monotonicity**: adding KC sub-codes never drops an attack
  pattern whose kc_requires gate previously passed.

Each hypothesis example materialises its fixtures in its own
``TemporaryDirectory`` — ``load_kc_threat_mapping`` is path-keyed and
cached, so reusing one directory across examples would poison later
examples with the first example's parsed mapping.  All inputs are
fixture files; no LLM endpoint is contacted.
"""

from __future__ import annotations

import json
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from hypothesis import HealthCheck, given, settings, strategies as st

from asago_scenario_generator.data.loaders import load_risk_extraction
from asago_scenario_generator.data.threat_gating import (
    _evaluate_prerequisite_capabilities,
    determine_threat_scope,
)
from asago_scenario_generator.models import CapabilityProfile
from asago_scenario_generator.models.capability_profile import ToolInventoryEntry
from asago_scenario_generator.models.threat_surface import ThreatSurface
from asago_scenario_generator.pipeline.threats import (
    _KC6_GATED_TECHNIQUES,
    determine_threat_surface,
)

# ---------------------------------------------------------------------------
# Generation pools
# ---------------------------------------------------------------------------

_THREAT_POOL = [f"T{i}" for i in range(1, 7)]  # fixture threats file declares T1..T6
_LLM_POOL = [f"LLM{i:02d}" for i in range(1, 11)]
_ATLAS_POOL = ["AML.T0001", "AML.T0002", "AML.T0053", "AML.T0080"]  # T0053 gated
_ASI_POOL = [f"ASI{i:02d}" for i in range(1, 11)]
_KC_POOL = ["KC1.1", "KC2.3", "KC4.3", "KC6.4"]
_RISK_POOL = ["atlas-prompt-injection", "atlas-memory-poisoning", "atlas-orphan-risk"]


# ---------------------------------------------------------------------------
# Fixture model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SurfaceFixture:
    """Generated inputs for one derivation, kept in public-data shapes."""

    risks: list[str] = field(default_factory=list)
    sssom_rows: list[tuple[str, str]] = field(default_factory=list)  # (risk, LLM id)
    t_to_llm: list[tuple[str, str]] = field(default_factory=list)  # (threat, LLM id)
    t_to_atlas: dict[str, list[str]] = field(default_factory=dict)
    t_to_asi: list[tuple[str, str]] = field(default_factory=list)  # (threat, ASI id)
    t_direct: list[str] = field(default_factory=list)
    kc_mapping: dict[str, list[str]] = field(default_factory=dict)
    profile_kcs: list[str] = field(default_factory=list)
    patterns: dict[str, str] = field(default_factory=dict)  # pattern id -> threat id

    def reachable_threats(self, risk_id: str) -> set[str]:
        """Threats reachable from the card via the LLM hop (pre-gating)."""
        llm_ids = {llm for r, llm in self.sssom_rows if r == risk_id}
        return {t for t, llm in self.t_to_llm if llm in llm_ids}

    def atlas_of(self, threat_id: str) -> set[str]:
        return set(self.t_to_atlas.get(threat_id, []))


@st.composite
def surface_fixtures(draw: st.DrawFn) -> SurfaceFixture:
    """Draw a small, valid fixture input set."""
    risks = draw(
        st.lists(st.sampled_from(_RISK_POOL), min_size=0, max_size=3, unique=True)
    )

    # SSSOM rows: each card maps to 0..2 distinct OWASP LLM entries.
    sssom_rows = []
    for risk in risks:
        for llm in draw(
            st.lists(st.sampled_from(_LLM_POOL), min_size=0, max_size=2, unique=True)
        ):
            sssom_rows.append((risk, llm))

    t_to_llm = draw(
        st.lists(
            st.tuples(st.sampled_from(_THREAT_POOL), st.sampled_from(_LLM_POOL)),
            min_size=0,
            max_size=5,
            unique=True,
        )
    )
    t_to_atlas: dict[str, list[str]] = {}
    for threat in draw(
        st.lists(st.sampled_from(_THREAT_POOL), min_size=0, max_size=4, unique=True)
    ):
        atlas = draw(
            st.lists(st.sampled_from(_ATLAS_POOL), min_size=1, max_size=2, unique=True)
        )
        # Draw each per-threat ATLAS list in canonical order so overlapping
        # source lists cannot disagree (T1=[X,Y] vs T2=[Y,X] is unsatisfiable
        # for the "each source list is an ordered subsequence" property).
        t_to_atlas[threat] = sorted(atlas)
    t_to_asi = sorted(
        draw(
            st.lists(
                st.tuples(st.sampled_from(_THREAT_POOL), st.sampled_from(_ASI_POOL)),
                min_size=0,
                max_size=3,
                unique=True,
            )
        )
    )
    t_direct = draw(
        st.lists(st.sampled_from(_THREAT_POOL), min_size=0, max_size=3, unique=True)
    )

    # Gating inputs: independent KC-code choices for mapping and profile.
    mapping_codes = draw(
        st.lists(st.sampled_from(_KC_POOL), min_size=0, max_size=4, unique=True)
    )
    kc_mapping = {
        code: draw(
            st.lists(st.sampled_from(_THREAT_POOL), min_size=0, max_size=2, unique=True)
        )
        for code in mapping_codes
    }
    profile_kcs = draw(
        st.lists(st.sampled_from(_KC_POOL), min_size=1, max_size=4, unique=True)
    )

    patterns: dict[str, str] = {}
    for threat in draw(
        st.lists(st.sampled_from(_THREAT_POOL), min_size=0, max_size=2, unique=True)
    ):
        for n in range(draw(st.integers(min_value=1, max_value=2))):
            patterns[f"AP-{threat}-{n:02d}"] = threat

    return SurfaceFixture(
        risks=risks,
        sssom_rows=sssom_rows,
        t_to_llm=t_to_llm,
        t_to_atlas=t_to_atlas,
        t_to_asi=t_to_asi,
        t_direct=t_direct,
        kc_mapping=kc_mapping,
        profile_kcs=profile_kcs,
        patterns=patterns,
    )


# ---------------------------------------------------------------------------
# Materialisation
# ---------------------------------------------------------------------------


@contextmanager
def _case_dir_ctx() -> Iterator[Path]:
    """A fresh per-example directory with deterministic lifetime."""
    with tempfile.TemporaryDirectory() as td:
        yield Path(td)


def _write_risk_cards(path: Path, fixture: SurfaceFixture) -> None:
    risks = [
        {
            "risk_id": risk_id,
            "risk_name": f"Risk {risk_id}",
            "risk_description": f"Description for {risk_id}",
            "taxonomy": "ibm-risk-atlas",
            "confidence": 0.9,
            "grounding_confidence": "high",
        }
        for risk_id in fixture.risks
    ]
    path.write_text(json.dumps({"risks": risks}) + "\n", encoding="utf-8")


def _write_sssom(path: Path, fixture: SurfaceFixture) -> None:
    header = (
        "subject_id\tsubject_source\tpredicate_id\tobject_id"
        "\tobject_source\tmapping_justification"
    )
    lines = [header]
    for risk_id, llm_id in fixture.sssom_rows:
        num = llm_id.removeprefix("LLM")
        lines.append(
            f"{risk_id}\tibm-risk-atlas\tskos:exactMatch\tllm{num}-fixture"
            "\towasp-llm-top10\tsemapv:ManualMappingCuration"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_cross_taxonomy(path: Path, fixture: SurfaceFixture) -> None:
    data = {
        "t_to_llm": [
            {"source": threat, "target": llm} for threat, llm in fixture.t_to_llm
        ],
        "t_to_atlas": [
            {"source": threat, "targets": list(atlas)}
            for threat, atlas in fixture.t_to_atlas.items()
        ],
        "t_to_asi": [
            {"source": threat, "target": asi} for threat, asi in fixture.t_to_asi
        ],
        "t_direct": [
            {"source": threat, "source_name": f"Direct {threat}"}
            for threat in fixture.t_direct
        ],
    }
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def _write_threats(path: Path) -> None:
    threats = {tid: {"id": tid, "name": f"Threat {tid}"} for tid in _THREAT_POOL}
    path.write_text(
        yaml.safe_dump({"threats": threats}, sort_keys=False), encoding="utf-8"
    )


def _write_kc_mapping(path: Path, fixture: SurfaceFixture) -> None:
    data = {"kc_to_threats": fixture.kc_mapping, "hitl": {"threat_ids": []}}
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def _write_attack_patterns(path: Path, fixture: SurfaceFixture) -> None:
    patterns = {
        pid: {
            "id": pid,
            "threat_id": threat,
            "name": pid,
            "description": f"Pattern {pid}",
        }
        for pid, threat in fixture.patterns.items()
    }
    path.write_text(
        yaml.safe_dump({"patterns": patterns}, sort_keys=False), encoding="utf-8"
    )


def _materialize(
    case_dir: Path, fixture: SurfaceFixture
) -> tuple[Path, Path, Path, Path, Path]:
    """Write the fixture files and return their paths."""
    risks_path = case_dir / "risk-extraction.json"
    sssom_path = case_dir / "risk-atlas-llm.sssom.tsv"
    cross_path = case_dir / "cross-taxonomy-mappings.yaml"
    kc_path = case_dir / "kc-threat-mapping.yaml"
    patterns_path = case_dir / "attack-patterns.yaml"
    _write_risk_cards(risks_path, fixture)
    _write_sssom(sssom_path, fixture)
    _write_cross_taxonomy(cross_path, fixture)
    _write_kc_mapping(kc_path, fixture)
    _write_threats(case_dir / "threats.yaml")
    _write_attack_patterns(patterns_path, fixture)
    return risks_path, sssom_path, cross_path, kc_path, patterns_path


def _profile(fixture: SurfaceFixture) -> CapabilityProfile:
    return _make_profile(fixture.profile_kcs)


def _make_profile(codes: list[str]) -> CapabilityProfile:
    """A valid profile; KC codes activating tool_execution require an inventory."""
    return CapabilityProfile(
        zones_active=["input", "reasoning"],
        entry_points=["user input (zone 1)"],
        confidence="medium",
        kc_subcodes=list(codes),
        tool_inventory=[
            ToolInventoryEntry(name="test_tool", description="A test tool")
        ],
    )


def _derive(fixture: SurfaceFixture) -> tuple[ThreatSurface, CapabilityProfile]:
    """Materialise the fixture in a fresh temp dir and derive the surface."""
    with _case_dir_ctx() as case_dir:
        risks_path, sssom_path, cross_path, kc_path, patterns_path = _materialize(
            case_dir, fixture
        )
        profile = _profile(fixture)
        surface = determine_threat_surface(
            profile,
            load_risk_extraction(risks_path),
            sssom_path,
            cross_path,
            threats_path=case_dir / "threats.yaml",
            kc_mapping_path=kc_path,
            attack_patterns_path=patterns_path,
        )
        return surface, profile


def _first_seen_union(lists: list[list[str]]) -> list[str]:
    """De-duplicated first-seen union preserving source order."""
    collected: list[str] = []
    for items in lists:
        for item in items:
            if item not in collected:
                collected.append(item)
    return collected


def _kc6_gate_off(fixture: SurfaceFixture) -> bool:
    """True when the KC6 ATLAS gate removes gated techniques."""
    mapping_declares_kc6 = any(code.startswith("KC6.") for code in fixture.kc_mapping)
    profile_has_kc6 = any(code.startswith("KC6.") for code in fixture.profile_kcs)
    return not (mapping_declares_kc6 and profile_has_kc6)


# ---------------------------------------------------------------------------
# Properties
# ---------------------------------------------------------------------------


@settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(fixture=surface_fixtures())
def test_every_risk_card_yields_exactly_one_entry(fixture: SurfaceFixture):
    """Actionable and governance entries partition the risk cards."""
    surface, _ = _derive(fixture)

    actionable_ids = {e.risk_card.risk_id for e in surface.entries}
    governance_ids = {e.risk_card.risk_id for e in surface.governance_only}
    assert actionable_ids.isdisjoint(governance_ids)
    assert actionable_ids | governance_ids == set(fixture.risks)
    assert len(surface.entries) + len(surface.governance_only) == len(fixture.risks)
    for entry in surface.entries:
        assert entry.governance_only is False
    for entry in surface.governance_only:
        assert entry.governance_only is True


@settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(fixture=surface_fixtures())
def test_no_duplicate_ids_in_any_entry_list(fixture: SurfaceFixture):
    """Every ID list on every entry is duplicate-free (first-seen union)."""
    surface, _ = _derive(fixture)
    for entry in surface.entries + surface.governance_only:
        for field_name in (
            "owasp_llm_ids",
            "agentic_threat_ids",
            "atlas_technique_ids",
            "attack_pattern_ids",
            "owasp_asi_ids",
        ):
            values = getattr(entry, field_name)
            assert len(values) == len(set(values)), (
                f"duplicate {field_name} in {entry.risk_card.risk_id}: {values}"
            )


@settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(fixture=surface_fixtures())
def test_threat_membership_stays_within_gated_scope(fixture: SurfaceFixture):
    """Actionable threats come from the gated scope; governance entries carry none."""
    with _case_dir_ctx() as case_dir:
        risks_path, sssom_path, cross_path, kc_path, patterns_path = _materialize(
            case_dir, fixture
        )
        profile = _profile(fixture)
        scope = determine_threat_scope(
            profile,
            case_dir / "threats.yaml",
            kc_path,
            patterns_path,
        )
        in_scope_ids = {e.threat_id for e in scope.in_scope}
        surface = determine_threat_surface(
            profile,
            load_risk_extraction(risks_path),
            sssom_path,
            cross_path,
            threats_path=case_dir / "threats.yaml",
            kc_mapping_path=kc_path,
            attack_patterns_path=patterns_path,
        )

    kept_by_threat = {e.threat_id: set(e.attack_pattern_ids) for e in scope.in_scope}
    for entry in surface.entries:
        assert set(entry.agentic_threat_ids) <= in_scope_ids
        kept_union: set[str] = set()
        for threat in entry.agentic_threat_ids:
            kept_union.update(kept_by_threat.get(threat, set()))
        assert set(entry.attack_pattern_ids) == kept_union
        expected_asi = {
            asi
            for threat, asi in fixture.t_to_asi
            if threat in entry.agentic_threat_ids
        }
        assert set(entry.owasp_asi_ids) == expected_asi

    for entry in surface.governance_only:
        assert entry.agentic_threat_ids == []
        assert entry.attack_pattern_ids == []
        assert entry.atlas_technique_ids == []
        assert entry.owasp_asi_ids == []


@settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(fixture=surface_fixtures())
def test_llm_ids_match_card_sssom_rows_in_first_seen_order(fixture: SurfaceFixture):
    """The LLM ID list is the card's SSSOM rows, deduplicated in row order."""
    surface, _ = _derive(fixture)
    for entry in surface.entries + surface.governance_only:
        risk_id = entry.risk_card.risk_id
        rows = [llm for r, llm in fixture.sssom_rows if r == risk_id]
        assert entry.owasp_llm_ids == _first_seen_union([rows])


@settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(fixture=surface_fixtures())
def test_direct_threats_join_only_on_atlas_overlap(fixture: SurfaceFixture):
    """A direct-path threat is appended only when it shares ATLAS techniques
    with the card's in-scope three-hop threats, in sorted order."""
    surface, _ = _derive(fixture)
    direct_set = set(fixture.t_direct)

    for entry in surface.entries:
        risk_id = entry.risk_card.risk_id
        three_hop = [
            t
            for t in entry.agentic_threat_ids
            if t in fixture.reachable_threats(risk_id)
        ]
        three_hop_atlas = set()
        for threat in three_hop:
            three_hop_atlas.update(fixture.atlas_of(threat))
        for threat in entry.agentic_threat_ids:
            if threat not in three_hop:
                # Joined via the direct path: must be direct-mapped and overlap.
                assert threat in direct_set, (
                    f"{threat} joined {risk_id} without a direct mapping"
                )
                assert fixture.atlas_of(threat) & three_hop_atlas, (
                    f"{threat} joined {risk_id} without ATLAS overlap"
                )
        joined_direct = [
            t
            for t in entry.agentic_threat_ids
            if t in direct_set and t not in three_hop
        ]
        assert joined_direct == sorted(joined_direct)


@settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(fixture=surface_fixtures())
def test_kc6_gate_drops_gated_techniques_only_without_kc6(fixture: SurfaceFixture):
    """ATLAS techniques gated on KC6 stay exactly when the profile has a
    mapping-declared KC6 sub-code."""
    surface, _ = _derive(fixture)
    gate_off = _kc6_gate_off(fixture)

    for entry in surface.entries:
        expected_atlas = _first_seen_union(
            [fixture.t_to_atlas.get(t, []) for t in entry.agentic_threat_ids]
        )
        if gate_off:
            assert entry.atlas_technique_ids == [
                a for a in expected_atlas if a not in _KC6_GATED_TECHNIQUES
            ]
        else:
            assert entry.atlas_technique_ids == expected_atlas


@settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(fixture=surface_fixtures())
def test_atlas_and_asi_lists_preserve_source_order(fixture: SurfaceFixture):
    """Each threat's own ATLAS/ASI order survives as a subsequence of the
    entry's union (relative first-seen ordering)."""
    surface, _ = _derive(fixture)
    gate_off = _kc6_gate_off(fixture)
    asi_by_threat: dict[str, list[str]] = {}
    for threat, asi in fixture.t_to_asi:
        asi_by_threat.setdefault(threat, []).append(asi)

    for entry in surface.entries:
        for threat in entry.agentic_threat_ids:
            atlas_source = fixture.t_to_atlas.get(threat, [])
            if gate_off:
                atlas_source = [
                    a for a in atlas_source if a not in _KC6_GATED_TECHNIQUES
                ]
            restricted = [
                a for a in entry.atlas_technique_ids if a in set(atlas_source)
            ]
            assert restricted == _first_seen_union([atlas_source])
            asi_source = asi_by_threat.get(threat, [])
            restricted_asi = [a for a in entry.owasp_asi_ids if a in set(asi_source)]
            assert restricted_asi == _first_seen_union([asi_source])


@settings(max_examples=25, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(fixture=surface_fixtures())
def test_derivation_is_deterministic(fixture: SurfaceFixture):
    """Identical inputs produce identical surfaces."""
    first, _ = _derive(fixture)
    second, _ = _derive(fixture)
    assert first.model_dump() == second.model_dump()


@settings(max_examples=25, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(fixture=surface_fixtures())
def test_surface_survives_yaml_round_trip(fixture: SurfaceFixture):
    """The persisted surface shape round-trips through YAML unchanged."""
    surface, _ = _derive(fixture)
    dumped = yaml.safe_dump(
        surface.model_dump(mode="json", exclude_none=True),
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
    )
    restored = ThreatSurface.model_validate(yaml.safe_load(dumped))
    assert restored == surface


@settings(max_examples=25, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(fixture=surface_fixtures())
def test_scope_covers_every_threat_in_the_taxonomy_file(fixture: SurfaceFixture):
    """Gating evaluates every declared threat: none are silently skipped."""
    with _case_dir_ctx() as case_dir:
        _, _, _, kc_path, patterns_path = _materialize(case_dir, fixture)
        scope = determine_threat_scope(
            _profile(fixture),
            case_dir / "threats.yaml",
            kc_path,
            patterns_path,
        )
    in_scope_ids = {e.threat_id for e in scope.in_scope}
    out_ids = {tid for group in scope.out_of_scope for tid in group.threat_ids}
    assert in_scope_ids | out_ids == set(_THREAT_POOL)
    assert in_scope_ids.isdisjoint(out_ids)


# ---------------------------------------------------------------------------
# Gating monotonicity
# ---------------------------------------------------------------------------


@settings(max_examples=50, deadline=None)
@given(
    any_codes=st.lists(st.sampled_from(_KC_POOL), max_size=3, unique=True),
    all_codes=st.lists(st.sampled_from(_KC_POOL), max_size=3, unique=True),
    base=st.lists(st.sampled_from(_KC_POOL), min_size=1, max_size=4, unique=True),
    extra=st.lists(st.sampled_from(_KC_POOL), max_size=2, unique=True),
)
def test_kc_requires_gate_is_monotone_in_profile_codes(
    any_codes: list[str], all_codes: list[str], base: list[str], extra: list[str]
):
    """Adding KC sub-codes never drops a pattern whose kc_requires passed."""
    prereqs = {"kc_requires": {"any": any_codes, "all": all_codes}}
    base_profile = _make_profile(base)
    superset_profile = _make_profile(sorted(set(base) | set(extra)))
    if _evaluate_prerequisite_capabilities(prereqs, base_profile):
        assert _evaluate_prerequisite_capabilities(prereqs, superset_profile)
