"""Property tests for taxonomy threat-scope gating.

Hypothesis-driven invariants over generated fixture inputs for
``determine_threat_scope``:

- **Coverage**: gating evaluates every declared threat exactly once.
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

from asago_scenario_generator.data.threat_gating import (
    _evaluate_prerequisite_capabilities,
    determine_threat_scope,
)
from asago_scenario_generator.models import CapabilityProfile
from asago_scenario_generator.models.capability_profile import ToolInventoryEntry

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


# ---------------------------------------------------------------------------
# Properties
# ---------------------------------------------------------------------------


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
