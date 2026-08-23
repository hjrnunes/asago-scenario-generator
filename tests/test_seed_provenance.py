"""Tests for SSSOM provenance fields on ScenarioSeed.

Verifies that expand_seeds() populates owasp_origin, laaf_technique_ids,
and atlas_provenance_ids from the SSSOM provenance index, and that
atlas_provenance_ids is filtered to only include ATLAS IDs that survived
zone-3 gating (i.e. present in the seed's atlas_technique_ids).

The pipeline iterates AP-* IDs directly from ThreatSurfaceEntry.attack_pattern_ids,
looking up pattern metadata from the AP-* YAML. SSSOM provenance provides
LAAF and ATLAS cross-references for each AP-* pattern.
"""

from __future__ import annotations

from unittest.mock import patch

from asago_scenario_generator.data.sssom import SSSOMMapping
from asago_scenario_generator.models.capability_profile import ConfidenceLevel
from asago_scenario_generator.models.scenario import RiskCardRef
from asago_scenario_generator.pipeline.seeds import ScenarioSeed, expand_seeds
from asago_scenario_generator.models import ThreatSurface, ThreatSurfaceEntry


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_ref(risk_id: str = "risk-1", confidence: float = 0.9) -> RiskCardRef:
    return RiskCardRef(
        risk_id=risk_id,
        risk_name=f"Risk {risk_id}",
        risk_description=f"Description for {risk_id}",
        taxonomy="ibm-risk-atlas",
        confidence=confidence,
        grounding_confidence=ConfidenceLevel.high,
    )


def _make_entry(
    risk_id: str,
    owasp_llm_ids: list[str],
    agentic_threat_ids: list[str],
    attack_pattern_ids: list[str],
    atlas_technique_ids: list[str] | None = None,
) -> ThreatSurfaceEntry:
    return ThreatSurfaceEntry(
        risk_card=_make_ref(risk_id),
        owasp_llm_ids=owasp_llm_ids,
        agentic_threat_ids=agentic_threat_ids,
        atlas_technique_ids=atlas_technique_ids or [],
        attack_pattern_ids=attack_pattern_ids,
    )


def _sssom(
    subject_id: str,
    object_id: str,
    object_source: str,
) -> SSSOMMapping:
    return SSSOMMapping(
        subject_id=subject_id,
        subject_source="asago-scenario-generator",
        predicate_id="skos:relatedMatch",
        object_id=object_id,
        object_source=object_source,
        mapping_justification="semapv:ManualMappingCuration",
    )


# Minimal threat data
_FAKE_THREATS = {
    "T7": {
        "name": "Misaligned & Deceptive Behaviors",
        "scenarios": [
            {"id": "T7-S1", "name": "Constraint bypass", "description": "Desc"},
        ],
    },
    "T2": {
        "name": "Tool Misuse",
        "scenarios": [
            {"id": "T2-S1", "name": "Tool abuse", "description": "Desc tool"},
        ],
    },
}

# Attack pattern metadata (keyed by AP-* ID)
_FAKE_PATTERNS = {
    "AP-T7-01": {
        "id": "AP-T7-01",
        "name": "Constraint bypass via goal-priority conflict",
        "description": "Agent bypasses constraints",
        "threat_id": "T7",
    },
    "AP-T2-01": {
        "id": "AP-T2-01",
        "name": "Unauthorized tool invocation",
        "description": "Agent invokes tools beyond its mandate",
        "threat_id": "T2",
    },
}

# SSSOM provenance: AP-T7-01 derives from T7-S1, maps to LAAF S1/M3
# and ATLAS AML.T0054 / AML.T0015 / AML.T0053 (zone-3-gated)
_FAKE_PROV = [
    _sssom("AP-T7-01", "T7-S1", "owasp-agentic"),
    _sssom("AP-T7-01", "S1", "laaf"),
    _sssom("AP-T7-01", "M3", "laaf"),
    _sssom("AP-T7-01", "AML.T0054", "mitre-atlas"),
    _sssom("AP-T7-01", "AML.T0015", "mitre-atlas"),
    _sssom("AP-T7-01", "AML.T0053", "mitre-atlas"),  # zone-3-gated
]


def _run_expand(
    entries: list[ThreatSurfaceEntry],
    patterns: dict | None = None,
    prov: list[SSSOMMapping] | None = None,
) -> list[ScenarioSeed]:
    """Run expand_seeds with fake data, bypassing file I/O."""
    ts = ThreatSurface(entries=entries, governance_only=[])
    with (
        patch(
            "asago_scenario_generator.pipeline.seeds.load_agentic_threats",
            return_value=_FAKE_THREATS,
        ),
        patch(
            "asago_scenario_generator.pipeline.seeds.load_attack_patterns",
            return_value=patterns if patterns is not None else {},
        ),
        patch(
            "asago_scenario_generator.pipeline.seeds.load_attack_pattern_provenance",
            return_value=prov if prov is not None else [],
        ),
    ):
        return expand_seeds(ts)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestSeedProvenanceFields:
    """Verify owasp_origin, laaf_technique_ids, atlas_provenance_ids on seeds."""

    def test_provenance_fields_populated_for_ap_seed(self):
        """AP-T7-01 directly in attack_pattern_ids should carry
        LAAF and ATLAS provenance from SSSOM."""
        entry = _make_entry(
            "risk-a",
            ["LLM01"],
            ["T7"],
            ["AP-T7-01"],
            atlas_technique_ids=["AML.T0054", "AML.T0015", "AML.T0053"],
        )
        seeds = _run_expand([entry], patterns=_FAKE_PATTERNS, prov=_FAKE_PROV)

        seed = next(s for s in seeds if s.seed_id == "AP-T7-01")
        assert seed.owasp_origin == "T7-S1"
        assert seed.laaf_technique_ids == ["S1", "M3"]
        assert set(seed.atlas_provenance_ids) == {
            "AML.T0054",
            "AML.T0015",
            "AML.T0053",
        }

    def test_attack_pattern_name_from_pattern(self):
        """Seeds should get attack_pattern_name and attack_pattern_description from
        the AP-* pattern dict."""
        entry = _make_entry(
            "risk-a",
            ["LLM01"],
            ["T7"],
            ["AP-T7-01"],
        )
        seeds = _run_expand([entry], patterns=_FAKE_PATTERNS, prov=_FAKE_PROV)

        seed = next(s for s in seeds if s.seed_id == "AP-T7-01")
        assert seed.attack_pattern_name == "Constraint bypass via goal-priority conflict"
        assert seed.attack_pattern_description == "Agent bypasses constraints"

    def test_atlas_provenance_filtered_by_zone3_gating(self):
        """atlas_provenance_ids should only include ATLAS IDs that are present
        in atlas_technique_ids (i.e. survived zone-3 gating).

        AML.T0053 is zone-3-gated and should be excluded when not in
        atlas_technique_ids."""
        # Entry WITHOUT AML.T0053 (zone-3-gated technique excluded)
        entry = _make_entry(
            "risk-a",
            ["LLM01"],
            ["T7"],
            ["AP-T7-01"],
            atlas_technique_ids=["AML.T0054", "AML.T0015"],
        )
        seeds = _run_expand([entry], patterns=_FAKE_PATTERNS, prov=_FAKE_PROV)

        seed = next(s for s in seeds if s.seed_id == "AP-T7-01")
        assert "AML.T0053" not in seed.atlas_provenance_ids
        assert set(seed.atlas_provenance_ids) == {"AML.T0054", "AML.T0015"}

    def test_no_provenance_when_sssom_missing(self):
        """When SSSOM provenance is not available, provenance fields default empty."""
        entry = _make_entry(
            "risk-a",
            ["LLM01"],
            ["T7"],
            ["AP-T7-01"],
            atlas_technique_ids=["AML.T0054"],
        )
        # No provenance data -- load_attack_pattern_provenance raises FileNotFoundError
        ts = ThreatSurface(entries=[entry], governance_only=[])
        with (
            patch(
                "asago_scenario_generator.pipeline.seeds.load_agentic_threats",
                return_value=_FAKE_THREATS,
            ),
            patch(
                "asago_scenario_generator.pipeline.seeds.load_attack_patterns",
                return_value=_FAKE_PATTERNS,
            ),
            patch(
                "asago_scenario_generator.pipeline.seeds.load_attack_pattern_provenance",
                side_effect=FileNotFoundError,
            ),
        ):
            seeds = expand_seeds(ts)

        # Without SSSOM, the pattern is still found (via attack_pattern_ids),
        # but provenance fields are empty
        seed = next(s for s in seeds if s.seed_id == "AP-T7-01")
        assert seed.owasp_origin is None
        assert seed.laaf_technique_ids == []
        assert seed.atlas_provenance_ids == []

    def test_unknown_ap_id_skipped(self):
        """AP IDs not in the patterns dict are silently skipped."""
        entry = _make_entry(
            "risk-a",
            ["LLM01"],
            ["T7"],
            ["AP-T7-99"],  # not in _FAKE_PATTERNS
            atlas_technique_ids=["AML.T0054"],
        )
        seeds = _run_expand([entry], patterns=_FAKE_PATTERNS, prov=[])

        assert len(seeds) == 0

    def test_provenance_defaults_on_model(self):
        """New provenance fields have sensible defaults for backwards compat."""
        seed = ScenarioSeed(
            seed_id="AP-T1-01",
            threat_id="T1",
            threat_name="Test",
            attack_pattern_name="Sub",
            attack_pattern_description="Desc",
            risk_card_ref=_make_ref("risk-1"),
            owasp_llm_ids=["LLM01"],
            agentic_threat_ids=["T1"],
        )
        assert seed.owasp_origin is None
        assert seed.laaf_technique_ids == []
        assert seed.atlas_provenance_ids == []

    def test_merged_seed_atlas_provenance_filtered(self):
        """When two entries merge into one AP-* seed, atlas_provenance_ids is
        filtered against the merged atlas_technique_ids set."""
        # Entry A has AML.T0054
        entry_a = _make_entry(
            "risk-a",
            ["LLM01"],
            ["T7"],
            ["AP-T7-01"],
            atlas_technique_ids=["AML.T0054"],
        )
        # Entry B adds AML.T0015 (but not AML.T0053)
        entry_b = _make_entry(
            "risk-b",
            ["LLM02"],
            ["T7"],
            ["AP-T7-01"],
            atlas_technique_ids=["AML.T0015"],
        )
        seeds = _run_expand(
            [entry_a, entry_b], patterns=_FAKE_PATTERNS, prov=_FAKE_PROV
        )

        seed = next(s for s in seeds if s.seed_id == "AP-T7-01")
        # Merged atlas_technique_ids should be ["AML.T0054", "AML.T0015"]
        assert set(seed.atlas_technique_ids) == {"AML.T0054", "AML.T0015"}
        # atlas_provenance_ids filtered: AML.T0053 excluded (not in merged set)
        assert "AML.T0053" not in seed.atlas_provenance_ids
        assert set(seed.atlas_provenance_ids) == {"AML.T0054", "AML.T0015"}


class TestReportProvenanceBlock:
    """Verify _build_provenance_block reads from scenario seed metadata."""

    def test_provenance_block_renders_from_seed_metadata(self):
        """Provenance block should render OWASP origin, LAAF, and ATLAS from
        the scenario's scenario_seed_metadata dict."""
        from asago_scenario_generator.report.template import _build_provenance_block

        scenario = {
            "scenario_seed_metadata": {
                "seed_id": "AP-T7-01",
                "owasp_origin": "T7-S1",
                "laaf_technique_ids": ["S1", "M3"],
                "atlas_provenance_ids": ["AML.T0054", "AML.T0015"],
            }
        }
        html = _build_provenance_block(scenario)
        assert "T7-S1" in html
        assert "S1" in html
        assert "M3" in html
        assert "AML.T0054" in html
        assert "AML.T0015" in html
        assert "SSSOM Provenance" in html

    def test_provenance_block_empty_for_non_ap_seed(self):
        """Non-AP seeds should produce empty provenance block."""
        from asago_scenario_generator.report.template import _build_provenance_block

        scenario = {
            "scenario_seed_metadata": {
                "seed_id": "T2-S1",
                "owasp_origin": None,
                "laaf_technique_ids": [],
                "atlas_provenance_ids": [],
            }
        }
        html = _build_provenance_block(scenario)
        assert html == ""

    def test_provenance_block_empty_without_metadata(self):
        """Scenario without seed metadata should produce empty provenance block."""
        from asago_scenario_generator.report.template import _build_provenance_block

        html = _build_provenance_block({})
        assert html == ""

    def test_provenance_block_excludes_gated_technique(self):
        """When atlas_provenance_ids omits a zone-3-gated technique,
        the rendered block should not contain it."""
        from asago_scenario_generator.report.template import _build_provenance_block

        scenario = {
            "scenario_seed_metadata": {
                "seed_id": "AP-T7-01",
                "owasp_origin": "T7-S1",
                "laaf_technique_ids": ["S1"],
                "atlas_provenance_ids": ["AML.T0054"],  # AML.T0053 excluded
            }
        }
        html = _build_provenance_block(scenario)
        assert "AML.T0054" in html
        assert "AML.T0053" not in html
