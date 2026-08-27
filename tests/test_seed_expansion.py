"""Direct branch tests for the decomposed seed-expansion helpers.

The decomposition split ``expand_seeds`` and ``_extract_seed_constraints``
into single-purpose helpers; every helper below gets unit tests covering
each branch.  Public-API behaviour is covered by ``test_seed_provenance.py``,
``test_seed_dedup.py``, and ``test_kill_chain_scaffold.py``.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from asago_scenario_generator.models.capability_profile import ConfidenceLevel
from asago_scenario_generator.models.scenario import RiskCardRef
from asago_scenario_generator.pipeline.seeds import (
    ScenarioSeed,
    _build_new_seed,
    _collect_required_capabilities,
    _dedupe_preserve_order,
    _expand_entries,
    _extract_seed_constraints,
    _gated_atlas_provenance,
    _load_seed_expansion_inputs,
    _merge_seed,
    _seed_threat_metadata,
)
from asago_scenario_generator.models import ThreatSurface, ThreatSurfaceEntry


def _make_ref(risk_id: str = "risk-1") -> RiskCardRef:
    return RiskCardRef(
        risk_id=risk_id,
        risk_name=f"Risk {risk_id}",
        risk_description=f"Description for {risk_id}",
        taxonomy="ibm-risk-atlas",
        confidence=0.9,
        grounding_confidence=ConfidenceLevel.high,
    )


def _make_entry(
    risk_id: str = "risk-1",
    attack_pattern_ids: list[str] | None = None,
    atlas_technique_ids: list[str] | None = None,
    governance_only: bool = False,
) -> ThreatSurfaceEntry:
    return ThreatSurfaceEntry(
        risk_card=_make_ref(risk_id),
        owasp_llm_ids=["LLM01"],
        agentic_threat_ids=["T7"],
        atlas_technique_ids=atlas_technique_ids or [],
        attack_pattern_ids=attack_pattern_ids or ["AP-T7-01"],
        governance_only=governance_only,
    )


def _pattern(**overrides) -> dict:
    base = {
        "id": "AP-T7-01",
        "name": "Constraint bypass",
        "description": "Agent bypasses constraints",
        "threat_id": "T7",
    }
    base.update(overrides)
    return base


def _threat(name: str = "Misaligned behaviors") -> dict:
    return {"name": name, "description": "Full threat description"}


def _seed(**overrides) -> ScenarioSeed:
    base = ScenarioSeed(
        seed_id="AP-T7-01",
        threat_id="T7",
        threat_name="Misaligned behaviors",
        attack_pattern_name="Constraint bypass",
        attack_pattern_description="Agent bypasses constraints",
        risk_card_ref=_make_ref(),
        contributing_risk_cards=[_make_ref()],
        owasp_llm_ids=["LLM01"],
        agentic_threat_ids=["T7"],
        atlas_technique_ids=["AML.T0054"],
    )
    if overrides:
        return base.model_copy(update=overrides)
    return base


# ---------------------------------------------------------------------------
# Seed constraint helpers
# ---------------------------------------------------------------------------


class TestCollectRequiredCapabilities:
    def test_maps_kcx_subcodes_and_extends_multiple(self) -> None:
        caps = _collect_required_capabilities({"all": ["KCX-MAGENT", "KCX-PMEM"]})
        assert sorted(caps) == ["multi_agent", "persistent_memory"]

    def test_skips_unrelated_kcx_codes(self) -> None:
        assert _collect_required_capabilities({"all": ["KCX-UNKNOWN"]}) == []

    def test_empty_requires(self) -> None:
        assert _collect_required_capabilities({}) == []
        assert _collect_required_capabilities({"all": []}) == []


class TestDedupePreserveOrder:
    def test_deduplicates_while_preserving_first_occurrence(self) -> None:
        assert _dedupe_preserve_order(["a", "b", "a", "c", "b"]) == ["a", "b", "c"]

    def test_empty_input(self) -> None:
        assert _dedupe_preserve_order([]) == []


class TestExtractSeedConstraints:
    def test_min_complexity_and_caps(self) -> None:
        pattern = _pattern(
            min_complexity="advanced",
            prerequisite_capabilities={
                "kc_requires": {"all": ["KCX-MAGENT", "KCX-SHMEM"]}
            },
        )
        min_complexity, caps = _extract_seed_constraints(pattern)
        assert min_complexity == "advanced"
        assert caps == ["multi_agent", "persistent_memory"]

    def test_missing_min_complexity(self) -> None:
        min_complexity, caps = _extract_seed_constraints(_pattern())
        assert min_complexity is None
        assert caps is None

    def test_missing_prerequisite_capabilities(self) -> None:
        pattern = _pattern()
        pattern.pop("prerequisite_capabilities", None)
        assert _extract_seed_constraints(pattern) == (None, None)

    def test_missing_kc_requires(self) -> None:
        pattern = _pattern(prerequisite_capabilities={"other": ["x"]})
        assert _extract_seed_constraints(pattern) == (None, None)


# ---------------------------------------------------------------------------
# Input loading and metadata helpers
# ---------------------------------------------------------------------------


class TestLoadSeedExpansionInputs:
    def test_default_paths_and_provenance_index(self) -> None:
        with (
            patch(
                "asago_scenario_generator.pipeline.seeds.load_agentic_threats",
                return_value={"T7": _threat()},
            ),
            patch(
                "asago_scenario_generator.pipeline.seeds.load_attack_patterns",
                return_value={"AP-T7-01": _pattern()},
            ),
            patch(
                "asago_scenario_generator.pipeline.seeds.load_attack_pattern_provenance",
                return_value=[],
            ),
        ):
            threats, patterns, prov = _load_seed_expansion_inputs(None, None)
        assert threats == {"T7": _threat()}
        assert patterns == {"AP-T7-01": _pattern()}
        assert prov == {}

    def test_explicit_threats_path_is_used(self) -> None:
        fake_path = Path("/fake/threats.yaml")
        with (
            patch(
                "asago_scenario_generator.pipeline.seeds.load_agentic_threats",
                return_value={"T7": _threat()},
            ) as load_threats,
            patch(
                "asago_scenario_generator.pipeline.seeds.load_attack_patterns",
                return_value={},
            ),
            patch(
                "asago_scenario_generator.pipeline.seeds.load_attack_pattern_provenance",
                return_value=[],
            ),
        ):
            _load_seed_expansion_inputs(fake_path, None)
        load_threats.assert_called_once_with(fake_path)

    def test_missing_provenance_file_is_tolerated(self) -> None:
        with (
            patch(
                "asago_scenario_generator.pipeline.seeds.load_agentic_threats",
                return_value={},
            ),
            patch(
                "asago_scenario_generator.pipeline.seeds.load_attack_patterns",
                return_value={},
            ),
            patch(
                "asago_scenario_generator.pipeline.seeds.load_attack_pattern_provenance",
                side_effect=FileNotFoundError,
            ),
        ):
            _, _, prov = _load_seed_expansion_inputs(None, None)
        assert prov == {}


class TestSeedThreatMetadata:
    def test_threat_present(self) -> None:
        pattern = _pattern()
        assert _seed_threat_metadata(pattern, _threat()) == (
            "T7",
            "Misaligned behaviors",
            "Full threat description",
        )

    def test_threat_missing_defaults_metadata(self) -> None:
        assert _seed_threat_metadata(_pattern(), None) == ("T7", "", "")

    def test_threat_without_description(self) -> None:
        assert _seed_threat_metadata(_pattern(), _threat()) == (
            "T7",
            "Misaligned behaviors",
            "Full threat description",
        )


class TestGatedAtlasProvenance:
    def test_keeps_ids_in_pool(self) -> None:
        assert _gated_atlas_provenance(
            ["AML.T0054", "AML.T0053", "AML.T0015"],
            ["AML.T0054", "AML.T0015"],
        ) == ["AML.T0054", "AML.T0015"]

    def test_empty_pool_filters_everything(self) -> None:
        assert _gated_atlas_provenance(["AML.T0054"], []) == []


# ---------------------------------------------------------------------------
# Merge and build helpers
# ---------------------------------------------------------------------------


class TestMergeSeed:
    def test_merges_taxonomy_ids_and_appends_new_risk_card(self) -> None:
        existing = _seed()
        entry = _make_entry(risk_id="risk-2", atlas_technique_ids=["AML.T0099"])
        merged = _merge_seed(existing, entry, {"mitre-atlas": ["AML.T0099"]})
        assert merged.owasp_llm_ids == ["LLM01"]  # union is deduplicated
        assert [r.risk_id for r in merged.contributing_risk_cards] == [
            "risk-1",
            "risk-2",
        ]
        assert merged.atlas_technique_ids == ["AML.T0054", "AML.T0099"]

    def test_known_risk_card_is_not_duplicated(self) -> None:
        existing = _seed()
        entry = _make_entry(risk_id="risk-1")
        merged = _merge_seed(existing, entry, {"mitre-atlas": []})
        assert [r.risk_id for r in merged.contributing_risk_cards] == ["risk-1"]

    def test_merge_filters_provenance_against_entry_pool(self) -> None:
        existing = _seed()
        entry = _make_entry(risk_id="risk-2", atlas_technique_ids=["AML.T0001"])
        merged = _merge_seed(existing, entry, {"mitre-atlas": ["AML.T0001", "AML.T0002"]})
        # Only AML.T0001 survives zone-3 gating for the new entry.
        assert merged.atlas_technique_ids == ["AML.T0054", "AML.T0001"]
        assert merged.atlas_provenance_ids == ["AML.T0054", "AML.T0001"]


class TestBuildNewSeed:
    def test_builds_seed_with_constraints_and_provenance(self) -> None:
        entry = _make_entry(atlas_technique_ids=["AML.T0054", "AML.T0053"])
        pattern = _pattern(min_complexity="expert")
        prov = {
            "owasp-agentic": ["T7-S1"],
            "laaf": ["S1"],
            "mitre-atlas": ["AML.T0054", "AML.T0053"],
        }
        seed = _build_new_seed(
            "AP-T7-01",
            entry,
            pattern,
            {"T7": _threat()},
            prov,
            ("expert", ["multi_agent"]),
        )
        assert seed.seed_id == "AP-T7-01"
        assert seed.owasp_origin == "T7-S1"
        assert seed.laaf_technique_ids == ["S1"]
        assert seed.atlas_technique_ids == ["AML.T0054", "AML.T0053"]
        assert seed.min_complexity == "expert"
        assert seed.required_capabilities == ["multi_agent"]

    def test_builds_seed_without_provenance_and_no_owasp_origin(self) -> None:
        entry = _make_entry()
        seed = _build_new_seed(
            "AP-T7-01", entry, _pattern(), {"T7": _threat()}, {}, (None, None)
        )
        assert seed.owasp_origin is None
        assert seed.laaf_technique_ids == []
        assert seed.atlas_technique_ids == []
        assert seed.min_complexity is None


class TestExpandEntries:
    def test_skips_governance_only_entries(self) -> None:
        seen = _expand_entries(
            [_make_entry(governance_only=True)],
            {"AP-T7-01": _pattern()},
            {"T7": _threat()},
            {},
        )
        assert seen == {}

    def test_skips_unknown_pattern_ids(self) -> None:
        entry = _make_entry(attack_pattern_ids=["AP-T7-99"])
        seen = _expand_entries([entry], {"AP-T7-01": _pattern()}, {}, {})
        assert seen == {}

    def test_merges_repeated_pattern_ids(self) -> None:
        entries = [_make_entry(risk_id="risk-1"), _make_entry(risk_id="risk-2")]
        seen = _expand_entries(entries, {"AP-T7-01": _pattern()}, {"T7": _threat()}, {})
        assert list(seen) == ["AP-T7-01"]
        assert [r.risk_id for r in seen["AP-T7-01"].contributing_risk_cards] == [
            "risk-1",
            "risk-2",
        ]
