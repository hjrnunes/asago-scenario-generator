"""Tests for taxonomy loaders moved to data.loaders (bead 8bt5).

Verifies that load_attack_goals_taxonomy and load_threat_goal_affinity
are importable from data.loaders, return correct types, cache properly,
and accept an explicit path parameter.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from asago_scenario_generator.data.loaders import (
    _load_document_cached,
    _load_threat_goal_affinity_cached,
    load_attack_goals_taxonomy,
    load_attack_patterns,
    load_threat_goal_affinity,
)


class TestLoadAttackGoalsTaxonomy:
    """Tests for load_attack_goals_taxonomy in data.loaders."""

    def test_importable_from_data_loaders(self):
        """Function is importable from asago_scenario_generator.data.loaders."""
        assert callable(load_attack_goals_taxonomy)

    def test_returns_dict_with_expected_keys(self):
        """Returns a dict with 'version' and 'categories' keys."""
        result = load_attack_goals_taxonomy()
        assert isinstance(result, dict)
        assert "version" in result
        assert "categories" in result

    def test_cache_returns_same_object(self):
        """Second call returns the exact same object (cache hit)."""
        first = load_attack_goals_taxonomy()
        second = load_attack_goals_taxonomy()
        assert first is second

    def test_explicit_path(self, tmp_path: Path):
        """Loading from an explicit path works."""
        data = {"version": "test", "categories": []}
        p = tmp_path / "goals.json"
        p.write_text(json.dumps(data))

        result = load_attack_goals_taxonomy(path=p)
        assert result == data

    def test_categories_are_list(self):
        """The 'categories' value is a list."""
        result = load_attack_goals_taxonomy()
        assert isinstance(result["categories"], list)
        assert len(result["categories"]) > 0


class TestLoadThreatGoalAffinity:
    """Tests for load_threat_goal_affinity in data.loaders."""

    def test_importable_from_data_loaders(self):
        """Function is importable from asago_scenario_generator.data.loaders."""
        assert callable(load_threat_goal_affinity)

    def test_returns_dict(self):
        """Returns a dict keyed by threat IDs."""
        result = load_threat_goal_affinity()
        assert isinstance(result, dict)
        assert len(result) > 0

    def test_values_have_affinity_keys(self):
        """Each threat entry has 'primary', 'secondary', 'excluded' keys."""
        result = load_threat_goal_affinity()
        for threat_id, entry in result.items():
            assert "primary" in entry, f"{threat_id} missing 'primary'"
            assert "secondary" in entry, f"{threat_id} missing 'secondary'"
            assert "excluded" in entry, f"{threat_id} missing 'excluded'"

    def test_cache_returns_same_object(self):
        """Second call returns the exact same object (cache hit)."""
        first = load_threat_goal_affinity()
        second = load_threat_goal_affinity()
        assert first is second

    def test_explicit_path(self, tmp_path: Path):
        """Loading from an explicit path works."""
        data = {
            "affinities": {
                "T99": {
                    "primary": ["CAT-A"],
                    "secondary": ["CAT-B"],
                    "excluded": [],
                }
            }
        }
        p = tmp_path / "affinity.yaml"
        p.write_text(yaml.dump(data))

        result = load_threat_goal_affinity(path=p)
        assert result == data["affinities"]


@pytest.fixture(autouse=True)
def _clear_lru_caches():
    """Clear LRU caches before each test to ensure isolation."""
    _load_document_cached.cache_clear()
    _load_threat_goal_affinity_cached.cache_clear()
    yield
    _load_document_cached.cache_clear()
    _load_threat_goal_affinity_cached.cache_clear()


class TestLoadAttackPatternsDuplicateGuard:
    """Cross-file merged pattern-ID collisions fail loudly (422o.2.1)."""

    def _write_patterns(self, path: Path, ids: list[str]) -> None:
        patterns = {
            pid: {
                "threat_id": "T1",
                "name": pid,
                "description": "test pattern",
                "prerequisite_capabilities": {"min_zones": ["input"]},
            }
            for pid in ids
        }
        path.write_text(yaml.dump({"patterns": patterns}), encoding="utf-8")

    def test_bundled_catalog_merges_without_duplicates(self):
        """The real catalog spans files with disjoint pattern IDs."""
        assert len(load_attack_patterns()) == 49

    def test_cross_file_duplicate_ids_raise_deterministically(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.setattr(
            "asago_scenario_generator.data.loaders._DEFAULT_ATTACK_PATTERNS_DIR", tmp_path
        )
        self._write_patterns(
            tmp_path / "attack-patterns-a.yaml", ["AP-T1-01", "AP-T1-02"]
        )
        self._write_patterns(
            tmp_path / "attack-patterns-b.yaml", ["AP-T1-02", "AP-T1-03"]
        )
        with pytest.raises(
            ValueError, match="duplicate attack pattern id 'AP-T1-02'"
        ) as first:
            load_attack_patterns()
        with pytest.raises(ValueError) as second:
            load_attack_patterns()
        assert str(first.value) == str(second.value)
        assert "attack-patterns-a.yaml" in str(first.value)
        assert "attack-patterns-b.yaml" in str(first.value)

    def test_disjoint_files_still_merge(self, tmp_path: Path, monkeypatch):
        monkeypatch.setattr(
            "asago_scenario_generator.data.loaders._DEFAULT_ATTACK_PATTERNS_DIR", tmp_path
        )
        self._write_patterns(tmp_path / "attack-patterns-a.yaml", ["AP-T1-01"])
        self._write_patterns(
            tmp_path / "attack-patterns-b.yaml", ["AP-T1-02", "AP-T1-03"]
        )
        assert sorted(load_attack_patterns()) == ["AP-T1-01", "AP-T1-02", "AP-T1-03"]

    def test_single_file_load_is_unchanged(self, tmp_path: Path):
        """Explicit-path loads keep their previous single-file behavior."""
        path = tmp_path / "attack-patterns.yaml"
        self._write_patterns(path, ["AP-T9-01"])
        assert list(load_attack_patterns(path=path)) == ["AP-T9-01"]
