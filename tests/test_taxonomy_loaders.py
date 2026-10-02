"""Tests for taxonomy loaders moved to data.loaders (bead 8bt5).

Verifies that load_attack_goals_taxonomy and load_threat_goal_affinity
are importable from data.loaders, return correct types, cache properly,
and accept an explicit path parameter.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from asago_scenario_generator.data.loaders import (
    _load_document_cached,
    load_attack_patterns,
)


@pytest.fixture(autouse=True)
def _clear_lru_caches():
    """Clear LRU caches before each test to ensure isolation."""
    _load_document_cached.cache_clear()
    yield
    _load_document_cached.cache_clear()


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
