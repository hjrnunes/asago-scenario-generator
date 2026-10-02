"""Direct tests for the taxonomy data loaders (card: data layer)."""

from __future__ import annotations


import pytest
import yaml

from asago_scenario_generator.data.loaders import load_attack_patterns


class TestLoadAttackPatterns:
    def test_single_file_path(self, tmp_path) -> None:
        path = tmp_path / "attack-patterns.yaml"
        path.write_text(yaml.safe_dump({"patterns": {"AP-T1-01": {"threat_id": "T1"}}}))
        assert load_attack_patterns(path) == {"AP-T1-01": {"threat_id": "T1"}}

    def test_glob_merge_and_duplicate_rejection(self, tmp_path, monkeypatch) -> None:
        import asago_scenario_generator.data.loaders as loaders_module

        first = tmp_path / "attack-patterns-a.yaml"
        first.write_text(
            yaml.safe_dump({"patterns": {"AP-T1-01": {"threat_id": "T1"}}})
        )
        second = tmp_path / "attack-patterns-b.yaml"
        second.write_text(
            yaml.safe_dump({"patterns": {"AP-T2-01": {"threat_id": "T2"}}})
        )
        monkeypatch.setattr(loaders_module, "_DEFAULT_ATTACK_PATTERNS_DIR", tmp_path)
        assert load_attack_patterns() == {
            "AP-T1-01": {"threat_id": "T1"},
            "AP-T2-01": {"threat_id": "T2"},
        }
        duplicate = tmp_path / "attack-patterns-c.yaml"
        duplicate.write_text(
            yaml.safe_dump({"patterns": {"AP-T1-01": {"threat_id": "T9"}}})
        )
        with pytest.raises(ValueError, match="duplicate attack pattern id"):
            load_attack_patterns()

    def test_empty_glob_falls_back_to_default_path(self, tmp_path, monkeypatch) -> None:
        import asago_scenario_generator.data.loaders as loaders_module

        fallback = tmp_path / "attack-patterns.yaml"
        fallback.write_text(
            yaml.safe_dump({"patterns": {"AP-T1-01": {"threat_id": "T1"}}})
        )
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        monkeypatch.setattr(loaders_module, "_DEFAULT_ATTACK_PATTERNS_DIR", empty_dir)
        monkeypatch.setattr(loaders_module, "_DEFAULT_ATTACK_PATTERNS_PATH", fallback)
        assert load_attack_patterns() == {"AP-T1-01": {"threat_id": "T1"}}
