"""Tests for the attack-pattern loader and the bundled taxonomy data."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from asago_scenario_generator.data.loaders import (
    _load_document_cached,
    load_attack_patterns,
)
from asago_scenario_generator.data.paths import DATA_ROOT

_MAPPINGS = DATA_ROOT / "taxonomies" / "mappings"
_ATLAS_NAMES_PATH = DATA_ROOT / "taxonomies" / "atlas" / "ATLAS-2026.05.yaml"
_OWASP_LLM_2025_NAMES = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}
# Techniques whose labels the crosswalks once carried wrongly.
_ATLAS_RENAMED = {
    "AML.T0015": "Evade AI Model",
    "AML.T0025": "Exfiltration via Cyber Means",
    "AML.T0040": "AI Model Inference API Access",
    "AML.T0071": "False RAG Entry Injection",
}


def _atlas_technique_names() -> dict[str, str]:
    """Map every ATLAS technique ID to its name in the bundled release."""
    document = yaml.safe_load(_ATLAS_NAMES_PATH.read_text(encoding="utf-8"))
    names: dict[str, str] = {}
    pending = [document]
    while pending:
        node = pending.pop()
        if isinstance(node, dict):
            if str(node.get("id", "")).startswith("AML.T") and "name" in node:
                names[node["id"]] = node["name"]
            pending.extend(node.values())
        elif isinstance(node, list):
            pending.extend(node)
    return names


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
            "asago_scenario_generator.data.loaders._DEFAULT_ATTACK_PATTERNS_DIR",
            tmp_path,
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
            "asago_scenario_generator.data.loaders._DEFAULT_ATTACK_PATTERNS_DIR",
            tmp_path,
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


class TestBundledTaxonomyData:
    """Labels and lists in the bundled taxonomy data stay correct."""

    def test_no_pattern_lists_a_capability_twice(self):
        for pattern_id, pattern in load_attack_patterns().items():
            requires = pattern["prerequisite_capabilities"].get("kc_requires") or {}
            for gate, codes in requires.items():
                assert len(codes) == len(set(codes)), f"{pattern_id} {gate}"

    def test_t_to_llm_names_use_the_2025_owasp_names(self):
        cross = yaml.safe_load(
            (_MAPPINGS / "cross-taxonomy-mappings.yaml").read_text(encoding="utf-8")
        )

        assert {
            (item["target"], item["target_name"]) for item in cross["t_to_llm"]
        } <= set(_OWASP_LLM_2025_NAMES.items())

    def test_t_to_atlas_names_match_the_atlas_release(self):
        cross = yaml.safe_load(
            (_MAPPINGS / "cross-taxonomy-mappings.yaml").read_text(encoding="utf-8")
        )
        atlas = _atlas_technique_names()

        for item in cross["t_to_atlas"]:
            assert len(item["targets"]) == len(item["target_names"]), item["source"]
            for technique, label in zip(item["targets"], item["target_names"]):
                if technique in _ATLAS_RENAMED:
                    assert label == _ATLAS_RENAMED[technique] == atlas[technique]

    def test_llm_atlas_crosswalk_labels_the_four_techniques_correctly(self):
        text = (_MAPPINGS / "crosswalk-llm-atlas.md").read_text(encoding="utf-8")
        rows = re.findall(r"^\| ([^|]+) \| \[(AML\.T\d+)\]", text, re.MULTILINE)

        labelled = {technique: label.strip() for label, technique in rows}
        for technique, name in _ATLAS_RENAMED.items():
            assert labelled[technique] == name

    def test_system_prompt_extraction_is_not_filed_under_supply_chain(self):
        text = (_MAPPINGS / "crosswalk-llm-atlas.md").read_text(encoding="utf-8")
        summary = {
            line.split("|")[1].strip(): line
            for line in text.splitlines()
            if re.match(r"\| LLM\d\d \|", line)
        }
        cross = yaml.safe_load(
            (_MAPPINGS / "cross-taxonomy-mappings.yaml").read_text(encoding="utf-8")
        )
        by_threat = {item["source"]: item for item in cross["t_to_atlas"]}

        assert "AML.T0056" not in summary["LLM03"]
        assert "AML.T0056" in summary["LLM07"]
        assert "AML.T0056" not in by_threat["T2"]["targets"]
        assert "AML.T0056" not in by_threat["T17"]["targets"]
