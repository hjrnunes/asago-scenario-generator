"""Direct tests for the taxonomy data loaders (card: data layer)."""

from __future__ import annotations

import json

import pytest
import yaml

from asago_scenario_generator.data.loaders import (
    load_attack_patterns,
    load_risk_extraction,
)


class TestLoadRiskExtraction:
    def test_filters_non_atlas_and_parses_cards(self, tmp_path) -> None:
        path = tmp_path / "risk-extraction.json"
        path.write_text(
            json.dumps(
                {
                    "risks": [
                        {
                            "taxonomy": "ibm-risk-atlas",
                            "risk_id": "risk-1",
                            "risk_name": "Name",
                            "risk_description": "Description",
                            "confidence": 0.9,
                            "grounding_confidence": "high",
                            "evidence": [
                                {
                                    "text": "evidence text",
                                    "document": "doc-1",
                                    "cross_encoder_score": 0.8,
                                }
                            ],
                            "mitigations": [
                                {
                                    "action_id": "M1",
                                    "description": "mitigation desc",
                                    "source": "src",
                                }
                            ],
                            "scores": {"severity": 0.8},
                            "threat": "T1",
                            "threat_source": "owasp",
                            "vulnerability": "V1",
                            "consequence": "C1",
                            "impact": "I1",
                        },
                        {
                            "taxonomy": "other",
                            "risk_id": "risk-2",
                            "risk_name": "Other",
                            "risk_description": "D",
                            "confidence": 0.1,
                            "grounding_confidence": "low",
                        },
                        {
                            "taxonomy": "ibm-risk-atlas",
                            "risk_id": "risk-3",
                            "risk_name": "Minimal",
                            "risk_description": "D3",
                            "confidence": 0.5,
                            "grounding_confidence": "medium",
                        },
                    ]
                }
            )
        )
        cards = load_risk_extraction(path)
        assert [card.risk_id for card in cards] == ["risk-1", "risk-3"]
        assert cards[0].evidence[0].source == "doc-1"
        assert cards[0].evidence[0].relevance == 0.8
        assert cards[0].mitigations[0].mitigation_id == "M1"
        assert cards[0].mitigations[0].source == "src"
        assert cards[0].scores == {"severity": 0.8}
        assert cards[0].threat == "T1"
        assert cards[0].consequence == "C1"
        assert cards[0].impact == "I1"
        assert cards[1].evidence == []
        assert cards[1].mitigations == []
        assert cards[1].scores is None

    def test_raw_list_document_without_risks_key(self, tmp_path) -> None:
        path = tmp_path / "risk-extraction.json"
        path.write_text(
            json.dumps(
                [
                    {
                        "taxonomy": "ibm-risk-atlas",
                        "risk_id": "risk-1",
                        "risk_name": "Name",
                        "risk_description": "Description",
                        "confidence": 0.9,
                        "grounding_confidence": "high",
                    }
                ]
            )
        )
        cards = load_risk_extraction(path)
        assert [card.risk_id for card in cards] == ["risk-1"]


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
