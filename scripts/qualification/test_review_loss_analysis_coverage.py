"""Offline verification of the standalone risk-coverage review tool.

These tests never contact a model endpoint.  They drive the tool with a fake
client and a small fixture graph, and they assert the artifact identity, the
per-row outcome, and the call evidence the product seam writes.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

import review_loss_analysis_coverage as tool  # noqa: E402
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.stpa.system_model.risk_coverage_review import (
    ARTIFACT_FILENAME,
    graph_digest,
)


class _FakeClient:
    """Client that returns one canned review response per call."""

    model = "fake-review-model"

    def __init__(self, responses: list[dict]) -> None:
        self.responses = responses
        self.call_count = 0

    def complete(self, **kwargs):
        from asago_scenario_generator.stpa.infra.llm import LLMResult

        payload = self.responses[min(self.call_count, len(self.responses) - 1)]
        self.call_count += 1
        return LLMResult(
            content=payload,
            prompt_tokens=11,
            completion_tokens=7,
            duration_ms=5,
        )


def _analysis() -> LossAnalysis:
    """Return a small gated graph with one cited and one cited card."""
    return LossAnalysis.model_validate(
        {
            "risk_card_losses": [
                {
                    "loss_id": "L-1",
                    "description": "Financial records are disclosed.",
                    "provenance": "risk_card",
                    "source_risk_cards": ["risk-a"],
                },
                {
                    "loss_id": "L-2",
                    "description": "Stored records are corrupted.",
                    "provenance": "risk_card",
                    "source_risk_cards": ["risk-b"],
                },
            ],
            "use_case_losses": [],
            "hazards": [
                {
                    "hazard_id": "H-1",
                    "description": "The agent transmits financial records.",
                    "related_losses": ["L-1"],
                },
                {
                    "hazard_id": "H-2",
                    "description": "The agent writes a corrupted record.",
                    "related_losses": ["L-2"],
                },
            ],
            "security_constraints": [
                {
                    "constraint_id": "SC-1",
                    "rule": "The agent must keep financial records inside the system.",
                    "applies_when": ["when handling account data"],
                    "related_hazards": ["H-1"],
                },
                {
                    "constraint_id": "SC-2",
                    "rule": "The agent must validate every stored record write.",
                    "applies_when": [],
                    "related_hazards": ["H-2"],
                },
            ],
            "risk_dispositions": [
                {"risk_ref": "risk-a", "disposition": "cited", "loss_ids": ["L-1"]},
                {"risk_ref": "risk-b", "disposition": "cited", "loss_ids": ["L-2"]},
            ],
        }
    )


def _write_analysis(tmp_path: Path) -> Path:
    path = tmp_path / "loss-analysis.yaml"
    path.write_text(
        yaml.safe_dump(_analysis().model_dump(mode="json")), encoding="utf-8"
    )
    return path


def _write_risk_set(tmp_path: Path) -> Path:
    payload = {
        "version": "1",
        "risks": [
            {
                "risk_id": "risk-a",
                "risk_name": "Unauthorized disclosure of financial records",
                "risk_description": "Account data reaches an unauthorized party.",
                "taxonomy": "ibm-risk-atlas",
                "consequence": "Financial records are exposed.",
            },
            {
                "risk_id": "risk-b",
                "risk_name": "Unauthorized write",
                "risk_description": "An attacker changes a stored record.",
                "taxonomy": "ibm-risk-atlas",
                "consequence": "Stored records are corrupted.",
            },
        ],
    }
    path = tmp_path / "risk-extraction.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _write_use_case(tmp_path: Path) -> Path:
    path = tmp_path / "use-case.txt"
    path.write_text("A customer service assistant.", encoding="utf-8")
    return path


def _valid_rows() -> list[dict]:
    return [
        {
            "risk_id": "risk-a",
            "protects": "financial records",
            "against": "provider leakage",
            "covering_constraints": ["SC-1"],
            "coverage": "full",
            "missing_protection": None,
            "evidence": [
                {
                    "source_ref": "risk-a",
                    "quote": "Unauthorized disclosure of financial records",
                    "meaning": "The card.",
                },
                {
                    "source_ref": "SC-1",
                    "quote": "The agent must keep financial records inside the system.",
                    "meaning": "The rule.",
                },
            ],
            "rationale": "SC-1 protects the same records.",
        },
        {
            "risk_id": "risk-b",
            "protects": "stored records",
            "against": "unauthorized writes",
            "covering_constraints": ["SC-2"],
            "coverage": "full",
            "missing_protection": None,
            "evidence": [
                {
                    "source_ref": "risk-b",
                    "quote": "Unauthorized write",
                    "meaning": "The card.",
                },
                {
                    "source_ref": "SC-2",
                    "quote": "The agent must validate every stored record write.",
                    "meaning": "The rule.",
                },
            ],
            "rationale": "SC-2 protects stored records.",
        },
    ]


def _run(monkeypatch, tmp_path, rows: list[dict]) -> Path:
    client = _FakeClient([{"rows": rows}])
    monkeypatch.setattr(
        tool,
        "resolve_llm_client_from_profile",
        lambda profiles_file, profile: (client, profile),
    )
    out = tmp_path / "out"
    exit_code = tool.main(
        [
            "--loss-analysis",
            str(_write_analysis(tmp_path)),
            "--risk-set",
            str(_write_risk_set(tmp_path)),
            "--use-case",
            str(_write_use_case(tmp_path)),
            "--out",
            str(out),
            "--profile",
            "fake-profile",
        ]
    )
    assert exit_code == 0
    return out


def test_writes_artifact_and_call_log_from_a_fake_client(monkeypatch, tmp_path):
    out = _run(monkeypatch, tmp_path, _valid_rows())

    artifact = yaml.safe_load((out / ARTIFACT_FILENAME).read_text())
    assert artifact["schema_version"] == "loss-analysis-risk-coverage-review-v3"
    assert artifact["reviewed_loss_analysis_digest"] == graph_digest(_analysis())
    assert artifact["status"] == "completed"
    assert artifact["summary"]["rows_valid"] == 2
    assert artifact["summary"]["rows_invalid"] == 0
    assert artifact["summary"]["rows_missing"] == 0
    assert artifact["summary"]["full"] == 2
    assert list(artifact["batching"]["planned_batch_sizes"]) == [2]
    entry = json.loads((out / "calls.jsonl").read_text().splitlines()[0])
    assert entry["step"] == "risk_coverage_review"
    assert entry["model"] == "fake-review-model"
    assert entry["prompt_tokens"] == 11


def test_invalid_rows_are_recorded_without_failing_the_tool(monkeypatch, tmp_path):
    rows = _valid_rows()
    rows[0]["evidence"][0]["quote"] = "not a quotation from the card"
    out = _run(monkeypatch, tmp_path, rows)

    artifact = yaml.safe_load((out / ARTIFACT_FILENAME).read_text())
    assert artifact["status"] == "partial"
    assert artifact["rows_invalid"] == [
        {"risk_id": "risk-a", "reason": "quote_not_a_substring"}
    ]
    assert artifact["summary"]["rows_valid"] == 1
    assert artifact["summary"]["rows_invalid"] == 1
    assert artifact["summary"]["rows_missing"] == 0


def test_missing_card_is_listed_under_rows_missing(monkeypatch, tmp_path):
    out = _run(monkeypatch, tmp_path, _valid_rows()[:1])

    artifact = yaml.safe_load((out / ARTIFACT_FILENAME).read_text())
    assert artifact["status"] == "partial"
    assert artifact["rows_missing"] == ["risk-b"]
    assert artifact["summary"]["rows_valid"] == 1
    assert artifact["summary"]["rows_missing"] == 1


def test_loss_analysis_loader_rejects_a_broken_graph(tmp_path):
    path = tmp_path / "broken.yaml"
    path.write_text("losses: []\n", encoding="utf-8")

    with pytest.raises(Exception):
        tool._load_loss_analysis(path)


def test_reviewed_risk_loader_keeps_every_supplied_card(tmp_path):
    cards = tool.load_reviewed_risk_extraction(_write_risk_set(tmp_path))

    assert [card.risk_id for card in cards] == ["risk-a", "risk-b"]
