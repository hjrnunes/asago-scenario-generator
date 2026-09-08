"""Tests for the advisory Stage 1a risk-coverage review (spec deviation 10).

The review is advisory: it never changes the graph and never blocks the run.
Every test uses a fake client and contacts no network.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from asago_scenario_generator.models.risk_card import RiskCard
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.system_model.risk_coverage_review import (
    ARTIFACT_FILENAME,
    RiskCoverageReview,
    estimated_review_tokens,
    graph_digest,
    run_risk_coverage_review,
    should_split_review,
)
from asago_scenario_generator.stpa.system_model.run import run_sp1
from tests.stpa.sp1_helpers import (
    MockLLMClient,
    make_risk_cards,
    read_calls_jsonl,
    setup_sp1_mock_client,
)


def _cards() -> list[RiskCard]:
    """Return four cards: three cited, one not applicable."""
    return [
        RiskCard(
            risk_id="risk-a",
            risk_name="Unauthorized disclosure of financial records",
            risk_description="Sensitive account data reaches an unauthorized party.",
            taxonomy="ibm-risk-atlas",
            confidence=0.9,
            grounding_confidence="high",
            consequence="Financial records are exposed.",
        ),
        RiskCard(
            risk_id="risk-b",
            risk_name="Unauthorized write",
            risk_description="An attacker changes a stored record.",
            taxonomy="ibm-risk-atlas",
            confidence=0.8,
            grounding_confidence="high",
            consequence="Stored records are corrupted.",
        ),
        RiskCard(
            risk_id="risk-c",
            risk_name="Output bias",
            risk_description="The model produces discriminatory output.",
            taxonomy="ibm-risk-atlas",
            confidence=0.7,
            grounding_confidence="medium",
            consequence="A protected group is disadvantaged.",
        ),
        RiskCard(
            risk_id="risk-d",
            risk_name="Physical robot harm",
            risk_description="A physical actuator injures a bystander.",
            taxonomy="ibm-risk-atlas",
            confidence=0.6,
            grounding_confidence="medium",
            consequence="A person is injured.",
        ),
    ]


def _analysis() -> LossAnalysis:
    """Return a gated graph with two constraints covering two of the cards."""
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
                {
                    "loss_id": "L-3",
                    "description": "A protected group is disadvantaged.",
                    "provenance": "risk_card",
                    "source_risk_cards": ["risk-c"],
                },
            ],
            "use_case_losses": [],
            "hazards": [
                {
                    "hazard_id": "H-1",
                    "description": "The agent transmits financial records to a provider.",
                    "related_losses": ["L-1"],
                },
                {
                    "hazard_id": "H-2",
                    "description": "The agent writes a corrupted stored record.",
                    "related_losses": ["L-2"],
                },
                {
                    "hazard_id": "H-3",
                    "description": "The agent emits discriminatory output.",
                    "related_losses": ["L-3"],
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
                {
                    "constraint_id": "SC-3",
                    "rule": "The agent must not emit discriminatory output.",
                    "applies_when": [],
                    "related_hazards": ["H-3"],
                },
            ],
            "risk_dispositions": [
                {
                    "risk_ref": "risk-a",
                    "disposition": "cited",
                    "loss_ids": ["L-1"],
                },
                {
                    "risk_ref": "risk-b",
                    "disposition": "cited",
                    "loss_ids": ["L-2"],
                },
                {
                    "risk_ref": "risk-c",
                    "disposition": "cited",
                    "loss_ids": ["L-3"],
                },
                {
                    "risk_ref": "risk-d",
                    "disposition": "not_applicable",
                    "loss_ids": [],
                    "reason": "The system has no physical actuator.",
                },
            ],
        }
    )


def _valid_rows() -> dict:
    """Return one valid row per card for the four-card fixture."""
    return {
        "rows": [
            {
                "risk_id": "risk-a",
                "protects": "customer financial records",
                "against": "provider leakage",
                "covering_constraints": ["SC-1"],
                "coverage": "full",
                "missing_protection": None,
                "evidence": [
                    {
                        "source_ref": "risk-a",
                        "quote": "Sensitive account data reaches an unauthorized party.",
                        "meaning": "The card names the disclosure.",
                    },
                    {
                        "source_ref": "SC-1",
                        "quote": "keep financial records inside the system",
                        "meaning": "The rule keeps the records inside.",
                    },
                ],
                "rationale": "The rule protects the same records from the same leak.",
            },
            {
                "risk_id": "risk-b",
                "protects": "stored record integrity",
                "against": "an attacker",
                "covering_constraints": [],
                "coverage": "none",
                "missing_protection": "No rule prevents an unauthorized record write.",
                "evidence": [
                    {
                        "source_ref": "risk-b",
                        "quote": "An attacker changes a stored record.",
                        "meaning": "The card names the write.",
                    }
                ],
                "rationale": "The validation rule does not constrain authorization.",
            },
            {
                "risk_id": "risk-c",
                "protects": "fair treatment of a protected group",
                "against": None,
                "covering_constraints": [],
                "coverage": "partial",
                "missing_protection": "No rule constrains output fairness.",
                "evidence": [
                    {
                        "source_ref": "risk-c",
                        "quote": "The model produces discriminatory output.",
                        "meaning": "The card names the biased output.",
                    }
                ],
                "rationale": "The graph has a hazard but no governing rule.",
            },
            {
                "risk_id": "risk-d",
                "protects": "bystander safety",
                "against": None,
                "covering_constraints": [],
                "coverage": "not_applicable_confirmed",
                "missing_protection": None,
                "evidence": [
                    {
                        "source_ref": "risk-d",
                        "quote": "A physical actuator injures a bystander.",
                        "meaning": "The card names a physical harm.",
                    }
                ],
                "rationale": "The system has no physical actuator.",
            },
        ]
    }


def _client_with_rows(rows: dict | None = None) -> MockLLMClient:
    client = MockLLMClient()
    client.set_response_for(
        RiskCoverageReview, rows if rows is not None else _valid_rows()
    )
    return client


def _run_review(
    tmp_path: Path,
    *,
    rows: dict | None = None,
    cards: list[RiskCard] | None = None,
    max_completion_tokens: int | None = None,
):
    analysis = _analysis()
    graph_path = tmp_path / "loss-analysis.yaml"
    from asago_scenario_generator.stpa.infra.yaml_io import write_yaml

    write_yaml(analysis, graph_path)
    digest = hashlib.sha256(graph_path.read_bytes()).hexdigest()
    return run_risk_coverage_review(
        llm_client=_client_with_rows(rows),
        loss_analysis=analysis,
        risk_cards=_cards() if cards is None else cards,
        use_case_text="Test use case",
        run_dir=tmp_path,
        template_loader=TemplateLoader(PROMPTS_DIR),
        temperature=0.4,
        reviewed_loss_analysis_digest=digest,
        max_completion_tokens=max_completion_tokens,
    )


class TestValidReview:
    def test_valid_response_writes_artifact_and_summary(self, tmp_path):
        outcome = _run_review(tmp_path)

        assert outcome.status == "completed"
        assert outcome.call_count == 1
        assert outcome.failure_reason is None
        artifact = yaml.safe_load((tmp_path / ARTIFACT_FILENAME).read_text())
        assert artifact["schema_version"] == "loss-analysis-risk-coverage-review-v1"
        assert artifact["status"] == "completed"
        assert artifact["call_count"] == 1
        assert artifact["failure_reason"] is None
        assert [row["risk_id"] for row in artifact["rows"]] == [
            "risk-a",
            "risk-b",
            "risk-c",
            "risk-d",
        ]
        summary = artifact["summary"]
        assert summary["full"] == 1
        assert summary["partial"] == 1
        assert summary["none"] == 1
        assert summary["not_applicable_confirmed"] == 1
        assert summary["not_applicable_disputed"] == 0
        reading = summary["reading_list"]
        assert [item["risk_id"] for item in reading] == ["risk-b", "risk-c"]
        assert reading[0]["missing_protection"]
        assert reading[0]["covering_constraints"] == []
        assert reading[1]["risk_name"] == "Output bias"

    def test_digests_pin_the_graph_and_risk_set(self, tmp_path):
        outcome = _run_review(tmp_path)

        artifact = yaml.safe_load((tmp_path / ARTIFACT_FILENAME).read_text())
        expected = graph_digest(_analysis())
        assert artifact["reviewed_loss_analysis_digest"] == expected
        # The digest is the canonical serialization the run publishes.
        assert (
            expected
            == hashlib.sha256(
                (tmp_path / "loss-analysis.yaml").read_bytes()
            ).hexdigest()
        )
        assert (
            artifact["risk_set_digest"]
            == hashlib.sha256(
                ",".join(card.risk_id for card in _cards()).encode()
            ).hexdigest()
        )
        assert outcome.reviewed_loss_analysis_digest == expected
        assert set(artifact["prompt_template_hashes"]) == {
            "stage1a_coverage_review_system.j2",
            "stage1a_coverage_review_user.j2",
        }


class TestDeterministicValidation:
    def test_non_substring_quote_is_unavailable(self, tmp_path):
        rows = _valid_rows()
        rows["rows"][0]["evidence"][1]["quote"] = "a paraphrase, not a quotation"
        outcome = _run_review(tmp_path, rows=rows)

        assert outcome.status == "unavailable"
        assert outcome.call_count == 1
        assert outcome.failure_reason is not None
        assert "not an exact substring" in outcome.failure_reason
        artifact = yaml.safe_load((tmp_path / ARTIFACT_FILENAME).read_text())
        assert artifact["status"] == "unavailable"
        assert artifact["failure_reason"] == outcome.failure_reason
        assert artifact["rows"] == []

    def test_cited_card_cannot_be_not_applicable(self, tmp_path):
        rows = _valid_rows()
        rows["rows"][0]["coverage"] = "not_applicable_confirmed"
        rows["rows"][0]["missing_protection"] = None
        rows["rows"][0]["covering_constraints"] = []
        outcome = _run_review(tmp_path, rows=rows)

        assert outcome.status == "unavailable"
        assert "cited in the analysis" in (outcome.failure_reason or "")

    def test_not_applicable_card_cannot_be_full(self, tmp_path):
        rows = _valid_rows()
        rows["rows"][3]["coverage"] = "full"
        rows["rows"][3]["covering_constraints"] = ["SC-1"]
        rows["rows"][3]["evidence"].append(
            {
                "source_ref": "SC-1",
                "quote": "keep financial records inside the system",
                "meaning": "The rule.",
            }
        )
        outcome = _run_review(tmp_path, rows=rows)

        assert outcome.status == "unavailable"
        assert "not_applicable in the analysis" in (outcome.failure_reason or "")

    def test_full_without_a_covering_constraint_fails(self, tmp_path):
        rows = _valid_rows()
        rows["rows"][0]["covering_constraints"] = []
        outcome = _run_review(tmp_path, rows=rows)

        assert outcome.status == "unavailable"
        assert "coverage full requires at least one" in (outcome.failure_reason or "")

    def test_partial_without_missing_protection_fails(self, tmp_path):
        rows = _valid_rows()
        rows["rows"][2]["missing_protection"] = None
        outcome = _run_review(tmp_path, rows=rows)

        assert outcome.status == "unavailable"
        assert "requires a nonblank missing_protection" in (
            outcome.failure_reason or ""
        )

    def test_disputed_requires_missing_protection(self, tmp_path):
        rows = _valid_rows()
        rows["rows"][3]["coverage"] = "not_applicable_disputed"
        rows["rows"][3]["missing_protection"] = None
        outcome = _run_review(tmp_path, rows=rows)

        assert outcome.status == "unavailable"
        assert "requires a nonblank missing_protection" in (
            outcome.failure_reason or ""
        )

    def test_missing_card_row_fails_by_schema(self, tmp_path):
        rows = _valid_rows()
        rows["rows"] = rows["rows"][:3]
        outcome = _run_review(tmp_path, rows=rows)

        assert outcome.status == "unavailable"
        assert "at least 4 items" in (outcome.failure_reason or "")

    def test_unknown_constraint_id_fails_by_schema(self, tmp_path):
        rows = _valid_rows()
        rows["rows"][0]["covering_constraints"] = ["SC-9"]
        rows["rows"][0]["evidence"][1]["source_ref"] = "SC-9"
        outcome = _run_review(tmp_path, rows=rows)

        assert outcome.status == "unavailable"
        assert outcome.failure_reason is not None

    def test_row_requires_its_own_card_quote(self, tmp_path):
        rows = _valid_rows()
        rows["rows"][1]["evidence"] = [
            {
                "source_ref": "L-2",
                "quote": "Stored records are corrupted.",
                "meaning": "The loss.",
            }
        ]
        outcome = _run_review(tmp_path, rows=rows)

        assert outcome.status == "unavailable"
        assert "its own risk_id" in (outcome.failure_reason or "")


class TestReviewNeverBlocks:
    def test_run_continues_to_stage_2_after_an_unavailable_review(self, tmp_path):
        client = setup_sp1_mock_client()
        bad = _valid_rows()
        bad["rows"][0]["evidence"][1]["quote"] = "not a quotation"
        client.set_response_for(RiskCoverageReview, bad)

        result = run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=make_risk_cards(),
            run_dir=tmp_path,
        )

        assert result.stage_errors == []
        assert result.loss_analysis is not None
        assert result.control_structure is not None
        artifact = yaml.safe_load((tmp_path / ARTIFACT_FILENAME).read_text())
        assert artifact["status"] == "unavailable"
        assert any(
            "risk_coverage_review unavailable" in warning
            for warning in result.stage_warnings
        )
        manifest = yaml.safe_load((tmp_path / "run-manifest.yaml").read_text())
        review = manifest["stage_summary"]["stage_1a"]["risk_coverage_review"]
        assert review["status"] == "unavailable"
        assert review["call_count"] == 1
        assert review["failure_reason"]

    def test_provider_error_is_recorded_as_unavailable(self, tmp_path):
        client = MockLLMClient()
        client.set_exception_for(RiskCoverageReview, RuntimeError("boom"))
        analysis = _analysis()
        from asago_scenario_generator.stpa.infra.yaml_io import write_yaml

        write_yaml(analysis, tmp_path / "loss-analysis.yaml")
        digest = hashlib.sha256(
            (tmp_path / "loss-analysis.yaml").read_bytes()
        ).hexdigest()
        outcome = run_risk_coverage_review(
            llm_client=client,
            loss_analysis=analysis,
            risk_cards=_cards(),
            use_case_text="Test use case",
            run_dir=tmp_path,
            template_loader=TemplateLoader(PROMPTS_DIR),
            temperature=0.4,
            reviewed_loss_analysis_digest=digest,
        )

        assert outcome.status == "unavailable"
        assert "boom" in (outcome.failure_reason or "")


class TestPinnedRuns:
    def test_pinned_run_skips_the_review(self, tmp_path):
        analysis = _analysis()
        from asago_scenario_generator.stpa.infra.yaml_io import write_yaml

        pinned = tmp_path / "pinned-loss-analysis.yaml"
        write_yaml(analysis, pinned)
        client = setup_sp1_mock_client()
        # Call 3 must cover the three-hazard graph exactly once.
        from asago_scenario_generator.stpa.system_model.control_structure import (
            CoordinationAnalysis,
        )
        from tests.stpa.sp1_helpers import valid_empty_coordination_analysis_dict

        client.set_response_for(
            CoordinationAnalysis,
            valid_empty_coordination_analysis_dict(
                constraint_ids=("SC-1", "SC-2", "SC-3"),
                hazard_ids=("H-1", "H-2", "H-3"),
                responsibility_ids=("RESP-1",),
                action_ids=("CA-1-1",),
            ),
        )
        # Register a review response that would be used only if the review
        # were (incorrectly) attempted on the pinned path.
        client.set_response_for(RiskCoverageReview, _valid_rows())

        result = run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_cards(),
            run_dir=tmp_path,
            loss_analysis_path=pinned,
        )

        assert result.stage_errors == []
        assert result.loss_analysis is not None
        steps = [entry["step"] for entry in read_calls_jsonl(tmp_path)]
        assert "risk_coverage_review" not in steps
        manifest = yaml.safe_load((tmp_path / "run-manifest.yaml").read_text())
        review = manifest["stage_summary"]["stage_1a"]["risk_coverage_review"]
        assert review["status"] == "skipped_pinned"
        assert review["call_count"] == 0
        assert manifest["stage_summary"]["stage_1a"]["call_count"] == 0
        assert not (tmp_path / ARTIFACT_FILENAME).exists()


class TestSplitRule:
    def test_threshold_splits_a_long_response_estimate(self):
        system = "system"
        user = "user"
        assert not should_split_review(system, user, 3, max_completion_tokens=8192)
        assert should_split_review(system, user, 49, max_completion_tokens=8192)
        assert estimated_review_tokens(system, user, 49) > 8192

    def test_single_card_never_splits(self):
        assert not should_split_review("system", "user", 1, max_completion_tokens=1)

    def test_split_merges_rows_in_card_order(self, tmp_path):
        # A one-token budget forces the documented two-call split.  Each call
        # gets the rows for its own half of the cards, in reverse order, so
        # the merged rows must be re-sorted into supplied card order.
        first = _valid_rows()
        first["rows"] = [first["rows"][1], first["rows"][0]]
        second = _valid_rows()
        second["rows"] = [second["rows"][3], second["rows"][2]]
        analysis = _analysis()
        from asago_scenario_generator.stpa.infra.yaml_io import write_yaml

        write_yaml(analysis, tmp_path / "loss-analysis.yaml")
        digest = hashlib.sha256(
            (tmp_path / "loss-analysis.yaml").read_bytes()
        ).hexdigest()
        client = MockLLMClient()
        client.set_response_for(RiskCoverageReview, [first, second])

        outcome = run_risk_coverage_review(
            llm_client=client,
            loss_analysis=analysis,
            risk_cards=_cards(),
            use_case_text="Test use case",
            run_dir=tmp_path,
            template_loader=TemplateLoader(PROMPTS_DIR),
            temperature=0.4,
            reviewed_loss_analysis_digest=digest,
            max_completion_tokens=1,
        )

        assert outcome.status == "completed"
        assert outcome.call_count == 2
        artifact = yaml.safe_load((tmp_path / ARTIFACT_FILENAME).read_text())
        assert artifact["call_count"] == 2
        assert [row["risk_id"] for row in artifact["rows"]] == [
            "risk-a",
            "risk-b",
            "risk-c",
            "risk-d",
        ]


class TestRowSchema:
    def test_row_is_closed_and_frozen(self):
        from asago_scenario_generator.stpa.system_model.risk_coverage_review import (
            RiskCoverageRow,
        )

        with pytest.raises(ValidationError):
            RiskCoverageRow.model_validate(
                {
                    "risk_id": "risk-a",
                    "protects": "x",
                    "coverage": "none",
                    "missing_protection": "y",
                    "evidence": [
                        {"source_ref": "risk-a", "quote": "q", "meaning": "m"}
                    ],
                    "rationale": "r",
                    "bogus": "extra",
                }
            )
