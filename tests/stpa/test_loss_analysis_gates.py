"""Phase 1 gates on the loss analysis: risk accounting and hazard-graph density.

Spec: ai/findings/target-grounded-scenario-generation-spec-2026-09-07.md,
Phase 1.  The iteration-20 replay anchors every check to the observed
failure that motivated the phase.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from asago_scenario_generator.models.risk_card import RiskCard
from asago_scenario_generator.stpa.infra.llm_helpers import StageError
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.models.loss_analysis import (
    LossAnalysis,
    SecurityConstraint,
)
from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.system_model.loss_analysis import (
    LossAnalysisDraft,
    derive_loss_analysis,
    normalize_disposition_citations,
)
from asago_scenario_generator.stpa.system_model.loss_analysis_gates import (
    UNCLASSIFIED,
    _keyword_hits,
    _revision_patch_to_draft,
    check_hazard_graph_density,
    check_risk_accounting,
    classify_constraint,
    extract_subject_phrases,
    gate_loss_analysis,
    load_behavior_classes,
)
from asago_scenario_generator.stpa.system_model.loss_analysis import (
    _Stage1aRevisionPatch,
)
from tests.stpa.sp1_helpers import (
    MockLLMClient,
    read_calls_jsonl,
    setup_sp1_mock_client,
    valid_empty_coordination_analysis_dict,
    valid_gap_draft_dict,
    valid_loss_analysis_dict,
    valid_risk_draft_dict,
)

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "iteration20-loss-analysis.yaml"

# The exact 49 risk card IDs supplied to the iteration-20 run, extracted from
# the run's own stage_1a/risk_derivation call evidence.
ITERATION20_RISK_IDS: tuple[str, ...] = (
    "atlas-generated-content-ownership",
    "credo-risk-026",
    "atlas-hallucination",
    "credo-risk-036",
    "credo-risk-037",
    "credo-risk-010",
    "ai-risk-taxonomy-unauthorized-disclosure---pii-(personal-identifiable-information)",
    "ai-risk-taxonomy-unauthorized-disclosure---financial-records",
    "atlas-personal-information-in-data",
    "credo-risk-021",
    "credo-risk-016",
    "atlas-exposing-personal-information",
    "mit-ai-risk-subdomain-2.1",
    "credo-risk-025",
    "atlas-prompt-priming",
    "atlas-nonconsensual-use",
    "ai-risk-taxonomy-unauthorized-processing---pii-(personal-identifiable-information)",
    "ai-risk-taxonomy-unauthorized-processing---financial-records",
    "ai-risk-taxonomy-unauthorized-distribution---pii-(personal-identifiable-information)",
    "mit-ai-risk-subdomain-5.1",
    "atlas-personal-information-in-prompt",
    "atlas-copyright-infringement",
    "atlas-revealing-confidential-information",
    "credo-risk-024",
    "atlas-ip-information-in-prompt",
    "mit-ai-risk-subdomain-3.1",
    "mit-ai-risk-subdomain-4.3",
    "credo-risk-023",
    "atlas-non-disclosure",
    "mit-ai-risk-subdomain-2.2",
    "atlas-dangerous-use",
    "atlas-data-usage",
    "credo-risk-038",
    "credo-risk-048",
    "atlas-output-bias",
    "mit-ai-risk-subdomain-1.1",
    "credo-risk-034",
    "mit-ai-risk-subdomain-7.3",
    "atlas-model-usage-rights",
    "credo-risk-039",
    "credo-risk-029",
    "credo-risk-027",
    "atlas-spreading-disinformation",
    "atlas-data-privacy-rights",
    "mit-ai-risk-subdomain-6.3",
    "atlas-over-or-under-reliance",
    "credo-risk-017",
    "atlas-confidential-data-in-prompt",
    "atlas-data-usage-rights",
)


@pytest.fixture
def iteration20_analysis() -> LossAnalysis:
    return LossAnalysis.model_validate(yaml.safe_load(FIXTURE_PATH.read_text()))


def _risk_cards(ids: tuple[str, ...] = ITERATION20_RISK_IDS) -> list[RiskCard]:
    return [
        RiskCard(
            risk_id=risk_id,
            risk_name=risk_id,
            risk_description=f"Risk {risk_id}",
            taxonomy="test",
            confidence=0.9,
            grounding_confidence="high",
        )
        for risk_id in ids
    ]


class TestIteration20Replay:
    """The iteration-20 analysis fails every Phase 1 gate offline."""

    def test_risk_accounting_fails_with_36_unaccounted_risks(
        self, iteration20_analysis: LossAnalysis
    ) -> None:
        report = check_risk_accounting(iteration20_analysis, _risk_cards())

        assert report.missing_dispositions == ITERATION20_RISK_IDS
        assert len(report.unaccounted_risk_refs) == 36
        assert not report.passed

    def test_hazard_graph_density_fails_with_the_specified_checks(
        self, iteration20_analysis: LossAnalysis
    ) -> None:
        report = check_hazard_graph_density(
            iteration20_analysis, load_behavior_classes()
        )

        checks = "\n".join(report.failing_checks)
        assert "loss L-2 has no hazard" in checks
        assert (
            "constraint SC-2 and hazard H-1 share no subject phrase"
            in report.advisory_checks
        )
        assert "behavior class unauthorized_write has no hazard of its own" in checks
        assert "behavior class missed_escalation has no hazard of its own" in checks
        # SC-1/H-1 do share a subject, so the subject rule is not vacuous.
        assert (
            "constraint SC-1 and hazard H-1 share no subject phrase"
            not in report.advisory_checks
        )
        assert not report.passed


class TestRiskAccountingCheck:
    def test_disposed_cards_pass(self) -> None:
        analysis = LossAnalysis.model_validate(valid_risk_draft_dict())
        report = check_risk_accounting(analysis, _risk_cards(("atlas-001",)))
        assert report.passed
        assert report.cited_refs == ("atlas-001",)

    def test_card_neither_disposed_nor_cited_is_unaccounted(self) -> None:
        analysis = LossAnalysis.model_validate(valid_risk_draft_dict())
        report = check_risk_accounting(
            analysis, _risk_cards(("atlas-001", "atlas-002"))
        )
        assert "atlas-002" in report.missing_dispositions
        assert report.unaccounted_risk_refs == ("atlas-002",)


class TestSubjectPhrases:
    def test_shared_noun_phrase_is_detected(self) -> None:
        constraint = "The agent must confirm every unintended payment before execution."
        hazard = "The agent executes an unintended payment."
        shared = extract_subject_phrases(constraint) & extract_subject_phrases(hazard)
        assert "unintended payment" in shared

    def test_generic_verb_or_actor_never_counts_as_a_subject(self) -> None:
        # Both sentences share only generic actor/verb vocabulary.
        first = "The system must ensure compliance."
        second = "The assistant must ensure safety."
        assert not (extract_subject_phrases(first) & extract_subject_phrases(second))

    def test_unigram_counts_only_as_a_whole_run(self) -> None:
        # "payment" appears inside a longer run on both sides, so the shared
        # unigram alone must not create a subject match.
        first = "The payment schedule changed."
        second = "The payment amount changed."
        shared = extract_subject_phrases(first) & extract_subject_phrases(second)
        assert not shared

    def test_sibilant_plurals_and_exceptions_singularize(self) -> None:
        # "exposes" is a verb form whose stem keeps its final e; the sibilant
        # exception nouns lose the whole es ("losses" -> "loss"); s-final
        # singulars stay intact ("bias" was a live subject-phrase miss).
        assert extract_subject_phrases("Agent exposes data.") & (
            extract_subject_phrases("Must not expose data")
        )
        assert extract_subject_phrases("Losses.") & extract_subject_phrases("The loss.")
        assert "bia" not in extract_subject_phrases("Bias detected.")


class TestBehaviorClasses:
    def _write_table(self, tmp_path: Path, payload: str) -> Path:
        table_path = tmp_path / "behavior-classes.yaml"
        table_path.write_text(payload, encoding="utf-8")
        return table_path

    def test_malformed_tables_fail_closed(self, tmp_path: Path) -> None:
        cases = [
            "not_a_mapping: true",
            "classes: []",
            "classes:\n  - keywords: [refund]",
            "classes:\n  - name: '  '\n    keywords: [refund]",
            "classes:\n  - name: disclosure\n    keywords: []",
            "classes:\n  - name: disclosure\n    keywords: [1, 2]",
        ]
        for payload in cases:
            table_path = self._write_table(tmp_path, payload)
            with pytest.raises(ValueError):
                load_behavior_classes(table_path)

    def test_classification_matches_keyword_majority(self) -> None:
        table = load_behavior_classes()
        assert (
            classify_constraint(
                "No PII may be included in the generated output sent to an "
                "unauthorized recipient.",
                table,
            )
            == "disclosure"
        )
        assert (
            classify_constraint(
                "Refund processing must match the intent and authorized "
                "parameters of the session.",
                table,
            )
            == "unauthorized_write"
        )

    def test_ties_resolve_to_earlier_class_in_file_order(self) -> None:
        table = load_behavior_classes()
        # "unauthorized recipient" (disclosure) and "refund" (write) hit once.
        text = "A refund must never reach an unauthorized recipient."
        assert classify_constraint(text, table) == "disclosure"

    def test_zero_hits_is_unclassified(self) -> None:
        table = load_behavior_classes()
        assert classify_constraint("Every session must be logged.", table) == (
            UNCLASSIFIED
        )


class TestHazardGraphDensityChecks:
    def _analysis(self, payload: dict) -> LossAnalysis:
        return LossAnalysis.model_validate(payload)

    def _base_payload(self) -> dict:
        return {
            "risk_card_losses": [
                {
                    "loss_id": "L-1",
                    "description": "Payment record is exposed.",
                    "provenance": "risk_card",
                    "source_risk_cards": ["atlas-001"],
                }
            ],
            "use_case_losses": [],
            "hazards": [
                {
                    "hazard_id": "H-1",
                    "description": "The payment record is exposed without authorization.",
                    "related_losses": ["L-1"],
                }
            ],
            "security_constraints": [
                {
                    "constraint_id": "SC-1",
                    "rule": "The payment record must stay protected.",
                    "applies_when": [],
                    "related_hazards": ["H-1"],
                }
            ],
        }

    def test_check1_loss_without_hazard_fails(self) -> None:
        payload = self._base_payload()
        payload["use_case_losses"].append(
            {
                "loss_id": "L-2",
                "description": "Customer trust is lost.",
                "provenance": "use_case",
                "source_risk_cards": [],
            }
        )
        report = check_hazard_graph_density(
            self._analysis(payload), load_behavior_classes()
        )
        assert "loss L-2 has no hazard" in report.failing_checks

    def test_check2_constraint_without_hazard_fails(self) -> None:
        payload = self._base_payload()
        payload["security_constraints"].append(
            {
                "constraint_id": "SC-2",
                "rule": "The payment record must never reach an outside party.",
                "applies_when": [],
                "related_hazards": [],
            }
        )
        report = check_hazard_graph_density(
            self._analysis(payload), load_behavior_classes()
        )
        assert "constraint SC-2 has no hazard" in report.failing_checks

    def test_check3_shared_subject_is_recorded_on_passing_edge(self) -> None:
        report = check_hazard_graph_density(
            self._analysis(self._base_payload()), load_behavior_classes()
        )
        assert report.passed
        assert report.subject_checks[0].shared_phrases == ("payment record",)

    def test_check3_subject_mismatch_is_advisory(self) -> None:
        payload = self._base_payload()
        payload["security_constraints"][0]["rule"] = (
            "The agent must escalate every regulated topic to a human."
        )
        report = check_hazard_graph_density(
            self._analysis(payload), load_behavior_classes()
        )
        expected = "constraint SC-1 and hazard H-1 share no subject phrase"
        assert report.subject_checks[0].passed is False
        assert report.advisory_checks == (expected,)
        assert expected not in report.failing_checks
        assert report.passed

    def _two_class_payload(self, *, shared_hazard: bool) -> dict:
        payload = self._base_payload()
        payload["risk_card_losses"][0]["description"] = "Wrong information is provided."
        payload["hazards"] = [
            {
                "hazard_id": "H-1",
                "description": (
                    "The assistant provides wrong information about fees, "
                    "policies, or payment terms."
                ),
                "related_losses": ["L-1"],
            }
        ]
        if not shared_hazard:
            payload["hazards"].append(
                {
                    "hazard_id": "H-2",
                    "description": (
                        "The assistant misses the escalation of a regulated "
                        "topic to a human agent."
                    ),
                    "related_losses": ["L-1"],
                }
            )
        payload["security_constraints"] = [
            {
                "constraint_id": "SC-1",
                "rule": (
                    "Responses about fees, policies, or payment terms must be "
                    "grounded in the approved knowledge base."
                ),
                "applies_when": [],
                "related_hazards": ["H-1"],
            },
            {
                "constraint_id": "SC-2",
                "rule": (
                    "The assistant must escalate to a human agent on "
                    "regulated topics instead of improvising."
                ),
                "applies_when": [],
                "related_hazards": ["H-1"] if shared_hazard else ["H-2"],
            },
        ]
        return payload

    def test_check4_two_classes_cannot_share_their_only_hazard(self) -> None:
        report = check_hazard_graph_density(
            self._analysis(self._two_class_payload(shared_hazard=True)),
            load_behavior_classes(),
        )
        checks = "\n".join(report.failing_checks)
        assert "behavior class wrong_information has no hazard of its own" in checks
        assert "behavior class missed_escalation has no hazard of its own" in checks

    def test_check4_distinct_hazards_per_class_pass(self) -> None:
        report = check_hazard_graph_density(
            self._analysis(self._two_class_payload(shared_hazard=False)),
            load_behavior_classes(),
        )
        assert report.passed

    def test_check5_every_hazard_covered_passes(self) -> None:
        report = check_hazard_graph_density(
            self._analysis(self._base_payload()), load_behavior_classes()
        )
        assert report.hazards_without_constraint == ()
        assert report.passed

    def test_check5_hazard_without_constraint_fails(self) -> None:
        payload = self._base_payload()
        payload["hazards"].append(
            {
                "hazard_id": "H-2",
                "description": "The agent erodes user trust.",
                "related_losses": ["L-1"],
            }
        )
        report = check_hazard_graph_density(
            self._analysis(payload), load_behavior_classes()
        )
        assert report.hazards_without_constraint == ("H-2",)
        assert "hazard H-2 has no constraint" in report.failing_checks
        assert not report.passed


class TestDeriveLossAnalysisAccounting:
    """The 1.1 gate joins Call 1's one targeted repair."""

    def test_missing_dispositions_get_one_targeted_repair_then_pass(
        self, tmp_path
    ) -> None:
        import json as jsonlib

        from asago_scenario_generator.stpa.system_model.loss_analysis_repair import (
            DispositionRepairResponse,
        )

        incomplete = valid_risk_draft_dict()
        incomplete["risk_dispositions"] = []
        client = MockLLMClient()
        client.set_response_for(
            LossAnalysisDraft,
            [incomplete, valid_gap_draft_dict()],
        )
        client.set_response_for(
            DispositionRepairResponse,
            {
                "risk_dispositions": [
                    {
                        "risk_ref": "atlas-001",
                        "disposition": "cited",
                        "loss_ids": ["L-1"],
                        "reason": None,
                    }
                ]
            },
        )
        result = derive_loss_analysis(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_risk_cards(("atlas-001",)),
            run_dir=tmp_path,
        )

        assert result.risk_dispositions[0].risk_ref == "atlas-001"
        assert result.risk_dispositions[0].disposition == "cited"
        entries = [
            jsonlib.loads(line)
            for line in (tmp_path / "calls.jsonl").read_text().splitlines()
        ]
        assert [entry["step"] for entry in entries] == [
            "risk_derivation",
            "risk_derivation_repair",
            "gap_analysis",
        ]
        assert [entry["success"] for entry in entries] == [False, True, True]
        repair_prompt = entries[1]["user_prompt_text"].lower()
        assert "failed risk accounting" in repair_prompt
        assert (
            "no risk_dispositions entry was returned for this supplied card"
            in repair_prompt
        )

    def test_failed_disposition_repair_is_fatal(self, tmp_path) -> None:
        from asago_scenario_generator.stpa.system_model.loss_analysis_repair import (
            DispositionRepairResponse,
        )

        incomplete = valid_risk_draft_dict()
        incomplete["risk_dispositions"] = []
        client = MockLLMClient()
        client.set_response_for(
            LossAnalysisDraft,
            [incomplete, valid_gap_draft_dict()],
        )
        # The single repair response cites a loss the draft never declared,
        # so the deterministic merge rejects it and the repair never retries.
        client.set_response_for(
            DispositionRepairResponse,
            {
                "risk_dispositions": [
                    {
                        "risk_ref": "atlas-001",
                        "disposition": "cited",
                        "loss_ids": ["L-99"],
                        "reason": None,
                    }
                ]
            },
        )
        with pytest.raises(StageError, match="targeted repair failed"):
            derive_loss_analysis(
                llm_client=client,
                use_case_text="Test use case",
                risk_cards=_risk_cards(("atlas-001",)),
                run_dir=tmp_path,
            )
        assert len(client.calls) == 2

    def test_dispositions_and_conditions_are_persisted(self, tmp_path) -> None:
        import yaml as yaml_lib

        from asago_scenario_generator.stpa.infra.yaml_io import read_yaml

        draft = valid_risk_draft_dict()
        draft["security_constraints"][0]["applies_when"] = ["before execution"]
        client = MockLLMClient()
        client.set_response_for(LossAnalysisDraft, [draft, valid_gap_draft_dict()])
        derive_loss_analysis(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_risk_cards(("atlas-001",)),
            run_dir=tmp_path,
        )

        loaded = read_yaml(tmp_path / "loss-analysis.yaml", LossAnalysis)
        assert loaded.risk_dispositions[0].risk_ref == "atlas-001"
        assert loaded.security_constraints[0].applies_when == ["before execution"]
        assert loaded.security_constraints[0].description == (
            "The agent must confirm every unintended payment. "
            "Applies when: before execution."
        )
        persisted = yaml_lib.safe_load((tmp_path / "loss-analysis.yaml").read_text())
        assert persisted["risk_dispositions"][0]["disposition"] == "cited"


def _revision_response(*, fix_constraint: bool) -> dict:
    """Return an explicit delta for the graph-revision call.

    Omitted hazards and constraints are carried forward by deterministic
    compilation.  The SC-2 edit includes obligations when its rule changes so
    no prior interpretation is silently reused.
    """
    gap_constraint_rule = (
        "The agent must preserve user trust."
        if fix_constraint
        else "The agent must maintain transparency about fees."
    )
    edit = {
        "constraint_id": "SC-2",
        "rule": gap_constraint_rule,
        "applies_when": ["through transparency"] if fix_constraint else [],
        "related_hazards": ["H-2", "H-3"] if fix_constraint else ["H-1"],
    }
    if fix_constraint:
        edit["obligations"] = []
    return {
        "hazard_edits": [],
        "hazard_additions": [],
        "security_constraint_edits": [edit],
        "security_constraint_additions": [],
    }


def _revision_response_with_hazard_addition(*, fix_constraint: bool) -> dict:
    """Return a delta that fixes SC-2 and adds a new unclassified chain."""
    response = _revision_response(fix_constraint=fix_constraint)
    response["hazard_additions"] = [
        {
            "handle": "operational_hazard",
            "description": "The service suffers operational disruption.",
            "related_losses": ["L-2"],
        }
    ]
    response["security_constraint_additions"] = [
        {
            "handle": "operational_constraint",
            "rule": (
                "The system must prevent operational disruption due to "
                "third-party service availability."
            ),
            "applies_when": [],
            "related_hazards": ["operational_hazard"],
            "obligations": [],
        }
    ]
    return response


def _revision_response_for_disallowed_deletion() -> dict:
    """A legacy whole-graph deletion shape, rejected by the current wire."""
    return {
        "hazard_edits": [],
        "hazard_additions": [],
        "security_constraint_edits": [],
        "security_constraint_additions": [],
        "security_constraints": [],
    }


def _legacy_revision_conditions_changed_same_rule() -> dict:
    """Return a current delta for an explicit applicability-only edit."""
    return {
        "hazard_edits": [
            {
                "hazard_id": "H-2",
                "description": "The agent maintains transparency about fees.",
                "related_losses": ["L-2"],
            }
        ],
        "hazard_additions": [],
        "security_constraint_edits": [
            {
                "constraint_id": "SC-1",
                "rule": "The agent must confirm every unintended payment.",
                "applies_when": ["before execution"],
                "related_hazards": ["H-1"],
            },
            {
                "constraint_id": "SC-2",
                "rule": "The agent must maintain transparency about fees.",
                "applies_when": ["for every customer question"],
                "related_hazards": ["H-2", "H-3"],
                "obligations": [],
            },
        ],
        "security_constraint_additions": [],
    }


def _structurally_failing_gap_draft() -> dict:
    """Return a gap draft with a blocking missing hazard edge."""
    draft = valid_gap_draft_dict()
    draft["hazards"].append(
        {
            "hazard_id": "H-3",
            "description": "The agent erodes user trust.",
            "related_losses": ["L-2"],
        }
    )
    draft["security_constraints"][0]["rule"] = (
        "The agent must maintain transparency about fees."
    )
    draft["security_constraints"][0]["applies_when"] = []
    return draft


def _set_three_hazard_review(client: MockLLMClient) -> None:
    """Configure Stage 2 review evidence for the structurally repaired graph."""
    from asago_scenario_generator.stpa.system_model.control_structure import (
        CoordinationAnalysis,
    )

    review = valid_empty_coordination_analysis_dict(
        constraint_ids=("SC-1", "SC-2"),
        hazard_ids=("H-1", "H-2", "H-3"),
    )
    review["semantic_review"]["constraints"][1]["related_hazards"] = ["H-2", "H-3"]
    client.set_response_for(CoordinationAnalysis, review)


class TestWireSchemaRetry:
    """A pydantic wire violation is salvaged row by row, never retried."""

    def test_invalid_gap_dispositions_are_dropped_and_accounting_survives(
        self, tmp_path
    ) -> None:
        import json as jsonlib

        # The live gemma4-oc run emitted a garbage risk_dispositions
        # collection in the gap response; the rows are out of contract, so
        # deterministic code drops them and Call 1's accounting survives.
        bad_gap = valid_gap_draft_dict()
        bad_gap["risk_dispositions"] = [
            {"risk_ref": "L-2", "disposition": "not_applicable"},
            {"risk_ref": "H-2", "disposition": "not_applicable"},
        ]
        client = MockLLMClient()
        client.set_response_for(
            LossAnalysisDraft,
            [valid_risk_draft_dict(), bad_gap],
        )
        warnings: list[str] = []
        result = derive_loss_analysis(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_risk_cards(("atlas-001",)),
            run_dir=tmp_path,
            normalization_warnings=warnings,
        )

        assert result.risk_dispositions[0].risk_ref == "atlas-001"
        assert any("dropped malformed risk_dispositions" in w for w in warnings)
        entries = [
            jsonlib.loads(line)
            for line in (tmp_path / "calls.jsonl").read_text().splitlines()
        ]
        gap_entries = [e for e in entries if e["step"] == "gap_analysis"]
        assert [e["success"] for e in gap_entries] == [False]
        # The drop is deterministic: no repair call follows the failure.
        assert not any(e["step"].endswith("_repair") for e in entries)
        assert len(client.calls) == 2

    def test_repeated_gap_wire_garbage_is_dropped_deterministically(
        self, tmp_path
    ) -> None:
        import json as jsonlib

        bad_gap = valid_gap_draft_dict()
        bad_gap["risk_dispositions"] = [
            {"risk_ref": f"SC-{index}", "disposition": "not_applicable"}
            for index in range(2, 20)
        ]
        client = MockLLMClient()
        client.set_response_for(LossAnalysisDraft, [valid_risk_draft_dict(), bad_gap])
        warnings: list[str] = []
        result = derive_loss_analysis(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_risk_cards(("atlas-001",)),
            run_dir=tmp_path,
            normalization_warnings=warnings,
        )

        # Every garbage row is dropped and the run proceeds deterministically.
        assert result.risk_dispositions[0].risk_ref == "atlas-001"
        assert sum("dropped malformed risk_dispositions" in w for w in warnings) == 18
        entries = [
            jsonlib.loads(line)
            for line in (tmp_path / "calls.jsonl").read_text().splitlines()
        ]
        gap_entries = [e for e in entries if e["step"] == "gap_analysis"]
        assert [e["success"] for e in gap_entries] == [False]
        assert not any(e["step"].endswith("_repair") for e in entries)


class TestRunSp1Gates:
    """The density gate runs inside run_sp1 after Stage 1a."""

    def test_subject_mismatch_passes_as_advisory_without_revision(self, tmp_path) -> None:
        import yaml as yaml_lib

        payload = valid_loss_analysis_dict()
        payload["risk_dispositions"] = [
            {
                "risk_ref": "atlas-001",
                "disposition": "cited",
                "loss_ids": ["L-1"],
                "reason": None,
            }
        ]
        payload["security_constraints"][1]["rule"] = (
            "The agent must escalate every regulated topic to a human."
        )
        analysis = LossAnalysis.model_validate(payload)
        client = MockLLMClient()

        outcome = gate_loss_analysis(
            llm_client=client,
            loss_analysis=analysis,
            use_case_text="Test use case",
            risk_cards=_risk_cards(("atlas-001",)),
            run_dir=tmp_path,
            template_loader=TemplateLoader(PROMPTS_DIR),
            temperature=0.4,
        )

        expected = "constraint SC-2 and hazard H-2 share no subject phrase"
        assert outcome.passed
        assert outcome.revision_attempted is False
        assert outcome.revision_applied is False
        assert outcome.density.advisory_checks == (expected,)
        assert client.calls == []
        artifact = yaml_lib.safe_load(
            (tmp_path / "loss-analysis-gates.yaml").read_text()
        )
        assert artifact["passed"] is True
        assert artifact["failing_checks"] == []
        assert artifact["advisory_checks"] == [expected]
        assert artifact["hazard_graph_density"]["subject_checks"][1]["passed"] is False

    def test_clean_graph_passes_without_a_revision_call(self, tmp_path) -> None:
        import json as jsonlib

        import yaml as yaml_lib

        from asago_scenario_generator.stpa.system_model.run import run_sp1

        client = setup_sp1_mock_client()
        result = run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_risk_cards(("atlas-001",)),
            run_dir=tmp_path,
        )

        assert result.loss_analysis is not None
        assert result.control_structure is not None
        entries = [
            jsonlib.loads(line)
            for line in (tmp_path / "calls.jsonl").read_text().splitlines()
        ]
        stage1a = [e for e in entries if e["stage"] == "stage_1a"]
        assert [e["step"] for e in stage1a] == [
            "risk_actionability",
            "risk_derivation",
            "gap_analysis",
            "stated_rule_extraction",
            "risk_coverage_review",
        ]
        manifest = yaml_lib.safe_load((tmp_path / "run-manifest.yaml").read_text())
        gates = manifest["stage_summary"]["stage_1a"]
        assert gates["hazard_graph_density"] == "passed"
        assert gates["risk_accounting"] == "passed"
        assert gates["graph_revision_call_count"] == 0
        artifact = yaml_lib.safe_load(
            (tmp_path / "loss-analysis-gates.yaml").read_text()
        )
        assert artifact["passed"] is True
        assert artifact["revision_attempted"] is False
        assert artifact["advisory_checks"] == []

    def test_normalized_accounting_recorded_in_gates_artifact(self, tmp_path) -> None:
        import yaml as yaml_lib

        from asago_scenario_generator.stpa.system_model.run import run_sp1

        client = setup_sp1_mock_client()
        contradictory = valid_risk_draft_dict()
        contradictory["risk_dispositions"] = [
            {
                "risk_ref": "atlas-001",
                "disposition": "not_applicable",
                "loss_ids": [],
                "reason": "No grounded loss applies.",
            }
        ]
        client.set_response_for(
            LossAnalysisDraft,
            [contradictory, valid_gap_draft_dict()],
        )
        result = run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_risk_cards(("atlas-001",)),
            run_dir=tmp_path,
        )

        assert result.loss_analysis is not None
        disposition = result.loss_analysis.risk_dispositions[0]
        assert disposition.disposition == "cited"
        artifact = yaml_lib.safe_load(
            (tmp_path / "loss-analysis-gates.yaml").read_text()
        )
        assert artifact["passed"] is True
        assert len(artifact["normalization_warnings"]) == 1
        assert "atlas-001" in artifact["normalization_warnings"][0]
        manifest = yaml_lib.safe_load((tmp_path / "run-manifest.yaml").read_text())
        assert any("atlas-001" in warning for warning in manifest["stage_warnings"])

    def test_failing_graph_gets_one_revision_then_passes(self, tmp_path) -> None:
        import json as jsonlib

        import yaml as yaml_lib

        from asago_scenario_generator.stpa.system_model.run import run_sp1

        client = setup_sp1_mock_client()
        client.set_response_for(
            LossAnalysisDraft,
            [
                valid_risk_draft_dict(),
                _structurally_failing_gap_draft(),
            ],
        )
        client.set_response_for(
            _Stage1aRevisionPatch, _revision_response(fix_constraint=True)
        )
        _set_three_hazard_review(client)
        result = run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_risk_cards(("atlas-001",)),
            run_dir=tmp_path,
        )

        assert result.stage_errors == []
        assert result.loss_analysis is not None
        assert result.loss_analysis.security_constraints[1].description == (
            "The agent must preserve user trust. Applies when: through transparency."
        )
        entries = [
            jsonlib.loads(line)
            for line in (tmp_path / "calls.jsonl").read_text().splitlines()
        ]
        stage1a = [e for e in entries if e["stage"] == "stage_1a"]
        assert [e["step"] for e in stage1a] == [
            "risk_actionability",
            "risk_derivation",
            "gap_analysis",
            "stated_rule_extraction",
            "hazard_graph_revision",
            "risk_coverage_review",
        ]
        assert all(e["success"] for e in stage1a)
        revision_prompt = stage1a[4]["user_prompt_text"]
        assert "hazard H-3 has no constraint" in revision_prompt
        assert "share no subject phrase" not in revision_prompt
        assert "Do not suggest" not in revision_prompt
        manifest = yaml_lib.safe_load((tmp_path / "run-manifest.yaml").read_text())
        gates = manifest["stage_summary"]["stage_1a"]
        assert gates["hazard_graph_density"] == "passed_after_revision"
        assert gates["graph_revision_call_count"] == 1

    def test_uncovered_hazard_gets_one_revision_then_passes(self, tmp_path) -> None:
        import json as jsonlib

        import yaml as yaml_lib

        from asago_scenario_generator.stpa.system_model.run import run_sp1

        client = setup_sp1_mock_client()
        client.set_response_for(
            LossAnalysisDraft,
            [
                valid_risk_draft_dict(),
                _gap_draft_with_uncovered_hazard(),
            ],
        )
        client.set_response_for(_Stage1aRevisionPatch, _revision_covering_h2())
        result = run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_risk_cards(("atlas-001",)),
            run_dir=tmp_path,
        )

        assert result.stage_errors == []
        assert result.loss_analysis is not None
        assert result.control_structure is not None
        entries = [
            jsonlib.loads(line)
            for line in (tmp_path / "calls.jsonl").read_text().splitlines()
        ]
        stage1a = [e for e in entries if e["stage"] == "stage_1a"]
        assert [e["step"] for e in stage1a] == [
            "risk_actionability",
            "risk_derivation",
            "gap_analysis",
            "stated_rule_extraction",
            "hazard_graph_revision",
            "risk_coverage_review",
        ]
        revision_prompt = stage1a[4]["user_prompt_text"]
        assert "hazard H-2 has no constraint" in revision_prompt
        manifest = yaml_lib.safe_load((tmp_path / "run-manifest.yaml").read_text())
        gates = manifest["stage_summary"]["stage_1a"]
        assert gates["hazard_graph_density"] == "passed_after_revision"
        assert gates["graph_revision_call_count"] == 1

    def test_deletion_shaped_revision_fails_closed_after_one_correction(
        self, tmp_path
    ) -> None:
        import json as jsonlib

        import yaml as yaml_lib

        from asago_scenario_generator.stpa.system_model.run import run_sp1

        client = setup_sp1_mock_client()
        client.set_response_for(
            LossAnalysisDraft,
            [
                valid_risk_draft_dict(),
                _gap_draft_with_uncovered_hazard(),
            ],
        )
        client.set_response_for(_Stage1aRevisionPatch, _revision_leaving_h2_uncovered())
        result = run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_risk_cards(("atlas-001",)),
            run_dir=tmp_path,
        )

        assert result.loss_analysis is None
        assert result.control_structure is None
        assert any(
            "graph revision call failed" in error for error in result.stage_errors
        )
        assert any(
            "Extra inputs are not permitted" in error for error in result.stage_errors
        )
        entries = [
            jsonlib.loads(line)
            for line in (tmp_path / "calls.jsonl").read_text().splitlines()
        ]
        revisions = [e for e in entries if e["step"] == "hazard_graph_revision"]
        assert [e["success"] for e in revisions] == [False, False]
        assert [e["attempt_number"] for e in revisions] == [1, 2]
        artifact = yaml_lib.safe_load(
            (tmp_path / "loss-analysis-gates.yaml").read_text()
        )
        assert artifact["revision_attempted"] is True
        assert artifact["revision_applied"] is False
        assert artifact["revision_call_count"] == 2
        assert artifact["passed"] is False
        assert artifact["advisory_checks"] == []
        assert artifact["hazard_graph_density"]["hazards_without_constraint"] == ["H-2"]
        manifest = yaml_lib.safe_load((tmp_path / "run-manifest.yaml").read_text())
        assert manifest["stage_summary"]["stage_1a"]["graph_revision_call_count"] == 2

    def test_second_density_failure_is_fatal_with_exact_checks(self, tmp_path) -> None:
        import yaml as yaml_lib

        from asago_scenario_generator.stpa.system_model.run import run_sp1

        client = setup_sp1_mock_client()
        client.set_response_for(
            LossAnalysisDraft,
            [
                valid_risk_draft_dict(),
                _structurally_failing_gap_draft(),
            ],
        )
        client.set_response_for(
            _Stage1aRevisionPatch, _revision_response(fix_constraint=False)
        )
        result = run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_risk_cards(("atlas-001",)),
            run_dir=tmp_path,
        )

        assert result.loss_analysis is None
        assert result.control_structure is None
        assert any(
            "hazard graph density gate failed" in error for error in result.stage_errors
        )
        assert any(
            "hazard H-2 has no constraint" in error
            for error in result.stage_errors
        )
        manifest = yaml_lib.safe_load((tmp_path / "run-manifest.yaml").read_text())
        assert manifest["stage_errors"]
        gates = manifest["stage_summary"]["stage_1a"]
        assert gates["hazard_graph_density"] == "failed"
        assert gates["risk_accounting"] == "passed"
        # A valid revision that still fails gets exactly one more round.
        assert gates["graph_revision_call_count"] == 2
        # One actionability call, two derivations, the stated-rule
        # extraction, and two revisions.
        assert gates["call_count"] == 6
        assert any(
            "second revision still failing: hazard H-2 has no constraint" in error
            for error in result.stage_errors
        )
        artifact = yaml_lib.safe_load(
            (tmp_path / "loss-analysis-gates.yaml").read_text()
        )
        assert artifact["revision_attempted"] is True
        assert artifact["revision_applied"] is False
        assert artifact["passed"] is False
        assert [entry["round"] for entry in artifact["revision_rounds"]] == [1, 2]
        assert all(entry["revision_valid"] for entry in artifact["revision_rounds"])
        second_round = artifact["revision_rounds"][1]
        assert "hazard H-2 has no constraint" in second_round["failing_checks_after"]

    def test_second_revision_round_clears_residual_checks(self, tmp_path) -> None:
        import json as jsonlib

        import yaml as yaml_lib

        from asago_scenario_generator.stpa.system_model.run import run_sp1

        client = setup_sp1_mock_client()
        client.set_response_for(
            LossAnalysisDraft,
            [valid_risk_draft_dict(), _structurally_failing_gap_draft()],
        )
        client.set_response_for(
            _Stage1aRevisionPatch,
            [
                _revision_response(fix_constraint=False),
                _revision_response(fix_constraint=True),
            ],
        )
        _set_three_hazard_review(client)
        result = run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_risk_cards(("atlas-001",)),
            run_dir=tmp_path,
        )

        assert result.stage_errors == []
        assert result.loss_analysis is not None
        entries = [
            jsonlib.loads(line)
            for line in (tmp_path / "calls.jsonl").read_text().splitlines()
        ]
        revisions = [e for e in entries if e["step"] == "hazard_graph_revision"]
        assert len(revisions) == 2
        second_prompt = revisions[1]["user_prompt_text"]
        assert "hazard H-3 has no constraint\n" in second_prompt
        artifact = yaml_lib.safe_load(
            (tmp_path / "loss-analysis-gates.yaml").read_text()
        )
        assert artifact["passed"] is True
        assert artifact["revision_applied"] is True
        assert artifact["revision_call_count"] == 2
        assert artifact["failing_checks"] == []
        assert artifact["revision_rounds"][1]["failing_checks_after"] == []
        manifest = yaml_lib.safe_load((tmp_path / "run-manifest.yaml").read_text())
        gates = manifest["stage_summary"]["stage_1a"]
        assert gates["hazard_graph_density"] == "passed_after_revision"
        assert gates["graph_revision_call_count"] == 2

    def test_second_round_labels_checks_the_first_round_introduced(
        self, tmp_path
    ) -> None:
        import json as jsonlib

        import yaml as yaml_lib

        from asago_scenario_generator.stpa.system_model.run import run_sp1

        first = _revision_covering_h2()
        first["hazard_additions"] = [
            {
                "handle": "fee_exposure_hazard",
                "description": "The agent exposes fee details without consent.",
                "related_losses": ["L-2"],
            }
        ]
        second = {
            "hazard_edits": [],
            "hazard_additions": [],
            "security_constraint_edits": [],
            "security_constraint_additions": [
                {
                    "handle": "fee_consent_constraint",
                    "rule": "The agent must not expose fee details without consent.",
                    "applies_when": [],
                    "related_hazards": ["H-3"],
                    "obligations": [],
                }
            ],
        }
        client = setup_sp1_mock_client()
        client.set_response_for(
            LossAnalysisDraft,
            [valid_risk_draft_dict(), _gap_draft_with_uncovered_hazard()],
        )
        client.set_response_for(_Stage1aRevisionPatch, [first, second])
        run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_risk_cards(("atlas-001",)),
            run_dir=tmp_path,
        )

        entries = [
            jsonlib.loads(line)
            for line in (tmp_path / "calls.jsonl").read_text().splitlines()
        ]
        revisions = [e for e in entries if e["step"] == "hazard_graph_revision"]
        assert len(revisions) == 2
        assert (
            "hazard H-3 has no constraint (introduced by the previous revision)"
            in revisions[1]["user_prompt_text"]
        )
        artifact = yaml_lib.safe_load(
            (tmp_path / "loss-analysis-gates.yaml").read_text()
        )
        assert artifact["revision_rounds"][0]["introduced_checks"] == [
            "hazard H-3 has no constraint"
        ]
        assert artifact["revision_rounds"][1]["failing_checks_after"] == []
        assert artifact["passed"] is True


_TRUST_RULE = "The agent must preserve user trust."
_VERBATIM_TRUST_SPAN = "must preserve user trust"


def _revision_covering_h2_with_span(rule_span: str) -> dict:
    """A covering revision whose added constraint carries one obligation."""
    response = _revision_covering_h2()
    response["security_constraint_additions"][0]["obligations"] = [
        {
            "obligation_id": "O1",
            "kind": "required",
            "behavior": "preserve user trust",
            "rule_span": rule_span,
            "realized_by": "reply",
        }
    ]
    return response


def _run_sp1_with_revisions(tmp_path: Path, revisions: list[dict]):
    from asago_scenario_generator.stpa.system_model.run import run_sp1

    client = setup_sp1_mock_client()
    client.set_response_for(
        LossAnalysisDraft,
        [valid_risk_draft_dict(), _gap_draft_with_uncovered_hazard()],
    )
    client.set_response_for(_Stage1aRevisionPatch, revisions)
    result = run_sp1(
        llm_client=client,
        use_case_text="Test use case",
        risk_cards=_risk_cards(("atlas-001",)),
        run_dir=tmp_path,
    )
    return result


def _revision_entries(tmp_path: Path) -> list[dict]:
    import json as jsonlib

    return [
        entry
        for entry in (
            jsonlib.loads(line)
            for line in (tmp_path / "calls.jsonl").read_text().splitlines()
        )
        if entry["step"] == "hazard_graph_revision"
    ]


def _trust_constraint(result) -> SecurityConstraint:
    return next(
        constraint
        for constraint in result.loss_analysis.security_constraints
        if constraint.rule == _TRUST_RULE
    )


class TestGraphRevisionRuleSpanHardening:
    """A revision span defect is repaired in code or corrected once."""

    def test_ellipsis_span_is_repaired_without_a_correction_call(
        self, tmp_path
    ) -> None:
        result = _run_sp1_with_revisions(
            tmp_path, [_revision_covering_h2_with_span("must ... user trust")]
        )

        assert result.stage_errors == []
        constraint = _trust_constraint(result)
        assert constraint.obligations[0].rule_span == _VERBATIM_TRUST_SPAN
        identity = f"{constraint.constraint_id}/O1"
        assert [e["success"] for e in _revision_entries(tmp_path)] == [True]

        record = yaml.safe_load((tmp_path / "loss-analysis-repair.yaml").read_text())
        assert record["records"] == [
            {
                "stage": "hazard_graph_revision",
                "attempt": "first",
                "kind": "rule_span_repaired",
                "identity": identity,
                "reason": (
                    "rule_span did not quote the constraint rule verbatim; a "
                    "unique ellipsis match mapped it to the verbatim rule text"
                ),
                "proposed": {"rule_span": "must ... user trust"},
                "applied": {"rule_span": _VERBATIM_TRUST_SPAN, "match": "ellipsis"},
                "outcome": "applied",
                "raw_step": "hazard_graph_revision",
            }
        ]
        manifest = yaml.safe_load((tmp_path / "run-manifest.yaml").read_text())
        stage_1a = manifest["stage_summary"]["stage_1a"]
        assert stage_1a["graph_revision_call_count"] == 1
        assert stage_1a["rule_span_repairs"] == [
            {
                "step": "hazard_graph_revision",
                "attempt": "first",
                "identity": identity,
                "match": "ellipsis",
                "outcome": "applied",
            }
        ]
        gates = yaml.safe_load((tmp_path / "loss-analysis-gates.yaml").read_text())
        assert gates["revision_call_count"] == 1
        assert any(
            f"rule_span {identity} repaired by ellipsis match" in warning
            for warning in gates["normalization_warnings"]
        )

    def test_whitespace_span_is_repaired_without_a_correction_call(
        self, tmp_path
    ) -> None:
        result = _run_sp1_with_revisions(
            tmp_path,
            [_revision_covering_h2_with_span("must  preserve\nuser trust")],
        )

        assert result.stage_errors == []
        constraint = _trust_constraint(result)
        assert constraint.obligations[0].rule_span == _VERBATIM_TRUST_SPAN
        manifest = yaml.safe_load((tmp_path / "run-manifest.yaml").read_text())
        repairs = manifest["stage_summary"]["stage_1a"]["rule_span_repairs"]
        assert [entry["match"] for entry in repairs] == ["whitespace"]

    def test_unrepairable_span_gets_one_correction_that_succeeds(
        self, tmp_path
    ) -> None:
        result = _run_sp1_with_revisions(
            tmp_path,
            [
                _revision_covering_h2_with_span("must keep users happy"),
                _revision_covering_h2_with_span(_VERBATIM_TRUST_SPAN),
            ],
        )

        assert result.stage_errors == []
        assert _trust_constraint(result).obligations[0].rule_span == (
            _VERBATIM_TRUST_SPAN
        )
        entries = _revision_entries(tmp_path)
        assert [e["success"] for e in entries] == [False, True]
        assert [e["attempt_number"] for e in entries] == [1, 2]
        verbatim_error = "rule_span must quote the constraint rule verbatim"
        assert verbatim_error in entries[0]["error"]
        correction_prompt = entries[1]["user_prompt_text"]
        assert correction_prompt.startswith(entries[0]["user_prompt_text"])
        assert "Correction request: the prior graph revision response" in (
            correction_prompt
        )
        assert "Prior structured response to correct in place" in correction_prompt
        assert "must keep users happy" in correction_prompt
        assert verbatim_error in correction_prompt
        manifest = yaml.safe_load((tmp_path / "run-manifest.yaml").read_text())
        stage_1a = manifest["stage_summary"]["stage_1a"]
        assert stage_1a["hazard_graph_density"] == "passed_after_revision"
        assert stage_1a["graph_revision_call_count"] == 2
        assert "rule_span_repairs" not in stage_1a

        from asago_scenario_generator.stpa.scenario_prod.run import (
            _stage_1a_gate_statuses,
        )

        product_statuses = _stage_1a_gate_statuses(tmp_path)
        assert product_statuses["graph_revision_call_count"] == 2
        assert product_statuses["hazard_graph_density"] == "passed_after_revision"

    def test_two_invalid_responses_keep_the_existing_stage_error(
        self, tmp_path
    ) -> None:
        result = _run_sp1_with_revisions(
            tmp_path,
            [
                _revision_covering_h2_with_span("must keep users happy"),
                _revision_covering_h2_with_span("must keep users very happy"),
            ],
        )

        assert result.loss_analysis is None
        revision_errors = [
            error
            for error in result.stage_errors
            if error.startswith(
                "stage_1a/hazard_graph_revision: graph revision call failed: "
                "ValidationError"
            )
        ]
        assert len(revision_errors) == 1
        verbatim_error = "rule_span must quote the constraint rule verbatim"
        assert verbatim_error in revision_errors[0]
        entries = _revision_entries(tmp_path)
        assert [e["success"] for e in entries] == [False, False]
        manifest = yaml.safe_load((tmp_path / "run-manifest.yaml").read_text())
        assert manifest["stage_summary"]["stage_1a"]["graph_revision_call_count"] == 2
        gates = yaml.safe_load((tmp_path / "loss-analysis-gates.yaml").read_text())
        assert gates["revision_applied"] is False
        assert gates["revision_call_count"] == 2

    def test_discarded_attempt_repairs_are_recorded_as_discarded(
        self, tmp_path
    ) -> None:
        extra = _revision_covering_h2_with_span("must ... user trust")
        # A second, unrepairable obligation forces the correction call.
        extra["security_constraint_additions"][0]["obligations"].append(
            {
                "obligation_id": "O2",
                "kind": "required",
                "behavior": "keep users happy",
                "rule_span": "must keep users happy",
                "realized_by": "reply",
            }
        )
        result = _run_sp1_with_revisions(
            tmp_path,
            [extra, _revision_covering_h2_with_span(_VERBATIM_TRUST_SPAN)],
        )

        assert result.stage_errors == []
        record = yaml.safe_load((tmp_path / "loss-analysis-repair.yaml").read_text())
        assert [
            (entry["attempt"], entry["identity"].split("/")[1], entry["outcome"])
            for entry in record["records"]
        ] == [("first", "O1", "discarded")]


class TestGraphRevisionEdgeRepair:
    """The offline delta merger changes the failing edge, not its surroundings."""

    def test_constraint_edge_repair_passes_density_and_preserves_other_records(self):
        prior_payload = valid_loss_analysis_dict()
        prior_payload["security_constraints"][1]["related_hazards"] = ["H-1"]
        prior = LossAnalysis.model_validate(prior_payload)
        patch = _Stage1aRevisionPatch.model_validate(
            {
                "hazard_edits": [],
                "hazard_additions": [],
                "security_constraint_edits": [
                    {
                        "constraint_id": "SC-2",
                        "rule": "The agent must preserve user trust.",
                        "applies_when": ["through transparency"],
                        "related_hazards": ["H-2"],
                        "obligations": [],
                    }
                ],
                "security_constraint_additions": [],
            }
        )

        revised_draft = _revision_patch_to_draft(prior, patch, [])
        revised = LossAnalysis.model_validate(revised_draft.model_dump())
        report = check_hazard_graph_density(revised, load_behavior_classes())

        assert report.passed
        assert revised.security_constraints[1].related_hazards == ["H-2"]
        assert revised.hazards == prior.hazards
        assert revised.security_constraints[0] == prior.security_constraints[0]

    def test_addition_cannot_fabricate_a_loss_to_satisfy_a_check(self):
        prior = LossAnalysis.model_validate(valid_loss_analysis_dict())
        patch = _Stage1aRevisionPatch.model_validate(
            {
                "hazard_edits": [],
                "hazard_additions": [
                    {
                        "handle": "invented_hazard",
                        "description": "An invented hazard.",
                        "related_losses": ["L-99"],
                    }
                ],
                "security_constraint_edits": [],
                "security_constraint_additions": [],
            }
        )

        with pytest.raises(ValueError, match="unknown loss ID"):
            _revision_patch_to_draft(prior, patch, [])


def _revision_dropping_h1() -> dict:
    """A delta omitting H-1; the compiler must carry it forward unchanged."""
    return _revision_response(fix_constraint=True)


def _gap_draft_with_uncovered_hazard() -> dict:
    """A gap draft that adds hazard H-2 and no constraint for it."""
    draft = valid_gap_draft_dict()
    draft["security_constraints"] = []
    return draft


def _revision_covering_h2() -> dict:
    """A revision patch that adds a new constraint for the named hazard H-2."""
    return {
        "hazard_edits": [],
        "hazard_additions": [],
        "security_constraint_edits": [],
        "security_constraint_additions": [
            {
                "handle": "trust_constraint",
                "rule": "The agent must preserve user trust.",
                "applies_when": ["through transparency"],
                "related_hazards": ["H-2"],
                "obligations": [],
            }
        ],
    }


def _revision_leaving_h2_uncovered() -> dict:
    """A deletion-shaped response rejected by the explicit delta wire."""
    return _revision_response_for_disallowed_deletion()


def _revision_adding_unclassified_constraint() -> dict:
    """A valid delta that adds a constraint matching no behavior class."""
    return _revision_response_with_hazard_addition(fix_constraint=True)


def _revision_conditions_changed_same_rule() -> dict:
    """A dense revision that changes SC-2's conditions on an unchanged rule.

    The prior SC-2 rule is kept; its applies_when list grows.  The hazard is
    reworded so the composed text still passes the subject-phrase check.
    """
    return _legacy_revision_conditions_changed_same_rule()


class TestRunSp1RevisionDefenses:
    """A failing revision call stops the run with recorded evidence."""

    def test_revision_omitting_a_hazard_carries_it_forward_with_evidence(
        self, tmp_path
    ) -> None:
        import yaml as yaml_lib

        from asago_scenario_generator.stpa.system_model.run import run_sp1

        client = setup_sp1_mock_client()
        client.set_response_for(
            LossAnalysisDraft,
            [
                valid_risk_draft_dict(),
                _structurally_failing_gap_draft(),
            ],
        )
        client.set_response_for(_Stage1aRevisionPatch, _revision_dropping_h1())
        _set_three_hazard_review(client)
        result = run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_risk_cards(("atlas-001",)),
            run_dir=tmp_path,
        )

        assert result.stage_errors == []
        assert result.loss_analysis is not None
        assert any(hazard.hazard_id == "H-1" for hazard in result.loss_analysis.hazards)
        # The manifest and the gates artifact both exist after the successful
        # carry-forward path.
        assert (tmp_path / "run-manifest.yaml").is_file()
        manifest = yaml_lib.safe_load((tmp_path / "run-manifest.yaml").read_text())
        assert manifest["stage_summary"]["stage_1a"]["hazard_graph_density"] == (
            "passed_after_revision"
        )
        artifact = yaml_lib.safe_load(
            (tmp_path / "loss-analysis-gates.yaml").read_text()
        )
        assert artifact["revision_attempted"] is True
        assert artifact["revision_applied"] is True
        assert artifact["passed"] is True

    def test_revision_changing_conditions_on_unchanged_rule_records_warning(
        self, tmp_path
    ) -> None:
        """A revision that changes a constraint's applies_when conditions on
        an unchanged rule is accepted and recorded as gate evidence.
        """
        import yaml as yaml_lib

        from asago_scenario_generator.stpa.system_model.run import run_sp1

        client = setup_sp1_mock_client()
        client.set_response_for(
            LossAnalysisDraft,
            [
                valid_risk_draft_dict(),
                _structurally_failing_gap_draft(),
            ],
        )
        client.set_response_for(
            _Stage1aRevisionPatch, _revision_conditions_changed_same_rule()
        )
        _set_three_hazard_review(client)
        result = run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_risk_cards(("atlas-001",)),
            run_dir=tmp_path,
        )

        assert result.stage_errors == []
        assert result.loss_analysis is not None
        sc2 = next(
            constraint
            for constraint in result.loss_analysis.security_constraints
            if constraint.constraint_id == "SC-2"
        )
        assert sc2.rule == "The agent must maintain transparency about fees."
        assert sc2.applies_when == ["for every customer question"]
        artifact = yaml_lib.safe_load(
            (tmp_path / "loss-analysis-gates.yaml").read_text()
        )
        assert artifact["revision_attempted"] is True
        assert artifact["revision_applied"] is True
        assert any(
            "changed the applies_when conditions of constraint SC-2 without "
            "changing its rule"
            in warning
            and "for every customer question" in warning
            for warning in artifact["normalization_warnings"]
        )

    def test_revision_adding_unclassified_constraint_records_warning(
        self, tmp_path
    ) -> None:
        """A revision may add unclassified constraints; the addition and its
        Phase 2 consequence are recorded as gate evidence, not fatal.
        """
        import yaml as yaml_lib

        from asago_scenario_generator.stpa.system_model.run import run_sp1

        client = setup_sp1_mock_client()
        client.set_response_for(
            LossAnalysisDraft,
            [
                valid_risk_draft_dict(),
                _structurally_failing_gap_draft(),
            ],
        )
        client.set_response_for(
            _Stage1aRevisionPatch, _revision_adding_unclassified_constraint()
        )
        from asago_scenario_generator.stpa.system_model.control_structure import (
            CoordinationAnalysis,
        )
        from tests.stpa.sp1_helpers import valid_empty_coordination_analysis_dict

        review = valid_empty_coordination_analysis_dict(
            constraint_ids=("SC-1", "SC-2", "SC-3"),
            hazard_ids=("H-1", "H-2", "H-3", "H-4"),
        )
        review["semantic_review"]["constraints"][1]["related_hazards"] = ["H-2", "H-3"]
        review["semantic_review"]["constraints"][2]["related_hazards"] = ["H-4"]
        client.set_response_for(CoordinationAnalysis, review)
        result = run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_risk_cards(("atlas-001",)),
            run_dir=tmp_path,
        )

        assert result.stage_errors == []
        assert result.loss_analysis is not None
        assert any(
            constraint.constraint_id == "SC-3"
            for constraint in result.loss_analysis.security_constraints
        )
        artifact = yaml_lib.safe_load(
            (tmp_path / "loss-analysis-gates.yaml").read_text()
        )
        assert artifact["revision_applied"] is True
        assert any(
            "SC-3" in warning and "behavior class" in warning
            for warning in artifact["normalization_warnings"]
        )


class TestPostReviewDensityRecheck:
    """The reviewed graph is re-checked before it replaces the canonical file."""

    def _unresolved_review(self) -> dict:
        from tests.stpa.sp1_helpers import valid_empty_coordination_analysis_dict

        payload = valid_empty_coordination_analysis_dict(
            constraint_ids=("SC-1", "SC-2"),
            hazard_ids=("H-1", "H-2"),
        )
        constraint_row = payload["semantic_review"]["constraints"][1]
        constraint_row["disposition"] = "unresolved"
        constraint_row["missing_fact"] = (
            "The supplied sources do not ground this constraint's wording."
        )
        constraint_row["related_hazards"] = []
        return payload

    def test_review_regression_fails_closed_and_records_the_second_report(
        self, tmp_path
    ) -> None:
        import yaml as yaml_lib

        from asago_scenario_generator.stpa.system_model.control_structure import (
            CoordinationAnalysis,
        )
        from asago_scenario_generator.stpa.system_model.run import run_sp1

        client = setup_sp1_mock_client()
        client.set_response_for(CoordinationAnalysis, self._unresolved_review())
        result = run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_risk_cards(("atlas-001",)),
            run_dir=tmp_path,
        )

        # Stage 2 fails closed and the published artifact is the exact graph
        # the gate evaluated: the reviewed graph replaced the canonical
        # loss-analysis.yaml before the re-check, so the artifact can no
        # longer silently keep an edge the gate rejected.  The pre-review
        # Stage 1a graph stays available as the draft artifact.
        # SC-2 is explicitly unresolved and therefore exempt, but the
        # preserved hazard H-2 lost its only constraint: a kept record left
        # without its partner still fails closed.
        assert result.control_structure is None
        assert any(
            "density gate failed after review" in error for error in result.stage_errors
        )
        assert any(
            "hazard H-2 has no constraint" in error for error in result.stage_errors
        )
        assert not any(
            "constraint SC-2 has no hazard" in error for error in result.stage_errors
        )
        canonical = yaml_lib.safe_load((tmp_path / "loss-analysis.yaml").read_text())
        assert [sc["related_hazards"] for sc in canonical["security_constraints"]] == [
            ["H-1"],
            [],
        ]
        draft = yaml_lib.safe_load((tmp_path / "loss-analysis-draft.yaml").read_text())
        assert [sc["related_hazards"] for sc in draft["security_constraints"]] == [
            ["H-1"],
            ["H-2"],
        ]
        artifact = yaml_lib.safe_load(
            (tmp_path / "loss-analysis-gates.yaml").read_text()
        )
        assert artifact["passed"] is False
        assert any(
            "post-review regression: hazard H-2 has no constraint" in check
            for check in artifact["failing_checks"]
        )
        assert (
            "post-review unresolved: constraint SC-2 has no hazard; the review "
            "marked it unresolved" in artifact["advisory_checks"]
        )
        post_review = artifact["post_review_density"]
        assert post_review["constraints_without_hazard"] == []
        assert post_review["hazards_without_constraint"] == ["H-2"]
        # The review got exactly one scoped correction round, which repeated
        # the unresolved decision, so the gate stays closed.
        steps = [call["step"] for call in read_calls_jsonl(tmp_path)]
        assert steps.count("call_3_density_correction") == 1
        assert [entry["round"] for entry in artifact["post_review_corrections"]] == [1]
        assert artifact["post_review_corrections"][0]["failing_checks_after"] == [
            "hazard H-2 has no constraint",
        ]

    def test_review_correction_restores_density_for_scoped_records_only(
        self, tmp_path
    ) -> None:
        import yaml as yaml_lib

        from asago_scenario_generator.stpa.system_model.control_structure import (
            CoordinationAnalysis,
        )
        from asago_scenario_generator.stpa.system_model.run import run_sp1
        from tests.stpa.sp1_helpers import valid_empty_coordination_analysis_dict

        corrected = valid_empty_coordination_analysis_dict(
            constraint_ids=("SC-1", "SC-2"),
            hazard_ids=("H-1", "H-2"),
        )
        # An out-of-scope edge change in the correction response is ignored.
        corrected["semantic_review"]["constraints"][0]["related_hazards"] = [
            "H-1",
            "H-2",
        ]
        client = setup_sp1_mock_client()
        client.set_response_for(
            CoordinationAnalysis, [self._unresolved_review(), corrected]
        )
        result = run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_risk_cards(("atlas-001",)),
            run_dir=tmp_path,
        )

        assert result.stage_errors == []
        assert result.control_structure is not None
        canonical = yaml_lib.safe_load((tmp_path / "loss-analysis.yaml").read_text())
        assert [sc["related_hazards"] for sc in canonical["security_constraints"]] == [
            ["H-1"],
            ["H-2"],
        ]
        calls = [
            call
            for call in read_calls_jsonl(tmp_path)
            if call["step"] == "call_3_density_correction"
        ]
        assert len(calls) == 1
        prompt = calls[0]["user_prompt_text"]
        assert "- hazard H-2 has no constraint" in prompt
        assert "- constraint SC-2 has no hazard" not in prompt
        assert "Review again only these records: H-2, SC-2." in prompt
        # The first review stays on disk unchanged; the applied merge is
        # written separately.
        first = yaml_lib.safe_load(
            (tmp_path / "control-structure-review.yaml").read_text()
        )
        assert first["semantic_review"]["constraints"][1]["disposition"] == (
            "unresolved"
        )
        merged = yaml_lib.safe_load(
            (tmp_path / "control-structure-review-corrected.yaml").read_text()
        )
        assert merged["semantic_review"]["constraints"][1]["related_hazards"] == ["H-2"]
        artifact = yaml_lib.safe_load(
            (tmp_path / "loss-analysis-gates.yaml").read_text()
        )
        assert artifact["passed"] is True
        assert artifact["post_review_density"]["constraints_without_hazard"] == []
        assert artifact["post_review_corrections"] == [
            {
                "round": 1,
                "failing_checks_before": [
                    "hazard H-2 has no constraint",
                ],
                "failing_checks_after": [],
                "introduced_checks": [],
                "revision_valid": True,
            }
        ]

    @staticmethod
    def _mark_hazard_unresolved(payload: dict, index: int) -> dict:
        row = payload["semantic_review"]["hazards"][index]
        row["disposition"] = "unresolved"
        row["missing_fact"] = "The supplied sources do not name the governing rule."
        return payload

    def test_unresolved_hazard_and_constraint_pass_as_advisories(
        self, tmp_path
    ) -> None:
        import yaml as yaml_lib

        from asago_scenario_generator.stpa.system_model.control_structure import (
            CoordinationAnalysis,
        )
        from asago_scenario_generator.stpa.system_model.run import run_sp1

        client = setup_sp1_mock_client()
        client.set_response_for(
            CoordinationAnalysis,
            self._mark_hazard_unresolved(self._unresolved_review(), 1),
        )
        result = run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_risk_cards(("atlas-001",)),
            run_dir=tmp_path,
        )

        assert result.stage_errors == []
        assert result.control_structure is not None
        steps = [call["step"] for call in read_calls_jsonl(tmp_path)]
        assert "call_3_density_correction" not in steps
        artifact = yaml_lib.safe_load(
            (tmp_path / "loss-analysis-gates.yaml").read_text()
        )
        assert artifact["passed"] is True
        assert artifact["post_review_corrections"] == []
        assert [
            check
            for check in artifact["advisory_checks"]
            if check.startswith("post-review unresolved:")
        ] == [
            "post-review unresolved: hazard H-2 has no constraint; the review "
            "marked it unresolved",
            "post-review unresolved: constraint SC-2 has no hazard; the review "
            "marked it unresolved",
        ]

    def test_correction_that_marks_the_orphaned_hazard_unresolved_passes(
        self, tmp_path
    ) -> None:
        import yaml as yaml_lib

        from asago_scenario_generator.stpa.system_model.control_structure import (
            CoordinationAnalysis,
        )
        from asago_scenario_generator.stpa.system_model.run import run_sp1

        corrected = self._mark_hazard_unresolved(self._unresolved_review(), 1)
        client = setup_sp1_mock_client()
        client.set_response_for(
            CoordinationAnalysis, [self._unresolved_review(), corrected]
        )
        result = run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_risk_cards(("atlas-001",)),
            run_dir=tmp_path,
        )

        assert result.stage_errors == []
        assert result.control_structure is not None
        calls = [
            call
            for call in read_calls_jsonl(tmp_path)
            if call["step"] == "call_3_density_correction"
        ]
        assert len(calls) == 1
        prompt = " ".join(calls[0]["user_prompt_text"].split())
        assert "the run then stops" not in prompt
        assert "does not fail the gate" in prompt
        artifact = yaml_lib.safe_load(
            (tmp_path / "loss-analysis-gates.yaml").read_text()
        )
        assert artifact["passed"] is True
        assert artifact["post_review_corrections"][0]["failing_checks_after"] == []
        assert (
            "post-review unresolved: hazard H-2 has no constraint; the review "
            "marked it unresolved" in artifact["advisory_checks"]
        )

    def test_dense_reviewed_graph_passes_and_records_the_second_report(
        self, tmp_path
    ) -> None:
        import yaml as yaml_lib

        from asago_scenario_generator.stpa.system_model.run import run_sp1

        client = setup_sp1_mock_client()
        result = run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_risk_cards(("atlas-001",)),
            run_dir=tmp_path,
        )

        assert result.stage_errors == []
        assert result.control_structure is not None
        artifact = yaml_lib.safe_load(
            (tmp_path / "loss-analysis-gates.yaml").read_text()
        )
        assert artifact["passed"] is True
        assert artifact["post_review_density"] is not None
        assert artifact["post_review_density"]["subject_checks"]

    def test_review_subject_mismatch_is_advisory_and_does_not_stop_run(
        self, tmp_path
    ) -> None:
        import yaml as yaml_lib

        from asago_scenario_generator.stpa.system_model.control_structure import (
            CoordinationAnalysis,
        )
        from asago_scenario_generator.stpa.system_model.run import run_sp1

        review = valid_empty_coordination_analysis_dict(
            constraint_ids=("SC-1", "SC-2"),
            hazard_ids=("H-1", "H-2"),
        )
        constraint = review["semantic_review"]["constraints"][1]
        constraint.update(
            {
                "disposition": "revise",
                "revised_description": (
                    "The agent must escalate every regulated topic to a human."
                ),
                "source_evidence": [
                    {
                        "source_ref": "source_3",
                        "meaning": "The loss of trust motivates the constraint.",
                    },
                ],
                "related_hazards": ["H-2"],
            }
        )
        client = setup_sp1_mock_client()
        client.set_response_for(CoordinationAnalysis, review)

        result = run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_risk_cards(("atlas-001",)),
            run_dir=tmp_path,
        )

        expected = "post-review: constraint SC-2 and hazard H-2 share no subject phrase"
        assert result.stage_errors == []
        assert result.loss_analysis is not None
        artifact = yaml_lib.safe_load(
            (tmp_path / "loss-analysis-gates.yaml").read_text()
        )
        assert artifact["passed"] is True
        assert artifact["failing_checks"] == []
        assert artifact["advisory_checks"] == [expected]
        assert any(
            check["constraint_id"] == "SC-2"
            and check["hazard_id"] == "H-2"
            and check["passed"] is False
            for check in artifact["post_review_density"]["subject_checks"]
        )


class TestAccountingGroundRules:
    """Spec rule 1.1(4): loss citations and dispositions must agree."""

    def _payload(self, *, disposition: dict, loss_sources: list[str]) -> dict:
        risk = valid_risk_draft_dict()
        risk["risk_card_losses"][0]["source_risk_cards"] = loss_sources
        risk["risk_dispositions"] = [disposition]
        return risk

    def test_not_applicable_card_cited_by_a_loss_fails(self) -> None:
        analysis = LossAnalysis.model_validate(
            self._payload(
                disposition={
                    "risk_ref": "atlas-001",
                    "disposition": "not_applicable",
                    "loss_ids": [],
                    "reason": "No grounded loss applies.",
                },
                loss_sources=["atlas-001"],
            )
        )
        report = check_risk_accounting(analysis, _risk_cards(("atlas-001",)))
        assert not report.passed
        assert any("not_applicable" in c and "L-1" in c for c in report.contradictions)

    def test_cited_disposition_with_matching_loss_citation_passes(self) -> None:
        payload = self._payload(
            disposition={
                "risk_ref": "atlas-001",
                "disposition": "cited",
                "loss_ids": ["L-1"],
                "reason": None,
            },
            loss_sources=["atlas-001"],
        )
        analysis = LossAnalysis.model_validate(payload)
        report = check_risk_accounting(analysis, _risk_cards(("atlas-001",)))
        assert report.passed
        assert report.contradictions == ()

    def test_cited_disposition_reason_echo_is_normalized(self) -> None:
        # Live gemma4-oc evidence: the provider echoes an empty reason field
        # on cited entries; the stray reason is dropped, not fatal.
        for echoed_reason in ("", "   ", None):
            analysis = LossAnalysis.model_validate(
                self._payload(
                    disposition={
                        "risk_ref": "atlas-001",
                        "disposition": "cited",
                        "loss_ids": ["L-1"],
                        "reason": echoed_reason,
                    },
                    loss_sources=["atlas-001"],
                )
            )
            assert analysis.risk_dispositions[0].reason is None

    def test_cited_disposition_with_substantive_reason_gets_targeted_repair(
        self, tmp_path
    ) -> None:
        # Re-review deviation #3: a non-empty reason on a cited entry is
        # contradictory evidence, so the malformed row joins the targeted
        # repair instead of being silently discarded.
        import json as jsonlib

        from asago_scenario_generator.stpa.system_model.loss_analysis_repair import (
            DispositionRepairResponse,
        )

        echoed = valid_risk_draft_dict()
        echoed["risk_dispositions"] = [
            {
                "risk_ref": "atlas-001",
                "disposition": "cited",
                "loss_ids": ["L-1"],
                "reason": "Cited via L-1.",
            }
        ]
        client = MockLLMClient()
        client.set_response_for(
            LossAnalysisDraft,
            [echoed, valid_gap_draft_dict()],
        )
        client.set_response_for(
            DispositionRepairResponse,
            {
                "risk_dispositions": [
                    {
                        "risk_ref": "atlas-001",
                        "disposition": "cited",
                        "loss_ids": ["L-1"],
                        "reason": None,
                    }
                ]
            },
        )
        result = derive_loss_analysis(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_risk_cards(("atlas-001",)),
            run_dir=tmp_path,
        )
        assert result.risk_dispositions[0].reason is None
        entries = [
            jsonlib.loads(line)
            for line in (tmp_path / "calls.jsonl").read_text().splitlines()
        ]
        assert [e["step"] for e in entries if e["stage"] == "stage_1a"] == [
            "risk_derivation",
            "risk_derivation_repair",
            "gap_analysis",
        ]
        repair_prompt = next(
            e["user_prompt_text"] for e in entries if e["step"].endswith("_repair")
        )
        # The repair prompt names the exact wire reason the row was dropped.
        assert "carries a reason" in repair_prompt

    def test_call1_missing_disposition_still_requires_repair(self, tmp_path) -> None:
        """A genuinely missing disposition cannot be normalized; it is repaired."""
        import json as jsonlib

        from asago_scenario_generator.stpa.system_model.loss_analysis_repair import (
            DispositionRepairResponse,
        )

        incomplete = valid_risk_draft_dict()
        incomplete["risk_dispositions"] = []
        client = MockLLMClient()
        client.set_response_for(
            LossAnalysisDraft,
            [incomplete, valid_gap_draft_dict()],
        )
        client.set_response_for(
            DispositionRepairResponse,
            {
                "risk_dispositions": [
                    {
                        "risk_ref": "atlas-001",
                        "disposition": "cited",
                        "loss_ids": ["L-1"],
                        "reason": None,
                    }
                ]
            },
        )
        result = derive_loss_analysis(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_risk_cards(("atlas-001",)),
            run_dir=tmp_path,
        )
        assert result.risk_dispositions[0].disposition == "cited"
        entries = [
            jsonlib.loads(line)
            for line in (tmp_path / "calls.jsonl").read_text().splitlines()
        ]
        assert [e["success"] for e in entries if e["stage"] == "stage_1a"] == [
            False,
            True,
            True,
        ]

    def test_contradictory_disposition_normalized_from_citation_evidence(
        self, tmp_path
    ) -> None:
        """A not_applicable card cited by a loss is flipped, not fatal."""
        import json as jsonlib

        # Live gemma4-oc evidence (v5): the model marked a risk
        # not_applicable while L-1 cited it as a source.  The response's
        # own citation evidence resolves the contradiction deterministically.
        contradictory = valid_risk_draft_dict()
        contradictory["risk_dispositions"] = [
            {
                "risk_ref": "atlas-001",
                "disposition": "not_applicable",
                "loss_ids": [],
                "reason": "No grounded loss applies.",
            }
        ]
        client = MockLLMClient()
        client.set_response_for(
            LossAnalysisDraft,
            [contradictory, valid_gap_draft_dict()],
        )
        warnings: list[str] = []
        result = derive_loss_analysis(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_risk_cards(("atlas-001",)),
            run_dir=tmp_path,
            normalization_warnings=warnings,
        )

        disposition = result.risk_dispositions[0]
        assert disposition.disposition == "cited"
        assert disposition.loss_ids == ["L-1"]
        assert disposition.reason is None
        assert len(warnings) == 1
        assert "atlas-001" in warnings[0]
        assert "cited" in warnings[0]
        # Re-review deviation #2: the model's dropped reason is retained in
        # the warning for reviewer visibility.
        assert "No grounded loss applies." in warnings[0]
        # No repair call was needed: normalization, not a retry, resolved it.
        entries = [
            jsonlib.loads(line)
            for line in (tmp_path / "calls.jsonl").read_text().splitlines()
        ]
        assert [e["success"] for e in entries if e["stage"] == "stage_1a"] == [
            True,
            True,
        ]

    def test_normalization_flags_bulk_citation_flips(self) -> None:
        # Re-review deviation #2: a flip whose only citing loss accounts
        # for many cards is flagged, since the dropped reason deserves
        # human attention there.  A flip via a small loss is not flagged.
        risk = valid_risk_draft_dict()
        loss = risk["risk_card_losses"][0]
        bulk_sources = [f"bulk-card-{i:02d}" for i in range(12)]
        loss["loss_id"] = "L-1"
        loss["source_risk_cards"] = bulk_sources + ["atlas-001"]
        small = dict(loss)
        small["loss_id"] = "L-2"
        small["description"] = "A small, focused loss."
        small["source_risk_cards"] = ["small-card"]
        risk["risk_card_losses"].append(small)
        risk["hazards"][0]["related_losses"] = ["L-1", "L-2"]
        risk["risk_dispositions"] = [
            {
                "risk_ref": "atlas-001",
                "disposition": "not_applicable",
                "loss_ids": [],
                "reason": "Not grounded in this system.",
            },
            *[
                {
                    "risk_ref": card,
                    "disposition": "not_applicable",
                    "loss_ids": [],
                    "reason": f"{card} does not apply.",
                }
                for card in bulk_sources
            ],
            {
                "risk_ref": "small-card",
                "disposition": "not_applicable",
                "loss_ids": [],
                "reason": "Not grounded here.",
            },
        ]
        analysis = LossAnalysis.model_validate(risk)
        warnings = normalize_disposition_citations(analysis)
        atlas_warning = next(w for w in warnings if "atlas-001" in w)
        assert "bulk citation" in atlas_warning
        assert "Not grounded in this system." in atlas_warning
        small_warning = next(w for w in warnings if "small-card" in w)
        assert "bulk citation" not in small_warning


class TestSubjectRuleDeterminism:
    """The fixed rule splits runs at stopwords and singularizes the rest."""

    def test_inflected_function_words_never_leak_into_phrases(self) -> None:
        phrases = extract_subject_phrases("The agent does data exposure matches.")
        assert all("doe" not in phrase.split() for phrase in phrases)
        assert all("matche" not in phrase.split() for phrase in phrases)

    def test_shared_noun_phrase_still_detected(self) -> None:
        shared = extract_subject_phrases("The agent does an unintended payment.") & (
            extract_subject_phrases("An unintended payment is created.")
        )
        assert "unintended payment" in shared

    def test_stopwords_separate_runs(self) -> None:
        # R2 regression: stopwords must end a run, so no cross-stopword
        # n-gram may count as a shared subject.
        phrases = extract_subject_phrases(
            "The agent must not share account data unless the customer "
            "explicitly consents."
        )
        joined = " | ".join(sorted(phrases))
        assert "account data" in phrases
        assert "explicitly consents" in phrases or "explicitly consent" in phrases
        for leaked in (
            "data unless",
            "unless the customer",
            "data unless the customer",
        ):
            assert leaked not in joined


class TestBehaviorClassWordBoundaries:
    """Keyword hits respect word boundaries."""

    def test_intent_does_not_match_intentionally(self) -> None:
        table = load_behavior_classes()
        assert (
            classify_constraint(
                "The agent must never intentionally mislead users.", table
            )
            == UNCLASSIFIED
        )
        assert (
            classify_constraint(
                "The agent must not change the intent of a transaction.", table
            )
            == "unauthorized_write"
        )

    def test_keyword_matching_requires_exact_words(self) -> None:
        table = load_behavior_classes()
        # A different word that merely contains a keyword never matches...
        assert (
            classify_constraint(
                "Data must never reach an unauthorised recipient.", table
            )
            == UNCLASSIFIED
        )
        # ...and the exact keyword phrase still does.
        assert (
            classify_constraint(
                "Data must never reach an unauthorized recipient.", table
            )
            == "disclosure"
        )

    def test_stem_keywords_match_inflected_forms(self) -> None:
        # R1 regression: whole-word matching silently killed the stem
        # keywords; each must classify its class's surface forms again.
        table = load_behavior_classes()
        assert (
            classify_constraint("The agent must never hallucinate a fee.", table)
            == "wrong_information"
        )
        assert (
            classify_constraint(
                "The agent must not discriminate against any customer.", table
            )
            == "harmful_or_discriminatory_output"
        )
        assert (
            classify_constraint("The agent must not manipulate the customer.", table)
            == "manipulation"
        )
        assert (
            classify_constraint(
                "The agent must never persuade the customer to share credentials.",
                table,
            )
            == "manipulation"
        )

    def test_every_table_keyword_matches_a_surface_form(self) -> None:
        # Dead keywords (keywords that can never match) are forbidden.
        table = load_behavior_classes()
        for name, keywords in table.classes:
            for keyword in keywords:
                candidates = [keyword]
                if keyword.endswith("*"):
                    stem = keyword[:-1]
                    candidates = [
                        stem,
                        stem + "e",
                        stem + "es",
                        stem + "ed",
                        stem + "ing",
                        stem + "ion",
                        stem + "ions",
                    ]
                assert any(
                    _keyword_hits(surface, keyword) > 0 for surface in candidates
                ), f"dead keyword {keyword!r} in class {name!r}"

    def test_plural_surface_forms_match_singular_keywords(self) -> None:
        """Live run v10: SC-4's plural surface form went unmatched.

        Both keyword and description tokens are singularized with the fixed
        rule before matching, so 'refunds' grounds against the table's
        'refund' and 'modifications' against 'modification' without per-run
        keyword edits.
        """
        table = load_behavior_classes()
        v10_sc4 = (
            "The system must only process refunds or payment modifications "
            "that match the intent and authorized parameters of the "
            "authenticated customer session."
        )
        assert classify_constraint(v10_sc4, table) == "unauthorized_write"

    def test_disclosure_class_covers_corporate_data_constraint(self) -> None:
        table = load_behavior_classes()
        assert (
            classify_constraint(
                "The system must prevent the transmission of sensitive Klarna "
                "corporate data or internal strategy information.",
                table,
            )
            == "disclosure"
        )


class TestConstraintRuleAndConditions:
    """Phase 1.3 as amended: authored rule + applies_when; code composes."""

    def test_composition_rendering_both_branches(self) -> None:
        conditional = SecurityConstraint.model_validate(
            {
                "constraint_id": "SC-1",
                "rule": "The assistant does not disclose personal information.",
                "applies_when": [
                    "the recipient is not authorized to receive that information"
                ],
                "related_hazards": ["H-1"],
            }
        )
        assert conditional.description == (
            "The assistant does not disclose personal information. "
            "Applies when: the recipient is not authorized to receive that "
            "information."
        )
        unconditional = SecurityConstraint.model_validate(
            {
                "constraint_id": "SC-2",
                "rule": "The agent confirms every payment.",
                "applies_when": [],
                "related_hazards": ["H-1"],
            }
        )
        assert unconditional.description == "The agent confirms every payment."

    def test_blank_condition_joins_the_bounded_retry(self) -> None:
        with pytest.raises(ValueError, match="non-empty"):
            SecurityConstraint.model_validate(
                {
                    "constraint_id": "SC-1",
                    "rule": "R.",
                    "applies_when": ["   "],
                    "related_hazards": ["H-1"],
                }
            )

    def test_duplicate_condition_joins_the_bounded_retry(self) -> None:
        with pytest.raises(ValueError, match="distinct"):
            SecurityConstraint.model_validate(
                {
                    "constraint_id": "SC-1",
                    "rule": "R.",
                    "applies_when": ["when a", "WHEN A"],
                    "related_hazards": ["H-1"],
                }
            )

    def test_condition_equal_to_rule_joins_the_bounded_retry(self) -> None:
        with pytest.raises(ValueError, match="invalid rule"):
            SecurityConstraint.model_validate(
                {
                    "constraint_id": "SC-1",
                    "rule": "Same rule.",
                    "applies_when": ["Same rule."],
                    "related_hazards": ["H-1"],
                }
            )

    def test_more_than_four_conditions_join_the_bounded_retry(self) -> None:
        with pytest.raises(ValueError):
            SecurityConstraint.model_validate(
                {
                    "constraint_id": "SC-1",
                    "rule": "R.",
                    "applies_when": ["a", "b", "c", "d", "e"],
                    "related_hazards": ["H-1"],
                }
            )

    def test_revision_patch_without_rule_fails_the_wire(self) -> None:
        with pytest.raises(ValueError):
            _Stage1aRevisionPatch.model_validate(
                {
                    "hazards": [],
                    "security_constraints": [
                        {
                            "constraint_id": "SC-1",
                            "description": "legacy description shape",
                            "related_hazards": ["H-1"],
                        }
                    ],
                }
            )

    def test_revision_conditions_changed_on_unchanged_rule_records_warning(
        self,
    ) -> None:
        prior = LossAnalysis.model_validate(valid_loss_analysis_dict())
        patch = _Stage1aRevisionPatch.model_validate(
            {
                "hazard_edits": [],
                "hazard_additions": [],
                "security_constraint_edits": [
                    {
                        "constraint_id": "SC-2",
                        "rule": "The agent must preserve user trust.",
                        "applies_when": ["in writing", "on request"],
                        "related_hazards": ["H-2"],
                        "obligations": [],
                    }
                ],
                "security_constraint_additions": [],
            }
        )
        warnings: list[str] = []
        draft = _revision_patch_to_draft(prior, patch, warnings)
        sc2 = next(c for c in draft.security_constraints if c.constraint_id == "SC-2")
        assert sc2.applies_when == ["in writing", "on request"]
        assert sc2.description == (
            "The agent must preserve user trust. Applies when: in writing; on request."
        )
        assert any(
            "changed the applies_when conditions of constraint SC-2 without "
            "changing its rule"
            in warning
            and "['through transparency'] -> ['in writing', 'on request']" in warning
            for warning in warnings
        )

    def test_revision_rule_changed_onto_disjoint_hazards_records_warning(
        self,
    ) -> None:
        prior = LossAnalysis.model_validate(valid_loss_analysis_dict())
        patch = _Stage1aRevisionPatch.model_validate(
            {
                "hazard_edits": [],
                "hazard_additions": [],
                "security_constraint_edits": [
                    {
                        "constraint_id": "SC-2",
                        "rule": "The agent must never improvise fee amounts.",
                        "applies_when": ["through transparency"],
                        "related_hazards": ["H-1"],
                        "obligations": [],
                    }
                ],
                "security_constraint_additions": [],
            }
        )
        warnings: list[str] = []
        _revision_patch_to_draft(prior, patch, warnings)
        assert any(
            "changed the rule of constraint SC-2 and re-pointed it to hazards "
            "['H-1'] sharing none of its prior hazards ['H-2']" in warning
            for warning in warnings
        )

    def test_revision_rule_changed_with_empty_prior_hazards_records_warning(
        self,
    ) -> None:
        prior_dict = valid_loss_analysis_dict()
        prior_dict["security_constraints"][1]["related_hazards"] = []
        prior = LossAnalysis.model_validate(prior_dict)
        patch = _Stage1aRevisionPatch.model_validate(
            {
                "hazard_edits": [],
                "hazard_additions": [],
                "security_constraint_edits": [
                    {
                        "constraint_id": "SC-2",
                        "rule": "The agent must never improvise fee amounts.",
                        "applies_when": [],
                        "related_hazards": ["H-2"],
                        "obligations": [],
                    }
                ],
                "security_constraint_additions": [],
            }
        )
        warnings: list[str] = []
        _revision_patch_to_draft(prior, patch, warnings)
        assert any(
            "changed the rule of constraint SC-2 and re-pointed it to hazards "
            "['H-2'] sharing none of its prior hazards []" in warning
            for warning in warnings
        )

    def test_revision_rule_changed_with_retained_hazard_records_no_warning(
        self,
    ) -> None:
        prior = LossAnalysis.model_validate(valid_loss_analysis_dict())
        patch = _Stage1aRevisionPatch.model_validate(
            {
                "hazard_edits": [],
                "hazard_additions": [],
                "security_constraint_edits": [
                    {
                        "constraint_id": "SC-2",
                        "rule": "The agent must preserve user trust explicitly.",
                        "applies_when": ["through transparency"],
                        "related_hazards": ["H-2"],
                        "obligations": [],
                    }
                ],
                "security_constraint_additions": [],
            }
        )
        warnings: list[str] = []
        _revision_patch_to_draft(prior, patch, warnings)
        assert not any("re-pointed" in warning for warning in warnings)
        assert warnings == []


class TestProductManifestGateStatuses:
    """The product run's manifest carries the Stage 1a gate evidence."""

    def test_gate_statuses_read_from_the_gates_artifact(self, tmp_path) -> None:
        import yaml as yaml_lib

        from asago_scenario_generator.stpa.scenario_prod.run import (
            _stage_1a_gate_statuses,
        )

        (tmp_path / "loss-analysis-gates.yaml").write_text(
            yaml_lib.dump(
                {
                    "risk_accounting": {"passed": True},
                    "hazard_graph_density": {},
                    "passed": True,
                    "revision_attempted": True,
                    "revision_applied": True,
                    "normalization_warnings": ["risk accounting normalized: x"],
                }
            )
        )
        statuses = _stage_1a_gate_statuses(tmp_path)
        assert statuses["risk_accounting"] == "passed"
        assert statuses["hazard_graph_density"] == "passed_after_revision"
        assert statuses["graph_revision_call_count"] == 1
        assert statuses["accounting_normalizations"] == 1

    def test_no_gates_artifact_yields_no_statuses(self, tmp_path) -> None:
        from asago_scenario_generator.stpa.scenario_prod.run import (
            _stage_1a_gate_statuses,
        )

        assert _stage_1a_gate_statuses(tmp_path) == {}

    def test_failed_gate_reports_failed(self, tmp_path) -> None:
        import yaml as yaml_lib

        from asago_scenario_generator.stpa.scenario_prod.run import (
            _stage_1a_gate_statuses,
        )

        (tmp_path / "loss-analysis-gates.yaml").write_text(
            yaml_lib.dump(
                {
                    "risk_accounting": {"passed": False},
                    "hazard_graph_density": {},
                    "passed": False,
                    "revision_attempted": False,
                    "revision_applied": False,
                }
            )
        )
        statuses = _stage_1a_gate_statuses(tmp_path)
        assert statuses["risk_accounting"] == "failed"
        assert statuses["hazard_graph_density"] == "failed"


class TestRetryPromptFailureKind:
    """The typed failure record names the actual failure, not the call type."""

    def test_non_accounting_call1_failure_is_typed_and_unsupported(
        self, tmp_path
    ) -> None:
        import json as jsonlib

        ungrounded = valid_risk_draft_dict()
        ungrounded["security_constraints"][0]["applies_when"] = ["", ""]
        client = MockLLMClient()
        client.set_response_for(LossAnalysisDraft, [ungrounded])
        with pytest.raises(StageError) as exc_info:
            derive_loss_analysis(
                llm_client=client,
                use_case_text="Test use case",
                risk_cards=_risk_cards(("atlas-001",)),
                run_dir=tmp_path,
            )
        message = str(exc_info.value)
        # A constraint-field wire violation is outside the approved repair
        # scope, so the current local-wire adapter stops before any repair.
        assert "targeted repair unsupported" in message
        assert "wire violation outside the approved repair scope" in message
        assert "no repair call was made" in message
        assert "applies_when" in message
        assert len(client.calls) == 1
        entries = [
            jsonlib.loads(line)
            for line in (tmp_path / "calls.jsonl").read_text().splitlines()
        ]
        assert [entry["success"] for entry in entries] == [False]
