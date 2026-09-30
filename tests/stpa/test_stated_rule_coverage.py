"""Stated use-case rule coverage after the Stage 1a gates.

Design: docs/development/designs/stated-rule-coverage-2026-09-30.md.  An
uncovered stated rule feeds the graph revision, but never fails the stage.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from asago_scenario_generator.models.risk_card import RiskCard
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.models.loss_analysis import (
    LossAnalysis,
    LossAnalysisDraft,
)
from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.system_model.heuristics import (
    uncited_security_constraints,
)
from asago_scenario_generator.stpa.system_model.loss_analysis import (
    _Stage1aRevisionPatch,
)
from asago_scenario_generator.stpa.system_model.loss_analysis_gates import (
    gate_loss_analysis,
)
from asago_scenario_generator.stpa.system_model.risk_coverage_review import (
    graph_digest,
)
from asago_scenario_generator.stpa.system_model.stated_rule_coverage import (
    StatedRuleExtractionResponse,
    StatedRuleFinding,
    StatedRuleMappingResponse,
    StatedRuleRevision,
    assess_stated_rules,
    coverage_warnings,
    finalize_stated_rule_coverage,
    locate_quote,
)
from tests.stpa.sp1_helpers import (
    MockLLMClient,
    read_calls_jsonl,
    setup_sp1_mock_client,
    valid_gap_draft_dict,
    valid_loss_analysis_dict,
    valid_risk_draft_dict,
)

USE_CASE = """# Use Case: Support assistant

## Knowledge
The assistant answers from approved articles. It **does not** quote fees that
are not in the   approved fee table. It hands billing disputes to human agents.
It cites only current policies.

## Deployment
The service launched in 2024 and handled 1 million chats.
"""
FEE_QUOTE = "It does not quote fees that are not in the approved fee table."
FEE_RULE = {
    "quote": FEE_QUOTE,
    "restatement": "The system must not quote fees absent from the approved fee table.",
    "modality": "forbids",
}
FEE_FINDING = StatedRuleFinding(
    rule_id="R-1",
    quote="It **does not** quote fees that\nare not in the   approved fee table.",
    restatement="The system must not quote fees absent from the approved fee table.",
)


FEE_CONSTRAINT = "The agent must not quote fees outside the approved fee table."


def _analysis(sc1: str | None = None, sc2: str | None = None) -> LossAnalysis:
    payload = valid_loss_analysis_dict()
    payload["risk_dispositions"] = [
        {"risk_ref": "atlas-001", "disposition": "cited", "loss_ids": ["L-1"]}
    ]
    for constraint, rule in zip(payload["security_constraints"], (sc1, sc2)):
        if rule is not None:
            constraint["rule"] = rule
    return LossAnalysis.model_validate(payload)


def _fee_analysis() -> LossAnalysis:
    """SC-2 carries the fee rule next to its original wording."""
    return _analysis(
        sc2=(
            "The agent must preserve user trust and must not quote fees "
            "outside the approved fee table."
        )
    )


def _cards() -> list[RiskCard]:
    return [
        RiskCard(
            risk_id="atlas-001",
            risk_name="atlas-001",
            risk_description="Risk atlas-001",
            taxonomy="test",
            confidence=0.9,
            grounding_confidence="high",
        )
    ]


def _mapping(
    verdict: str,
    ids: list[str],
    reason: str = "One sentence.",
    quote: str | None = None,
    terms: list[str] | None = None,
) -> dict:
    carried = verdict == "carried"
    if quote is None:
        quote = "must not quote fees outside the approved fee table" if carried else ""
    if terms is None:
        terms = ["approved fee table"] if carried else []
    return {
        "mappings": [
            {
                "rule_id": "R-1",
                "verdict": verdict,
                "constraint_ids": ids,
                "constraint_quote": quote,
                "shared_terms": terms,
                "reason": reason,
            }
        ]
    }


def _assess(client: MockLLMClient, tmp_path: Path, analysis: LossAnalysis):
    return assess_stated_rules(
        llm_client=client,
        use_case_text=USE_CASE,
        loss_analysis=analysis,
        loss_analysis_digest=graph_digest(analysis),
        run_dir=tmp_path,
        template_loader=TemplateLoader(PROMPTS_DIR),
        temperature=0.4,
    )


def _rule_carrying_edit() -> dict:
    """Extend SC-2's rule so it states the quoted fee rule."""
    return {
        "hazard_edits": [],
        "hazard_additions": [],
        "security_constraint_edits": [
            {
                "constraint_id": "SC-2",
                "rule": (
                    "The agent must preserve user trust and must not quote "
                    "fees that are not in the approved fee table."
                ),
                "applies_when": ["through transparency"],
                "obligations": [],
                "related_hazards": ["H-2"],
            }
        ],
        "security_constraint_additions": [],
    }


def _density_breaking_edit() -> dict:
    """Move SC-1 off H-1, leaving H-1 without a constraint."""
    return {
        "hazard_edits": [],
        "hazard_additions": [],
        "security_constraint_edits": [
            {
                "constraint_id": "SC-1",
                "rule": "The agent must confirm every unintended payment.",
                "applies_when": ["before execution"],
                "related_hazards": ["H-2"],
            }
        ],
        "security_constraint_additions": [],
    }


def _gate(client: MockLLMClient, tmp_path: Path, analysis: LossAnalysis, findings):
    return gate_loss_analysis(
        llm_client=client,
        loss_analysis=analysis,
        use_case_text=USE_CASE,
        risk_cards=_cards(),
        run_dir=tmp_path,
        template_loader=TemplateLoader(PROMPTS_DIR),
        temperature=0.4,
        stated_rule_findings=findings,
    )


class TestQuoteValidation:
    def test_quote_matches_across_case_whitespace_and_emphasis(self) -> None:
        excerpt = locate_quote(USE_CASE, FEE_QUOTE.upper())
        assert excerpt == (
            "It **does not** quote fees that\nare not in the   approved fee table."
        )

    def test_paraphrase_does_not_match(self) -> None:
        assert locate_quote(USE_CASE, "It never quotes unapproved fees.") is None

    def test_non_matching_quote_is_rejected(self, tmp_path) -> None:
        client = MockLLMClient()
        client.set_response_for(
            StatedRuleExtractionResponse,
            {
                "rules": [
                    FEE_RULE,
                    {
                        "quote": "It never quotes unapproved fees.",
                        "restatement": "The system must not quote unapproved fees.",
                        "modality": "forbids",
                    },
                    dict(FEE_RULE, quote=FEE_QUOTE.lower()),
                ]
            },
        )
        client.set_response_for(
            StatedRuleMappingResponse, _mapping("carried", ["SC-2"])
        )

        assessment = _assess(client, tmp_path, _analysis())

        assert [rule.rule_id for rule in assessment.rules] == ["R-1"]
        # The published quote is the exact source excerpt, not the model's copy.
        assert assessment.rules[0].quote == FEE_FINDING.quote
        assert [item.reason for item in assessment.rejected] == [
            "quote does not occur verbatim in the use-case text",
            "duplicates R-1",
        ]
        mapping_prompt = client.calls[1].user_prompt
        assert "It never quotes unapproved fees." not in mapping_prompt

    def test_restatement_that_is_not_a_system_rule_is_rejected(self, tmp_path) -> None:
        client = MockLLMClient()
        client.set_response_for(
            StatedRuleExtractionResponse,
            {
                "rules": [
                    {
                        "quote": "The service launched in 2024",
                        "restatement": "The service launched in 2024.",
                        "modality": "requires",
                    }
                ]
            },
        )

        assessment = _assess(client, tmp_path, _analysis())

        assert assessment.rules == []
        assert assessment.rejected[0].reason.startswith(
            "restatement does not state a rule for the system"
        )
        # No rules means no mapping call.
        assert len(client.calls) == 1


class TestRejectedRuleWarnings:
    def test_warning_reports_each_recorded_reason(self, tmp_path) -> None:
        client = MockLLMClient()
        client.set_response_for(
            StatedRuleExtractionResponse,
            {
                "rules": [
                    FEE_RULE,
                    {
                        "quote": "It never quotes unapproved fees.",
                        "restatement": "The system must not quote unapproved fees.",
                        "modality": "forbids",
                    },
                    dict(FEE_RULE, quote=FEE_QUOTE.lower()),
                ]
            },
        )
        client.set_response_for(StatedRuleMappingResponse, _mapping("uncovered", []))
        analysis = _analysis()
        assessment = _assess(client, tmp_path, analysis)
        artifact = finalize_stated_rule_coverage(
            assessment,
            llm_client=client,
            draft=analysis,
            final=analysis,
            final_digest=graph_digest(analysis),
            revision=StatedRuleRevision(),
            run_dir=tmp_path,
            template_loader=TemplateLoader(PROMPTS_DIR),
            temperature=0.4,
        )

        warnings = coverage_warnings(artifact)

        rejected = [item for item in warnings if "rejected" in item]
        assert rejected == [
            "stage_1a/stated_rule_coverage rejected: 'It never quotes unapproved "
            "fees.' (quote does not occur verbatim in the use-case text)",
            f"stage_1a/stated_rule_coverage rejected: {FEE_QUOTE.lower()!r} "
            "(duplicates R-1)",
        ]
        assert not any("quote failed validation" in item for item in warnings)


class TestMappingValidation:
    def test_covered_rule_is_not_a_finding(self, tmp_path) -> None:
        client = MockLLMClient()
        client.set_response_for(StatedRuleExtractionResponse, {"rules": [FEE_RULE]})
        client.set_response_for(
            StatedRuleMappingResponse, _mapping("carried", ["SC-2"])
        )

        assessment = _assess(client, tmp_path, _fee_analysis())

        assert assessment.findings == ()
        assert assessment.verdicts["R-1"].status == "covered"
        assert assessment.verdicts["R-1"].constraint_ids == ("SC-2",)
        assert assessment.verdicts["R-1"].shared_terms == ("approved fee table",)

    def test_mapping_request_shows_rule_text_only(self, tmp_path) -> None:
        client = MockLLMClient()
        client.set_response_for(StatedRuleExtractionResponse, {"rules": [FEE_RULE]})
        client.set_response_for(
            StatedRuleMappingResponse, _mapping("carried", ["SC-2"])
        )

        _assess(client, tmp_path, _analysis())

        mapping_prompt = client.calls[1].user_prompt
        assert "The agent must preserve user trust." in mapping_prompt
        # Coverage is judged by rule text; conditions are not shown.
        assert "through transparency" not in mapping_prompt
        assert USE_CASE not in mapping_prompt

    def test_disposition_with_reason_is_not_a_finding(self, tmp_path) -> None:
        client = MockLLMClient()
        client.set_response_for(StatedRuleExtractionResponse, {"rules": [FEE_RULE]})
        client.set_response_for(
            StatedRuleMappingResponse,
            _mapping("not_testable", [], "No conversation can show the table."),
        )

        assessment = _assess(client, tmp_path, _analysis())

        assert assessment.findings == ()
        verdict = assessment.verdicts["R-1"]
        assert verdict.status == "dispositioned"
        assert verdict.disposition == "not_testable"

    @pytest.mark.parametrize(
        "mapping",
        [
            _mapping("uncovered", [], "No rule limits quoted fees."),
            _mapping("out_of_scope", [], "   "),
            _mapping("carried", ["SC-9"]),
            {"mappings": []},
        ],
        ids=["uncovered", "disposition-without-reason", "unknown-id", "omitted"],
    )
    def test_uncovered_or_invalid_mapping_is_a_finding(self, tmp_path, mapping) -> None:
        client = MockLLMClient()
        client.set_response_for(StatedRuleExtractionResponse, {"rules": [FEE_RULE]})
        client.set_response_for(StatedRuleMappingResponse, mapping)

        assessment = _assess(client, tmp_path, _analysis())

        assert [finding.rule_id for finding in assessment.findings] == ["R-1"]

    def test_quote_located_in_another_rule_moves_coverage_there(self, tmp_path) -> None:
        client = MockLLMClient()
        client.set_response_for(StatedRuleExtractionResponse, {"rules": [FEE_RULE]})
        client.set_response_for(
            StatedRuleMappingResponse,
            _mapping("carried", ["SC-2"], quote="must not quote fees outside"),
        )

        assessment = _assess(client, tmp_path, _analysis(sc1=FEE_CONSTRAINT))

        assert assessment.findings == ()
        verdict = assessment.verdicts["R-1"]
        assert verdict.status == "covered"
        # The quote locates the carrying constraint; the cited ID is replaced.
        assert verdict.constraint_ids == ("SC-1",)
        assert any(
            "R-1" in item and "SC-2" in item and "SC-1" in item
            for item in assessment.warnings
        )

    def test_quote_found_in_no_rule_is_a_finding(self, tmp_path) -> None:
        # A wrong ID with invented wording must not hide a missed rule.
        client = MockLLMClient()
        client.set_response_for(StatedRuleExtractionResponse, {"rules": [FEE_RULE]})
        client.set_response_for(
            StatedRuleMappingResponse,
            _mapping(
                "carried", ["SC-2"], quote="must not quote fees outside the table"
            ),
        )

        assessment = _assess(client, tmp_path, _analysis())

        assert [finding.rule_id for finding in assessment.findings] == ["R-1"]
        verdict = assessment.verdicts["R-1"]
        assert verdict.status == "unresolved"
        assert verdict.constraint_ids == ()
        assert "constraint_quote" in verdict.reason

    def test_blank_quote_on_carried_is_a_finding(self, tmp_path) -> None:
        client = MockLLMClient()
        client.set_response_for(StatedRuleExtractionResponse, {"rules": [FEE_RULE]})
        client.set_response_for(
            StatedRuleMappingResponse, _mapping("carried", ["SC-2"], quote="  ")
        )

        assessment = _assess(client, tmp_path, _analysis())

        assert assessment.verdicts["R-1"].status == "unresolved"

    def test_quote_matching_several_rules_keeps_the_cited_ones(self, tmp_path) -> None:
        client = MockLLMClient()
        client.set_response_for(StatedRuleExtractionResponse, {"rules": [FEE_RULE]})
        client.set_response_for(
            StatedRuleMappingResponse,
            _mapping("carried", ["SC-1"], quote="The agent must"),
        )

        assessment = _assess(client, tmp_path, _analysis(sc1=FEE_CONSTRAINT))

        verdict = assessment.verdicts["R-1"]
        assert verdict.status == "covered"
        assert verdict.constraint_ids == ("SC-1",)
        assert assessment.warnings == []

    def test_findings_sent_to_revision_are_capped(self, tmp_path) -> None:
        words = ["answers", "approved", "articles", "quote", "fees", "table"]
        client = MockLLMClient()
        client.set_response_for(
            StatedRuleExtractionResponse,
            {
                "rules": [
                    {
                        "quote": word,
                        "restatement": f"The system must {word}.",
                        "modality": "requires",
                    }
                    for word in words
                ]
            },
        )
        client.set_response_for(
            StatedRuleMappingResponse,
            {
                "mappings": [
                    {
                        "rule_id": f"R-{index}",
                        "verdict": "uncovered",
                        "constraint_ids": [],
                        "constraint_quote": "",
                        "shared_terms": [],
                        "reason": "No rule states it.",
                    }
                    for index in range(1, len(words) + 1)
                ]
            },
        )

        assessment = _assess(client, tmp_path, _analysis())

        assert [f.rule_id for f in assessment.findings] == [
            "R-1",
            "R-2",
            "R-3",
            "R-4",
            "R-5",
        ]

    def test_provider_errors_leave_the_step_unavailable(self, tmp_path) -> None:
        client = MockLLMClient()
        client.set_exception_for(
            StatedRuleExtractionResponse, RuntimeError("provider down")
        )

        assessment = _assess(client, tmp_path, _analysis())

        assert assessment.status == "unavailable"
        assert "provider down" in (assessment.failure_reason or "")
        assert assessment.findings == ()

    def test_mapping_error_marks_rows_unavailable(self, tmp_path) -> None:
        client = MockLLMClient()
        client.set_response_for(StatedRuleExtractionResponse, {"rules": [FEE_RULE]})
        client.set_exception_for(StatedRuleMappingResponse, RuntimeError("timeout"))

        assessment = _assess(client, tmp_path, _analysis())

        assert assessment.findings == ()
        assert assessment.verdicts["R-1"].status == "unavailable"


class TestGateRevisionTrigger:
    def test_uncovered_rule_triggers_a_revision_on_a_passing_graph(
        self, tmp_path
    ) -> None:
        client = MockLLMClient()
        client.set_response_for(_Stage1aRevisionPatch, _rule_carrying_edit())

        outcome = _gate(client, tmp_path, _analysis(), (FEE_FINDING,))

        assert outcome.passed
        assert outcome.revision_applied is False
        assert outcome.stated_rule_revision == StatedRuleRevision(
            trigger="stated_rules", applied=True, call_count=1
        )
        assert (
            "must not quote fees" in outcome.loss_analysis.security_constraints[1].rule
        )
        [call] = client.calls
        assert "## Stated Rules No Constraint Carries" in call.user_prompt
        assert f'R-1: "{FEE_FINDING.quote}"' in call.user_prompt
        assert "None. The current graph passes" in call.user_prompt
        assert "## Stated rules no constraint carries" in call.system_prompt
        artifact = yaml.safe_load((tmp_path / "loss-analysis-gates.yaml").read_text())
        assert artifact["passed"] is True
        assert artifact["failing_checks"] == []
        assert artifact["stated_rule_findings"] == [f"R-1: {FEE_FINDING.quote}"]
        assert artifact["revision_rounds"][0]["trigger"] == "stated_rules"

    def test_no_findings_make_no_call(self, tmp_path) -> None:
        client = MockLLMClient()

        outcome = _gate(client, tmp_path, _analysis(), ())

        assert outcome.passed
        assert client.calls == []
        assert outcome.stated_rule_revision.trigger == "none"

    def test_failed_rule_only_revision_keeps_the_unrevised_graph(
        self, tmp_path
    ) -> None:
        client = MockLLMClient()
        client.set_exception_for(_Stage1aRevisionPatch, RuntimeError("provider down"))
        analysis = _analysis()

        outcome = _gate(client, tmp_path, analysis, (FEE_FINDING,))

        assert outcome.passed
        assert outcome.loss_analysis == analysis
        revision = outcome.stated_rule_revision
        assert revision.trigger == "stated_rules"
        assert revision.applied is False
        assert "provider down" in (revision.error or "")
        artifact = yaml.safe_load((tmp_path / "loss-analysis-gates.yaml").read_text())
        assert artifact["passed"] is True

    def test_rule_only_revision_that_breaks_density_is_discarded(
        self, tmp_path
    ) -> None:
        client = MockLLMClient()
        client.set_response_for(_Stage1aRevisionPatch, _density_breaking_edit())
        analysis = _analysis()

        outcome = _gate(client, tmp_path, analysis, (FEE_FINDING,))

        assert outcome.passed
        assert outcome.loss_analysis == analysis
        assert outcome.stated_rule_revision.applied is False
        assert "revision broke structural checks" in (
            outcome.stated_rule_revision.error or ""
        )
        assert len(client.calls) == 1

    def test_density_and_rule_findings_share_one_revision(self, tmp_path) -> None:
        payload = valid_loss_analysis_dict()
        payload["risk_dispositions"] = [
            {"risk_ref": "atlas-001", "disposition": "cited", "loss_ids": ["L-1"]}
        ]
        # SC-2 points at H-1, so H-2 has no constraint.
        payload["security_constraints"][1]["related_hazards"] = ["H-1"]
        analysis = LossAnalysis.model_validate(payload)
        client = MockLLMClient()
        client.set_response_for(_Stage1aRevisionPatch, _rule_carrying_edit())

        outcome = _gate(client, tmp_path, analysis, (FEE_FINDING,))

        assert outcome.passed
        assert outcome.revision_applied is True
        assert outcome.stated_rule_revision.trigger == "combined"
        assert outcome.stated_rule_revision.applied is True
        [call] = client.calls
        assert "hazard H-2 has no constraint" in call.user_prompt
        assert f'R-1: "{FEE_FINDING.quote}"' in call.user_prompt

    def test_density_only_revision_prompt_has_no_rule_section(self, tmp_path) -> None:
        payload = valid_loss_analysis_dict()
        payload["risk_dispositions"] = [
            {"risk_ref": "atlas-001", "disposition": "cited", "loss_ids": ["L-1"]}
        ]
        payload["security_constraints"][1]["related_hazards"] = ["H-1"]
        client = MockLLMClient()
        client.set_response_for(_Stage1aRevisionPatch, _rule_carrying_edit())

        _gate(client, tmp_path, LossAnalysis.model_validate(payload), ())

        [call] = client.calls
        assert "Stated Rules" not in call.user_prompt
        assert "Stated rules" not in call.system_prompt


class TestSharedTerms:
    """A carried verdict must name words the constraint repeats from the rule."""

    def _verdict(self, tmp_path, analysis, **mapping):
        client = MockLLMClient()
        client.set_response_for(StatedRuleExtractionResponse, {"rules": [FEE_RULE]})
        client.set_response_for(
            StatedRuleMappingResponse, _mapping("carried", **mapping)
        )
        assessment = _assess(client, tmp_path, analysis)
        return assessment, assessment.verdicts["R-1"], client

    def test_mapping_prompt_explains_shared_terms(self, tmp_path) -> None:
        _, _, client = self._verdict(tmp_path, _fee_analysis(), ids=["SC-2"])

        system_prompt = client.calls[1].system_prompt
        assert "shared_terms" in system_prompt
        assert "not carried" in system_prompt

    def test_term_in_quote_and_cited_rule_is_accepted(self, tmp_path) -> None:
        _, verdict, _ = self._verdict(tmp_path, _fee_analysis(), ids=["SC-2"])

        assert verdict.status == "covered"
        assert verdict.shared_terms == ("approved fee table",)
        assert verdict.rejected_terms == ()

    def test_term_matching_ignores_case_whitespace_and_punctuation(
        self, tmp_path
    ) -> None:
        _, verdict, _ = self._verdict(
            tmp_path,
            _fee_analysis(),
            ids=["SC-2"],
            terms=["“Approved  Fee-Table”"],
        )

        assert verdict.status == "covered"
        assert len(verdict.shared_terms) == 1

    def test_carried_without_terms_is_a_finding(self, tmp_path) -> None:
        assessment, verdict, _ = self._verdict(
            tmp_path, _fee_analysis(), ids=["SC-2"], terms=[]
        )

        assert verdict.status == "unresolved"
        assert "shared term" in verdict.reason
        assert [f.rule_id for f in assessment.findings] == ["R-1"]

    def test_term_absent_from_the_stated_quote_is_rejected(self, tmp_path) -> None:
        _, verdict, _ = self._verdict(
            tmp_path, _fee_analysis(), ids=["SC-2"], terms=["outside"]
        )

        assert verdict.status == "unresolved"
        [rejected] = verdict.rejected_terms
        assert rejected.term == "outside"
        assert "stated rule's quote" in rejected.reason

    def test_term_absent_from_the_carrying_rule_is_rejected(self, tmp_path) -> None:
        # The quote locates SC-1, which never says "does not quote".
        _, verdict, _ = self._verdict(
            tmp_path,
            _analysis(sc1=FEE_CONSTRAINT),
            ids=["SC-1"],
            quote="must not quote fees",
            terms=["does not quote"],
        )

        assert verdict.status == "unresolved"
        [rejected] = verdict.rejected_terms
        assert "SC-1" in rejected.reason

    def test_term_in_more_than_half_the_rules_is_rejected(self, tmp_path) -> None:
        analysis = _analysis(
            sc1="The agent must not quote an unintended payment amount.",
            sc2=FEE_CONSTRAINT,
        )
        _, verdict, _ = self._verdict(
            tmp_path, analysis, ids=["SC-2"], quote=FEE_CONSTRAINT, terms=["quote"]
        )

        assert verdict.status == "unresolved"
        [rejected] = verdict.rejected_terms
        assert "2 of 2 constraint rules" in rejected.reason

    def test_short_term_is_rejected(self, tmp_path) -> None:
        _, verdict, _ = self._verdict(
            tmp_path, _fee_analysis(), ids=["SC-2"], terms=["fee"]
        )

        assert verdict.status == "unresolved"
        [rejected] = verdict.rejected_terms
        assert "characters" in rejected.reason

    def _plural_verdict(self, tmp_path, quote, constraint, term):
        client = MockLLMClient()
        client.set_response_for(
            StatedRuleExtractionResponse,
            {
                "rules": [
                    {
                        "quote": quote,
                        "restatement": "The system must follow the stated limit.",
                        "modality": "requires",
                    }
                ]
            },
        )
        client.set_response_for(
            StatedRuleMappingResponse,
            _mapping("carried", ["SC-1"], quote=constraint, terms=[term]),
        )
        assessment = _assess(client, tmp_path, _analysis(sc1=constraint))
        return assessment.verdicts["R-1"]

    def test_singular_term_matches_plural_quote(self, tmp_path) -> None:
        verdict = self._plural_verdict(
            tmp_path,
            "It hands billing disputes to human agents.",
            "The agent must hand every billing dispute to a human agent.",
            "human agent",
        )

        assert verdict.status == "covered"
        assert verdict.shared_terms == ("human agent",)

    def test_plural_term_matches_singular_rule(self, tmp_path) -> None:
        verdict = self._plural_verdict(
            tmp_path,
            "It hands billing disputes to human agents.",
            "The agent must hand every billing dispute to a human agent.",
            "billing disputes",
        )

        assert verdict.status == "covered"

    def test_ies_plural_matches_y_singular(self, tmp_path) -> None:
        verdict = self._plural_verdict(
            tmp_path,
            "It cites only current policies.",
            "The agent must cite only a current policy.",
            "current policy",
        )

        assert verdict.status == "covered"

    def test_plural_tolerance_keeps_word_boundaries(self, tmp_path) -> None:
        verdict = self._plural_verdict(
            tmp_path,
            "It hands billing disputes to human agents.",
            "The agent must hand every billing dispute to a human agent.",
            "human agen",
        )

        assert verdict.status == "unresolved"

    def test_one_accepted_term_is_enough(self, tmp_path) -> None:
        _, verdict, _ = self._verdict(
            tmp_path,
            _fee_analysis(),
            ids=["SC-2"],
            terms=["not", "approved fee table"],
        )

        assert verdict.status == "covered"
        assert verdict.shared_terms == ("approved fee table",)
        assert [item.term for item in verdict.rejected_terms] == ["not"]

    def test_coverage_keeps_only_rules_that_repeat_a_term(self, tmp_path) -> None:
        # The quote occurs in both rules; only SC-1 repeats the fee limit.
        _, verdict, _ = self._verdict(
            tmp_path,
            _analysis(sc1=FEE_CONSTRAINT),
            ids=["SC-1", "SC-2"],
            quote="The agent must",
        )

        assert verdict.status == "covered"
        assert verdict.constraint_ids == ("SC-1",)

    def test_artifact_records_accepted_and_rejected_terms(self, tmp_path) -> None:
        client = MockLLMClient()
        client.set_response_for(StatedRuleExtractionResponse, {"rules": [FEE_RULE]})
        client.set_response_for(
            StatedRuleMappingResponse,
            _mapping("carried", ["SC-2"], terms=["not", "approved fee table"]),
        )
        analysis = _fee_analysis()
        assessment = _assess(client, tmp_path, analysis)

        finalize_stated_rule_coverage(
            assessment,
            llm_client=client,
            draft=analysis,
            final=analysis,
            final_digest=graph_digest(analysis),
            revision=StatedRuleRevision(),
            run_dir=tmp_path,
            template_loader=TemplateLoader(PROMPTS_DIR),
            temperature=0.4,
        )

        persisted = yaml.safe_load((tmp_path / "stated-rule-coverage.yaml").read_text())
        [row] = persisted["rules"]
        assert row["shared_terms"] == ["approved fee table"]
        assert row["rejected_terms"][0]["term"] == "not"
        assert row["rejected_terms"][0]["reason"]


class TestFinalize:
    def test_unrepaired_finding_is_recorded_unresolved(self, tmp_path) -> None:
        client = MockLLMClient()
        client.set_response_for(StatedRuleExtractionResponse, {"rules": [FEE_RULE]})
        client.set_response_for(StatedRuleMappingResponse, _mapping("uncovered", []))
        analysis = _analysis()
        assessment = _assess(client, tmp_path, analysis)

        artifact = finalize_stated_rule_coverage(
            assessment,
            llm_client=client,
            draft=analysis,
            final=analysis,
            final_digest=graph_digest(analysis),
            revision=StatedRuleRevision(
                trigger="stated_rules", call_count=1, error="provider down"
            ),
            run_dir=tmp_path,
            template_loader=TemplateLoader(PROMPTS_DIR),
            temperature=0.4,
        )

        [row] = artifact.rules
        assert row.status == "unresolved"
        assert row.sent_to_revision is True
        assert row.quote == FEE_FINDING.quote
        # No re-mapping when the graph did not change.
        assert len(client.calls) == 2
        persisted = yaml.safe_load((tmp_path / "stated-rule-coverage.yaml").read_text())
        assert persisted["schema_version"] == "stated-rule-coverage-v1"
        assert persisted["rules"][0]["status"] == "unresolved"


class TestRunSp1:
    def test_uncovered_rule_is_repaired_and_recorded(self, tmp_path) -> None:
        from asago_scenario_generator.stpa.system_model.run import run_sp1

        client = setup_sp1_mock_client()
        client.set_response_for(StatedRuleExtractionResponse, {"rules": [FEE_RULE]})
        client.set_response_for(
            StatedRuleMappingResponse,
            [
                _mapping("uncovered", []),
                _mapping("carried", ["SC-2"], quote="must not quote fees"),
            ],
        )
        client.set_response_for(_Stage1aRevisionPatch, _rule_carrying_edit())

        result = run_sp1(
            llm_client=client,
            use_case_text=USE_CASE,
            risk_cards=_cards(),
            run_dir=tmp_path,
        )

        assert result.stage_errors == []
        steps = [
            e["step"] for e in read_calls_jsonl(tmp_path) if e["stage"] == "stage_1a"
        ]
        assert steps == [
            "risk_actionability",
            "risk_derivation",
            "gap_analysis",
            "stated_rule_extraction",
            "stated_rule_mapping",
            "hazard_graph_revision",
            "stated_rule_mapping_after_revision",
            "risk_coverage_review",
        ]
        artifact = yaml.safe_load((tmp_path / "stated-rule-coverage.yaml").read_text())
        [row] = artifact["rules"]
        assert row["status"] == "covered"
        assert row["constraint_ids"] == ["SC-2"]
        assert row["added_by_revision"] is True
        assert row["sent_to_revision"] is True
        assert artifact["revision"]["trigger"] == "stated_rules"
        assert (
            artifact["mapped_loss_analysis_digest"]
            == (artifact["final_loss_analysis_digest"])
        )
        manifest = yaml.safe_load((tmp_path / "run-manifest.yaml").read_text())
        stage_1a = manifest["stage_summary"]["stage_1a"]
        assert stage_1a["hazard_graph_density"] == "passed"
        assert stage_1a["stated_rule_coverage"]["counts"]["covered"] == 1
        # Actionability, two derivations, one revision, three rule calls,
        # and the coverage review.
        assert stage_1a["call_count"] == 8

    def test_failed_rule_revision_never_fails_the_stage(self, tmp_path) -> None:
        from asago_scenario_generator.stpa.system_model.run import run_sp1

        client = setup_sp1_mock_client()
        client.set_response_for(StatedRuleExtractionResponse, {"rules": [FEE_RULE]})
        client.set_response_for(StatedRuleMappingResponse, _mapping("uncovered", []))
        client.set_exception_for(_Stage1aRevisionPatch, RuntimeError("provider down"))

        result = run_sp1(
            llm_client=client,
            use_case_text=USE_CASE,
            risk_cards=_cards(),
            run_dir=tmp_path,
        )

        assert result.stage_errors == []
        assert result.loss_analysis is not None
        assert result.control_structure is not None
        manifest = yaml.safe_load((tmp_path / "run-manifest.yaml").read_text())
        assert any(
            warning.startswith("stage_1a/stated_rule_coverage unresolved R-1")
            for warning in manifest["stage_warnings"]
        )
        artifact = yaml.safe_load((tmp_path / "stated-rule-coverage.yaml").read_text())
        assert artifact["rules"][0]["status"] == "unresolved"
        assert artifact["revision"]["applied"] is False

    def test_density_failure_still_fails_with_rule_findings(self, tmp_path) -> None:
        from asago_scenario_generator.stpa.system_model.run import run_sp1

        failing_gap = valid_gap_draft_dict()
        failing_gap["security_constraints"][0]["related_hazards"] = ["H-1"]
        client = setup_sp1_mock_client()
        client.set_response_for(
            LossAnalysisDraft, [valid_risk_draft_dict(), failing_gap]
        )
        client.set_response_for(StatedRuleExtractionResponse, {"rules": [FEE_RULE]})
        client.set_response_for(StatedRuleMappingResponse, _mapping("uncovered", []))
        client.set_exception_for(_Stage1aRevisionPatch, RuntimeError("provider down"))

        result = run_sp1(
            llm_client=client,
            use_case_text=USE_CASE,
            risk_cards=_cards(),
            run_dir=tmp_path,
        )

        # The density gate keeps its fail-closed behavior; the rule rows are
        # still recorded.
        assert result.loss_analysis is None
        assert result.stage_errors
        artifact = yaml.safe_load((tmp_path / "stated-rule-coverage.yaml").read_text())
        assert artifact["revision"]["trigger"] == "combined"
        assert artifact["rules"][0]["status"] == "unresolved"


class TestStage2Citation:
    def test_uncited_constraint_is_reported(self) -> None:
        from tests.stpa.sp1_helpers import (
            valid_control_element_set_dict,
            valid_responsibility_set_dict,
        )

        responsibilities = valid_responsibility_set_dict()["responsibilities"]
        elements = valid_control_element_set_dict()
        cs = ControlStructure.model_validate(
            {
                "controllers": elements.get("controllers", []),
                "responsibilities": responsibilities,
                "controlled_processes": elements.get("controlled_processes", []),
            }
        )

        assert uncited_security_constraints(cs, _analysis()) == ["SC-2"]

    def test_uncited_constraint_is_a_manifest_warning(self, tmp_path) -> None:
        from asago_scenario_generator.stpa.system_model.run import run_sp1

        result = run_sp1(
            llm_client=setup_sp1_mock_client(),
            use_case_text=USE_CASE,
            risk_cards=_cards(),
            run_dir=tmp_path,
        )

        assert result.stage_errors == []
        assert (
            "stage_2/constraint_citation: security constraint SC-2 is not cited "
            "by any Stage 2 responsibility"
        ) in result.stage_warnings
        manifest = yaml.safe_load((tmp_path / "run-manifest.yaml").read_text())
        assert manifest["stage_summary"]["stage_2"]["uncited_security_constraints"] == [
            "SC-2"
        ]
