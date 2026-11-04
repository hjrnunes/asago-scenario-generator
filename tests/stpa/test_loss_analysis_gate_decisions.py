"""The six graph-revision decisions as values, and the gate's use of them.

A revision round ends in one of six ways: the gate accepts the response, asks
for a correction, asks for another round, keeps the response without the
records it broke, keeps the prior graph, or stops the run.  The gate used to
encode each of those as control flow.  These tests pin the six values, the
functions that return them, and that the runner follows a decision it is
handed.  Every fixture is synthetic; no test contacts a model endpoint.
"""

from __future__ import annotations

import dataclasses

import pytest

from asago_scenario_generator.stpa.infra.llm_helpers import StageError
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.stpa.system_model import loss_analysis_gates
from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.system_model.loss_analysis import (
    _Stage1aRevisionPatch,
)
from asago_scenario_generator.stpa.system_model.loss_analysis_gate_checks import (
    HazardGraphDensityReport,
    check_hazard_graph_density,
)
from asago_scenario_generator.stpa.system_model.loss_analysis_gate_decisions import (
    Accept,
    Correct,
    KeepPartial,
    KeepPrior,
    Revise,
    Stop,
    decide_correction,
    decide_density_round,
    decide_revision_call,
    decide_stated_rule_round,
)
from asago_scenario_generator.stpa.system_model.loss_analysis_gates import (
    REVISION_CORRECTION_SCOPE,
    _revision_policy,
    _run_graph_revision_call,
    _run_stated_rule_revision,
)
from tests.helpers.stpa_builders import make_loss_analysis, make_risk_cards
from tests.stpa.sp1_helpers import MockLLMClient
from tests.stpa.test_loss_analysis_gates import (
    _conditional_gapped_graph,
    _sc2_edit_patch,
)
from tests.stpa.test_stated_rule_coverage import (
    FEE_CONSTRAINT,
    FEE_FINDING,
    USE_CASE,
    _analysis,
)
from tests.stpa.test_stated_rule_round_repair import _addition, _patch

DECISIONS = (Accept, Correct, Revise, KeepPartial, KeepPrior, Stop)


def _failing_report() -> HazardGraphDensityReport:
    """One loss without a hazard; every other check passes."""
    return HazardGraphDensityReport(
        losses_without_hazard=("L-9",),
        constraints_without_hazard=(),
        hazards_without_constraint=(),
        subject_checks=(),
        class_own_hazard_checks=(),
        constraint_classes=(),
        unclassified_constraints=(),
    )


def _passing_report() -> HazardGraphDensityReport:
    return check_hazard_graph_density(make_loss_analysis())


def _stated_rule_reply() -> dict:
    """A valid stated-rule addition: a new constraint beside SC-2's H-2."""
    return _patch(additions=[_addition("fee_rule", FEE_CONSTRAINT, ["H-2"])])


class TestTheDecisionsAreValues:
    """Each decision names one outcome and carries what that outcome needs."""

    @pytest.mark.parametrize("decision", DECISIONS, ids=lambda d: d.__name__)
    def test_each_decision_is_a_frozen_dataclass(self, decision: type) -> None:
        assert dataclasses.is_dataclass(decision)
        assert decision.__dataclass_params__.frozen

    def test_accept_carries_the_graph_to_keep(self) -> None:
        analysis = make_loss_analysis()

        decision = Accept(analysis=analysis)

        assert decision.analysis == analysis

    def test_correct_carries_the_scope_and_the_retry_budget(self) -> None:
        decision = Correct(scope="graph revision reply", retries=1)

        assert (decision.scope, decision.retries) == ("graph revision reply", 1)

    def test_revise_carries_the_graph_the_findings_and_the_round(self) -> None:
        analysis = make_loss_analysis()
        findings = _failing_report()

        decision = Revise(analysis=analysis, findings=findings, round_number=1)

        assert decision.analysis == analysis
        assert decision.findings == findings
        assert decision.round_number == 1

    def test_keep_partial_carries_the_records_it_dropped(self) -> None:
        analysis = make_loss_analysis()
        record = {"record": "security_constraint_addition", "constraint_id": "SC-3"}

        decision = KeepPartial(analysis=analysis, records=(record,))

        assert decision.analysis == analysis
        assert decision.records == (record,)

    def test_keep_prior_carries_the_reason(self) -> None:
        assert KeepPrior(reason="the revision broke a check").reason == (
            "the revision broke a check"
        )

    def test_stop_carries_the_reason_and_the_findings(self) -> None:
        findings = _failing_report()

        decision = Stop(reason="tried twice", findings=findings)

        assert decision.reason == "tried twice"
        assert decision.findings == findings

    def test_a_decision_cannot_be_changed_after_it_is_made(self) -> None:
        decision = Accept(analysis=make_loss_analysis())

        with pytest.raises(dataclasses.FrozenInstanceError):
            decision.analysis = make_loss_analysis()  # type: ignore[misc]


class TestDecideRevisionCall:
    """What one graph-revision call leaves the runner to do."""

    def test_a_valid_reply_is_accepted(self) -> None:
        analysis = make_loss_analysis()

        decision = decide_revision_call(analysis)

        assert decision == Accept(analysis=analysis)

    def test_a_rebuilt_reply_is_kept_without_the_records_it_dropped(self) -> None:
        analysis = make_loss_analysis()
        record = {
            "record": "security_constraint_addition",
            "constraint_id": "SC-3",
            "error": "its rule_span is not in the rule",
        }

        decision = decide_revision_call(analysis, records=(record,))

        assert decision == KeepPartial(analysis=analysis, records=(record,))

    def test_a_call_that_produced_no_graph_stops_the_run(self) -> None:
        decision = decide_revision_call(None, error="graph revision call failed: bad")

        assert decision == Stop(reason="graph revision call failed: bad")


class TestDecideDensityRound:
    """What the density gate does with one valid revision round."""

    def test_a_passing_revision_is_accepted(self) -> None:
        analysis = make_loss_analysis()

        decision = decide_density_round(
            analysis, _passing_report(), round_number=1, rounds=2
        )

        assert decision == Accept(analysis=analysis)

    def test_a_still_failing_revision_earns_another_round(self) -> None:
        analysis = make_loss_analysis()
        findings = _failing_report()

        decision = decide_density_round(analysis, findings, round_number=1, rounds=2)

        assert decision == Revise(analysis=analysis, findings=findings, round_number=1)

    def test_a_failure_after_the_last_round_stops_the_run(self) -> None:
        analysis = make_loss_analysis()
        findings = _failing_report()

        decision = decide_density_round(analysis, findings, round_number=2, rounds=2)

        assert isinstance(decision, Stop)
        assert decision.reason == "loss L-9 has no hazard"
        assert decision.findings == findings


class TestDecideStatedRuleRound:
    """What the non-fatal stated-rule round leaves the runner to do."""

    def test_a_revision_that_passes_every_check_is_accepted(self) -> None:
        analysis = make_loss_analysis()

        decision = decide_stated_rule_round(analysis, rejection=None)

        assert decision == Accept(analysis=analysis)

    def test_a_rejected_revision_keeps_the_prior_graph(self) -> None:
        decision = decide_stated_rule_round(
            make_loss_analysis(), rejection="revision broke structural checks"
        )

        assert decision == KeepPrior(reason="revision broke structural checks")

    def test_a_trimmed_revision_is_kept_without_the_trimmed_records(self) -> None:
        analysis = make_loss_analysis()
        record = {"record": "security_constraint_addition", "constraint_id": "SC-3"}

        decision = decide_stated_rule_round(analysis, rejection=None, records=(record,))

        assert decision == KeepPartial(analysis=analysis, records=(record,))


class TestDecideCorrection:
    """Whether a reply that failed decoding or validation earns a correction."""

    def test_a_failed_reply_with_a_budget_earns_one_correction(self) -> None:
        decision = decide_correction(scope="graph revision reply", retries=1)

        assert decision == Correct(scope="graph revision reply", retries=1)

    def test_a_failed_reply_without_a_budget_stops(self) -> None:
        decision = decide_correction(scope="graph revision reply", retries=0)

        assert isinstance(decision, Stop)
        assert "graph revision reply" in decision.reason


class TestTheGateFollowsTheDecision:
    """A decision handed to the runner changes what the runner does."""

    def test_the_revision_call_raises_the_stop_reasons(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            loss_analysis_gates,
            "decide_revision_call",
            lambda *args, **kwargs: Stop(reason="the decision stopped the call"),
        )
        client = MockLLMClient()
        client.set_response_for(_Stage1aRevisionPatch, [_stated_rule_reply()])

        with pytest.raises(StageError, match="the decision stopped the call"):
            _run_graph_revision_call(
                llm_client=client,
                loss_analysis=_analysis(),
                use_case_text=USE_CASE,
                failing_checks=[],
                run_dir=tmp_path,
                template_loader=TemplateLoader(PROMPTS_DIR),
                temperature=0.4,
                attempts_out=[],
                stated_rules=(FEE_FINDING,),
                addition_only=True,
            )

    def test_the_stated_rule_round_keeps_the_prior_graph_on_keep_prior(
        self, tmp_path, monkeypatch
    ) -> None:
        monkeypatch.setattr(
            loss_analysis_gates,
            "decide_stated_rule_round",
            lambda *args, **kwargs: KeepPrior(reason="the decision kept the graph"),
        )
        prior: LossAnalysis = _analysis()
        client = MockLLMClient()
        client.set_response_for(_Stage1aRevisionPatch, [_stated_rule_reply()])

        revised, revision, _record, _warnings = _run_stated_rule_revision(
            llm_client=client,
            loss_analysis=prior,
            use_case_text=USE_CASE,
            findings=(FEE_FINDING,),
            density=check_hazard_graph_density(prior),
            run_dir=tmp_path,
            template_loader=TemplateLoader(PROMPTS_DIR),
            temperature=0.4,
            repair_record=None,
        )

        assert revised == prior
        assert revision.applied is False
        assert "the decision kept the graph" in (revision.error or "")

    def test_the_density_gate_stops_a_round_the_decision_stops(
        self, tmp_path, monkeypatch
    ) -> None:
        def stop_after_the_first_round(revised, findings, *, round_number, rounds):
            decision = decide_density_round(
                revised, findings, round_number=round_number, rounds=rounds
            )
            assert isinstance(decision, Revise)
            return Stop(reason=decision.findings.failing_checks[0])

        monkeypatch.setattr(
            loss_analysis_gates, "decide_density_round", stop_after_the_first_round
        )
        client = MockLLMClient()
        patch = _sc2_edit_patch(
            rule="The payment record must stay protected.",
            applies_when=[],
            related_hazards=["H-2"],
        )
        client.set_response_queue([patch, patch])

        with pytest.raises(StageError):
            loss_analysis_gates.gate_loss_analysis(
                llm_client=client,
                loss_analysis=_conditional_gapped_graph(),
                use_case_text="A service receives a request.",
                risk_cards=make_risk_cards(("atlas-001",)),
                run_dir=tmp_path,
                template_loader=TemplateLoader(PROMPTS_DIR),
                temperature=0.4,
            )

        # The real decision asks for a second round; the stop ends the gate
        # after the one reply it already had.
        assert len(client.calls) == 1

    def test_the_revision_policy_is_built_from_the_correction_decision(
        self, monkeypatch
    ) -> None:
        monkeypatch.setattr(loss_analysis_gates, "REVISION_VALIDATION_RETRIES", 0)

        policy = _revision_policy(TemplateLoader(PROMPTS_DIR))

        assert policy.validation_retries == 0
        assert policy.correct_undecodable is False

    def test_the_revision_policy_names_the_scope_the_decision_carries(self) -> None:
        decision = decide_correction(
            scope=REVISION_CORRECTION_SCOPE,
            retries=loss_analysis_gates.REVISION_VALIDATION_RETRIES,
        )

        assert isinstance(decision, Correct)
        assert _revision_policy(TemplateLoader(PROMPTS_DIR)).validation_retries == (
            decision.retries
        )
