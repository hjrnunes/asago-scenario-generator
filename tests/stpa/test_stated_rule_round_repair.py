"""Stated-rule revision rounds that fail only on structure or rule_span.

The round keeps what is valid: a record whose ``rule_span`` is not in its
rule is dropped, a new hazard only that record cited goes with it, and an
added constraint that takes over a hazard another behavior class owns alone is
trimmed.  Each drop is recorded.  The replies below follow the recorded
patterns: out-of-rule spans with an orphaned new hazard, an add-only edit
beside a slip, and a cross-class citation.
"""

from __future__ import annotations

import yaml

from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.system_model.loss_analysis import (
    _Stage1aRevisionPatch,
)
from asago_scenario_generator.stpa.system_model.loss_analysis_gates import (
    _run_graph_revision_call,
)
from tests.stpa.sp1_helpers import MockLLMClient
from tests.stpa.test_stated_rule_coverage import (
    FEE_CONSTRAINT,
    FEE_FINDING,
    USE_CASE,
    _analysis,
    _edit,
    _gate,
)

BAD_SPAN = "this text is not in the rule"
FEE_SPAN = "must not quote fees"


def _obligation(span: str) -> dict:
    return {
        "obligation_id": "O1",
        "kind": "required",
        "behavior": "keep quoted fees inside the approved table",
        "rule_span": span,
        "realized_by": "reply",
    }


def _addition(
    handle: str,
    rule: str,
    hazards: list[str],
    *,
    span: str | None = None,
    behavior_class: str | None = None,
) -> dict:
    addition: dict = {
        "handle": handle,
        "rule": rule,
        "applies_when": [],
        "related_hazards": hazards,
        "obligations": [] if span is None else [_obligation(span)],
    }
    if behavior_class is not None:
        addition["behavior_class"] = behavior_class
    return addition


def _hazard(handle: str, description: str) -> dict:
    return {"handle": handle, "description": description, "related_losses": ["L-2"]}


def _patch(*, hazards=(), additions=(), hazard_edits=()) -> dict:
    return {
        "hazard_edits": list(hazard_edits),
        "hazard_additions": list(hazards),
        "security_constraint_edits": [],
        "security_constraint_additions": list(additions),
    }


def _call(tmp_path, replies, *, addition_only: bool, analysis=None):
    client = MockLLMClient()
    client.set_response_for(_Stage1aRevisionPatch, replies)
    attempts: list = []
    prior = analysis or _analysis()
    revised = _run_graph_revision_call(
        llm_client=client,
        loss_analysis=prior,
        use_case_text=USE_CASE,
        failing_checks=[],
        run_dir=tmp_path,
        template_loader=TemplateLoader(PROMPTS_DIR),
        temperature=0.4,
        attempts_out=attempts,
        stated_rules=(FEE_FINDING,),
        addition_only=addition_only,
        drop_unquoted_spans=True,
    )
    return prior, revised, attempts, client


def _edited_hazard() -> dict:
    return {
        "hazard_id": "H-2",
        "description": "The agent erodes user trust by quoting unapproved fees.",
        "related_losses": ["L-2"],
    }


class TestDropPrunesHazardsOnlyTheDroppedRecordsCited:
    """A new hazard left without a constraint by a drop goes with the drop."""

    def _reply(self, *, shared: bool = False) -> dict:
        good_hazards = ["H-2", "fee_hazard"] if shared else ["H-2"]
        return _patch(
            hazards=[_hazard("fee_hazard", "The agent quotes an unapproved fee.")],
            additions=[
                _addition("fee_rule", FEE_CONSTRAINT, good_hazards, span=FEE_SPAN),
                _addition(
                    "slipping",
                    "The agent must cite policies.",
                    ["fee_hazard"],
                    span=BAD_SPAN,
                ),
            ],
        )

    def test_the_hazard_only_the_dropped_record_cited_is_pruned(self, tmp_path) -> None:
        prior, revised, attempts, _ = _call(
            tmp_path, [self._reply(), self._reply()], addition_only=True
        )

        assert revised.hazards == prior.hazards
        assert [c.rule for c in revised.security_constraints[2:]] == [FEE_CONSTRAINT]
        assert [d["handle"] for d in attempts[-1].dropped] == ["slipping"]

    def test_a_hazard_a_kept_record_also_cites_stays(self, tmp_path) -> None:
        prior, revised, _, _ = _call(
            tmp_path,
            [self._reply(shared=True), self._reply(shared=True)],
            addition_only=True,
        )

        assert [h.hazard_id for h in revised.hazards] == ["H-1", "H-2", "H-3"]
        assert revised.security_constraints[2].related_hazards == ["H-2", "H-3"]


class TestDropRebuildKeepsTheAddOnlyFilter:
    """The rebuild after a dropped record runs the same filter as the first parse."""

    def _reply(self) -> dict:
        return _patch(
            hazard_edits=[_edited_hazard()],
            additions=[
                _addition("fee_rule", FEE_CONSTRAINT, ["H-2"], span=FEE_SPAN),
                _addition(
                    "slipping", "The agent must cite policies.", ["H-2"], span=BAD_SPAN
                ),
            ],
        )

    def test_an_add_only_rebuild_leaves_a_hazard_edit_out(self, tmp_path) -> None:
        prior, revised, attempts, client = _call(
            tmp_path, [self._reply(), self._reply()], addition_only=True
        )

        assert revised.hazards == prior.hazards
        assert [c.rule for c in revised.security_constraints[2:]] == [FEE_CONSTRAINT]
        assert len(client.calls) == 2
        assert [d["handle"] for d in attempts[-1].dropped] == ["slipping"]
        assert any("dropped an edit" in w for w in attempts[-1].warnings)

    def test_a_full_revision_rebuild_keeps_the_edit(self, tmp_path) -> None:
        prior, revised, _, _ = _call(
            tmp_path, [self._reply(), self._reply()], addition_only=False
        )

        assert revised.hazards != prior.hazards
        assert revised.hazards[1].description == _edited_hazard()["description"]


def _gate_round(tmp_path, replies, analysis=None, check=None):
    client = MockLLMClient()
    client.set_response_for(_Stage1aRevisionPatch, replies)
    prior = analysis or _analysis()
    outcome = _gate(client, tmp_path, prior, (FEE_FINDING,), check=check)
    return prior, outcome, client


def _artifact(tmp_path) -> dict:
    return yaml.safe_load((tmp_path / "loss-analysis-gates.yaml").read_text())


class TestRuleRoundDropsUnquotedRecords:
    """A rule_span slip that survives the correction no longer voids the round."""

    def _slipping(self) -> dict:
        return _patch(
            hazards=[_hazard("fee_hazard", "The agent quotes an unapproved fee.")],
            additions=[
                _addition("fee_rule", FEE_CONSTRAINT, ["H-2"], span=FEE_SPAN),
                _addition(
                    "slipping",
                    "The agent must cite policies.",
                    ["fee_hazard"],
                    span=BAD_SPAN,
                ),
            ],
        )

    def test_the_valid_addition_is_kept_after_the_correction(self, tmp_path) -> None:
        prior, outcome, client = _gate_round(
            tmp_path, [self._slipping(), self._slipping()]
        )

        revision = outcome.stated_rule_revision
        assert revision.applied is True
        assert revision.call_count == 2
        assert len(client.calls) == 2
        assert outcome.loss_analysis.hazards == prior.hazards
        added = outcome.loss_analysis.security_constraints[2:]
        assert [c.rule for c in added] == [FEE_CONSTRAINT]

    def test_a_round_with_nothing_valid_left_keeps_the_unrevised_graph(
        self, tmp_path
    ) -> None:
        only_slip = _patch(
            additions=[_addition("slipping", FEE_CONSTRAINT, ["H-2"], span=BAD_SPAN)]
        )
        prior, outcome, _ = _gate_round(tmp_path, [only_slip, only_slip])

        assert outcome.loss_analysis == prior
        assert outcome.stated_rule_revision.applied is False
        assert "graph revision call failed" in (
            outcome.stated_rule_revision.error or ""
        )


class TestRuleRoundKeepsWhatIsValidBesideASlip:
    """The drop leaves valid edits and additions alone and rejects an empty remainder."""

    def test_a_valid_extension_beside_a_slipping_addition_is_kept(
        self, tmp_path
    ) -> None:
        rule = (
            "The agent must preserve user trust and must not quote fees "
            "outside the approved fee table."
        )
        reply = _edit(rule=rule)
        reply["security_constraint_additions"] = [
            _addition(
                "slipping", "The agent must cite policies.", ["H-2"], span=BAD_SPAN
            )
        ]

        prior, outcome, _ = _gate_round(tmp_path, [reply, reply])

        assert outcome.stated_rule_revision.applied is True
        assert outcome.loss_analysis.security_constraints[1].rule == rule
        assert len(outcome.loss_analysis.security_constraints) == len(
            prior.security_constraints
        )

    def test_a_remainder_the_add_only_filter_empties_keeps_the_unrevised_graph(
        self, tmp_path
    ) -> None:
        reply = _patch(
            hazard_edits=[_edited_hazard()],
            additions=[_addition("slipping", FEE_CONSTRAINT, ["H-2"], span=BAD_SPAN)],
        )

        prior, outcome, _ = _gate_round(tmp_path, [reply, reply])

        assert outcome.loss_analysis == prior
        assert outcome.stated_rule_revision.applied is False
        assert "graph revision call failed" in (
            outcome.stated_rule_revision.error or ""
        )

    def test_a_check_that_raises_rejects_the_round(self, tmp_path) -> None:
        def broken(_revised):
            raise ZeroDivisionError("remap")

        clean = _patch(additions=[_addition("fee_rule", FEE_CONSTRAINT, ["H-2"])])
        prior, outcome, _ = _gate_round(tmp_path, [clean], check=broken)

        assert outcome.loss_analysis == prior
        assert "revision check failed: ZeroDivisionError" in (
            outcome.stated_rule_revision.error or ""
        )


def _classed_analysis() -> LossAnalysis:
    """SC-1 (disclosure) owns H-1 and SC-2 (unauthorized_write) owns H-2."""
    payload = _analysis().model_dump()
    payload["security_constraints"][0]["behavior_class"] = "disclosure"
    payload["security_constraints"][1]["behavior_class"] = "unauthorized_write"
    return LossAnalysis.model_validate(payload)


def _constraint_rules(analysis: LossAnalysis) -> list[str]:
    return [c.rule for c in analysis.security_constraints]


class TestRuleRoundTrimsCrossClassCitations:
    """An addition that takes over another class's only hazard is trimmed."""

    def _reply(self) -> dict:
        # The recorded pattern: the model cites the hazard it finds closest
        # in meaning, which the disclosure class owns alone.
        return _patch(
            hazards=[_hazard("fee_hazard", "The agent quotes an unapproved fee.")],
            additions=[
                _addition(
                    "fee_rule",
                    FEE_CONSTRAINT,
                    ["fee_hazard"],
                    span=FEE_SPAN,
                    behavior_class="wrong_information",
                ),
                _addition(
                    "cross_class",
                    "The agent must cite only current policies.",
                    ["H-1"],
                    behavior_class="wrong_information",
                ),
            ],
        )

    def test_the_cross_class_addition_is_trimmed_and_the_round_kept(
        self, tmp_path
    ) -> None:
        prior, outcome, client = _gate_round(
            tmp_path, [self._reply()], _classed_analysis()
        )

        revision = outcome.stated_rule_revision
        assert revision.applied is True
        assert revision.call_count == 1
        assert len(client.calls) == 1
        added = outcome.loss_analysis.security_constraints[2:]
        assert [c.rule for c in added] == [FEE_CONSTRAINT]
        assert [h.hazard_id for h in outcome.loss_analysis.hazards] == [
            "H-1",
            "H-2",
            "H-3",
        ]
        assert _artifact(tmp_path)["passed"] is True

    def test_a_new_hazard_only_the_trimmed_addition_cited_is_pruned(
        self, tmp_path
    ) -> None:
        reply = self._reply()
        reply["hazard_additions"].append(
            _hazard("spare", "The agent cites a stale policy.")
        )
        reply["security_constraint_additions"][1]["related_hazards"] = ["H-1", "spare"]

        _, outcome, _ = _gate_round(tmp_path, [reply], _classed_analysis())

        assert outcome.stated_rule_revision.applied is True
        assert [h.hazard_id for h in outcome.loss_analysis.hazards] == [
            "H-1",
            "H-2",
            "H-3",
        ]
        descriptions = [h.description for h in outcome.loss_analysis.hazards]
        assert "The agent cites a stale policy." not in descriptions

    def test_a_trim_that_still_fails_density_keeps_the_unrevised_graph(
        self, tmp_path
    ) -> None:
        # Two classes share the one new hazard, so neither owns a hazard of
        # its own after the trim.
        reply = self._reply()
        reply["security_constraint_additions"].append(
            _addition(
                "second_class",
                "The agent must not reveal fee internals.",
                ["fee_hazard"],
                behavior_class="manipulation",
            )
        )

        prior, outcome, _ = _gate_round(tmp_path, [reply], _classed_analysis())

        assert outcome.loss_analysis == prior
        assert outcome.stated_rule_revision.applied is False
        error = outcome.stated_rule_revision.error or ""
        assert "revision broke structural checks" in error
        assert "has no hazard of its own" in error

    def test_a_round_whose_additions_are_all_trimmed_keeps_the_unrevised_graph(
        self, tmp_path
    ) -> None:
        only_cross = _patch(
            additions=[
                _addition(
                    "cross_class",
                    FEE_CONSTRAINT,
                    ["H-1"],
                    behavior_class="wrong_information",
                )
            ]
        )

        prior, outcome, _ = _gate_round(tmp_path, [only_cross], _classed_analysis())

        assert outcome.loss_analysis == prior
        assert outcome.stated_rule_revision.applied is False
        assert "revision broke structural checks" in (
            outcome.stated_rule_revision.error or ""
        )

    def test_an_addition_in_the_hazards_own_class_is_not_trimmed(
        self, tmp_path
    ) -> None:
        same_class = _patch(
            additions=[
                _addition(
                    "fee_rule", FEE_CONSTRAINT, ["H-1"], behavior_class="disclosure"
                )
            ]
        )

        _, outcome, _ = _gate_round(tmp_path, [same_class], _classed_analysis())

        assert outcome.stated_rule_revision.applied is True
        assert _constraint_rules(outcome.loss_analysis)[-1] == FEE_CONSTRAINT

    def test_a_failure_other_than_class_ownership_is_not_trimmed(
        self, tmp_path
    ) -> None:
        # A new hazard no constraint cites fails the hazard check; the trim
        # does not run, so the cross-class addition does not hide it.
        reply = self._reply()
        reply["hazard_additions"].append(_hazard("orphan", "The agent leaks a fee."))

        prior, outcome, _ = _gate_round(tmp_path, [reply], _classed_analysis())

        assert outcome.loss_analysis == prior
        assert "has no constraint" in (outcome.stated_rule_revision.error or "")


class TestRuleRoundRecordsWhatItDropped:
    """Every dropped constraint is visible in the round record and the warnings."""

    def test_a_trimmed_constraint_is_recorded_with_its_reason(self, tmp_path) -> None:
        reply = TestRuleRoundTrimsCrossClassCitations()._reply()
        _gate_round(tmp_path, [reply], _classed_analysis())

        artifact = _artifact(tmp_path)
        dropped = artifact["revision_rounds"][-1]["dropped_records"]
        assert [(d["record"], d["constraint_id"]) for d in dropped] == [
            ("security_constraint_addition", "SC-3")
        ]
        assert "H-1" in dropped[0]["error"]
        assert "disclosure" in dropped[0]["error"]
        assert any(
            "dropped" in w and "SC-3" in w and "H-1" in w
            for w in artifact["normalization_warnings"]
        )

    def test_a_span_dropped_addition_is_recorded_by_handle(self, tmp_path) -> None:
        reply = TestRuleRoundDropsUnquotedRecords()._slipping()
        _gate_round(tmp_path, [reply, reply])

        artifact = _artifact(tmp_path)
        dropped = artifact["revision_rounds"][-1]["dropped_records"]
        assert [d["handle"] for d in dropped] == ["slipping"]
        assert BAD_SPAN in dropped[0]["error"]
        assert any(
            "dropped" in w and "slipping" in w
            for w in artifact["normalization_warnings"]
        )

    def test_a_round_that_drops_nothing_records_nothing_dropped(self, tmp_path) -> None:
        clean = _patch(additions=[_addition("fee_rule", FEE_CONSTRAINT, ["H-2"])])
        _, outcome, _ = _gate_round(tmp_path, [clean])

        assert outcome.stated_rule_revision.applied is True
        artifact = _artifact(tmp_path)
        assert "dropped_records" not in artifact["revision_rounds"][-1]
        assert not any("dropped" in w for w in artifact["normalization_warnings"])


class TestRuleRoundRequestCarriesTheCitationInstructions:
    """The rendered stated-rule request tells the model which hazards to cite."""

    CITE = "Cite only a hazard that already serves the constraint's own"
    COPY = "Copy each obligation's `rule_span` from the constraint's `rule`"

    def test_the_rule_round_system_prompt_names_both_instructions(
        self, tmp_path
    ) -> None:
        clean = _patch(additions=[_addition("fee_rule", FEE_CONSTRAINT, ["H-2"])])
        _, _, client = _gate_round(tmp_path, [clean])

        [call] = client.calls
        flat = " ".join(call.system_prompt.split())
        assert self.CITE in flat
        assert "`behavior_class`, or a new hazard added in the same response" in flat
        assert f"{self.COPY} character for character" in flat

    def test_a_density_round_system_prompt_has_neither(self, tmp_path) -> None:
        from tests.stpa.test_stated_rule_coverage import (
            _density_failing_analysis,
            _density_fix,
        )

        client = MockLLMClient()
        client.set_response_for(_Stage1aRevisionPatch, _density_fix())
        _gate(client, tmp_path, _density_failing_analysis(), ())

        [call] = client.calls
        assert self.CITE not in " ".join(call.system_prompt.split())
        assert self.COPY not in " ".join(call.system_prompt.split())


class TestRuleRoundLeavesOtherOwnershipFailuresAlone:
    def test_classes_that_share_a_new_hazard_are_not_trimmed(self, tmp_path) -> None:
        # Neither addition cites a hazard another class owns, so nothing is
        # trimmed and the ownership failure stands.
        reply = _patch(
            hazards=[_hazard("fee_hazard", "The agent quotes an unapproved fee.")],
            additions=[
                _addition(
                    "first",
                    FEE_CONSTRAINT,
                    ["fee_hazard"],
                    behavior_class="wrong_information",
                ),
                _addition(
                    "second",
                    "The agent must not reveal fee internals.",
                    ["fee_hazard"],
                    behavior_class="manipulation",
                ),
            ],
        )

        prior, outcome, _ = _gate_round(tmp_path, [reply], _classed_analysis())

        assert outcome.loss_analysis == prior
        assert "has no hazard of its own" in (outcome.stated_rule_revision.error or "")
        assert "dropped_records" not in _artifact(tmp_path)["revision_rounds"][-1]
