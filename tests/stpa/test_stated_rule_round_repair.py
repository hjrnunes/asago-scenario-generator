"""Stated-rule revision rounds that fail only on structure or rule_span.

The round keeps what is valid: a record whose ``rule_span`` is not in its
rule is dropped, a new hazard only that record cited goes with it, and an
added constraint that takes over a hazard another behavior class owns alone is
trimmed.  Each drop is recorded.  The replies below follow the recorded
patterns: out-of-rule spans with an orphaned new hazard, an add-only edit
beside a slip, and a cross-class citation.
"""

from __future__ import annotations


from asago_scenario_generator.stpa.infra.templates import TemplateLoader
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
