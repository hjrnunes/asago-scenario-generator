"""A blank ``applies_when`` entry drops its record, like an unquoted span.

When the final graph-revision response still fails validation, the round
drops each constraint edit or addition that carries a blank ``applies_when``
entry or an obligation span no repair maps onto its rule, records each drop
with its reason, and keeps the prior constraint for a dropped edit.  A blank
entry is never rewritten to an empty list, because an empty list on an edit
would delete the prior conditions.  The fixture is the trimmed G2 klarna-r2
revision (b8-glm batch): both replies edit SC-1 with ``applies_when: [""]``
and add NEW-2 with a span that reads "or" where the rule reads "and".
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.system_model.loss_analysis import (
    _Stage1aRevisionPatch,
)
from asago_scenario_generator.stpa.system_model.loss_analysis_gates import (
    _run_graph_revision_call,
)
from asago_scenario_generator.stpa.infra.llm_helpers import StageError
from tests.stpa.sp1_helpers import MockLLMClient

_FIXTURE = json.loads(
    (
        Path(__file__).resolve().parents[1]
        / "fixtures"
        / "unit_loss"
        / "g2-klarna-r2-graph-revision.json"
    ).read_text(encoding="utf-8")
)
_BLANK_ERROR = (
    "applies_when entries must be non-empty condition sentences: entry 1 is ''."
)
_NEW_2_RULE = (
    "The assistant must only invoke `process_refund` or `schedule_payment` with "
    "parameters that match the authenticated user's legitimate intent and "
    "eligibility."
)


def _prior() -> LossAnalysis:
    return LossAnalysis.model_validate(_FIXTURE["prior_loss_analysis"])


def _attempt(index: int) -> dict:
    return json.loads(json.dumps(_FIXTURE["revision_attempts"][index]))


def _call(tmp_path: Path, replies: list[dict], prior: LossAnalysis | None = None):
    client = MockLLMClient()
    client.set_response_for(_Stage1aRevisionPatch, replies)
    attempts: list = []
    revised = _run_graph_revision_call(
        llm_client=client,
        loss_analysis=prior or _prior(),
        use_case_text="A Klarna customer-service assistant.",
        failing_checks=["hazard H-1 has no constraint"],
        run_dir=tmp_path,
        template_loader=TemplateLoader(PROMPTS_DIR),
        temperature=0.4,
        attempts_out=attempts,
        drop_defective_records=True,
    )
    return revised, attempts, client


def _constraints(analysis: LossAnalysis) -> dict:
    return {item.constraint_id: item for item in analysis.security_constraints}


def _kept_fields(constraint) -> dict:
    """The authored fields a dropped edit must leave as the prior graph has them."""
    return constraint.model_dump(
        include={"rule", "applies_when", "related_hazards", "obligations"}
    )


class TestRecordedRevision:
    """The G2 klarna-r2 revision keeps everything but SC-1's edit and NEW-2."""

    def test_both_defective_records_are_dropped_and_the_rest_applied(
        self, tmp_path
    ) -> None:
        prior = _prior()

        revised, attempts, client = _call(tmp_path, [_attempt(0), _attempt(1)], prior)

        assert len(client.calls) == 2
        assert _kept_fields(_constraints(revised)["SC-1"]) == _kept_fields(
            _constraints(prior)["SC-1"]
        )
        rules = [item.rule for item in revised.security_constraints]
        assert _NEW_2_RULE not in rules
        assert (
            "The assistant must not include protected works in its conversational "
            "output." in rules
        )
        assert len(revised.hazards) == len(prior.hazards) + 1
        dropped = attempts[-1].dropped
        assert [
            (d["record"], d.get("handle") or d["constraint_id"]) for d in dropped
        ] == [
            ("security_constraint_addition", "NEW-2"),
            ("security_constraint_edit", "SC-1"),
        ]
        assert (
            "match the authenticated user's legitimate intent or eligibility"
            in (dropped[0]["error"])
        )
        assert dropped[1]["error"] == _BLANK_ERROR


def _blank_edit_only() -> dict:
    """The recorded second reply with NEW-2's span quoted as its rule has it."""
    reply = _attempt(1)
    reply["security_constraint_additions"][1]["obligations"][0]["rule_span"] = (
        "match the authenticated user's legitimate intent and eligibility"
    )
    return reply


class TestBlankEntryOnly:
    """A blank entry alone drops its edit; the prior constraint stays."""

    def test_the_blank_edit_is_dropped_and_every_addition_kept(self, tmp_path) -> None:
        prior = _prior()

        revised, attempts, _ = _call(
            tmp_path, [_blank_edit_only(), _blank_edit_only()], prior
        )

        assert _constraints(revised)["SC-1"].applies_when == list(
            _constraints(prior)["SC-1"].applies_when
        )
        assert _NEW_2_RULE in [item.rule for item in revised.security_constraints]
        assert attempts[-1].dropped == [
            {
                "record": "security_constraint_edit",
                "constraint_id": "SC-1",
                "error": _BLANK_ERROR,
            }
        ]

    def test_a_blank_entry_on_an_addition_drops_that_addition(self, tmp_path) -> None:
        reply = _blank_edit_only()
        reply["security_constraint_edits"] = []
        reply["security_constraint_additions"][2]["applies_when"] = ["  "]

        revised, attempts, _ = _call(tmp_path, [reply, reply])

        assert attempts[-1].dropped == [
            {
                "record": "security_constraint_addition",
                "handle": "NEW-3",
                "error": (
                    "applies_when entries must be non-empty condition sentences: "
                    "entry 1 is '  '."
                ),
            }
        ]
        assert _NEW_2_RULE in [item.rule for item in revised.security_constraints]


class TestNothingLeft:
    """Dropping every record still stops the round."""

    def test_a_patch_left_empty_still_stops(self, tmp_path) -> None:
        reply = {
            "hazard_edits": [],
            "hazard_additions": [],
            "security_constraint_edits": _attempt(1)["security_constraint_edits"],
            "security_constraint_additions": [],
        }

        with pytest.raises(StageError, match="graph revision call failed"):
            _call(tmp_path, [reply, reply])
