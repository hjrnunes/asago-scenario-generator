"""A graph-revision hazard with a blank description takes the step's correction.

The fixture is the reply that added hazard H-10 with a one-space description
in a recorded OcciAI run; every synthesis ICA prompt then named a hazard
outside its authoritative slice.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from asago_scenario_generator.stpa.infra.llm_helpers import (
    StageError,
    count_requests,
)
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.system_model.loss_analysis_gates import (
    REVISION_CORRECTION_FEEDBACK,
    _RevisionAttempt,
    _run_graph_revision_call,
)
from tests.helpers.calls_log import read_calls_jsonl
from tests.helpers.scripted_client import ScriptedClient, _request_digest

_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "unit_loss"
_PRIOR = json.loads(
    (_FIXTURES / "g2-klarna-r2-graph-revision.json").read_text(encoding="utf-8")
)["prior_loss_analysis"]
_BLANK_ADDITION = json.loads(
    (_FIXTURES / "p-r24-occiai-blank-hazard-revision.json").read_text(encoding="utf-8")
)["hazard_addition"]
_DESCRIPTION = (
    "The assistant discloses one customer's account details to another customer."
)
_ERROR_PHRASE = "a blank or whitespace-only description is not a hazard"
_ERROR_LABEL = "Exact validation error from the prior response:"


def _patch(*, additions=(), edits=()) -> dict:
    return {
        "hazard_edits": list(edits),
        "hazard_additions": list(additions),
        "security_constraint_edits": [],
        "security_constraint_additions": [],
    }


_BLANK = _patch(additions=[_BLANK_ADDITION])
_VALID = _patch(additions=[{**_BLANK_ADDITION, "description": _DESCRIPTION}])


def _call(
    tmp_path: Path,
    replies: list,
    *,
    attempts: list[_RevisionAttempt] | None = None,
    drop_defective_records: bool = False,
    addition_only: bool = False,
):
    client = ScriptedClient(replies)
    revised = _run_graph_revision_call(
        llm_client=client,
        loss_analysis=LossAnalysis.model_validate(_PRIOR),
        use_case_text="A Klarna customer-service assistant.",
        failing_checks=["hazard H-1 has no constraint"],
        run_dir=tmp_path,
        template_loader=TemplateLoader(PROMPTS_DIR),
        temperature=0.4,
        attempts_out=[] if attempts is None else attempts,
        drop_defective_records=drop_defective_records,
        addition_only=addition_only,
    )
    return revised, client


class TestBlankHazardThenValidReply:
    def test_the_revision_succeeds_after_exactly_two_requests(self, tmp_path) -> None:
        with count_requests() as tally:
            revised, client = _call(tmp_path, [_BLANK, _VALID])

        assert tally.requests == 2
        assert len(client.calls) == 2
        added = [h for h in revised.hazards if h.hazard_id not in _prior_hazard_ids()]
        assert [h.description for h in added] == [_DESCRIPTION]
        assert all(h.description.strip() for h in revised.hazards)

    def test_the_correction_carries_the_validation_error(self, tmp_path) -> None:
        _, client = _call(tmp_path, [_BLANK, _VALID])

        first, correction = client.prompts
        assert correction.startswith(first + REVISION_CORRECTION_FEEDBACK)
        error = correction[correction.index(_ERROR_LABEL) :]
        assert "ValueError" in error
        assert "hazard addition NEW-1" in error
        assert _ERROR_PHRASE in error

    def test_the_call_log_records_the_failed_attempt(self, tmp_path) -> None:
        attempts: list[_RevisionAttempt] = []

        _call(tmp_path, [_BLANK, _VALID], attempts=attempts)

        entries = read_calls_jsonl(tmp_path)
        assert [e["success"] for e in entries] == [False, True]
        assert "hazard addition NEW-1" in entries[0]["error"]
        assert [attempt.failed for attempt in attempts] == [True, False]


@pytest.mark.parametrize("description", ["", " ", "\t\n  "])
def test_an_empty_or_whitespace_addition_is_corrected(tmp_path, description) -> None:
    blank = _patch(additions=[{**_BLANK_ADDITION, "description": description}])

    with count_requests() as tally:
        _call(tmp_path, [blank, _VALID])

    assert tally.requests == 2


def test_a_whitespace_hazard_edit_is_corrected_and_names_the_hazard(
    tmp_path,
) -> None:
    edit = {"hazard_id": "H-2", "description": "  ", "related_losses": ["L-3"]}

    with count_requests() as tally:
        revised, client = _call(tmp_path, [_patch(edits=[edit]), _VALID])

    assert tally.requests == 2
    error = client.prompts[1][client.prompts[1].index(_ERROR_LABEL) :]
    assert "hazard edit H-2" in error
    prior = {h.hazard_id: h for h in LossAnalysis.model_validate(_PRIOR).hazards}
    kept = {h.hazard_id: h for h in revised.hazards}
    assert kept["H-2"].description == prior["H-2"].description


class TestBothRepliesBlank:
    @pytest.mark.parametrize("drop_defective_records", [False, True])
    @pytest.mark.parametrize("addition_only", [False, True])
    def test_the_step_ends_after_exactly_two_requests(
        self, tmp_path, drop_defective_records, addition_only
    ) -> None:
        replies = [_BLANK, _BLANK, _VALID]
        with count_requests() as tally, pytest.raises(StageError) as raised:
            _call(
                tmp_path,
                replies,
                drop_defective_records=drop_defective_records,
                addition_only=addition_only,
            )

        message = str(raised.value)
        assert tally.requests == 2
        assert message.startswith(
            "stage_1a/hazard_graph_revision: graph revision call failed: ValueError"
        )
        assert "hazard addition NEW-1" in message
        assert [e["success"] for e in read_calls_jsonl(tmp_path)] == [False, False]


# The first request of ``_call`` as the current revision prompt sends it: the same digest
# pins the first request in test_graph_revision_undecodable_reply.py.
_FIRST_REQUEST_DIGEST = (
    "7f95b8e0f4dbb07d6273bbcfdf07ae4d362ed83674559f881a896ea2784c1e6b"
)


def test_a_valid_hazard_addition_sends_one_request_with_unchanged_bytes(
    tmp_path,
) -> None:
    with count_requests() as tally:
        revised, client = _call(tmp_path, [_VALID, _VALID])

    assert tally.requests == 1
    assert len(client.calls) == 1
    assert _request_digest(client.calls[0]) == _FIRST_REQUEST_DIGEST
    assert _DESCRIPTION in [h.description for h in revised.hazards]


def _prior_hazard_ids() -> set[str]:
    return {h.hazard_id for h in LossAnalysis.model_validate(_PRIOR).hazards}
