"""An undecodable reply earns the call's one correction in Stage 1b and Stage 2.

A reply that stops before its JSON object is complete (a completion cap, or
a whitespace runaway) used to end the Stage 1b draw outright, end a Stage 2
call after its one repeat, and discard the critic findings or the revision.
Each of those calls now sends its one correction for such a reply: the
correction names the call's reply, carries the exact decode error, and asks
for the complete object again.  No call sends more requests than before:

- Stage 1b: at most two requests per draw, as before.
- Stage 2 Calls 1, 2a, 2b and 3: the repeat of an undecodable reply stays;
  a second undecodable reply takes the one correction, so the shared policy
  sends at most three requests, as before.  Call 2b may then add its one
  missing-action repair or reference correction, so it can reach four
  requests, before and after this change.
- Critic and revision: at most two requests, as before.

A reply with an extra field that the reply model rejects already takes the
same one correction, which names the field.  Stage 1b and Call 1 ignore an
extra field, so such a reply succeeds in one request.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from asago_scenario_generator.stpa.infra.llm_helpers import (
    StageError,
    count_requests,
)
from asago_scenario_generator.stpa.infra.provider_record import ProviderCallSession
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlStructure,
    ElementRef,
    FeedbackChannel,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
)
from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.system_model.control_structure import (
    _INTERMEDIATE_VALIDATION_RETRY_FEEDBACK,
    ControlElementSet,
    CoordinationAnalysis,
    RequirementSet,
    ResponsibilitySet,
    _call_2b_control_elements,
    _CoordinationProviderEnvelope,
    _MissingActionProviderSet,
)
from asago_scenario_generator.stpa.system_model.critic import (
    _CRITIC_VALIDATION_FEEDBACK,
    _REVISION_VALIDATION_FEEDBACK,
    CriticFindings,
    run_completeness_critic,
    run_revision,
)
from asago_scenario_generator.stpa.system_model.profile import (
    derive_capability_profile,
)
from tests.helpers.calls_log import read_calls_jsonl
from tests.helpers.provider_call_record import (
    _client,
    _completion,
    _Provider,
    _records,
)
from tests.helpers.sp1_control_structure import _responsibilities
from tests.helpers.stpa_builders import make_capability_profile
from tests.stpa.sp1_helpers import (
    MockLLMClient,
    run_sp1_default,
    setup_sp1_mock_client,
    valid_control_element_set_dict,
    valid_critic_findings_dict_no_gaps,
    valid_empty_coordination_analysis_dict,
    valid_requirement_set_dict,
    valid_responsibility_set_dict,
    valid_stage1_profile_dict,
)

_LOADER = TemplateLoader(PROMPTS_DIR)
# A reply cut off inside its first record, then a whitespace runaway.
_UNDECODABLE = '{"items": [{"name": "first"' + "\n" * 12 + "   "
_DECODE_ERROR = "JSONDecodeError at line 1, column 28: Expecting ',' delimiter"
_ERROR_LABEL = "Exact validation error from the prior response:"
_PRIOR_LABEL = "Prior structured response to correct in place:"


def _instruction(reply_name: str) -> str:
    return _LOADER.render_prompt(
        "undecodable_reply_correction.j2", reply_name=reply_name
    )


def _with_extra_field(reply: dict[str, Any]) -> dict[str, Any]:
    return {**reply, "note": ""}


def _assert_attempt_chain(entries: list[dict[str, Any]]) -> None:
    """Each attempt continues the step's numbering and names the one before."""
    assert [entry["attempt_number"] for entry in entries] == list(
        range(1, len(entries) + 1)
    )
    assert "retry_of" not in entries[0]
    for prior, entry in zip(entries, entries[1:]):
        assert entry["retry_of"] == prior["attempt_id"]


# ---------------------------------------------------------------------------
# Recorded provider: every request leaves a provider-calls.jsonl record
# ---------------------------------------------------------------------------


def _recorded_client(run_dir: Path, *replies: str) -> tuple[Any, _Provider]:
    queue = list(replies)
    provider = _Provider(lambda **_: _completion(queue.pop(0)))
    client = _client(provider, session=ProviderCallSession(record_dir=run_dir))
    return client, provider


def _user_prompts(provider: _Provider) -> list[str]:
    return [
        next(m["content"] for m in request["messages"] if m["role"] == "user")
        for request in provider.requests
    ]


def _assert_recorded(run_dir: Path, step: str, successes: list[bool]) -> None:
    """calls.jsonl and provider-calls.jsonl hold every attempt of *step*."""
    entries = [e for e in read_calls_jsonl(run_dir) if e["step"] == step]
    records = [r for r in _records(run_dir) if r["identity"]["step"] == step]
    assert [entry["success"] for entry in entries] == successes
    _assert_attempt_chain(entries)
    assert [r["identity"]["attempt_number"] for r in records] == list(
        range(1, len(successes) + 1)
    )
    assert [entry["provider_requests"] for entry in entries] == [
        [{"sequence": r["sequence"], "request_sha256": r["request_sha256"]}]
        for r in records
    ]


# ---------------------------------------------------------------------------
# Stage 1b capability profile
# ---------------------------------------------------------------------------

_PROFILE = json.dumps(valid_stage1_profile_dict())


def _derive_profile(run_dir: Path, *replies: str) -> _Provider:
    client, provider = _recorded_client(run_dir, *replies)
    derive_capability_profile(
        llm_client=client, use_case_text="Test use case", run_dir=run_dir
    )
    return provider


class TestStage1bCapabilityProfile:
    def test_an_undecodable_reply_earns_one_correction(self, tmp_path) -> None:
        with count_requests() as tally:
            provider = _derive_profile(tmp_path, _UNDECODABLE, _PROFILE)

        assert tally.requests == 2
        first, correction = _user_prompts(provider)
        assert correction.startswith(
            first + "\n\n" + _instruction("capability profile")
        )
        assert (
            f"{_PRIOR_LABEL}\n```json\n{_UNDECODABLE.rstrip()}\n```\n\n"
            f"{_ERROR_LABEL}\n{_DECODE_ERROR}"
        ) in correction
        _assert_recorded(tmp_path, "capability_profile", [False, True])

    def test_an_extra_field_is_ignored_in_one_request(self, tmp_path) -> None:
        reply = json.dumps(_with_extra_field(valid_stage1_profile_dict()))

        with count_requests() as tally:
            _derive_profile(tmp_path, reply, _PROFILE)

        assert tally.requests == 1
        _assert_recorded(tmp_path, "capability_profile", [True])

    def test_a_reply_the_schema_rejects_keeps_its_correction_wording(
        self, tmp_path
    ) -> None:
        rejected = json.dumps({**valid_stage1_profile_dict(), "entry_points": []})

        provider = _derive_profile(tmp_path, rejected, _PROFILE)

        first, correction = _user_prompts(provider)
        assert correction.startswith(f"{first}\n\n{_PRIOR_LABEL}\n```json\n")
        assert "did not decode as JSON" not in correction
        _assert_recorded(tmp_path, "capability_profile", [False, True])

    def test_a_second_failure_ends_the_draw(self, tmp_path) -> None:
        with count_requests() as tally, pytest.raises(StageError) as raised:
            _derive_profile(tmp_path, _UNDECODABLE, _UNDECODABLE, _PROFILE)

        assert tally.requests == 2
        assert "JSONDecodeError" in str(raised.value)
        _assert_recorded(tmp_path, "capability_profile", [False, False])


# ---------------------------------------------------------------------------
# Stage 2 Calls 1, 2a, 2b and 3
# ---------------------------------------------------------------------------

_STAGE2_CALLS = [
    pytest.param(
        (RequirementSet,),
        valid_requirement_set_dict(),
        "call_1_requirements",
        "requirement set",
        None,
        id="call-1",
    ),
    pytest.param(
        (ResponsibilitySet,),
        valid_responsibility_set_dict(),
        "call_2a_responsibilities",
        "responsibility set",
        "note: Extra inputs are not permitted (extra_forbidden)",
        id="call-2a",
    ),
    pytest.param(
        (ControlElementSet,),
        valid_control_element_set_dict(),
        "call_2b_control_elements",
        "control element set",
        "note: Extra inputs are not permitted (extra_forbidden)",
        id="call-2b",
    ),
    pytest.param(
        (CoordinationAnalysis, _CoordinationProviderEnvelope),
        valid_empty_coordination_analysis_dict(constraint_ids=("SC-1", "SC-2")),
        "call_3_coordination",
        "coordination review",
        "code-owned or unknown fields: note",
        id="call-3",
    ),
]


def _run_stage2(
    run_dir: Path, reply_types: tuple[type, ...], replies: list[Any]
) -> tuple[Any, MockLLMClient]:
    client = setup_sp1_mock_client()
    for reply_type in reply_types:
        client.set_response_for(reply_type, list(replies))
    return run_sp1_default(client, run_dir), client


def _stage2_attempts(
    run_dir: Path, client: MockLLMClient, step: str
) -> list[dict[str, Any]]:
    entries = read_calls_jsonl(run_dir)
    # Every request the client received has its own call-log entry.
    assert len(entries) == client.call_count
    attempts = [entry for entry in entries if entry["step"] == step]
    _assert_attempt_chain(attempts)
    return attempts


@pytest.mark.parametrize(
    ("reply_types", "valid", "step", "reply_name", "extra_error"), _STAGE2_CALLS
)
class TestStage2Calls:
    def test_one_undecodable_reply_is_repeated_unchanged(
        self, tmp_path, reply_types, valid, step, reply_name, extra_error
    ) -> None:
        result, client = _run_stage2(tmp_path, reply_types, [_UNDECODABLE, valid])

        attempts = _stage2_attempts(tmp_path, client, step)
        assert result.control_structure is not None
        assert [entry["success"] for entry in attempts] == [False, True]
        first, repeat = (entry["user_prompt_text"] for entry in attempts)
        assert repeat == first

    def test_a_second_undecodable_reply_earns_one_correction(
        self, tmp_path, reply_types, valid, step, reply_name, extra_error
    ) -> None:
        result, client = _run_stage2(
            tmp_path, reply_types, [_UNDECODABLE, _UNDECODABLE, valid]
        )

        attempts = _stage2_attempts(tmp_path, client, step)
        assert result.control_structure is not None
        assert result.stage_errors == []
        assert [entry["success"] for entry in attempts] == [False, False, True]
        first, _, correction = (entry["user_prompt_text"] for entry in attempts)
        suffix = correction[len(first) :]
        assert correction.startswith(first)
        assert suffix.startswith("\n\n" + _instruction(reply_name))
        assert (
            f"{_PRIOR_LABEL}\n```json\n{_UNDECODABLE.rstrip()}\n```\n\n"
            f"{_ERROR_LABEL}\n{_DECODE_ERROR}"
        ) in suffix
        assert _INTERMEDIATE_VALIDATION_RETRY_FEEDBACK not in suffix

    def test_a_third_undecodable_reply_ends_the_unit(
        self, tmp_path, reply_types, valid, step, reply_name, extra_error
    ) -> None:
        result, client = _run_stage2(
            tmp_path, reply_types, [_UNDECODABLE, _UNDECODABLE, _UNDECODABLE, valid]
        )

        attempts = _stage2_attempts(tmp_path, client, step)
        assert result.control_structure is None
        assert [entry["success"] for entry in attempts] == [False] * 3
        assert len(result.stage_errors) == 1
        assert result.stage_errors[0].startswith(f"stage_2/{step}: JSONDecodeError")

    def test_an_extra_field_reply_earns_one_correction(
        self, tmp_path, reply_types, valid, step, reply_name, extra_error
    ) -> None:
        result, client = _run_stage2(
            tmp_path, reply_types, [_with_extra_field(valid), valid]
        )

        attempts = _stage2_attempts(tmp_path, client, step)
        assert result.control_structure is not None
        if extra_error is None:
            # Call 1 ignores a field outside its reply model.
            assert [entry["success"] for entry in attempts] == [True]
            return
        assert [entry["success"] for entry in attempts] == [False, True]
        first, correction = (entry["user_prompt_text"] for entry in attempts)
        suffix = correction[len(first) :]
        assert suffix.startswith(_INTERMEDIATE_VALIDATION_RETRY_FEEDBACK)
        assert extra_error in suffix
        assert "did not decode as JSON" not in suffix

    def test_a_second_extra_field_reply_ends_the_unit(
        self, tmp_path, reply_types, valid, step, reply_name, extra_error
    ) -> None:
        if extra_error is None:
            pytest.skip("Call 1 ignores a field outside its reply model")
        extra = _with_extra_field(valid)

        result, client = _run_stage2(tmp_path, reply_types, [extra, extra, valid])

        attempts = _stage2_attempts(tmp_path, client, step)
        assert result.control_structure is None
        assert [entry["success"] for entry in attempts] == [False, False]
        assert result.stage_errors[0].startswith(f"stage_2/{step}: ")

    def test_an_undecodable_correction_spends_the_one_correction(
        self, tmp_path, reply_types, valid, step, reply_name, extra_error
    ) -> None:
        if extra_error is None:
            pytest.skip("Call 1 ignores a field outside its reply model")

        result, client = _run_stage2(
            tmp_path,
            reply_types,
            [_UNDECODABLE, _UNDECODABLE, _with_extra_field(valid), valid],
        )

        attempts = _stage2_attempts(tmp_path, client, step)
        assert result.control_structure is None
        assert [entry["success"] for entry in attempts] == [False] * 3


# ---------------------------------------------------------------------------
# Call 2b: the undecodable correction and the missing control action repair
# ---------------------------------------------------------------------------


def _action(number: int) -> dict[str, Any]:
    return {
        "ca_id": f"CA-{number}-1",
        "description": f"Deliver the result of responsibility {number}",
        "target": {"type": "controlled_process", "id": "CP-1"},
        "effect_kind": "model_output",
        "temporality": "discrete",
        "operation": None,
        "process_model_refs": [f"PM-{number}-1"],
    }


def _call_2b_reply(*owners: int) -> dict[str, Any]:
    return {
        "control_actions": [_action(number) for number in owners],
        "feedback": [
            {
                "fb_id": f"FB-{number}-1",
                "description": f"Report the state of responsibility {number}",
                "updates": f"PM-{number}-1",
                "source": {"type": "controlled_process", "id": "CP-1"},
                "source_kind": "operation_result",
            }
            for number in (1, 2, 3)
        ],
        "controlled_processes": [{"cp_id": "CP-1", "description": "Caller interface"}],
    }


def _run_call_2b(run_dir: Path, *replies: Any) -> tuple[Any, MockLLMClient]:
    client = MockLLMClient()
    client.set_response_queue(list(replies))
    parsed = _call_2b_control_elements(
        llm_client=client,
        use_case_text="Test use case",
        responsibility_set=ResponsibilitySet(responsibilities=_responsibilities()),
        run_dir=run_dir,
        loader=_LOADER,
        temperature=0.4,
    )
    return parsed, client


class TestCall2bCorrectionsShareTheBudget:
    def test_a_corrected_reply_missing_an_owner_earns_the_repair(
        self, tmp_path
    ) -> None:
        with count_requests() as tally:
            parsed, client = _run_call_2b(
                tmp_path,
                _UNDECODABLE,
                _UNDECODABLE,
                _call_2b_reply(1, 2),
                {"control_actions": [_action(3)]},
            )

        assert tally.requests == 4
        assert sorted(action.ca_id for action in parsed.control_actions) == [
            "CA-1-1",
            "CA-2-1",
            "CA-3-1",
        ]
        assert "did not decode as JSON" in client.calls[2].user_prompt
        assert client.calls[3].response_format is _MissingActionProviderSet
        assert "did not decode as JSON" not in client.calls[3].user_prompt
        attempts = [
            e
            for e in read_calls_jsonl(tmp_path)
            if e["step"] == "call_2b_control_elements"
        ]
        assert [entry["success"] for entry in attempts] == [False, False, False, True]
        assert [entry["attempt_number"] for entry in attempts] == [1, 2, 3, 4]

    def test_a_failed_repair_still_ends_the_unit(self, tmp_path) -> None:
        with count_requests() as tally, pytest.raises(StageError) as raised:
            _run_call_2b(
                tmp_path,
                _UNDECODABLE,
                _UNDECODABLE,
                _call_2b_reply(1, 2),
                {"control_actions": []},
            )

        assert tally.requests == 4
        assert "missing control action repair failed" in str(raised.value)


# ---------------------------------------------------------------------------
# Completeness critic
# ---------------------------------------------------------------------------

_FINDINGS = json.dumps(valid_critic_findings_dict_no_gaps())
_PROCESS = ElementRef(type=ReferenceType.controlled_process, id="CP-1")


def _structure() -> ControlStructure:
    return ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="Issue approved refunds",
                process_model_parts=[
                    ProcessModelPart(
                        pm_id="PM-1-1", description="Refund approval state"
                    ),
                    ProcessModelPart(pm_id="PM-1-2", description="Refund amount"),
                ],
                control_actions=[
                    ControlAction(
                        ca_id="CA-1-1", description="Issue a refund", target=_PROCESS
                    )
                ],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-1-1",
                        description=(
                            "The requester's statement that the refund was approved"
                        ),
                        updates="PM-1-1",
                        source=_PROCESS,
                    )
                ],
            )
        ],
        controlled_processes=[{"cp_id": "CP-1", "description": "Refund ledger"}],
    )


def _critic(run_dir: Path, *replies: str) -> tuple[CriticFindings, _Provider]:
    client, provider = _recorded_client(run_dir, *replies)
    findings = run_completeness_critic(
        llm_client=client,
        control_structure=_structure(),
        capability_profile=make_capability_profile(),
        use_case_text="Test use case",
        run_dir=run_dir,
    )
    return findings, provider


class TestCompletenessCritic:
    def test_an_undecodable_reply_earns_one_correction(self, tmp_path) -> None:
        with count_requests() as tally:
            findings, provider = _critic(tmp_path, _UNDECODABLE, _FINDINGS)

        assert tally.requests == 2
        assert findings == CriticFindings.model_validate_json(_FINDINGS)
        first, correction = _user_prompts(provider)
        assert correction == (
            f"{first}\n\n{_instruction('critic findings')}\n\n"
            f"{_ERROR_LABEL}\n{_DECODE_ERROR}\n\n"
            "Return one JSON object matching the response schema already supplied."
        )
        _assert_recorded(tmp_path, "critic", [False, True])

    def test_an_extra_field_reply_earns_one_correction(self, tmp_path) -> None:
        extra = json.dumps(_with_extra_field(valid_critic_findings_dict_no_gaps()))

        with count_requests() as tally:
            findings, provider = _critic(tmp_path, extra, _FINDINGS)

        assert tally.requests == 2
        assert findings == CriticFindings.model_validate_json(_FINDINGS)
        first, correction = _user_prompts(provider)
        assert correction.startswith(first + _CRITIC_VALIDATION_FEEDBACK)
        assert "- note: Extra inputs are not permitted (extra_forbidden)" in correction
        _assert_recorded(tmp_path, "critic", [False, True])

    def test_a_second_failure_ends_the_critic(self, tmp_path) -> None:
        with count_requests() as tally:
            findings, _ = _critic(tmp_path, _UNDECODABLE, _UNDECODABLE, _FINDINGS)

        assert tally.requests == 2
        assert findings == CriticFindings()
        _assert_recorded(tmp_path, "critic", [False, False])


# ---------------------------------------------------------------------------
# Revision, and its authority correction
# ---------------------------------------------------------------------------

_GAP_FINDINGS = CriticFindings(
    gaps=[
        {
            "gap_type": "missing_feedback",
            "description": "Refund approval comes only from the requester",
            "related_attack_path": "A requester claims an approval",
            "suggested_remedy": "Assess the approval feedback",
        }
    ]
)
_NO_CHANGE = {
    "new_responsibilities": [],
    "new_controlled_processes": [],
    "new_coordination_links": [],
    "modified_responsibilities": [],
    "dismissed_gaps": ["Refund approval comes only from the requester"],
}
_RESTATED_BASIS = "user input is unverified"
_RESTATED_REASON = (
    "feedback channel FB-1-1 authority basis only restates source kind "
    "'user_message'; state why that source may or may not establish this "
    "value and cite supplied evidence"
)


def _unsupported_authority_revision() -> dict[str, Any]:
    """A revision that restates FB-1-1 with a basis the checks reject."""
    return {
        **_NO_CHANGE,
        "dismissed_gaps": [],
        "modified_responsibilities": [
            {
                "resp_id": "RESP-1",
                "description": "Issue approved refunds",
                "process_model_parts": [
                    {"pm_id": "PM-1-1", "description": "Refund approval state"},
                    {"pm_id": "PM-1-2", "description": "Refund amount"},
                ],
                "control_actions": [
                    {
                        "ca_id": "CA-1-1",
                        "description": "Issue a refund",
                        "target": {"type": "controlled_process", "id": "CP-1"},
                    }
                ],
                "feedback_channels": [
                    {
                        "fb_id": "FB-1-1",
                        "description": (
                            "The requester's statement that the refund was approved"
                        ),
                        "updates": "PM-1-1",
                        "source": {"type": "controlled_process", "id": "CP-1"},
                        "source_kind": "user_message",
                        "authority_for_update": {
                            "status": "non_authoritative",
                            "basis": _RESTATED_BASIS,
                        },
                    }
                ],
            }
        ],
    }


def _revise(
    run_dir: Path, *replies: str
) -> tuple[ControlStructure, list[str], _Provider]:
    client, provider = _recorded_client(run_dir, *replies)
    revised, warnings = run_revision(
        llm_client=client,
        control_structure=_structure(),
        critic_findings=_GAP_FINDINGS,
        use_case_text="A refund assistant issues refunds the finance reviewer approved.",
        run_dir=run_dir,
    )
    return revised, warnings, provider


def _failed(warnings: list[str]) -> bool:
    return any(warning.startswith("Revision failed") for warning in warnings)


class TestRevision:
    def test_an_undecodable_reply_earns_one_correction(self, tmp_path) -> None:
        with count_requests() as tally:
            _, warnings, provider = _revise(
                tmp_path, _UNDECODABLE, json.dumps(_NO_CHANGE)
            )

        assert tally.requests == 2
        assert not _failed(warnings)
        first, correction = _user_prompts(provider)
        assert correction == (
            f"{first}\n\n{_instruction('revision delta')}\n\n"
            f"{_PRIOR_LABEL}\n```json\n{_UNDECODABLE.rstrip()}\n```\n\n"
            f"{_ERROR_LABEL}\n{_DECODE_ERROR}\n\n"
            "Return one JSON object matching the response schema already supplied."
        )
        _assert_recorded(tmp_path, "revision", [False, True])

    def test_an_extra_field_reply_earns_one_correction(self, tmp_path) -> None:
        extra = json.dumps(_with_extra_field(_NO_CHANGE))

        with count_requests() as tally:
            _, warnings, provider = _revise(tmp_path, extra, json.dumps(_NO_CHANGE))

        assert tally.requests == 2
        assert not _failed(warnings)
        first, correction = _user_prompts(provider)
        assert correction.startswith(first + _REVISION_VALIDATION_FEEDBACK)
        assert "- note: Extra inputs are not permitted (extra_forbidden)" in correction
        assert "did not decode as JSON" not in correction
        _assert_recorded(tmp_path, "revision", [False, True])

    def test_a_second_failure_discards_the_revision(self, tmp_path) -> None:
        with count_requests() as tally:
            revised, warnings, _ = _revise(
                tmp_path, _UNDECODABLE, _UNDECODABLE, json.dumps(_NO_CHANGE)
            )

        assert tally.requests == 2
        assert revised == _structure()
        assert warnings[0].startswith("Revision failed: JSONDecodeError")
        _assert_recorded(tmp_path, "revision", [False, False])

    def test_an_undecodable_correction_leaves_no_authority_correction(
        self, tmp_path
    ) -> None:
        with count_requests() as tally:
            revised, warnings, _ = _revise(
                tmp_path,
                _UNDECODABLE,
                json.dumps(_unsupported_authority_revision()),
                json.dumps(_NO_CHANGE),
            )

        # The correction is spent, so the failing basis is dropped, unsent.
        assert tally.requests == 2
        [channel] = revised.responsibilities[0].feedback_channels
        assert channel.authority_for_update is None
        assert warnings[0] == (
            "Revision dropped the authority_for_update of feedback channel "
            f"FB-1-1: {_RESTATED_REASON}"
        )
        _assert_recorded(tmp_path, "revision", [False, False])

    def test_an_authority_correction_leaves_no_undecodable_correction(
        self, tmp_path
    ) -> None:
        with count_requests() as tally:
            revised, warnings, provider = _revise(
                tmp_path,
                json.dumps(_unsupported_authority_revision()),
                _UNDECODABLE,
                json.dumps(_NO_CHANGE),
            )

        assert tally.requests == 2
        assert "did not decode as JSON" not in _user_prompts(provider)[1]
        assert revised == _structure()
        assert warnings[0].startswith("Revision failed: JSONDecodeError")
        _assert_recorded(tmp_path, "revision", [False, False])
