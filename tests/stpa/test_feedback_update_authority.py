"""A feedback channel records whether it may establish the variable it updates.

``authority_for_update`` assesses the channel's ``updates`` relation: a status
and the basis that cites the supplied evidence.  It is optional, a missing
assessment means unknown, and an unset field stays out of the dump so a
structure written before the field existed keeps its bytes.  The assessment
is never derived from ``source_kind`` and does not change ``untrusted``.

Stage 2 Call 2b and the revision accept the field on their wires, the
critic and revision requests show it beside the channel, and a revision that
omits it keeps the earlier assessment while the channel updates the same
variable.  Requests go through the real client with a mocked transport, or
the SP1 mock client; no request leaves the process.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest
import yaml
from pydantic import ValidationError

from asago_scenario_generator.stpa.infra.llm import LLMClient
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.models.control_structure import (
    UNKNOWN_UPDATE_AUTHORITY,
    ControlAction,
    ControlStructure,
    ElementRef,
    FeedbackAuthorityStatus,
    FeedbackChannel,
    FeedbackSourceKind,
    FeedbackUpdateAuthority,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
)
from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.system_model.control_structure import (
    ResponsibilitySet,
    _call_2b_control_elements,
)
from asago_scenario_generator.stpa.system_model.critic import (
    CriticFindings,
    _revised_responsibility,
    _RevisionDeltaProviderSet,
    run_completeness_critic,
    run_revision,
)
from tests.helpers.stpa_builders import make_capability_profile
from tests.stpa.sp1_helpers import MockLLMClient, valid_critic_findings_dict_no_gaps

_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
# A control structure saved before the field existed, and the SHA-256 of its
# JSON dump as the code before the field produced it.
_SAVED_STRUCTURE = (
    _FIXTURES / "generate_report" / "miniklarna-1" / "control-structure.yaml"
)
_SAVED_STRUCTURE_DUMP_SHA256 = (
    "c021b5fc84bf5f74210bd1b187a41194de1d93f8df5fab6c754661d7784a5f61"
)

_BASIS = (
    "The use case says the finance reviewer decides refund approvals; the "
    "requester can only report that one was given."
)
_NON_AUTHORITATIVE = FeedbackUpdateAuthority(
    status=FeedbackAuthorityStatus.non_authoritative, basis=_BASIS
)
_PROCESS = ElementRef(type=ReferenceType.controlled_process, id="CP-1")


def _channel(**fields: Any) -> FeedbackChannel:
    return FeedbackChannel(
        fb_id="FB-1-1",
        description="The requester's statement that the refund was approved",
        updates="PM-1-1",
        source=_PROCESS,
        **fields,
    )


def _responsibility(*channels: FeedbackChannel) -> Responsibility:
    return Responsibility(
        resp_id="RESP-1",
        description="Issue approved refunds",
        process_model_parts=[
            ProcessModelPart(pm_id="PM-1-1", description="Refund approval state"),
            ProcessModelPart(pm_id="PM-1-2", description="Refund amount"),
        ],
        control_actions=[
            ControlAction(ca_id="CA-1-1", description="Issue a refund", target=_PROCESS)
        ],
        feedback_channels=list(channels),
    )


# ---------------------------------------------------------------------------
# The model
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "status",
    [
        FeedbackAuthorityStatus.authoritative,
        FeedbackAuthorityStatus.non_authoritative,
        FeedbackAuthorityStatus.conditional,
    ],
)
def test_a_settled_status_requires_a_basis(status: FeedbackAuthorityStatus) -> None:
    with pytest.raises(ValidationError, match="requires a basis"):
        FeedbackUpdateAuthority(status=status)


def test_an_unknown_status_needs_no_basis_and_may_name_what_is_open() -> None:
    assert FeedbackUpdateAuthority(status="unknown").basis is None
    open_question = FeedbackUpdateAuthority(
        status="unknown", basis="The use case does not say who approves refunds."
    )
    assert open_question.basis == "The use case does not say who approves refunds."


@pytest.mark.parametrize(
    "value",
    [
        {"status": "authoritative", "basis": "   "},
        {"status": "trusted", "basis": _BASIS},
        {"status": "unknown", "notes": "keep"},
    ],
    ids=["blank-basis", "unknown-status", "extra-field"],
)
def test_the_assessment_rejects_a_malformed_value(value: dict[str, str]) -> None:
    with pytest.raises(ValidationError):
        FeedbackUpdateAuthority.model_validate(value)


def test_a_channel_without_the_field_is_unknown() -> None:
    channel = _channel()

    assert channel.authority_for_update is None
    assert channel.update_authority == UNKNOWN_UPDATE_AUTHORITY
    assert channel.update_authority.status is FeedbackAuthorityStatus.unknown


def test_an_unset_field_stays_out_of_the_dump() -> None:
    dumped = _channel().model_dump(mode="json")

    assert "authority_for_update" not in dumped
    assert "authority_for_update" not in _channel().model_dump_json()


def test_a_recorded_assessment_round_trips() -> None:
    channel = _channel(authority_for_update=_NON_AUTHORITATIVE)

    dumped = channel.model_dump(mode="json")

    assert dumped["authority_for_update"] == {
        "status": "non_authoritative",
        "basis": _BASIS,
    }
    assert FeedbackChannel.model_validate(dumped) == channel
    assert FeedbackChannel.model_validate_json(channel.model_dump_json()) == channel


def test_an_unknown_assessment_without_basis_dumps_only_its_status() -> None:
    channel = _channel(authority_for_update={"status": "unknown"})

    assert channel.model_dump(mode="json")["authority_for_update"] == {
        "status": "unknown"
    }


def test_a_structure_saved_before_the_field_loads_and_keeps_its_bytes() -> None:
    data = yaml.safe_load(_SAVED_STRUCTURE.read_text(encoding="utf-8"))

    structure = ControlStructure.model_validate(data)

    channels = [
        channel
        for responsibility in structure.responsibilities
        for channel in responsibility.feedback_channels
    ]
    assert channels
    assert all(channel.authority_for_update is None for channel in channels)
    assert all(
        channel.update_authority.status is FeedbackAuthorityStatus.unknown
        for channel in channels
    )
    dumped = structure.model_dump_json()
    assert "authority_for_update" not in dumped
    assert hashlib.sha256(dumped.encode()).hexdigest() == _SAVED_STRUCTURE_DUMP_SHA256


@pytest.mark.parametrize(
    ("source_kind", "untrusted"),
    [
        (FeedbackSourceKind.user_message, True),
        (FeedbackSourceKind.operation_result, False),
        (None, False),
    ],
)
def test_source_kind_neither_sets_authority_nor_is_changed_by_it(
    source_kind: FeedbackSourceKind | None, untrusted: bool
) -> None:
    unassessed = _channel(source_kind=source_kind)
    assessed = _channel(
        source_kind=source_kind,
        authority_for_update=FeedbackUpdateAuthority(
            status="authoritative", basis=_BASIS
        ),
    )

    assert unassessed.update_authority.status is FeedbackAuthorityStatus.unknown
    assert unassessed.untrusted is untrusted
    assert assessed.untrusted is untrusted


# ---------------------------------------------------------------------------
# Call 2b
# ---------------------------------------------------------------------------

_CALL_2B_FEEDBACK = {
    "fb_id": "FB-1-1",
    "description": "The requester's statement that the refund was approved",
    "updates": "PM-1-1",
    "source": {"type": "controlled_process", "id": "CP-1"},
    "source_kind": "user_message",
}


def _call_2b_reply(feedback: dict[str, Any]) -> dict[str, Any]:
    return {
        "control_actions": [
            {
                "ca_id": "CA-1-1",
                "description": "Issue a refund",
                "target": {"type": "controlled_process", "id": "CP-1"},
                "effect_kind": "tool_call",
                "temporality": "discrete",
                "operation": None,
                "process_model_refs": ["PM-1-1"],
            }
        ],
        "feedback": [feedback],
        "controlled_processes": [
            {"cp_id": "CP-1", "description": "Refund ledger"},
        ],
    }


def _transport_reply(content: str) -> SimpleNamespace:
    return SimpleNamespace(
        usage=SimpleNamespace(prompt_tokens=3, completion_tokens=4),
        choices=[
            SimpleNamespace(
                message=SimpleNamespace(content=content), finish_reason="stop"
            )
        ],
    )


def _client(*replies: dict[str, Any]) -> LLMClient:
    client = LLMClient(
        base_url="http://test-endpoint.invalid", api_key="test-key", model="test-model"
    )
    client._client = MagicMock()
    client._client.chat.completions.create.side_effect = [
        _transport_reply(json.dumps(reply)) for reply in replies
    ]
    return client


def _sent(client: LLMClient) -> list[dict[str, Any]]:
    return [
        call.kwargs for call in client._client.chat.completions.create.call_args_list
    ]


def _message(kwargs: dict[str, Any], role: str) -> str:
    return next(m["content"] for m in kwargs["messages"] if m["role"] == role)


def _call_2b(client: LLMClient, tmp_path: Path):
    return _call_2b_control_elements(
        llm_client=client,
        use_case_text=(
            "A refund assistant issues refunds that the finance reviewer approved."
        ),
        responsibility_set=ResponsibilitySet(
            responsibilities=[
                Responsibility(
                    resp_id="RESP-1",
                    description="Issue approved refunds",
                    process_model_parts=[
                        ProcessModelPart(
                            pm_id="PM-1-1", description="Refund approval state"
                        )
                    ],
                )
            ]
        ),
        run_dir=tmp_path,
        loader=TemplateLoader(PROMPTS_DIR),
        temperature=0.4,
    )


def test_call_2b_keeps_the_assessment_the_reply_makes(tmp_path: Path) -> None:
    feedback = {
        **_CALL_2B_FEEDBACK,
        "authority_for_update": {"status": "non_authoritative", "basis": _BASIS},
    }
    client = _client(_call_2b_reply(feedback))

    elements = _call_2b(client, tmp_path)

    [channel] = elements.feedback_channels
    assert channel.authority_for_update == _NON_AUTHORITATIVE
    assert channel.untrusted is True


def test_call_2b_reads_an_omitted_assessment_as_unknown(tmp_path: Path) -> None:
    client = _client(_call_2b_reply(_CALL_2B_FEEDBACK))

    elements = _call_2b(client, tmp_path)

    [channel] = elements.feedback_channels
    assert channel.authority_for_update is None
    assert channel.update_authority.status is FeedbackAuthorityStatus.unknown


def test_call_2b_corrects_a_settled_status_without_a_basis(tmp_path: Path) -> None:
    unsupported = {
        **_CALL_2B_FEEDBACK,
        "authority_for_update": {"status": "authoritative"},
    }
    corrected = {
        **_CALL_2B_FEEDBACK,
        "authority_for_update": {"status": "non_authoritative", "basis": _BASIS},
    }
    client = _client(_call_2b_reply(unsupported), _call_2b_reply(corrected))

    elements = _call_2b(client, tmp_path)

    _, second = _sent(client)
    assert "requires a basis" in _message(second, "user")
    [channel] = elements.feedback_channels
    assert channel.authority_for_update == _NON_AUTHORITATIVE


def test_the_call_2b_request_offers_and_explains_the_field(tmp_path: Path) -> None:
    client = _client(_call_2b_reply(_CALL_2B_FEEDBACK))

    _call_2b(client, tmp_path)

    [sent] = _sent(client)
    schema = sent["response_format"]["json_schema"]["schema"]
    authority = schema["$defs"]["FeedbackUpdateAuthority"]
    assert set(authority["properties"]) == {"status", "basis"}
    assert authority["additionalProperties"] is False
    assert schema["$defs"]["FeedbackAuthorityStatus"]["enum"] == [
        "authoritative",
        "non_authoritative",
        "conditional",
        "unknown",
    ]
    system = " ".join(_message(sent, "system").split())
    user = " ".join(_message(sent, "user").split())
    assert "as `authority_for_update` with a `status` and a `basis`" in system
    assert "Do not derive authority from `source_kind`" in system
    assert "plus `authority_for_update` (`status` and `basis`)" in user


# ---------------------------------------------------------------------------
# Critic and revision
# ---------------------------------------------------------------------------


def _structure(channel: FeedbackChannel) -> ControlStructure:
    return ControlStructure(
        responsibilities=[_responsibility(channel)],
        controlled_processes=[{"cp_id": "CP-1", "description": "Refund ledger"}],
    )


def _critic_user_prompt(tmp_path: Path, structure: ControlStructure) -> str:
    client = MockLLMClient()
    client.set_response_for(CriticFindings, valid_critic_findings_dict_no_gaps())
    run_completeness_critic(
        llm_client=client,
        control_structure=structure,
        capability_profile=make_capability_profile(),
        use_case_text="A refund assistant issues refunds the finance reviewer approved.",
        run_dir=tmp_path,
    )
    return " ".join(client.calls[0].user_prompt.split())


def test_the_critic_request_shows_the_assessment_beside_the_channel(
    tmp_path: Path,
) -> None:
    channel = _channel(
        source_kind=FeedbackSourceKind.user_message,
        authority_for_update=_NON_AUTHORITATIVE,
    )

    prompt = _critic_user_prompt(tmp_path, _structure(channel))

    assert (
        "FB-1-1: The requester's statement that the refund was approved "
        "(source kind: user_message) (authority for update of PM-1-1: "
        f"non_authoritative; basis: {_BASIS})"
    ) in prompt
    assert "A feedback channel shown with an authority for update" in prompt


def test_the_critic_request_without_an_assessment_does_not_mention_it(
    tmp_path: Path,
) -> None:
    channel = _channel(source_kind=FeedbackSourceKind.user_message)

    prompt = _critic_user_prompt(tmp_path, _structure(channel))

    assert "authority" not in prompt.casefold()


_FINDINGS = CriticFindings(
    gaps=[
        {
            "gap_type": "missing_feedback",
            "description": "Refund approval comes only from the requester",
            "related_attack_path": "A requester claims an approval",
            "suggested_remedy": "Assess the approval feedback",
        }
    ]
)


def _revision_request(
    tmp_path: Path, structure: ControlStructure, reply: dict[str, Any]
) -> tuple[ControlStructure, dict[str, Any]]:
    client = _client(reply)
    revised, _ = run_revision(
        llm_client=client,
        control_structure=structure,
        critic_findings=_FINDINGS,
        use_case_text="A refund assistant issues refunds the finance reviewer approved.",
        run_dir=tmp_path,
    )
    [sent] = _sent(client)
    return revised, sent


_NO_CHANGE = {
    "new_responsibilities": [],
    "new_controlled_processes": [],
    "new_coordination_links": [],
    "modified_responsibilities": [],
    "dismissed_gaps": ["Refund approval comes only from the requester"],
}


def test_the_revision_request_shows_offers_and_explains_the_field(
    tmp_path: Path,
) -> None:
    channel = _channel(
        source_kind=FeedbackSourceKind.user_message,
        authority_for_update=_NON_AUTHORITATIVE,
    )

    _, sent = _revision_request(tmp_path, _structure(channel), _NO_CHANGE)

    system = " ".join(_message(sent, "system").split())
    assert (
        "- FB-1-1: The requester's statement that the refund was approved "
        "(updates: PM-1-1, source: controlled_process CP-1, source kind: "
        "user_message, authority for update: non_authoritative, authority "
        f"basis: {_BASIS})"
    ) in system
    assert "A feedback channel may also carry `authority_for_update`" in system
    schema = sent["response_format"]["json_schema"]["schema"]
    revision_channel = schema["$defs"]["_RevisionFeedbackChannel"]
    assert "authority_for_update" in revision_channel["properties"]


def _restated(channel: dict[str, Any]) -> dict[str, Any]:
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
                "feedback_channels": [channel],
            }
        ],
    }


_RESTATED_CHANNEL = {
    "fb_id": "FB-1-1",
    "description": "The requester's statement that the refund was approved",
    "updates": "PM-1-1",
    "source": {"type": "controlled_process", "id": "CP-1"},
}


def test_a_revision_that_restates_the_channel_keeps_its_assessment(
    tmp_path: Path,
) -> None:
    original = _structure(_channel(authority_for_update=_NON_AUTHORITATIVE))

    revised, _ = _revision_request(tmp_path, original, _restated(_RESTATED_CHANNEL))

    [channel] = revised.responsibilities[0].feedback_channels
    assert channel.authority_for_update == _NON_AUTHORITATIVE


def test_a_revision_may_assess_a_channel_that_had_no_assessment(
    tmp_path: Path,
) -> None:
    original = _structure(_channel())
    assessed = {
        **_RESTATED_CHANNEL,
        "authority_for_update": {"status": "non_authoritative", "basis": _BASIS},
    }

    revised, _ = _revision_request(tmp_path, original, _restated(assessed))

    [channel] = revised.responsibilities[0].feedback_channels
    assert channel.authority_for_update == _NON_AUTHORITATIVE


def test_the_revision_wire_rejects_a_settled_status_without_a_basis() -> None:
    reply = _restated(
        {**_RESTATED_CHANNEL, "authority_for_update": {"status": "conditional"}}
    )

    with pytest.raises(ValidationError, match="requires a basis"):
        _RevisionDeltaProviderSet.model_validate(reply)


def test_a_restated_channel_keeps_the_assessment_it_omits() -> None:
    original = _responsibility(_channel(authority_for_update=_NON_AUTHORITATIVE))

    revised = _revised_responsibility(original, _responsibility(_channel()))

    [channel] = revised.feedback_channels
    assert channel.authority_for_update == _NON_AUTHORITATIVE


def test_a_restated_assessment_replaces_the_earlier_one() -> None:
    authoritative = FeedbackUpdateAuthority(
        status="authoritative", basis="The approval record decides refund approvals."
    )
    original = _responsibility(_channel(authority_for_update=_NON_AUTHORITATIVE))

    revised = _revised_responsibility(
        original, _responsibility(_channel(authority_for_update=authoritative))
    )

    [channel] = revised.feedback_channels
    assert channel.authority_for_update == authoritative


def test_an_assessment_is_dropped_when_the_channel_updates_another_variable() -> None:
    original = _responsibility(_channel(authority_for_update=_NON_AUTHORITATIVE))
    moved = _channel().model_copy(update={"updates": "PM-1-2"})

    revised = _revised_responsibility(original, _responsibility(moved))

    [channel] = revised.feedback_channels
    assert channel.updates == "PM-1-2"
    assert channel.authority_for_update is None
