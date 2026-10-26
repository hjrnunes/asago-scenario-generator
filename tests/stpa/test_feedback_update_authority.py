"""A feedback channel records whether it may establish the variable it updates.

``authority_for_update`` assesses the channel's ``updates`` relation: a status
and the basis that cites the supplied evidence.  It is optional, a missing
assessment means unknown, and an unset field stays out of the dump so a
structure written before the field existed keeps its bytes.  The assessment
is never derived from ``source_kind`` and does not change ``untrusted``.

Stage 2 Call 2b and the revision accept the field on their wires, the
critic and revision requests show it beside the channel, and a revision that
omits it keeps the earlier assessment while the channel updates the same
variable.  A basis that still fails the deterministic checks after the
existing correction is dropped with a warning instead of stopping the step.  Requests go through the real client with a mocked transport, or
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
from asago_scenario_generator.stpa.infra.llm_helpers import StageError
from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossAnalysis,
    LossProvenance,
    SecurityConstraint,
)
from asago_scenario_generator.stpa.system_model.control_structure import (
    ControlElementSet,
    CoordinationAnalysis,
    RequirementSet,
    ResponsibilitySet,
    _call_2b_control_elements,
    derive_control_structure,
)
from asago_scenario_generator.stpa.system_model.critic import (
    CriticFindings,
    _revised_responsibility,
    _RevisionDeltaProviderSet,
    run_completeness_critic,
    run_revision,
)
from asago_scenario_generator.stpa.system_model.target_evidence import (
    EvidenceSessionField,
    TargetEvidence,
)
from tests.phrase_tables import CASES
from tests.helpers.stpa_builders import make_capability_profile
from tests.stpa.sp1_helpers import (
    MockLLMClient,
    valid_critic_findings_dict_no_gaps,
    valid_empty_coordination_analysis_dict,
)

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
_AUTHORITY_EVIDENCE = TargetEvidence(
    session_fields=(
        EvidenceSessionField(name="authenticated_reviewer", value="reviewer-1"),
    )
)
_USER_INPUT_CITED_BASIS = (
    "The user input names the reviewer for this refund; "
    "session:authenticated_reviewer establishes which reviewer may approve it."
)


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


def _call_2b(
    client: LLMClient,
    tmp_path: Path,
    *,
    target_evidence: TargetEvidence | None = None,
    warnings: list[str] | None = None,
):
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
        target_evidence=target_evidence,
        warnings=warnings,
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


@pytest.mark.parametrize(
    ("invalid_basis", "error_text", "target_evidence"),
    [
        pytest.param(
            "user input is unverified",
            "only restates source kind",
            None,
            id="source-kind-restatement",
        ),
        pytest.param(
            "The finance reviewer decides refund approvals.",
            "must cite the supplied use case",
            None,
            id="no-offered-evidence-citation",
        ),
        pytest.param(
            "session:authenticated_reviewer",
            "scope in domain words",
            _AUTHORITY_EVIDENCE,
            id="bare-ref-without-domain-scope",
        ),
        pytest.param(
            "Refund approval is decided by state:refunds.approved",
            "not offered in this request",
            _AUTHORITY_EVIDENCE,
            id="invented-evidence-ref",
        ),
    ],
)
def test_call_2b_corrects_invalid_authority_bases_through_validation_retry(
    tmp_path: Path,
    invalid_basis: str,
    error_text: str,
    target_evidence: TargetEvidence | None,
) -> None:
    invalid = {
        **_CALL_2B_FEEDBACK,
        "authority_for_update": {
            "status": "non_authoritative",
            "basis": invalid_basis,
        },
    }
    corrected = {
        **_CALL_2B_FEEDBACK,
        "authority_for_update": {
            "status": "non_authoritative",
            "basis": _BASIS,
        },
    }
    client = _client(_call_2b_reply(invalid), _call_2b_reply(corrected))

    elements = _call_2b(client, tmp_path, target_evidence=target_evidence)

    _, correction = _sent(client)
    assert error_text in _message(correction, "user")
    assert elements.feedback_channels[0].authority_for_update == _NON_AUTHORITATIVE


def test_call_2b_accepts_an_offered_ref_with_domain_scope(tmp_path: Path) -> None:
    basis = (
        "Reviewer identity from session:authenticated_reviewer establishes the "
        "reviewer who may approve refunds."
    )
    feedback = {
        **_CALL_2B_FEEDBACK,
        "authority_for_update": {"status": "authoritative", "basis": basis},
    }
    client = _client(_call_2b_reply(feedback))

    elements = _call_2b(client, tmp_path, target_evidence=_AUTHORITY_EVIDENCE)

    assert elements.feedback_channels[0].authority_for_update == (
        FeedbackUpdateAuthority(status="authoritative", basis=basis)
    )


def test_call_2b_accepts_user_input_wording_that_cites_offered_evidence(
    tmp_path: Path,
) -> None:
    feedback = {
        **_CALL_2B_FEEDBACK,
        "authority_for_update": {
            "status": "authoritative",
            "basis": _USER_INPUT_CITED_BASIS,
        },
    }
    client = _client(_call_2b_reply(feedback))

    elements = _call_2b(client, tmp_path, target_evidence=_AUTHORITY_EVIDENCE)

    assert elements.feedback_channels[0].authority_for_update == (
        FeedbackUpdateAuthority(status="authoritative", basis=_USER_INPUT_CITED_BASIS)
    )
    assert len(_sent(client)) == 1


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


def test_the_unassessed_critic_request_keeps_its_exact_bytes() -> None:
    prompt = CASES["unassessed-critic"]("critic_user.j2")

    assert hashlib.sha256(prompt.encode()).hexdigest() == (
        "5894b11f6f9102be7791fdd604c45a825a26384f9230b62f8ff0f83389a24393"
    )


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


def _revision_attempts(
    tmp_path: Path,
    structure: ControlStructure,
    *replies: dict[str, Any],
    target_evidence: TargetEvidence | None = None,
) -> tuple[ControlStructure, list[dict[str, Any]]]:
    client = _client(*replies)
    revised, _ = run_revision(
        llm_client=client,
        control_structure=structure,
        critic_findings=_FINDINGS,
        use_case_text="A refund assistant issues refunds the finance reviewer approved.",
        run_dir=tmp_path,
        target_evidence=target_evidence,
    )
    return revised, _sent(client)


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
        "updates: PM-1-1 source: controlled_process CP-1 source_kind: "
        "user_message authority_for_update.status: non_authoritative "
        f"authority_for_update.basis: {_BASIS}"
    ) in system
    assert "A feedback channel may also carry `authority_for_update`" in system
    assert "## Supplied Use-Case Evidence" in system
    assert "A refund assistant issues refunds" in system
    user = " ".join(_message(sent, "user").split())
    assert "A refund assistant issues refunds" not in user
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


@pytest.mark.parametrize(
    ("invalid_basis", "error_text", "target_evidence"),
    [
        pytest.param(
            "user-provided text",
            "only restates source kind",
            None,
            id="source-kind-restatement",
        ),
        pytest.param(
            "The finance reviewer decides refund approvals.",
            "must cite the supplied use case",
            None,
            id="no-offered-evidence-citation",
        ),
        pytest.param(
            "session:authenticated_reviewer",
            "scope in domain words",
            _AUTHORITY_EVIDENCE,
            id="bare-ref-without-domain-scope",
        ),
        pytest.param(
            "Refund approval is decided by state:refunds.approved",
            "not offered in this request",
            _AUTHORITY_EVIDENCE,
            id="invented-evidence-ref",
        ),
    ],
)
def test_revision_corrects_invalid_authority_bases_through_existing_retry(
    tmp_path: Path,
    invalid_basis: str,
    error_text: str,
    target_evidence: TargetEvidence | None,
) -> None:
    original = _structure(_channel())
    invalid = {
        **_RESTATED_CHANNEL,
        "source_kind": "user_message",
        "authority_for_update": {
            "status": "non_authoritative",
            "basis": invalid_basis,
        },
    }
    corrected = {
        **_RESTATED_CHANNEL,
        "source_kind": "user_message",
        "authority_for_update": {
            "status": "non_authoritative",
            "basis": _BASIS,
        },
    }

    revised, sent = _revision_attempts(
        tmp_path,
        original,
        _restated(invalid),
        _restated(corrected),
        target_evidence=target_evidence,
    )

    assert len(sent) == 2
    assert error_text in _message(sent[1], "user")
    [channel] = revised.responsibilities[0].feedback_channels
    assert channel.authority_for_update == _NON_AUTHORITATIVE


def test_revision_accepts_user_input_wording_that_cites_offered_evidence(
    tmp_path: Path,
) -> None:
    original = _structure(_channel())
    assessed = {
        **_RESTATED_CHANNEL,
        "source_kind": "user_message",
        "authority_for_update": {
            "status": "authoritative",
            "basis": _USER_INPUT_CITED_BASIS,
        },
    }

    revised, sent = _revision_attempts(
        tmp_path,
        original,
        _restated(assessed),
        target_evidence=_AUTHORITY_EVIDENCE,
    )

    assert len(sent) == 1
    [channel] = revised.responsibilities[0].feedback_channels
    assert channel.authority_for_update == FeedbackUpdateAuthority(
        status="authoritative", basis=_USER_INPUT_CITED_BASIS
    )


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


# ---------------------------------------------------------------------------
# A basis the correction does not fix is dropped
# ---------------------------------------------------------------------------

_UNSUPPORTED_BASES = [
    pytest.param(
        "user input is unverified",
        "feedback channel FB-1-1 authority basis only restates source kind "
        "'user_message'; state why that source may or may not establish this "
        "value and cite supplied evidence",
        None,
        id="source-kind-restatement",
    ),
    pytest.param(
        "The finance reviewer decides refund approvals.",
        "feedback channel FB-1-1 settled authority basis must cite the supplied "
        "use case or an exact target-evidence ref",
        None,
        id="no-offered-evidence-citation",
    ),
    pytest.param(
        "session:authenticated_reviewer",
        "feedback channel FB-1-1 authority basis must state its scope in domain "
        "words, not only evidence refs",
        _AUTHORITY_EVIDENCE,
        id="bare-ref-without-domain-scope",
    ),
    pytest.param(
        "Refund approval is decided by state:refunds.approved",
        "feedback channel FB-1-1 authority basis cites target-evidence ref(s) "
        "not offered in this request: state:refunds.approved",
        _AUTHORITY_EVIDENCE,
        id="invented-evidence-ref",
    ),
]


def _assessed(basis: str, **fields: Any) -> dict[str, Any]:
    return {
        **_CALL_2B_FEEDBACK,
        **fields,
        "authority_for_update": {"status": "non_authoritative", "basis": basis},
    }


def _dropped_warning(reason: str) -> str:
    return (
        "stage_2/call_2b_control_elements: dropped the authority_for_update of "
        f"feedback channel FB-1-1; its authority is unknown: {reason}"
    )


@pytest.mark.parametrize(("basis", "reason", "target_evidence"), _UNSUPPORTED_BASES)
def test_call_2b_drops_a_basis_the_correction_does_not_fix(
    tmp_path: Path,
    basis: str,
    reason: str,
    target_evidence: TargetEvidence | None,
) -> None:
    reply = _call_2b_reply(_assessed(basis))
    client = _client(reply, reply)
    warnings: list[str] = []

    elements = _call_2b(
        client, tmp_path, target_evidence=target_evidence, warnings=warnings
    )

    first, correction = _sent(client)
    assert (
        f"Exact validation error from the prior response:\nValueError: {reason}"
    ) in _message(correction, "user")
    [channel] = elements.feedback_channels
    assert channel.authority_for_update is None
    assert channel.update_authority == UNKNOWN_UPDATE_AUTHORITY
    assert channel.description == _CALL_2B_FEEDBACK["description"]
    assert warnings == [_dropped_warning(reason)]


def test_call_2b_drops_only_the_bases_that_fail(tmp_path: Path) -> None:
    reply = _call_2b_reply(_assessed("user input is unverified"))
    reply["feedback"].append(
        {
            **_assessed(_BASIS),
            "fb_id": "FB-1-2",
            "description": "The finance reviewer's recorded approval",
        }
    )
    client = _client(reply, reply)
    warnings: list[str] = []

    elements = _call_2b(client, tmp_path, warnings=warnings)

    assert len(_sent(client)) == 2
    unsupported, supported = elements.feedback_channels
    assert unsupported.authority_for_update is None
    assert supported.authority_for_update == _NON_AUTHORITATIVE
    [warning] = warnings
    assert "feedback channel FB-1-1" in warning


def test_call_2b_drops_a_basis_the_reference_correction_introduces(
    tmp_path: Path,
) -> None:
    misreferenced = _call_2b_reply(_CALL_2B_FEEDBACK)
    misreferenced["control_actions"][0]["target"] = {
        "type": "controlled_process",
        "id": "CP-9",
    }
    corrected = _call_2b_reply(_assessed("user input is unverified"))
    client = _client(misreferenced, misreferenced, corrected)
    warnings: list[str] = []

    elements = _call_2b(client, tmp_path, warnings=warnings)

    assert len(_sent(client)) == 3
    assert elements.control_actions[0].target.id == "CP-1"
    [channel] = elements.feedback_channels
    assert channel.authority_for_update is None
    [warning] = warnings
    assert "only restates source kind 'user_message'" in warning


def test_call_2b_keeps_a_supported_basis_without_warning(tmp_path: Path) -> None:
    client = _client(_call_2b_reply(_assessed(_BASIS)))
    warnings: list[str] = []

    elements = _call_2b(client, tmp_path, warnings=warnings)

    assert elements.feedback_channels[0].authority_for_update == _NON_AUTHORITATIVE
    assert warnings == []


@pytest.mark.parametrize(
    "feedback",
    [
        pytest.param(
            {**_assessed("user input is unverified"), "description": ""},
            id="blank-description-beside-an-unsupported-basis",
        ),
        pytest.param(
            {**_CALL_2B_FEEDBACK, "authority_for_update": {"status": "authoritative"}},
            id="settled-status-without-basis",
        ),
    ],
)
def test_call_2b_still_stops_on_other_failures(
    tmp_path: Path, feedback: dict[str, Any]
) -> None:
    reply = _call_2b_reply(feedback)
    client = _client(reply, reply)
    warnings: list[str] = []

    with pytest.raises(StageError):
        _call_2b(client, tmp_path, warnings=warnings)

    assert len(_sent(client)) == 2
    assert warnings == []


def test_stage_2_completes_with_the_dropped_assessment_as_a_warning(
    tmp_path: Path,
) -> None:
    client = MockLLMClient()
    client.set_response_for(
        RequirementSet,
        {
            "requirements": [
                {
                    "req_id": "REQ-1",
                    "description": "Issue only approved refunds",
                    "classification": "control",
                    "source_constraint": "SC-1",
                }
            ]
        },
    )
    client.set_response_for(
        ResponsibilitySet,
        {
            "responsibilities": [
                {
                    "resp_id": "RESP-1",
                    "description": "Issue approved refunds",
                    "security_constraint_refs": [],
                    "process_model_parts": [
                        {"pm_id": "PM-1-1", "description": "Refund approval state"}
                    ],
                }
            ]
        },
    )
    client.set_response_for(
        ControlElementSet, _call_2b_reply(_assessed("user input is unverified"))
    )
    client.set_response_for(
        CoordinationAnalysis, valid_empty_coordination_analysis_dict()
    )
    loss_analysis = LossAnalysis(
        risk_card_losses=[],
        use_case_losses=[
            Loss(
                loss_id="L-1",
                description="An unapproved refund is paid",
                provenance=LossProvenance.use_case,
            )
        ],
        hazards=[
            Hazard(
                hazard_id="H-1",
                description="A refund is issued without approval",
                related_losses=["L-1"],
            )
        ],
        security_constraints=[
            SecurityConstraint(
                constraint_id="SC-1",
                rule="Issue a refund only after approval",
                related_hazards=["H-1"],
            )
        ],
    )

    result = derive_control_structure(
        llm_client=client,
        use_case_text="A refund assistant issues refunds the finance reviewer approved.",
        loss_analysis=loss_analysis,
        run_dir=tmp_path,
    )

    call_2b_requests = [
        call
        for call in client.calls
        if call.response_format is not None
        and issubclass(call.response_format, ControlElementSet)
    ]
    assert len(call_2b_requests) == 2
    [channel] = result.control_structure.responsibilities[0].feedback_channels
    assert channel.authority_for_update is None
    assert result.warnings[0] == _dropped_warning(
        "feedback channel FB-1-1 authority basis only restates source kind "
        "'user_message'; state why that source may or may not establish this "
        "value and cite supplied evidence"
    )


@pytest.mark.parametrize(("basis", "reason", "target_evidence"), _UNSUPPORTED_BASES)
def test_revision_drops_a_basis_the_correction_does_not_fix(
    tmp_path: Path,
    basis: str,
    reason: str,
    target_evidence: TargetEvidence | None,
) -> None:
    invalid = _restated(
        {
            **_RESTATED_CHANNEL,
            "source_kind": "user_message",
            "authority_for_update": {"status": "non_authoritative", "basis": basis},
        }
    )
    client = _client(invalid, invalid)

    revised, warnings = run_revision(
        llm_client=client,
        control_structure=_structure(_channel()),
        critic_findings=_FINDINGS,
        use_case_text="A refund assistant issues refunds the finance reviewer approved.",
        run_dir=tmp_path,
        target_evidence=target_evidence,
    )

    sent = _sent(client)
    assert len(sent) == 2
    assert reason in _message(sent[1], "user")
    [channel] = revised.responsibilities[0].feedback_channels
    assert channel.source_kind is FeedbackSourceKind.user_message
    assert channel.authority_for_update is None
    assert [p.pm_id for p in revised.responsibilities[0].process_model_parts] == [
        "PM-1-1",
        "PM-1-2",
    ]
    assert warnings[0] == (
        "Revision dropped the authority_for_update of feedback channel FB-1-1: "
        f"{reason}"
    )
    assert not any(warning.startswith("Revision failed") for warning in warnings)


def test_revision_still_discards_a_reply_with_another_failure(tmp_path: Path) -> None:
    invalid = _restated(
        {
            **_RESTATED_CHANNEL,
            "description": "",
            "source_kind": "user_message",
            "authority_for_update": {
                "status": "non_authoritative",
                "basis": "user input is unverified",
            },
        }
    )
    client = _client(invalid, invalid)
    original = _structure(_channel())

    revised, warnings = run_revision(
        llm_client=client,
        control_structure=original,
        critic_findings=_FINDINGS,
        use_case_text="A refund assistant issues refunds the finance reviewer approved.",
        run_dir=tmp_path,
    )

    assert revised == original
    assert warnings[0].startswith("Revision failed: ")
