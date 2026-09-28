from __future__ import annotations

import json

import pytest

from asago_scenario_generator.models.target_realization import (
    SystemicControlAction,
    TargetDerivedICAOperationContext,
    TargetDerivedICASlotProposal,
    TargetDerivedICARequest,
    TargetDerivedICASlot,
    TargetOperationObservation,
    TargetOperationReference,
    TargetRealizationExtensionRequest,
)
from asago_scenario_generator.stpa.target_realization import (
    TargetDerivedICALlmFinder,
    TargetRealizationLlmInterpreter,
)
from asago_scenario_generator.pipeline.target_realization import (
    realize_target_operations,
)
from tests.stpa.sp1_helpers import MockLLMClient
from tests.test_target_realization import _baseline, _profile


def test_supported_mapping_retains_selected_operation_as_candidate(tmp_path):
    client = MockLLMClient()
    selected = {
        "resource_id": "mcp:mini:escalate_to_human",
        "operation_id": "escalate_to_human",
    }
    client.set_response_queue(
        [
            {
                "control_action_id": "CA-1-1",
                "disposition": "supported",
                "candidate_operations": [],
                "selected_operation": selected,
                "evidence_refs": ["inventory:tool:escalate_to_human:description"],
                "rationale": "The operation routes work to a human.",
            },
            {
                "decision": "verified",
                "detail": "The observed operation realizes the action.",
                "evidence_refs": ["inventory:tool:escalate_to_human:description"],
                "effect_match": "exact",
                "recipient_match": "exact",
                "completion_match": "established",
            },
        ]
    )
    adapter = TargetRealizationLlmInterpreter(client, tmp_path, temperature=0.4)

    response = adapter(
        action={
            "control_action_id": "CA-1-1",
            "controller_id": "RESP-1",
            "description": "Route the conversation to a human.",
            "effect_kind": "agent_message",
            "temporality": "discrete",
        },
        operations=(
            {
                **selected,
                "description": "Hand the conversation to a human agent.",
                "argument_names": ["topic", "reason"],
                "effect": "escalate",
                "state_effect": "none",
            },
        ),
    )

    assert response.selected_operation is not None
    assert response.candidate_operations == (response.selected_operation,)
    assert {call.max_completion_tokens for call in client.calls} == {4096}
    verifier_prompt = client.calls[1].user_prompt
    assert "candidate_operations" not in verifier_prompt
    assert "PROPOSAL_BEGIN" not in verifier_prompt
    assert "escalate_to_human" in verifier_prompt
    assert "Hand the conversation to a human agent." in verifier_prompt


def test_target_realization_call_variants_have_distinct_attempt_identities(tmp_path):
    """Enrichment and realization calls remain separate accounting attempts."""
    selected = {
        "resource_id": "mcp:mini:escalate_to_human",
        "operation_id": "escalate_to_human",
    }
    action = {
        "control_action_id": "CA-1-1",
        "controller_id": "RESP-1",
        "description": "Route the conversation to a human.",
        "effect_kind": "agent_message",
        "temporality": "discrete",
    }
    operations = (
        {
            **selected,
            "description": "Hand the conversation to a human agent.",
            "argument_names": ["topic", "reason"],
            "effect": "escalate",
            "state_effect": "none",
        },
    )
    responses = [
        {
            "control_action_id": "CA-1-1",
            "disposition": "supported",
            "candidate_operations": [],
            "selected_operation": selected,
            "evidence_refs": ["inventory:tool:escalate_to_human:description"],
            "rationale": "The operation routes work to a human.",
        },
        {
            "decision": "verified",
            "detail": "The observed operation realizes the action.",
            "evidence_refs": ["inventory:tool:escalate_to_human:description"],
            "effect_match": "exact",
            "recipient_match": "exact",
            "completion_match": "established",
        },
    ]
    enrichment_client = MockLLMClient()
    enrichment_client.set_response_queue(responses)
    realization_client = MockLLMClient()
    realization_client.set_response_queue(responses)

    for client, variant in (
        (enrichment_client, "control_action_enrichment"),
        (realization_client, "target_realization"),
    ):
        TargetRealizationLlmInterpreter(
            client,
            tmp_path,
            temperature=0.4,
            call_variant=variant,
        )(action=action, operations=operations)

    entries = [
        json.loads(line) for line in (tmp_path / "calls.jsonl").read_text().splitlines()
    ]
    assert len(entries) == 4
    assert len({entry["attempt_id"] for entry in entries}) == 4
    assert {entry["step"].split(":", 1)[0] for entry in entries} == {
        "control_action_enrichment",
        "target_realization",
    }


@pytest.mark.parametrize(
    (
        "action_id",
        "action_description",
        "effect_match",
        "recipient_match",
        "completion_match",
        "expected_status",
    ),
    (
        (
            "CA-6-1",
            "Signal the review controller that escalation prerequisites are satisfied.",
            "prerequisite_only",
            "different",
            "not_established",
            "rejected",
        ),
        (
            "CA-7-1",
            "Transfer the customer conversation to a human reviewer for handling.",
            "exact",
            "exact",
            "established",
            "verified",
        ),
        (
            "CA-6-1",
            "Signal the review controller that escalation prerequisites are satisfied.",
            "unknown",
            "unknown",
            "unknown",
            "unverified",
        ),
    ),
)
def test_shared_escalation_operation_requires_semantic_axes(
    tmp_path,
    action_id,
    action_description,
    effect_match,
    recipient_match,
    completion_match,
    expected_status,
):
    """A shared operation name cannot erase the action's immediate meaning."""
    client = MockLLMClient()
    selected = {
        "resource_id": "mcp:mini:escalate_to_human",
        "operation_id": "escalate_to_human",
    }
    client.set_response_queue(
        [
            {
                "control_action_id": action_id,
                "disposition": "supported",
                "selected_operation": selected,
                "evidence_refs": ["inventory:tool:escalate_to_human"],
            },
            {
                "decision": "verified",
                "detail": "The operation is an escalation.",
                "evidence_refs": ["inventory:tool:escalate_to_human"],
                "effect_match": effect_match,
                "recipient_match": recipient_match,
                "completion_match": completion_match,
            },
        ]
    )
    adapter = TargetRealizationLlmInterpreter(client, tmp_path, temperature=0.4)

    response = adapter(
        action={
            "control_action_id": action_id,
            "controller_id": "RESP-6",
            "description": action_description,
            "effect_kind": "agent_message",
            "target": {"type": "responsibility", "id": "RESP-7"},
            "temporality": "discrete",
        },
        operations=(
            {
                **selected,
                "description": "Hand the customer case to a human agent.",
                "argument_names": ["reason"],
                "effect": "escalate",
                "state_effect": "none",
            },
        ),
    )

    assert response.verifier is not None
    assert response.verifier.status == expected_status
    if expected_status == "rejected":
        assert "prerequisite_only" in response.verifier.detail
        assert "not_established" in response.verifier.detail
    if expected_status == "unverified":
        assert "effect_match=unknown" in response.verifier.detail


def test_exact_internal_message_tool_remains_a_valid_specialization(tmp_path):
    client = MockLLMClient()
    selected = {
        "resource_id": "mcp:mini:send_internal_signal",
        "operation_id": "send_internal_signal",
    }
    client.set_response_queue(
        [
            {
                "control_action_id": "CA-6-1",
                "disposition": "supported",
                "selected_operation": selected,
                "evidence_refs": ["inventory:tool:send_internal_signal"],
            },
            {
                "decision": "verified",
                "detail": "The tool sends the named internal message.",
                "evidence_refs": ["inventory:tool:send_internal_signal"],
                "effect_match": "exact",
                "recipient_match": "exact",
                "completion_match": "established",
            },
        ]
    )
    adapter = TargetRealizationLlmInterpreter(client, tmp_path, temperature=0.4)

    response = adapter(
        action={
            "control_action_id": "CA-6-1",
            "controller_id": "RESP-6",
            "description": "Send an internal escalation signal to the review controller.",
            "effect_kind": "agent_message",
            "target": {"type": "responsibility", "id": "RESP-7"},
            "temporality": "discrete",
        },
        operations=(
            {
                **selected,
                "description": "Send an internal escalation signal to the review controller.",
                "argument_names": ["reason"],
                "effect": "notify",
                "state_effect": "none",
            },
        ),
    )

    assert response.verifier is not None
    assert response.verifier.status == "verified"


def test_external_approval_request_is_not_completed_approval(tmp_path):
    client = MockLLMClient()
    selected = {
        "resource_id": "mcp:mini:request_human_approval",
        "operation_id": "request_human_approval",
    }
    client.set_response_queue(
        [
            {
                "control_action_id": "CA-7-1",
                "disposition": "supported",
                "selected_operation": selected,
                "evidence_refs": ["inventory:tool:request_human_approval"],
            },
            {
                "decision": "verified",
                "detail": "The operation involves human approval.",
                "evidence_refs": ["inventory:tool:request_human_approval"],
                "effect_match": "prerequisite_only",
                "recipient_match": "exact",
                "completion_match": "not_established",
            },
        ]
    )
    adapter = TargetRealizationLlmInterpreter(client, tmp_path, temperature=0.4)

    response = adapter(
        action={
            "control_action_id": "CA-7-1",
            "controller_id": "RESP-7",
            "description": "Approve the customer's refund request.",
            "effect_kind": "agent_message",
            "target": {"type": "responsibility", "id": "RESP-8"},
            "temporality": "instantaneous",
        },
        operations=(
            {
                **selected,
                "description": "Request a human reviewer to approve the customer's refund.",
                "argument_names": ["reason"],
                "effect": "request_approval",
                "state_effect": "none",
            },
        ),
    )

    assert response.verifier is not None
    assert response.verifier.status == "rejected"
    assert "prerequisite_only" in response.verifier.detail


def test_public_realization_prompt_serializes_frozen_profile_schema(tmp_path):
    client = MockLLMClient()
    selected = {
        "resource_id": "mcp:target:mini:schedule_payment",
        "operation_id": "schedule_payment",
    }
    client.set_response_queue(
        [
            {
                "control_action_id": "CA-1-1",
                "disposition": "supported",
                "candidate_operations": [selected],
                "selected_operation": selected,
                "evidence_refs": [
                    "inventory:tool:schedule_payment:description",
                ],
                "rationale": "The observed payment operation matches the action.",
            },
            {
                "decision": "verified",
                "detail": "The exact observed operation realizes the action.",
                "evidence_refs": [
                    "inventory:tool:schedule_payment:description",
                ],
                "effect_match": "exact",
                "recipient_match": "not_applicable",
                "completion_match": "established",
            },
            {
                "outcomes": [
                    {
                        "operation": {
                            "resource_id": "mcp:target:mini:get_payment",
                            "operation_id": "get_payment",
                        },
                        "disposition": "rejected",
                        "evidence_refs": ["inventory:tool:get_payment"],
                        "rationale": "No systemic hazard depends on this read.",
                    }
                ]
            },
        ]
    )
    adapter = TargetRealizationLlmInterpreter(client, tmp_path, temperature=0.4)

    result = realize_target_operations(_baseline(), _profile(), lambda: adapter)

    assert result.rows[0].selected_operation is not None
    assert result.rows[0].selected_operation.identity == (
        selected["resource_id"],
        selected["operation_id"],
    )
    assert len(client.calls) == 3
    assert "properties:" in client.calls[0].user_prompt
    assert "customer_id" in client.calls[0].user_prompt
    extension_prompt = client.calls[2].user_prompt
    assert extension_prompt.startswith("Assess these uncovered target operations")
    assert "operation_id: get_payment" in extension_prompt
    assert "state_changing: false" in extension_prompt
    assert (
        "operation_id: schedule_payment"
        not in extension_prompt.split("operations:", 1)[1]
    )


def test_target_realization_provider_uses_compiler_owned_extension_ids(tmp_path):
    client = MockLLMClient()
    client.set_response_queue(
        [
            {
                "outcomes": [
                    {
                        "operation": {
                            "resource_id": "mcp:mini:schedule_payment",
                            "operation_id": "schedule_payment",
                        },
                        "disposition": "accepted",
                        "control_action": {
                            "controller_id": "RESP-1",
                            "target": {
                                "type": "responsibility",
                                "id": "RESP-1",
                            },
                        },
                        "ica_slots": [
                            {
                                "uca_type": "NOT_PROVIDED",
                                "action_temporality": "instantaneous",
                            }
                        ],
                        "evidence_refs": ["inventory:tool:schedule_payment"],
                        "rationale": "The operation changes payment state.",
                    }
                ]
            },
            {
                "decision": "verified",
                "detail": "The exact observed operation realizes the additive action.",
                "evidence_refs": ["verification:tool:schedule_payment"],
                "effect_match": "exact",
                "recipient_match": "not_applicable",
                "completion_match": "established",
            },
        ]
    )
    adapter = TargetRealizationLlmInterpreter(
        client,
        tmp_path,
        temperature=0.4,
    )
    request = TargetRealizationExtensionRequest(
        baseline=_baseline(),
        operations=(
            TargetOperationObservation(
                reference=TargetOperationReference(
                    resource_id="mcp:mini:schedule_payment",
                    operation_id="schedule_payment",
                ),
                description="Schedule a payment for the supplied customer.",
                input_schema={
                    "type": "object",
                    "properties": {"customer_id": {"type": "string"}},
                    "required": ["customer_id"],
                },
                state_changing=True,
                evidence_refs=("inventory:tool:schedule_payment",),
            ),
        ),
    )

    response = adapter.extend(request)

    proposal = response.outcomes[0]
    assert proposal.control_action is not None
    assert not hasattr(proposal.control_action, "control_action_id")
    assert not hasattr(proposal.ica_slots[0], "slot_id")
    assert client.calls[0].max_completion_tokens == 4096
    assert "ica_enumeration" not in client.calls[0].user_prompt
    assert "schedule_payment" in client.calls[0].user_prompt
    assert len(client.calls) == 2
    assert proposal.verification is not None
    assert proposal.verification.status == "verified"
    assert (
        "Schedule a payment for the supplied customer." in client.calls[1].user_prompt
    )
    assert "payment controller" in client.calls[1].user_prompt
    assert "security_constraint_refs" in client.calls[1].user_prompt
    assert "SC-1" in client.calls[1].user_prompt


def test_target_extension_uca_type_is_a_closed_literal() -> None:
    with pytest.raises(ValueError, match="uca_type"):
        TargetDerivedICASlotProposal(
            uca_type="INCORRECT:1-1-1",
            action_temporality="instantaneous",
        )


def test_target_extension_retries_missing_evidence_once(tmp_path) -> None:
    client = MockLLMClient()
    operation = {
        "resource_id": "mcp:mini:schedule_payment",
        "operation_id": "schedule_payment",
    }
    outcome = {
        "operation": operation,
        "disposition": "accepted",
        "control_action": {
            "controller_id": "RESP-1",
            "target_new_controlled_process": True,
        },
        "controlled_process": {
            "description": "payment ledger",
        },
        "ica_slots": [
            {
                "uca_type": "INCORRECT",
                "action_temporality": "instantaneous",
            }
        ],
        "rationale": "The operation changes payment state.",
    }
    client.set_response_queue(
        [
            {"outcomes": [outcome]},
            {
                "outcomes": [
                    outcome
                    | {
                        "evidence_refs": [
                            "inventory:tool:schedule_payment",
                            "H-1",
                        ]
                    }
                ]
            },
            {
                "decision": "verified",
                "detail": "The exact observed operation realizes the extension action.",
                "evidence_refs": ["verification:tool:schedule_payment"],
                "effect_match": "exact",
                "recipient_match": "not_applicable",
                "completion_match": "established",
            },
        ]
    )
    adapter = TargetRealizationLlmInterpreter(client, tmp_path, temperature=0.2)
    request = TargetRealizationExtensionRequest(
        baseline=_baseline(),
        operations=(
            TargetOperationObservation(
                reference=TargetOperationReference(**operation),
                state_changing=True,
                evidence_refs=("inventory:tool:schedule_payment",),
            ),
        ),
    )

    response = adapter.extend(request)

    assert len(client.calls) == 3
    assert response.outcomes[0].evidence_refs == (
        "H-1",
        "inventory:tool:schedule_payment",
    )
    assert response.outcomes[0].verification is not None
    assert response.outcomes[0].verification.status == "verified"
    assert "failed validation" in client.calls[1].user_prompt
    assert "payment ledger" in client.calls[2].user_prompt


def test_unmapped_mapping_skips_action_operation_verifier(tmp_path) -> None:
    client = MockLLMClient()
    client.set_response_queue(
        [
            {
                "control_action_id": "CA-1-1",
                "disposition": "unmapped",
                "candidate_operations": [],
                "evidence_refs": ["inventory:tool:schedule_payment"],
                "rationale": "No exact operation relationship was established.",
            }
        ]
    )
    adapter = TargetRealizationLlmInterpreter(client, tmp_path, temperature=0.4)

    response = adapter(
        action={
            "control_action_id": "CA-1-1",
            "controller_id": "RESP-1",
            "description": "Schedule a payment",
            "effect_kind": "state_change",
            "temporality": "discrete",
        },
        operations=(
            {
                "resource_id": "mcp:mini:schedule_payment",
                "operation_id": "schedule_payment",
                "description": "Schedule a payment",
                "input_schema": {"type": "object", "properties": {}},
            },
        ),
    )

    assert response.disposition.value == "unmapped"
    assert response.verifier is None
    assert len(client.calls) == 1


def test_extension_verifier_sees_proposed_meaning_and_exact_payment_schema(tmp_path):
    client = MockLLMClient()
    client.set_response_queue(
        [
            {
                "outcomes": [
                    {
                        "operation": {
                            "resource_id": "mcp:mini:refund_payment",
                            "operation_id": "refund_payment",
                        },
                        "disposition": "accepted",
                        "control_action": {
                            "controller_id": "RESP-1",
                        },
                        "evidence_refs": ["inventory:tool:refund_payment"],
                    }
                ]
            },
            {
                "decision": "rejected",
                "detail": "The generic proposal does not establish refund semantics.",
                "evidence_refs": ["verification:tool:refund_payment"],
                "effect_match": "different",
                "recipient_match": "not_applicable",
                "completion_match": "not_established",
            },
        ]
    )
    adapter = TargetRealizationLlmInterpreter(client, tmp_path, temperature=0.4)
    request = TargetRealizationExtensionRequest(
        baseline=_baseline(),
        operations=(
            TargetOperationObservation(
                reference=TargetOperationReference(
                    resource_id="mcp:mini:refund_payment",
                    operation_id="refund_payment",
                ),
                description="Refund a payment for an order.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "amount": {"type": "number"},
                        "order_id": {"type": "string"},
                    },
                    "required": ["amount", "order_id"],
                },
                state_changing=True,
                evidence_refs=("inventory:tool:refund_payment",),
            ),
        ),
    )

    response = adapter.extend(request)

    verification = response.outcomes[0].verification
    assert verification is not None
    assert verification.status == "rejected"
    assert "Authorize backend API mutation" not in client.calls[1].user_prompt
    assert "Refund a payment for an order." in client.calls[1].user_prompt
    assert "amount" in client.calls[1].user_prompt
    assert "order_id" in client.calls[1].user_prompt
    assert "SC-1" in client.calls[1].user_prompt


def test_target_derived_ica_provider_separates_draft_and_verification(tmp_path):
    client = MockLLMClient()
    slot_id = "RESP-1:CA-1-2:NOT_PROVIDED"
    ica_id = f"{slot_id}:1"
    client.set_response_queue(
        [
            {
                "findings": [
                    {
                        "slot_id": slot_id,
                        "ica_id": "provider-invented-id",
                        "ica_text": "The payment action is not provided when required.",
                        "hazardous_context": "An approved payment remains pending.",
                        "loss_scenario": "The customer incurs a missed-payment loss.",
                        "related_hazards": ["H-1"],
                        "related_constraints": ["SC-1"],
                    }
                ]
            },
            {
                "decisions": [
                    {
                        "ica_id": ica_id,
                        "action_state": "absent",
                        "hazard_path": "supported",
                        "detail": "The exact slot and baseline references agree.",
                        "evidence_refs": ["H-1", "SC-1"],
                    }
                ]
            },
        ]
    )
    finder = TargetDerivedICALlmFinder(
        client,
        tmp_path,
        temperature=0.4,
    )
    request = TargetDerivedICARequest(
        baseline=_baseline(),
        target_derived_control_actions=(
            SystemicControlAction(
                control_action_id="CA-1-2",
                controller_id="RESP-1",
                description="Schedule a payment in the target.",
                effect_kind="tool_call",
                temporality="instantaneous",
                provenance="target_derived",
            ),
        ),
        target_derived_ica_slots=(
            TargetDerivedICASlot(
                slot_id=slot_id,
                responsibility="RESP-1",
                control_action="CA-1-2",
                action_temporality="instantaneous",
                uca_type="NOT_PROVIDED",
            ),
        ),
        target_operation_context=(
            TargetDerivedICAOperationContext(
                control_action_id="CA-1-2",
                operation=TargetOperationObservation(
                    reference=TargetOperationReference(
                        resource_id="mcp:target:mini",
                        operation_id="schedule_payment",
                    ),
                    description="Schedule a payment for the supplied customer.",
                    input_schema={
                        "type": "object",
                        "properties": {"customer_id": {"type": "string"}},
                        "required": ["customer_id"],
                    },
                    state_changing=True,
                    state_effect="changes",
                    evidence_refs=("inventory:tool:schedule_payment",),
                ),
            ),
        ),
    )

    response = finder(request)

    assert len(client.calls) == 2
    assert response.findings[0].verification.status == "verified"
    assert response.findings[0].ica_id == ica_id
    assert {call.max_completion_tokens for call in client.calls} == {4096}
    assert "ica_enumeration" not in client.calls[0].user_prompt
    assert "Accepted target-derived control actions" in client.calls[1].user_prompt
    assert "CA-1-2" in client.calls[1].user_prompt
    assert "uca_type:" not in client.calls[1].user_prompt
    assert (
        "Schedule a payment for the supplied customer." in client.calls[1].user_prompt
    )


@pytest.mark.parametrize(
    ("action_state", "hazard_path", "expected_status"),
    [
        # The fixed action is absent, but a generic system description or an
        # imagined prevention sequence does not establish the harm.
        ("absent", "insufficient_evidence", "unverified"),
        # A supported harm for a different action/category cannot confirm this
        # NOT_PROVIDED slot.
        ("performed_unsafe", "supported", "rejected"),
    ],
)
def test_target_derived_verifier_requires_matching_action_and_hazard_axes(
    tmp_path,
    action_state,
    hazard_path,
    expected_status,
):
    client = MockLLMClient()
    slot_id = "RESP-1:CA-1-2:NOT_PROVIDED"
    ica_id = f"{slot_id}:1"
    client.set_response_queue(
        [
            {
                "findings": [
                    {
                        "slot_id": slot_id,
                        "ica_id": "provider-id-is-rebound",
                        "ica_text": "The payment operation is not provided.",
                        "deviation": "The exact payment operation is absent.",
                        "hazardous_context": "An explicit payment consequence.",
                        "loss_scenario": "The supplied loss is realized.",
                        "related_hazards": ["H-1"],
                        "related_constraints": ["SC-1"],
                    }
                ]
            },
            {
                "decisions": [
                    {
                        "ica_id": ica_id,
                        "action_state": action_state,
                        "hazard_path": hazard_path,
                        # Deliberately positive prose cannot override either
                        # compiler-owned semantic axis.
                        "detail": "The proposal is verified.",
                    }
                ]
            },
        ]
    )
    finder = TargetDerivedICALlmFinder(client, tmp_path, temperature=0.4)
    request = TargetDerivedICARequest(
        baseline=_baseline(),
        target_derived_control_actions=(
            SystemicControlAction(
                control_action_id="CA-1-2",
                controller_id="RESP-1",
                description="Schedule a payment in the target.",
                effect_kind="tool_call",
                temporality="instantaneous",
                provenance="target_derived",
            ),
        ),
        target_derived_ica_slots=(
            TargetDerivedICASlot(
                slot_id=slot_id,
                responsibility="RESP-1",
                control_action="CA-1-2",
                action_temporality="instantaneous",
                uca_type="NOT_PROVIDED",
            ),
        ),
        target_operation_context=(
            TargetDerivedICAOperationContext(
                control_action_id="CA-1-2",
                operation=TargetOperationObservation(
                    reference=TargetOperationReference(
                        resource_id="mcp:target:mini",
                        operation_id="schedule_payment",
                    ),
                    description="Schedule a payment for the supplied customer.",
                    input_schema={
                        "type": "object",
                        "properties": {"customer_id": {"type": "string"}},
                        "required": ["customer_id"],
                    },
                    state_changing=True,
                    state_effect="changes",
                    evidence_refs=("inventory:tool:schedule_payment",),
                ),
            ),
        ),
    )

    response = finder(request)

    assert len(client.calls) == 2
    assert response.findings[0].ica_id == ica_id
    assert response.findings[0].verification.status == expected_status


def test_target_derived_verifier_requires_operation_context_for_positive_finding(
    tmp_path,
):
    client = MockLLMClient()
    slot_id = "RESP-1:CA-1-2:NOT_PROVIDED"
    client.set_response_queue(
        [
            {
                "findings": [
                    {
                        "slot_id": slot_id,
                        "ica_id": "provider-id-is-rebound",
                        "ica_text": "The payment operation is not provided.",
                        "hazardous_context": "An explicit payment consequence.",
                        "loss_scenario": "The supplied loss is realized.",
                        "related_hazards": ["H-1"],
                        "related_constraints": ["SC-1"],
                    }
                ]
            },
            {
                "decisions": [
                    {
                        "ica_id": f"{slot_id}:1",
                        "action_state": "absent",
                        "hazard_path": "supported",
                        "detail": "The exact path is supported.",
                    }
                ]
            },
        ]
    )
    finder = TargetDerivedICALlmFinder(client, tmp_path, temperature=0.4)
    request = TargetDerivedICARequest(
        baseline=_baseline(),
        target_derived_control_actions=(
            SystemicControlAction(
                control_action_id="CA-1-2",
                controller_id="RESP-1",
                description="Schedule a payment in the target.",
                effect_kind="tool_call",
                temporality="instantaneous",
                provenance="target_derived",
            ),
        ),
        target_derived_ica_slots=(
            TargetDerivedICASlot(
                slot_id=slot_id,
                responsibility="RESP-1",
                control_action="CA-1-2",
                action_temporality="instantaneous",
                uca_type="NOT_PROVIDED",
            ),
        ),
    )

    response = finder(request)

    assert response.findings[0].verification.status == "unverified"
