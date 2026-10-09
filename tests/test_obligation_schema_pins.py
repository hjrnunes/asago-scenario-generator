"""Pin the model-facing schemas and response digests of the obligation-aware stage.

The generated payload types appear by name in the schema of every recorded
request, and the response envelopes feed recorded response digests.  Each case
fixes the exact bytes so a refactor of how the types are built cannot change
a request or a digest unnoticed.
"""

from __future__ import annotations

import hashlib
import json

import pytest
from pydantic import ValidationError

from asago_scenario_generator.models.canonical import compute_framed_digest
from asago_scenario_generator.stpa.obligation_aware import governance_provider
from asago_scenario_generator.stpa.obligation_aware import provider
from asago_scenario_generator.stpa.obligation_aware.contracts import (
    RevisionDraft,
    StructuralRevisionResponse,
    StructuralRoutingResponse,
    SynthesisSlotResponse,
)
from asago_scenario_generator.stpa.obligation_aware.revision import (
    REVISION_RESPONSE_DIGEST_DOMAIN,
)
from asago_scenario_generator.stpa.obligation_aware.routing import (
    ROUTING_RESPONSE_DIGEST_DOMAIN,
)
from asago_scenario_generator.stpa.obligation_aware.slot_filling import (
    SLOT_RESPONSE_DIGEST_DOMAIN,
)

OB_IDS = ("ob:v1:" + "1" * 64, "ob:v1:" + "2" * 64)
REQUEST_DIGEST = "a" * 64


def fingerprint(model: type) -> tuple[str, str, str]:
    """Name, defining module, and schema-text hash of one generated type."""
    text = json.dumps(model.model_json_schema())
    return model.__name__, model.__module__, hashlib.sha256(text.encode()).hexdigest()


FACTORY_CASES = {
    "routing-1": lambda: provider._routing_provider_payload_type(1),
    "routing-3": lambda: provider._routing_provider_payload_type(3),
    "routing-exact": lambda: provider._routing_provider_payload_type(
        2, obligation_ids=OB_IDS
    ),
    "mechanism-1": lambda: provider._mechanism_verdict_payload_type(1),
    "mechanism-4": lambda: provider._mechanism_verdict_payload_type(4),
    "ica-1": lambda: provider._ica_hazard_provider_payload_type(1),
    "ica-4": lambda: provider._ica_hazard_provider_payload_type(4),
    "slot-1-0": lambda: provider._slot_provider_payload_type(1, 0),
    "slot-3-2": lambda: provider._slot_provider_payload_type(3, 2),
    "slot-exact": lambda: provider._slot_provider_payload_type(
        2, 1, constraint_ids=("SC-1", "SC-2")
    ),
    "governance-1": lambda: governance_provider.governance_payload_type(("risk-a",)),
    "governance-2": lambda: governance_provider.governance_payload_type(
        ("risk-a", "risk-b")
    ),
    "revision": lambda: provider._RevisionProviderPayload,
}

EXPECTED_FACTORIES: dict[str, tuple[str, str, str]] = {
    "governance-1": (
        "_GovernancePayload1",
        "asago_scenario_generator.stpa.obligation_aware.governance_provider",
        "aecdd63ad62018382119be1a385afc796e001156ffd944d7ac96d75aa874e7fe",
    ),
    "governance-2": (
        "_GovernancePayload2",
        "asago_scenario_generator.stpa.obligation_aware.governance_provider",
        "c4b7a7e66dcf5d498f0b7bd07b7b72d604f6f5741a3fd48a1f16f2d9a8532af9",
    ),
    "ica-1": (
        "_IcaHazardProviderPayload1",
        "asago_scenario_generator.stpa.obligation_aware.provider",
        "e7304cec427d195df09bfa06ca121a15fd54473e48a89eabc96bb4c496425f93",
    ),
    "ica-4": (
        "_IcaHazardProviderPayload4",
        "asago_scenario_generator.stpa.obligation_aware.provider",
        "6329bb5ef5e131db4eaa830c2ad652bded57661307488764c96076662b7099e2",
    ),
    "mechanism-1": (
        "_MechanismVerdictPayload1",
        "asago_scenario_generator.stpa.obligation_aware.provider",
        "10b18bc942d5fd2eeb5e16785434ae36897d967321c7d94fb1d0e71b2dd0450b",
    ),
    "mechanism-4": (
        "_MechanismVerdictPayload4",
        "asago_scenario_generator.stpa.obligation_aware.provider",
        "1c63573ca4fc76421a874f444012195ab02aa0812456bedb6e3858c9bc25a0c3",
    ),
    "revision": (
        "_RevisionProviderPayload",
        "asago_scenario_generator.stpa.obligation_aware.provider",
        "c47db54603645bacb55cb3852ecf1e12a27ae76e15a5c190299c1d965e98f93c",
    ),
    "routing-1": (
        "_RoutingProviderPayload1",
        "asago_scenario_generator.stpa.obligation_aware.provider",
        "f281ddb0e1c14619d6dad8ccaf48f2b33f07ef62049cd27c9baeb1bb19441026",
    ),
    "routing-3": (
        "_RoutingProviderPayload3",
        "asago_scenario_generator.stpa.obligation_aware.provider",
        "f57eb9c3f58661a02a5a779d47b0caf868ab0e0bc9ba8129b10cc42dbc037def",
    ),
    "routing-exact": (
        "_RoutingProviderPayload2",
        "asago_scenario_generator.stpa.obligation_aware.provider",
        "2b25bcefda3a3124d6afa9ae247b35cf272bf11d4d26a96567689fe8a02c9448",
    ),
    "slot-1-0": (
        "_SlotProviderPayload1Pairs0",
        "asago_scenario_generator.stpa.obligation_aware.provider",
        "0dc0fd41cf6d49bf45eec18d85f2828bf9f77e28a68d9e860eeba6beb57167fe",
    ),
    "slot-3-2": (
        "_SlotProviderPayload3Pairs2",
        "asago_scenario_generator.stpa.obligation_aware.provider",
        "abf7c619edb6cbe05618cd1027b82dea4a8cfafc0930a11c6896a17764cac0d2",
    ),
    "slot-exact": (
        "_SlotProviderPayload2Pairs1",
        "asago_scenario_generator.stpa.obligation_aware.provider",
        "ee79ae9a36a85ca80c3f7f7b2b5f3e57e2bebaa0258145a4b75651e0311ef863",
    ),
}


@pytest.mark.parametrize("case", sorted(FACTORY_CASES))
def test_generated_payload_types_keep_their_name_module_and_schema(case):
    assert fingerprint(FACTORY_CASES[case]()) == EXPECTED_FACTORIES[case]


COUNT_CASES = {
    "route_count": provider._routing_provider_payload_type,
    "verdict_count": provider._mechanism_verdict_payload_type,
}


@pytest.mark.parametrize("bad", [0, -1, True, 1.0, "1"])
@pytest.mark.parametrize("name", sorted(COUNT_CASES))
def test_a_payload_type_requires_a_positive_integer_count(name, bad):
    with pytest.raises(ValueError, match=f"^{name} must be a positive integer$"):
        COUNT_CASES[name](bad)


@pytest.mark.parametrize("bad", [0, -1, True])
def test_the_ica_payload_type_requires_a_positive_integer_count(bad):
    with pytest.raises(ValueError, match="^verdict_count must be a positive integer$"):
        provider._ica_hazard_provider_payload_type(bad)


@pytest.mark.parametrize(
    ("args", "message"),
    [
        ((0, 0), "slot_count must be a positive integer"),
        ((True, 0), "slot_count must be a positive integer"),
        ((1, -1), "required_pair_count must be a non-negative integer"),
        ((1, True), "required_pair_count must be a non-negative integer"),
    ],
)
def test_the_slot_payload_type_requires_valid_counts(args, message):
    # ``True == 1`` hits a cached type, so start from an empty cache.
    provider._slot_provider_payload_type.cache_clear()
    with pytest.raises(ValueError, match=f"^{message}$"):
        provider._slot_provider_payload_type(*args)


def test_the_governance_payload_type_requires_a_risk_id():
    with pytest.raises(
        ValueError, match="^governance payload requires at least one risk id$"
    ):
        governance_provider.governance_payload_type(())


def test_payload_types_are_built_once_per_argument():
    assert provider._routing_provider_payload_type(
        2
    ) is provider._routing_provider_payload_type(2)


ENVELOPES = {
    "routing": (StructuralRoutingResponse, ROUTING_RESPONSE_DIGEST_DOMAIN, {}),
    "revision": (
        StructuralRevisionResponse,
        REVISION_RESPONSE_DIGEST_DOMAIN,
        {"status": "rejected", "draft": RevisionDraft(rationale="declined")},
    ),
    "slots": (SynthesisSlotResponse, SLOT_RESPONSE_DIGEST_DOMAIN, {}),
}

EXPECTED_ENVELOPES: dict[str, dict] = {
    "revision": {
        "digest": "6937d271f8937491a5b64455abb0d35c860e4db8af2193af8c1f546af22c7e19",
        "dump_keys": [
            "status",
            "request_digest",
            "draft",
            "adapter_kind",
            "request_ref",
            "response_ref",
            "provider_calls",
            "response_digest",
        ],
        "fake_with_calls": "Value error, fake adapter cannot report provider calls",
        "fields": [
            "status",
            "request_digest",
            "draft",
            "adapter_kind",
            "request_ref",
            "response_ref",
            "provider_calls",
            "response_digest",
        ],
        "provider_without_calls": "Value error, provider adapter must report at "
        "least one provider call",
        "refs": [
            "memory://stpa-obligation-revision/request",
            "memory://stpa-obligation-revision/response",
        ],
    },
    "routing": {
        "digest": "69ba32f011d8d29e101694846fcef101b44167327b69417219e5140566fae9b1",
        "dump_keys": [
            "status",
            "request_digest",
            "routes",
            "adapter_kind",
            "request_ref",
            "response_ref",
            "provider_calls",
            "response_digest",
        ],
        "fake_with_calls": "Value error, fake adapter cannot report provider calls",
        "fields": [
            "status",
            "request_digest",
            "routes",
            "adapter_kind",
            "request_ref",
            "response_ref",
            "provider_calls",
            "response_digest",
        ],
        "provider_without_calls": "Value error, provider adapter must report at "
        "least one provider call",
        "refs": [
            "memory://stpa-obligation-routing/request",
            "memory://stpa-obligation-routing/response",
        ],
    },
    "slots": {
        "digest": "f9cf967faab625c26c33173f5e047f068b9f0ccb0475082503c8087058e6e273",
        "dump_keys": [
            "status",
            "request_digest",
            "filled_slots",
            "considerations",
            "adapter_kind",
            "request_ref",
            "response_ref",
            "provider_calls",
            "response_digest",
        ],
        "fake_with_calls": "Value error, fake adapter cannot report provider calls",
        "fields": [
            "status",
            "request_digest",
            "filled_slots",
            "considerations",
            "adapter_kind",
            "request_ref",
            "response_ref",
            "provider_calls",
            "response_digest",
        ],
        "provider_without_calls": "Value error, provider adapter must report at "
        "least one provider call",
        "refs": [
            "memory://stpa-obligation-slots/request",
            "memory://stpa-obligation-slots/response",
        ],
    },
}


def _envelope_facts(name: str) -> dict:
    model, domain, payload = ENVELOPES[name]
    payload = {"request_digest": REQUEST_DIGEST, **payload}
    dump = model(adapter_kind="fake", **payload).model_dump(mode="json")
    return {
        "fields": list(model.model_fields),
        "refs": [
            model.model_fields["request_ref"].default,
            model.model_fields["response_ref"].default,
        ],
        "dump_keys": list(dump),
        "digest": compute_framed_digest(domain, dump),
        "fake_with_calls": _message(model, payload, "fake", 1),
        "provider_without_calls": _message(model, payload, "provider", 0),
    }


def _message(model, payload, kind: str, calls: int) -> str:
    try:
        model(adapter_kind=kind, provider_calls=calls, **payload)
    except ValidationError as exc:
        return exc.errors()[0]["msg"]
    return "accepted"


@pytest.mark.parametrize("name", sorted(ENVELOPES))
def test_response_envelopes_keep_their_fields_defaults_and_digest(name):
    assert _envelope_facts(name) == EXPECTED_ENVELOPES[name]


def test_the_revision_draft_definition_keeps_its_title_description_and_fields():
    definition = provider._RevisionProviderPayload.model_json_schema()["$defs"][
        "_RevisionProviderDraft"
    ]
    assert definition["title"] == "_RevisionProviderDraft"
    assert (
        definition["description"]
        == "Request-local revision fields without legacy final-gap identities."
    )
    assert list(definition["properties"]) == [
        "losses",
        "hazards",
        "security_constraints",
        "responsibilities",
        "controlled_processes",
        "process_model_parts",
        "control_actions",
        "feedback_channels",
        "coordination_links",
        "rationale",
    ]
    assert "required" not in definition


def test_the_revision_payload_requires_the_gap_decisions_beside_the_draft():
    schema = provider._RevisionProviderPayload.model_json_schema()
    assert schema["required"] == ["draft", "gap_decisions"]


def test_the_revision_payload_rejects_a_reply_without_gap_decisions():
    with pytest.raises(ValidationError, match="gap_decisions"):
        provider._RevisionProviderPayload.model_validate({"draft": {}})


def test_the_revision_payload_accepts_an_empty_gap_decision_list():
    payload = provider._RevisionProviderPayload.model_validate(
        {"draft": {}, "gap_decisions": []}
    )
    assert payload.gap_decisions == ()


def test_the_revision_draft_carries_no_gap_decisions_of_its_own():
    with pytest.raises(ValidationError, match="gap_decisions"):
        provider._RevisionProviderPayload.model_validate(
            {"draft": {"gap_decisions": []}, "gap_decisions": []}
        )
