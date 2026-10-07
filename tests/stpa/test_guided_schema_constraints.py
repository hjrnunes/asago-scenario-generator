"""Guided-decoding request schemas close the vocabularies code later needs.

Guided decoding (vLLM ``response_format`` JSON Schema) samples only what the
schema allows.  A field the schema leaves optional can be omitted, and a free
string can hold an invented label.  Clients whose profile sets
``use_guided_decoding`` therefore receive tighter request schemas.

Every other client must receive exactly the schemas producer main sent before
this tightening existed, so the non-guided tests pin SHA-256 digests of the
``response_format`` payloads that producer main ``d5fce78`` builds.  The
digests hash ``json.dumps(payload, separators=(",", ":"), ensure_ascii=False)``
of ``_json_schema_response_format(model, strict_json_schema=...)`` for the
model main passes at each call site (discovery with seven tools), computed in
a ``git archive d5fce78`` export with its locked environment.
"""

from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from asago_scenario_generator.stpa.infra.llm_helpers import CallOutcome, StageError
from asago_scenario_generator.models.capability_profile import (
    KCX_SUBCODES,
    VALID_KC_SUBCODES,
    CapabilityProfile,
    Stage1Profile,
)
from asago_scenario_generator.stpa.infra.llm import (
    LLMClient,
    LLMResult,
    _json_schema_response_format,
)
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysisDraft
from asago_scenario_generator.stpa.system_model.loss_analysis import (
    _Stage1aRiskProviderDraft,
    derive_loss_analysis,
)
from asago_scenario_generator.stpa.system_model.loss_analysis_repair import (
    DispositionRepairResponse,
)
from asago_scenario_generator.stpa.system_model.profile import (
    derive_capability_profile,
)
from asago_scenario_generator.target_discovery import (
    TargetDiscoveryLlmInterpreter,
    TargetInterpretationRequest,
    TargetToolPromptView,
)
from asago_scenario_generator.target_discovery.llm_interpreter import (
    SEMANTIC_ROLE_VOCABULARY,
)
from tests.stpa.sp1_helpers import (
    MockLLMClient,
    make_risk_cards,
    valid_gap_draft_dict,
    valid_risk_draft_dict,
)
from tests.helpers.stage1a_targeted_repair import (
    _SAVED_CARD_IDS,
    _SAVED_MISSING_SEVEN,
    _USE_CASE,
    _attempt_two_response,
    _disposition_repair_rows,
    _empty_gap_response,
    _occiai_cards,
)

# The risk-derivation digests changed when constraints gained ``behavior_class``.
MAIN_DIGESTS = {
    ("stage1b_capability_profile", False): (
        "ab17e8274325f9be4b0c86c86494c9566bbe00a26ecbb0b1af5d314a3c2d1d2c"
    ),
    ("stage1b_capability_profile", True): (
        "fe6f58836b0d634cfdb80c8ebf21ce75eb6627ce879f8f8641cbf08a7fc89331"
    ),
    ("stage1a_risk_derivation", False): (
        "c26dc0e12297ccb243736622720573fd501a2fe5b6ef3397ff3c8137c676c8ba"
    ),
    ("stage1a_risk_derivation", True): (
        "c01d407405d10fc38a31c0a5394d1378dfd74f426369ae9a05e413a465e4b7f8"
    ),
    ("stage1a_disposition_repair", False): (
        "6e86fb6d7d1a202dc65d04d1c987d40e30969330e346d94572c928c12d3aa2e6"
    ),
    ("stage1a_disposition_repair", True): (
        "5de15cb04610c319f97f689a8a844b75f6a7922c4783031ba7b9b813334b2cce"
    ),
    ("discovery_interpretation_7", False): (
        "941ce861f35b89cd8681f3a7f3a94582955bfbbffb53ca4fc763d9ab9cce681e"
    ),
    ("discovery_interpretation_7", True): (
        "6aa51bf245c5beefe470007979b605dffc007c6177bcdb2e0aa2ecf069972d45"
    ),
    ("discovery_verification_7", False): (
        "8f24b80bba35c569da905ba2068e0bcb45ced274a2747d7bee4ef67f862fc039"
    ),
    ("discovery_verification_7", True): (
        "87d1621d2c9a7dbd89a9a220556545eaf6c2487629eb52e25b8177838c17040e"
    ),
}


def _assert_main_payload(name: str, model: type) -> None:
    for strict in (False, True):
        payload = _json_schema_response_format(model, strict_json_schema=strict)
        text = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
        digest = hashlib.sha256(text.encode()).hexdigest()
        assert digest == MAIN_DIGESTS[name, strict], (name, strict)


def _guided(client: MockLLMClient) -> MockLLMClient:
    client.use_guided_decoding = True
    return client


def _resolve(schema: dict, node: dict) -> dict:
    ref = node.get("$ref")
    if ref is None:
        return node
    return schema["$defs"][ref.rsplit("/", 1)[-1]]


def _stage1_profile_dict(**overrides) -> dict:
    data = {
        "entry_points": [
            {"name": "User chat", "direction": "input", "controllability": "direct"}
        ],
        "confidence": "medium",
        "kc_subcodes": ["KC1.1", "KC6.1.1"],
        "tool_inventory": [{"name": "payment_api", "description": "Pay"}],
    }
    data.update(overrides)
    return data


# --- Stage 1b ---------------------------------------------------------------


def _stage1b_call(client: MockLLMClient, tmp_path, responses: list[dict]):
    client.set_response_for(Stage1Profile, responses)
    return derive_capability_profile(
        llm_client=client, use_case_text="Use case", run_dir=tmp_path
    )


def test_stage1b_unguided_request_schema_is_mains(tmp_path):
    client = MockLLMClient()
    _stage1b_call(client, tmp_path, [_stage1_profile_dict()])

    model = client.calls[0].response_format
    assert model.__name__ == "Stage1Profile"
    _assert_main_payload("stage1b_capability_profile", model)


def test_stage1_profile_local_validation_is_mains():
    """The class itself keeps main's optional kc_subcodes and inventory."""
    draft = _stage1_profile_dict()
    del draft["kc_subcodes"]
    del draft["tool_inventory"]
    profile = Stage1Profile.model_validate(draft)
    assert profile.kc_subcodes == []
    assert profile.tool_inventory == []
    _assert_main_payload("stage1b_capability_profile", Stage1Profile)


def test_stage1b_unpromotable_unguided_draft_is_corrected_in_the_call(tmp_path):
    """Main would crash at promotion; the call now spends one correction."""
    missing = _stage1_profile_dict()
    del missing["kc_subcodes"]
    client = MockLLMClient()

    profile = _stage1b_call(client, tmp_path, [missing, _stage1_profile_dict()])

    assert isinstance(profile, CapabilityProfile)
    assert profile.kc_subcodes == ["KC1.1", "KC6.1.1"]
    assert len(client.calls) == 2
    assert "kc_subcodes" in client.calls[1].user_prompt


def test_stage1b_uncorrected_draft_fails_as_a_stage_error(tmp_path):
    missing = _stage1_profile_dict(kc_subcodes=[])
    client = MockLLMClient()

    with pytest.raises(StageError, match="kc_subcodes"):
        _stage1b_call(client, tmp_path, [missing, missing])
    assert len(client.calls) == 2


def test_stage1b_guided_schema_requires_kc_subcodes_and_inventory(tmp_path):
    client = _guided(MockLLMClient())
    _stage1b_call(client, tmp_path, [_stage1_profile_dict()])

    model = client.calls[0].response_format
    assert model.__name__ == "Stage1Profile"
    assert issubclass(model, Stage1Profile)
    schema = model.model_json_schema()
    kc = schema["properties"]["kc_subcodes"]
    assert {"kc_subcodes", "tool_inventory"} <= set(schema["required"])
    assert kc["minItems"] == 1
    assert set(kc["items"]["enum"]) == set(VALID_KC_SUBCODES) | set(KCX_SUBCODES)


def test_stage1b_guided_missing_inventory_is_corrected_in_the_call(tmp_path):
    """qwen38-oc omitted an optional inventory under guided decoding."""
    missing = _stage1_profile_dict(kc_subcodes=["KC1.1"])
    del missing["tool_inventory"]
    client = _guided(MockLLMClient())

    _stage1b_call(client, tmp_path, [missing, _stage1_profile_dict()])

    assert len(client.calls) == 2
    assert "tool_inventory" in client.calls[1].user_prompt


# --- Stage 1a risk derivation ------------------------------------------------


def _keyed_refs(array_schema: dict) -> list[list[str]]:
    """The per-position ``risk_ref`` enums of a one-row-per-key array."""
    assert array_schema["items"] is False
    count = len(array_schema["prefixItems"])
    assert array_schema["minItems"] == array_schema["maxItems"] == count
    refs = []
    for row in array_schema["prefixItems"]:
        assert next(iter(row["properties"])) == "risk_ref"
        assert set(row["properties"]) == {
            "risk_ref",
            "disposition",
            "loss_ids",
            "reason",
        }
        refs.append(row["properties"]["risk_ref"]["enum"])
    return refs


def _risk_call(client: MockLLMClient, tmp_path):
    client.set_response_for(
        LossAnalysisDraft, [valid_risk_draft_dict(), valid_gap_draft_dict()]
    )
    cards = make_risk_cards()
    derive_loss_analysis(
        llm_client=client,
        use_case_text="Test use case",
        risk_cards=cards,
        run_dir=tmp_path,
    )
    call = next(
        call
        for call in client.calls
        if call.response_format is not None
        and issubclass(call.response_format, _Stage1aRiskProviderDraft)
    )
    return call.response_format, cards


def test_risk_derivation_unguided_request_schema_is_mains(tmp_path):
    model, _ = _risk_call(MockLLMClient(), tmp_path)

    assert model is _Stage1aRiskProviderDraft
    _assert_main_payload("stage1a_risk_derivation", model)


def test_risk_derivation_guided_schema_asks_for_each_card_once_in_order(tmp_path):
    """An enum plus a row count still let qwen38-oc repeat and skip cards."""
    model, cards = _risk_call(_guided(MockLLMClient()), tmp_path)
    ids = [card.risk_id for card in cards]

    assert model.__name__ == "_Stage1aRiskProviderDraft"
    schema = model.model_json_schema()
    assert _keyed_refs(schema["properties"]["risk_dispositions"]) == [
        [ref] for ref in ids
    ]
    for collection in ("risk_card_losses", "use_case_losses"):
        loss = _resolve(schema, schema["properties"][collection]["items"])
        assert loss["properties"]["source_risk_cards"]["items"]["enum"] == ids
        assert next(iter(loss["properties"])) == "handle"


def test_risk_derivation_guided_local_validation_is_the_static_wires(tmp_path):
    """An unknown ID still parses, so risk accounting writes the feedback."""
    model, _ = _risk_call(_guided(MockLLMClient()), tmp_path)
    draft = model.model_validate(
        {
            "risk_card_losses": [],
            "use_case_losses": [],
            "hazards": [],
            "security_constraints": [],
            "risk_dispositions": [
                {"risk_ref": "atl-1", "disposition": "not_applicable", "reason": "x"},
                {"risk_ref": "atl-2", "disposition": "not_applicable", "reason": "y"},
            ],
        }
    )
    assert [row.risk_ref for row in draft.risk_dispositions] == ["atl-1", "atl-2"]


def _repair_call(client: MockLLMClient, tmp_path):
    client.set_response_for(
        LossAnalysisDraft, [_attempt_two_response(), _empty_gap_response()]
    )
    client.set_response_for(
        DispositionRepairResponse, {"risk_dispositions": _disposition_repair_rows()}
    )
    derive_loss_analysis(
        llm_client=client,
        use_case_text=_USE_CASE,
        risk_cards=_occiai_cards(),
        run_dir=tmp_path,
    )
    selected = set(_SAVED_MISSING_SEVEN)
    return client.calls[1].response_format, [
        ref for ref in _SAVED_CARD_IDS if ref in selected
    ]


def test_disposition_repair_unguided_request_schema_is_mains(tmp_path):
    model, _ = _repair_call(MockLLMClient(), tmp_path)

    assert model is DispositionRepairResponse
    _assert_main_payload("stage1a_disposition_repair", model)


def test_disposition_repair_guided_schema_asks_for_each_selected_card(tmp_path):
    model, selected = _repair_call(_guided(MockLLMClient()), tmp_path)

    assert issubclass(model, DispositionRepairResponse)
    schema = model.model_json_schema()
    assert _keyed_refs(schema["properties"]["risk_dispositions"]) == [
        [ref] for ref in selected
    ]


# --- Target discovery interpretation ----------------------------------------


def _discovery_request(count: int = 2) -> TargetInterpretationRequest:
    return TargetInterpretationRequest(
        batch_id="BATCH-1",
        tools=tuple(
            TargetToolPromptView(
                handle=f"TOOL-{index}",
                name=f"tool_{index}",
                input_schema={"type": "object"},
                evidence_refs=(f"inventory:tool:tool_{index}:name",),
            )
            for index in range(1, count + 1)
        ),
    )


def _discovery_formats(*, guided: bool, count: int = 2) -> tuple[type, type]:
    """Capture the interpretation and verification response formats."""
    request = _discovery_request(count)
    seen: list[type] = []

    def fake_call_with_policy(**kwargs):
        model = kwargs["response_format"]
        seen.append(model)
        if model.__name__ == "TargetInterpretationProviderVerification":
            data = {
                "verdicts": [
                    {"tool_handle": tool.handle, "reason": "r", "agreement": "agree"}
                    for tool in request.tools
                ]
            }
        else:
            data = {
                "interpretations": [
                    {
                        "tool_handle": tool.handle,
                        "disposition": "supported",
                        "likely_effect": "read",
                        "likely_state_effect": "none",
                        "semantic_roles": [],
                        "observer_tool_handles": [],
                        "evidence_refs": list(tool.evidence_refs),
                        "rationale": "r",
                    }
                    for tool in request.tools
                ]
            }
        value = model.model_validate(data)
        result = LLMResult(
            content=value,
            duration_ms=1,
            system_prompt=kwargs["system_prompt"],
            user_prompt=kwargs["user_prompt"],
        )
        return CallOutcome(value, result, None, 1)

    client = SimpleNamespace(model="fixture-model", use_guided_decoding=guided)
    with patch(
        "asago_scenario_generator.target_discovery.llm_interpreter.call_with_policy",
        side_effect=fake_call_with_policy,
    ):
        adapter = TargetDiscoveryLlmInterpreter(client)
        adapter.verify(request, adapter.interpret(request))
    return seen[0], seen[1]


def test_discovery_unguided_request_schemas_are_mains():
    interpretation, verification = _discovery_formats(guided=False, count=7)

    _assert_main_payload("discovery_interpretation_7", interpretation)
    _assert_main_payload("discovery_verification_7", verification)


def test_discovery_guided_interpretation_schema_closes_roles_and_handles():
    interpretation, _ = _discovery_formats(guided=True)
    schema = interpretation.model_json_schema()
    rows = schema["properties"]["interpretations"]
    assert rows["minItems"] == rows["maxItems"] == 2
    row = _resolve(schema, rows["items"])["properties"]

    # A lone ``text_search`` choice absorbs every other role a guided model
    # means to write, so the enum also offers roles that code does not act on.
    roles = row["semantic_roles"]
    assert roles["items"]["enum"][0] == "text_search"
    assert set(roles["items"]["enum"]) == set(SEMANTIC_ROLE_VOCABULARY)
    assert len(SEMANTIC_ROLE_VOCABULARY) > 1
    assert roles["maxItems"] == 1
    assert row["tool_handle"]["enum"] == ["TOOL-1", "TOOL-2"]
    assert row["observer_tool_handles"]["items"]["enum"] == ["TOOL-1", "TOOL-2"]
    # A batch-wide reference enum lets a row cite another tool's fields.
    assert "enum" not in row["evidence_refs"]["items"]


def test_discovery_guided_interpretation_local_validation_is_unchanged():
    interpretation, _ = _discovery_formats(guided=True)
    parsed = interpretation.model_validate(
        {
            "interpretations": [
                {
                    "tool_handle": handle,
                    "disposition": "supported",
                    "likely_effect": "read",
                    "likely_state_effect": "none",
                    "semantic_roles": ["reader"],
                    "observer_tool_handles": [],
                    "evidence_refs": ["inventory:tool:x:name"],
                    "rationale": "r",
                }
                for handle in ("TOOL-1", "TOOL-2")
            ]
        }
    )
    assert parsed.interpretations[0].semantic_roles == ("reader",)


def test_discovery_guided_verification_schema_closes_handles():
    _, verification = _discovery_formats(guided=True)
    schema = verification.model_json_schema()
    row = _resolve(schema, schema["properties"]["verdicts"]["items"])["properties"]
    assert row["tool_handle"]["enum"] == ["TOOL-1", "TOOL-2"]


# --- Transport: the flag selects the schema, not the request shape -----------


def _captured_response_format(use_guided_decoding: bool) -> dict:
    client = LLMClient(
        base_url="http://offline.invalid/v1",
        api_key="test",
        model="m",
        use_guided_decoding=use_guided_decoding,
    )
    message = SimpleNamespace(content=json.dumps(_stage1_profile_dict()))
    response = SimpleNamespace(
        choices=[SimpleNamespace(message=message, finish_reason="stop")],
        usage=None,
    )
    create = MagicMock(return_value=response)
    client._client = SimpleNamespace(
        chat=SimpleNamespace(completions=SimpleNamespace(create=create))
    )
    client.complete("s", "u", response_format=Stage1Profile)
    return create.call_args.kwargs["response_format"]


def test_strict_transport_sends_the_supplied_schema_regardless_of_the_flag():
    """Only call sites choose tighter schemas; the transport never does."""
    assert _captured_response_format(True) == _captured_response_format(False)
