"""Transport schemas close the vocabularies that guided decoding must obey.

Guided decoding (vLLM ``response_format`` JSON Schema) samples only what the
schema allows.  A field the schema leaves optional can be omitted, and a free
string can hold an invented label.  These tests pin the request schemas that
keep a guided model inside the values code later requires, and check that
local validation still reports violations through the correction path.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from asago_scenario_generator.models.capability_profile import (
    KCX_SUBCODES,
    VALID_KC_SUBCODES,
    CapabilityProfile,
    Stage1Profile,
)
from asago_scenario_generator.stpa.infra.llm import LLMClient
from asago_scenario_generator.stpa.infra.llm_helpers import StageError
from asago_scenario_generator.stpa.system_model.loss_analysis import (
    _risk_provider_draft_type,
    _Stage1aRiskProviderDraft,
    derive_loss_analysis,
)
from asago_scenario_generator.stpa.system_model.profile import (
    derive_capability_profile,
)
from asago_scenario_generator.target_discovery import (
    TargetInterpretationRequest,
    TargetToolPromptView,
)
from asago_scenario_generator.target_discovery.llm_interpreter import (
    SEMANTIC_ROLE_VOCABULARY,
    _provider_response_model,
    _provider_verification_model,
)
from tests.stpa.sp1_helpers import (
    MockLLMClient,
    make_risk_cards,
    valid_gap_draft_dict,
    valid_risk_draft_dict,
)


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


def test_stage1_profile_schema_requires_kc_subcodes_from_closed_vocabulary():
    schema = Stage1Profile.model_json_schema()
    kc = schema["properties"]["kc_subcodes"]

    assert "kc_subcodes" in schema["required"]
    assert kc["minItems"] == 1
    assert set(kc["items"]["enum"]) == set(VALID_KC_SUBCODES) | set(KCX_SUBCODES)


def test_stage1_profile_schema_asks_for_tool_inventory():
    """qwen38-oc omitted an optional inventory, even after the correction."""
    schema = Stage1Profile.model_json_schema()

    assert "tool_inventory" in schema["required"]
    without = _stage1_profile_dict(kc_subcodes=["KC1.1"])
    del without["tool_inventory"]
    assert Stage1Profile.model_validate(without).tool_inventory == []


def test_stage1_profile_rejects_a_draft_that_cannot_be_promoted():
    """Promotion failures surface as draft validation errors, not later."""
    with pytest.raises(ValueError, match="tool_inventory"):
        Stage1Profile.model_validate(
            _stage1_profile_dict(kc_subcodes=["KC1.1", "KC6.1.1"], tool_inventory=[])
        )


def test_stage1b_missing_kc_subcodes_is_corrected_in_the_call(tmp_path):
    missing = _stage1_profile_dict()
    del missing["kc_subcodes"]
    client = MockLLMClient()
    client.set_response_for(Stage1Profile, [missing, _stage1_profile_dict()])

    profile = derive_capability_profile(
        llm_client=client, use_case_text="Use case", run_dir=tmp_path
    )

    assert isinstance(profile, CapabilityProfile)
    assert profile.kc_subcodes == ["KC1.1", "KC6.1.1"]
    assert len(client.calls) == 2
    assert "kc_subcodes" in client.calls[1].user_prompt


def test_stage1b_uncorrected_kc_subcodes_fail_as_a_stage_error(tmp_path):
    missing = _stage1_profile_dict(kc_subcodes=[])
    client = MockLLMClient()
    client.set_response_for(Stage1Profile, [missing, missing])

    with pytest.raises(StageError, match="kc_subcodes"):
        derive_capability_profile(
            llm_client=client, use_case_text="Use case", run_dir=tmp_path
        )
    assert len(client.calls) == 2


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


def test_risk_provider_schema_asks_for_each_supplied_card_once_in_order():
    """An enum plus a row count still let qwen38-oc repeat and skip cards."""
    model = _risk_provider_draft_type(["risk-a", "risk-b"])
    schema = model.model_json_schema()

    assert issubclass(model, _Stage1aRiskProviderDraft)
    assert model.__name__ == "_Stage1aRiskProviderDraft"
    assert _keyed_refs(schema["properties"]["risk_dispositions"]) == [
        ["risk-a"],
        ["risk-b"],
    ]
    for collection in ("risk_card_losses", "use_case_losses"):
        loss = _resolve(schema, schema["properties"][collection]["items"])
        assert loss["properties"]["source_risk_cards"]["items"]["enum"] == [
            "risk-a",
            "risk-b",
        ]
        assert next(iter(loss["properties"])) == "handle"


def test_risk_provider_local_validation_is_unchanged():
    """An unknown ID still parses, so risk accounting writes the feedback."""
    model = _risk_provider_draft_type(["risk-a"])
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


def test_risk_provider_without_cards_keeps_the_static_wire():
    assert _risk_provider_draft_type([]) is _Stage1aRiskProviderDraft


def test_risk_derivation_call_sends_the_request_local_schema(tmp_path):
    from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysisDraft

    client = MockLLMClient()
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

    risk_call = next(
        call
        for call in client.calls
        if call.response_format is not None
        and issubclass(call.response_format, _Stage1aRiskProviderDraft)
    )
    schema = risk_call.response_format.model_json_schema()
    assert _keyed_refs(schema["properties"]["risk_dispositions"]) == [
        [card.risk_id] for card in cards
    ]


def test_disposition_repair_schema_asks_for_each_selected_card_once(tmp_path):
    from tests.stpa.test_stage1a_targeted_repair import (
        _SAVED_CARD_IDS,
        _SAVED_MISSING_SEVEN,
        _USE_CASE,
        _attempt_two_response,
        _disposition_repair_rows,
        _empty_gap_response,
        _occiai_cards,
    )
    from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysisDraft
    from asago_scenario_generator.stpa.system_model.loss_analysis_repair import (
        DispositionRepairResponse,
    )

    client = MockLLMClient()
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

    repair_call = client.calls[1]
    assert issubclass(repair_call.response_format, DispositionRepairResponse)
    schema = repair_call.response_format.model_json_schema()
    selected = set(_SAVED_MISSING_SEVEN)
    supplied_order = [ref for ref in _SAVED_CARD_IDS if ref in selected]
    assert _keyed_refs(schema["properties"]["risk_dispositions"]) == [
        [ref] for ref in supplied_order
    ]


# --- Target discovery interpretation ----------------------------------------


def _discovery_request() -> TargetInterpretationRequest:
    return TargetInterpretationRequest(
        batch_id="BATCH-1",
        tools=(
            TargetToolPromptView(
                handle="TOOL-1",
                name="retrieve_policy",
                input_schema={"type": "object"},
                evidence_refs=(
                    "inventory:tool:retrieve_policy:name",
                    "inventory:tool:retrieve_policy:description",
                ),
            ),
            TargetToolPromptView(
                handle="TOOL-2",
                name="get_state_summary",
                input_schema={"type": "object"},
                evidence_refs=("inventory:tool:get_state_summary:name",),
            ),
        ),
    )


def test_interpretation_schema_closes_roles_and_handles():
    request = _discovery_request()
    schema = _provider_response_model(len(request.tools), tools=request.tools)
    schema = schema.model_json_schema()
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
    assert {"read", "observe", "unknown"} <= set(
        _resolve(schema, row["likely_effect"])["enum"]
    )


def test_interpretation_local_validation_is_unchanged():
    request = _discovery_request()
    model = _provider_response_model(len(request.tools), tools=request.tools)
    parsed = model.model_validate(
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


def test_verification_schema_closes_handles():
    request = _discovery_request()
    schema = _provider_verification_model(
        len(request.tools), tools=request.tools
    ).model_json_schema()
    row = _resolve(schema, schema["properties"]["verdicts"]["items"])["properties"]
    assert row["tool_handle"]["enum"] == ["TOOL-1", "TOOL-2"]


# --- Transport: the same schema reaches guided and unguided profiles ---------


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


def test_strict_calls_send_the_same_schema_with_or_without_guided_decoding():
    guided = _captured_response_format(True)
    unguided = _captured_response_format(False)

    assert guided == unguided
    assert guided["type"] == "json_schema"
    assert "kc_subcodes" in guided["json_schema"]["schema"]["required"]
