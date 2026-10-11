"""The risk-derivation request bounds each loss's `source_risk_cards`.

Without guided decoding the request schema still lists the supplied card IDs
as the only `source_risk_cards` items and caps the list at 32 items, above
the longest list a stop reply has written (23). It adds no `uniqueItems`.
A probe found that Gemma enforces `enum` and `maxItems`, that an enum does
not stop repeats, and that a list cut at `maxItems` can garble its last
string. The cards and losses are the trimmed recorded Airbnb reply of
``test_stage1a_truncated_losses``; every test uses a fake client.
"""

from __future__ import annotations

import json

from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysisDraft
from asago_scenario_generator.stpa.system_model.loss_analysis import (
    _Stage1aRiskProviderDraft,
)
from tests.helpers.stage1a_targeted_repair import _stage1a_entries
from tests.stpa.sp1_helpers import MockLLMClient
from tests.stpa.test_stage1a_truncated_losses import (
    _CARD_IDS,
    _COMPLETE_LOSSES,
    _derive,
    _gap_reply,
    _loss,
)

_MAX_ITEMS = 32


def _risk_request_type(client: MockLLMClient, tmp_path) -> type:
    _derive(client, tmp_path)
    return next(
        call.response_format
        for call in client.calls
        if call.response_format is not None
        and issubclass(call.response_format, _Stage1aRiskProviderDraft)
    )


def _loss_schemas(model: type) -> list[dict]:
    schema = model.model_json_schema()
    loss_ref = schema["properties"]["risk_card_losses"]["items"]["$ref"]
    use_case_ref = schema["properties"]["use_case_losses"]["items"]["$ref"]
    return [schema["$defs"][ref.rsplit("/", 1)[-1]] for ref in (loss_ref, use_case_ref)]


def _dispositions() -> list[dict]:
    return [
        {
            "risk_ref": card,
            "disposition": "not_applicable",
            "loss_ids": [],
            "reason": "Neutralized reason: no declared loss here.",
        }
        for card in _CARD_IDS
    ]


def _reply(first_loss_cards: list[str]) -> dict:
    handle, _ = _COMPLETE_LOSSES[0]
    return {
        "risk_card_losses": [
            _loss(handle, first_loss_cards),
            *(_loss(*loss) for loss in _COMPLETE_LOSSES[1:]),
        ],
        "use_case_losses": [],
        "hazards": [],
        "security_constraints": [],
        "risk_dispositions": _dispositions(),
    }


def test_unguided_request_closes_and_caps_source_risk_cards(tmp_path) -> None:
    client = MockLLMClient()
    client.set_response_for(
        LossAnalysisDraft, [_reply(list(_COMPLETE_LOSSES[0][1])), _gap_reply()]
    )

    model = _risk_request_type(client, tmp_path)

    assert model.__name__ == "_Stage1aRiskProviderDraft"
    for loss in _loss_schemas(model):
        cards = loss["properties"]["source_risk_cards"]
        assert cards["items"] == {"type": "string", "enum": list(_CARD_IDS)}
        assert cards["maxItems"] == _MAX_ITEMS
        assert "uniqueItems" not in cards
    dispositions = model.model_json_schema()["properties"]["risk_dispositions"]
    assert "prefixItems" not in dispositions


def test_unguided_request_keeps_the_static_descriptions(tmp_path) -> None:
    client = MockLLMClient()
    client.set_response_for(
        LossAnalysisDraft, [_reply(list(_COMPLETE_LOSSES[0][1])), _gap_reply()]
    )

    sent = _risk_request_type(client, tmp_path).model_json_schema()

    static = _Stage1aRiskProviderDraft.model_json_schema()
    assert sent["description"] == static["description"]
    assert (
        sent["$defs"]["_ProviderLoss"]["description"]
        == (static["$defs"]["_ProviderLoss"]["description"])
    )


def test_a_list_cut_at_the_cap_with_a_garbled_last_item_parses(tmp_path) -> None:
    """Repeats collapse and the reply goes on in one request.

    The garbled item names no supplied card. No check rejects or drops an
    unsupplied ID in `source_risk_cards`, so the loss keeps it; this pins
    that gap so a later fix changes the test on purpose.
    """
    first = list(_COMPLETE_LOSSES[0][1])
    garbled = f'{first[0]}", '
    cut = [first[index % 2] for index in range(_MAX_ITEMS - 1)] + [garbled]
    client = MockLLMClient()
    client.set_response_for(LossAnalysisDraft, [json.dumps(_reply(cut)), _gap_reply()])

    result = _derive(client, tmp_path)

    assert [entry["step"] for entry in _stage1a_entries(tmp_path)] == [
        "risk_derivation",
        "gap_analysis",
    ]
    assert len(result.risk_card_losses) == len(_COMPLETE_LOSSES)
    cited = [
        loss.source_risk_cards
        for loss in result.risk_card_losses
        if set(first) <= set(loss.source_risk_cards)
    ]
    assert cited == [sorted({*first, garbled})]
