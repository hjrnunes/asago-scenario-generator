"""The target-derived ICA draft request closes `slot_id` and leaves out `ica_id`.

The draft schema lists exactly the request's slot IDs as `slot_id` values and
has no `ica_id` field, because code binds each ICA ID from its resolved slot.
Local parsing stays lenient, so the mapping of a `<slot>:<digits>` slot_id
and the drop of any other unknown slot remain as a backstop for a server that
does not enforce the schema. The fixture is the trimmed L1 klarna-r2 draft of
the b8-glm batch; every test uses a fake client.
"""

from __future__ import annotations

from tests.stpa.sp1_helpers import MockLLMClient
from tests.stpa.test_target_derived_ica_unknown_slots import (
    _INCORRECT,
    _NOT_PROVIDED,
    _WRONG_TIMING,
    _FIXTURE,
    _decisions,
    _klarna_request,
    _proposed,
    _recorded_draft,
)

from asago_scenario_generator.stpa.target_realization import (
    TargetDerivedICALlmFinder,
)
from asago_scenario_generator.stpa.target_realization.provider import (
    TargetDerivedICADraftResponse,
)


def _finding_schema(client: MockLLMClient) -> dict:
    schema = client.calls[0].response_format.model_json_schema()
    ref = schema["properties"]["findings"]["items"]["$ref"].rsplit("/", 1)[-1]
    return schema["$defs"][ref]


def _draft_without_ica_ids() -> dict:
    """The recorded draft as a schema-enforcing server would return it."""
    draft = _recorded_draft()
    for finding in draft["findings"]:
        finding.pop("ica_id")
        finding["slot_id"] = finding["slot_id"].rsplit(":", 1)[0]
    return draft


def test_draft_schema_closes_slot_id_to_the_request_slots(tmp_path) -> None:
    client = MockLLMClient()
    client.set_response_queue([_draft_without_ica_ids(), _decisions()])

    TargetDerivedICALlmFinder(client, tmp_path, temperature=0.4)(_klarna_request())

    finding = _finding_schema(client)
    assert finding["properties"]["slot_id"]["enum"] == list(_FIXTURE["request_slots"])
    assert "ica_id" not in finding["properties"]
    assert "ica_id" not in finding.get("required", [])


def test_draft_schema_keeps_the_static_descriptions(tmp_path) -> None:
    client = MockLLMClient()
    client.set_response_queue([_draft_without_ica_ids(), _decisions()])

    TargetDerivedICALlmFinder(client, tmp_path, temperature=0.4)(_klarna_request())

    sent = client.calls[0].response_format.model_json_schema()
    static = TargetDerivedICADraftResponse.model_json_schema()
    assert sent["description"] == static["description"]
    assert (
        _finding_schema(client)["description"]
        == (static["$defs"]["TargetDerivedICADraft"]["description"])
    )


def test_draft_without_ica_ids_is_bound_and_verified(tmp_path) -> None:
    canonical = (f"{_INCORRECT}:1", f"{_NOT_PROVIDED}:1", f"{_WRONG_TIMING}:1")
    client = MockLLMClient()
    client.set_response_queue([_draft_without_ica_ids(), _decisions(*canonical)])
    finder = TargetDerivedICALlmFinder(client, tmp_path, temperature=0.4)

    response = finder(_klarna_request())

    assert [(f.slot_id, f.ica_id) for f in response.findings] == [
        (_INCORRECT, f"{_INCORRECT}:1"),
        (_NOT_PROVIDED, f"{_NOT_PROVIDED}:1"),
        (_WRONG_TIMING, f"{_WRONG_TIMING}:1"),
    ]
    assert response.provider_diagnostics == ()
    assert [f["ica_id"] for f in _proposed(client.calls[1].user_prompt)] == list(
        canonical
    )


def test_an_unknown_slot_is_dropped_and_named_by_position(tmp_path) -> None:
    draft = _draft_without_ica_ids()
    draft["findings"][0]["slot_id"] = "RESP-9:CA-9-1:INCORRECT"
    client = MockLLMClient()
    client.set_response_queue(
        [draft, _decisions(f"{_NOT_PROVIDED}:1", f"{_WRONG_TIMING}:1")]
    )

    response = TargetDerivedICALlmFinder(client, tmp_path, temperature=0.4)(
        _klarna_request()
    )

    assert [f.ica_id for f in response.findings] == [
        f"{_NOT_PROVIDED}:1",
        f"{_WRONG_TIMING}:1",
    ]
    assert response.provider_diagnostics == (
        "target-derived ICA finding findings[0] is unresolved: unknown slot "
        "RESP-9:CA-9-1:INCORRECT; dropped before verification",
    )
