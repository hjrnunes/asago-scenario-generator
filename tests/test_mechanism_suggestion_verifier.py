"""The mechanism verifier's entry point for structural suggestions."""

from __future__ import annotations

import json

import pytest
import yaml

from asago_scenario_generator.stpa.mechanism_library import (
    MechanismId,
    bundled_mechanism_library,
)
from asago_scenario_generator.stpa.obligation_aware.mechanism_suggestion_provider import (
    INCOMPLETE_VERIFICATION,
    MECHANISM_SUGGESTION_BATCH_SIZE,
    suggestion_system_hazards,
    suggestion_verification_items,
)
from asago_scenario_generator.stpa.obligation_aware.mechanism_suggestions import (
    SuggestionVerificationRequest,
)
from asago_scenario_generator.stpa.obligation_aware.prompts import (
    _known_mechanism_glossary_yaml,
    _yaml,
)
from asago_scenario_generator.stpa.obligation_aware.provider import (
    ObligationAwareLLMAdapter,
)
from asago_scenario_generator.stpa.obligation_aware.stpa_index import (
    CROSS_CONTROLLER_MECHANISM,
    SOURCE_MECHANISMS,
    MechanismCandidate,
)
from tests.helpers.mechanism_suggestions import (
    ACTION_PATH,
    LINK_PATH,
    suggestion_structure,
)
from tests.helpers.obligation_aware import _controls, _loss_analysis
from tests.helpers.scripted_client import ScriptedClient

_USER_CLAIM = MechanismCandidate(MechanismId.user_claim, ACTION_PATH)
_DELEGATED = MechanismCandidate(MechanismId.delegated_authority, LINK_PATH)


def _verdicts(*relationships: str) -> str:
    return json.dumps(
        {
            "verdicts": [
                {
                    "item_handle": f"S{number}",
                    "relationship": relationship,
                    "rationale": f"rationale {number}",
                }
                for number, relationship in enumerate(relationships, 1)
            ]
        }
    )


def _request(*candidates: MechanismCandidate) -> SuggestionVerificationRequest:
    return SuggestionVerificationRequest(
        candidates=candidates,
        control_structure=suggestion_structure(),
        loss_analysis=_loss_analysis(),
    )


def _adapter(client, tmp_path) -> ObligationAwareLLMAdapter:
    return ObligationAwareLLMAdapter(client, run_dir=tmp_path, controls=_controls())


# Every mechanism the join can name: one per untrusted source kind, and the
# one for a path that reaches another controller.
_SUGGESTABLE = (*dict.fromkeys(SOURCE_MECHANISMS.values()), CROSS_CONTROLLER_MECHANISM)


def _suggestion_call(candidates, tmp_path) -> dict:
    client = ScriptedClient([_verdicts(*["insufficient_evidence"] * len(candidates))])
    _adapter(client, tmp_path).verify_mechanism_suggestions(_request(*candidates))
    (call,) = client.calls
    return call


def _every_suggestable_mechanism() -> tuple[MechanismCandidate, ...]:
    return tuple(
        MechanismCandidate(
            mechanism,
            LINK_PATH if mechanism is CROSS_CONTROLLER_MECHANISM else ACTION_PATH,
        )
        for mechanism in _SUGGESTABLE
    )


def test_an_item_shows_the_entry_and_exact_path_descriptions_only() -> None:
    items = suggestion_verification_items(
        (_USER_CLAIM, _DELEGATED), suggestion_structure()
    )

    entry = bundled_mechanism_library().entry("user_claim")
    assert items[0] == {
        "item_handle": "S1",
        "distinctive_mechanism": {"name": entry.name, "description": entry.question},
        "selected_structural_path": [
            {"id": "RESP-1", "description": "Handle refunds"},
            {"id": "FB-1-1", "description": "Requested refund amount"},
            {"id": "PM-1-1", "description": "Refund amount"},
            {"id": "CA-1-1", "description": "Refund"},
            {"id": "CP-1", "description": "Chat"},
        ],
        "known_mechanism_refs": ["user_claim"],
    }
    assert [item["id"] for item in items[1]["selected_structural_path"]] == [
        "RESP-1",
        "FB-1-1",
        "PM-1-1",
        "CL-1",
        "CM-1",
        "RESP-2",
    ]
    assert items[1]["known_mechanism_refs"] == ["delegated_authority"]


def test_the_hazards_list_each_hazard_with_its_governing_constraints() -> None:
    assert suggestion_system_hazards(_loss_analysis()) == [
        {
            "id": "H-1",
            "description": "An unsafe request is accepted.",
            "governing_constraints": [
                {"id": "SC-1", "description": "Requests must satisfy policy."}
            ],
        }
    ]


def test_a_suggestion_without_risk_alignment_is_judged_against_its_entry(
    tmp_path,
) -> None:
    client = ScriptedClient([_verdicts("mechanism_specific", "adjacent_control")])

    verdicts = _adapter(client, tmp_path).verify_mechanism_suggestions(
        _request(_USER_CLAIM, _DELEGATED)
    )

    assert [(item.candidate, item.relationship) for item in verdicts] == [
        (_USER_CLAIM, "mechanism_specific"),
        (_DELEGATED, "adjacent_control"),
    ]
    assert [item.survives for item in verdicts] == [True, False]
    (call,) = client.calls
    assert call["max_completion_tokens"] == 1024
    assert call["temperature"] == 0.0
    entry = bundled_mechanism_library().entry("user_claim")
    prompt = " ".join(call["user_prompt"].split())
    for text in (*entry.required_evidence, *entry.counterexamples):
        assert " ".join(text.split()) in prompt
    assert "An unsafe request is accepted." in prompt
    assert "Requests must satisfy policy." in prompt
    for prompt_text in (call["system_prompt"], call["user_prompt"]):
        assert "risk_alignment" not in prompt_text
        assert "source_kind" not in prompt_text
        assert "authority_for_update" not in prompt_text
    assert "structural suggestion" in call["system_prompt"]


def test_a_repeated_candidate_is_judged_once(tmp_path) -> None:
    client = ScriptedClient([_verdicts("insufficient_evidence")])

    verdicts = _adapter(client, tmp_path).verify_mechanism_suggestions(
        _request(_USER_CLAIM, _USER_CLAIM)
    )

    assert [item.relationship for item in verdicts] == ["insufficient_evidence"]


def test_a_failed_call_leaves_its_candidates_without_a_verdict(tmp_path) -> None:
    client = ScriptedClient(["not json"])

    verdicts = _adapter(client, tmp_path).verify_mechanism_suggestions(
        _request(_USER_CLAIM)
    )

    assert len(client.calls) == 1
    (verdict,) = verdicts
    assert verdict.relationship is None
    assert verdict.rationale == INCOMPLETE_VERIFICATION
    assert not verdict.survives


def test_candidates_are_judged_in_bounded_batches(tmp_path) -> None:
    structure = suggestion_structure()
    candidates = tuple(
        MechanismCandidate(MechanismId.user_claim, (f"FB-{number}", "PM-1-1", "CA-1-1"))
        for number in range(MECHANISM_SUGGESTION_BATCH_SIZE + 1)
    )
    channels = structure.responsibilities[0].feedback_channels
    template = channels[0]
    structure.responsibilities[0].feedback_channels = [
        template.model_copy(update={"fb_id": candidate.path[0]})
        for candidate in candidates
    ]
    request = SuggestionVerificationRequest(
        candidates=candidates,
        control_structure=structure,
        loss_analysis=_loss_analysis(),
    )
    client = ScriptedClient(
        [
            _verdicts(*["mechanism_specific"] * MECHANISM_SUGGESTION_BATCH_SIZE),
            _verdicts("adjacent_control"),
        ]
    )

    verdicts = _adapter(client, tmp_path).verify_mechanism_suggestions(request)

    assert len(client.calls) == 2
    assert "S9" not in client.calls[0]["user_prompt"]
    assert "S1" in client.calls[1]["user_prompt"]
    assert [item.relationship for item in verdicts][-2:] == [
        "mechanism_specific",
        "adjacent_control",
    ]


@pytest.mark.parametrize("handle", ["S2", "R1"])
def test_a_verdict_for_another_handle_is_repaired_once(tmp_path, handle) -> None:
    wrong = json.dumps(
        {
            "verdicts": [
                {
                    "item_handle": handle,
                    "relationship": "mechanism_specific",
                    "rationale": "wrong handle",
                }
            ]
        }
    )
    client = ScriptedClient([wrong, _verdicts("adjacent_control")])

    (verdict,) = _adapter(client, tmp_path).verify_mechanism_suggestions(
        _request(_USER_CLAIM)
    )

    assert verdict.relationship == "adjacent_control"
    assert len(client.calls) == 2


def test_the_suggestion_request_never_speaks_of_how_code_nominated_it(
    tmp_path,
) -> None:
    candidates = _every_suggestable_mechanism()
    call = _suggestion_call(candidates, tmp_path)
    items = suggestion_verification_items(candidates, suggestion_structure())

    # Library entries and structure descriptions are data and may use these
    # words; only the request's own instructions must not.
    instructions = call["user_prompt"]
    for block in (
        _yaml([dict(item) for item in items]),
        _known_mechanism_glossary_yaml(items),
        _yaml(suggestion_system_hazards(_loss_analysis())),
    ):
        assert block in instructions
        instructions = instructions.replace(block, "")
    for text in (call["system_prompt"], instructions):
        lowered = " ".join(text.lower().split())
        for term in (
            "source kind",
            "source_kind",
            "authority",
            "authoritative",
            "trust",
            "recorded",
            "filter",
        ):
            assert term not in lowered
    for item in items:
        assert set(item) == {
            "item_handle",
            "distinctive_mechanism",
            "selected_structural_path",
            "known_mechanism_refs",
        }


@pytest.mark.parametrize("mechanism", _SUGGESTABLE, ids=lambda item: item.value)
def test_the_suggestion_request_shows_its_mechanisms_counterexamples(
    tmp_path, mechanism
) -> None:
    (candidate,) = [
        item for item in _every_suggestable_mechanism() if item.mechanism is mechanism
    ]
    call = _suggestion_call((candidate,), tmp_path)

    # Read the glossary back from the rendered message, so YAML quoting of the
    # entry's text cannot hide or fake a match.
    user = call["user_prompt"]
    start = user.index("known_mechanism_refs):\n") + len("known_mechanism_refs):\n")
    end = user.index("\nSystem hazards (")
    (shown,) = yaml.safe_load(user[start:end])
    entry = bundled_mechanism_library().entry(mechanism)
    assert entry.counterexamples
    assert shown["id"] == mechanism.value
    assert shown["counterexamples"] == list(entry.counterexamples)
    assert shown["required_evidence"] == list(entry.required_evidence)
