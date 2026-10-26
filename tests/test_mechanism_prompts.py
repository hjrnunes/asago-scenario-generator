"""The routing and verifier requests render the linked mechanism entries.

Each test reads the rendered request, not the template: the concern or item
names its pattern's mechanisms, and the glossary block of the user message
carries exactly the library entry's question, evidence and counterexamples.
"""

from __future__ import annotations

from typing import Any

import pytest
import yaml

from asago_scenario_generator.data.loaders import load_attack_patterns
from asago_scenario_generator.models.attack_pattern_chain import AttackPattern
from asago_scenario_generator.stpa.mechanism_library import (
    bundled_mechanism_data_digest,
    bundled_mechanism_library,
)
from asago_scenario_generator.stpa.obligation_aware import provider
from asago_scenario_generator.stpa.obligation_aware.contracts import (
    StructuralRoutingRequest,
)
from asago_scenario_generator.stpa.obligation_aware.prompts import (
    build_mechanism_verification_prompts,
    build_structural_routing_prompts,
    known_mechanism_glossary,
    obligation_prompt_template_hashes,
)
from asago_scenario_generator.stpa.obligation_aware.provider import (
    ObligationAwareLLMAdapter,
)
from asago_scenario_generator.stpa.obligation_aware.routing import (
    build_neutral_briefs,
)
from asago_scenario_generator.stpa.threat_enum.slot_creation import create_slots
from tests.helpers.obligation_aware import _control_structure, _loss_analysis
from tests.helpers.obligation_factory import make_plan
from tests.helpers.projection_factory import get_test_raw_pattern
from tests.test_obligation_prompt_bytes import _RecordingClient, _controls, _inputs
from tests.helpers.known_mechanism import linked_brief

_ROUTING_GLOSSARY = (
    "Known mechanism glossary (each mechanism is defined once; concerns refer to "
    "it by\nknown_mechanism_refs):\n"
)
_VERIFIER_GLOSSARY = (
    "Known mechanism glossary (each mechanism is defined once; items refer to it "
    "by\nknown_mechanism_refs):\n"
)


def _block(text: str, heading: str, end: str) -> Any:
    start = text.index(heading) + len(heading)
    return yaml.safe_load(text[start : text.index(end, start)])


def _entry_view(mechanism_id: str) -> dict[str, Any]:
    entry = bundled_mechanism_library().entry(mechanism_id)
    return {
        "id": entry.id.value,
        "question": entry.question,
        "required_evidence": list(entry.required_evidence),
        "counterexamples": list(entry.counterexamples),
    }


def _brief():
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    return build_neutral_briefs(make_plan(), (pattern,))[0]


def _routing(brief) -> tuple[str, str]:
    structure = _control_structure()
    return build_structural_routing_prompts(
        briefs=(brief,),
        loss_analysis=_loss_analysis(),
        control_structure=structure,
        slots=create_slots(structure),
    )


def test_a_routing_concern_names_and_the_glossary_defines_its_mechanisms() -> None:
    system, user = _routing(linked_brief(_brief(), "AP-T6-03"))

    (concern,) = _block(user, "attack_pattern_name):\n", _ROUTING_GLOSSARY)
    glossary = _block(user, _ROUTING_GLOSSARY, "Compact obligation questions:")
    assert concern["known_mechanism_refs"] == ["retrieved_instructions"]
    assert glossary == [_entry_view("retrieved_instructions")]
    assert "`known_mechanism_refs`" in system
    assert "`required_evidence`" in system and "`counterexamples`" in system


def test_an_unlinked_routing_concern_shows_no_mechanism_material() -> None:
    system, user = _routing(_brief())

    assert "known_mechanism" not in system + user
    assert "Known mechanism glossary" not in user


def test_a_verifier_item_names_and_the_glossary_defines_its_mechanisms() -> None:
    record = load_attack_patterns()["AP-T6-08"]
    item = {
        "item_handle": "R1",
        "distinctive_mechanism": {
            "name": record["name"],
            "description": record["description"],
        },
        "selected_structural_path": [{"id": "CA-1-1", "description": "Reply."}],
        "known_mechanism_refs": ["user_claim"],
    }

    system, user = build_mechanism_verification_prompts([item])

    glossary = _block(user, _VERIFIER_GLOSSARY, "Return a JSON object")
    assert glossary == [_entry_view("user_claim")]
    assert "`known_mechanism_refs`" in system


def test_the_glossary_keeps_the_signature_and_safe_behavior_out() -> None:
    rows = known_mechanism_glossary(["delegated_authority", "user_claim"])

    assert [row["id"] for row in rows] == ["user_claim", "delegated_authority"]
    for row in rows:
        assert set(row) == {"id", "question", "required_evidence", "counterexamples"}


def test_an_unknown_mechanism_reference_fails() -> None:
    with pytest.raises(ValueError, match="unknown mechanism references"):
        known_mechanism_glossary(["fabricated_approval"])


def _routing_request() -> tuple[StructuralRoutingRequest, dict[str, Any]]:
    inputs = _inputs()
    request = StructuralRoutingRequest(
        batch_id="batch-1",
        briefs=inputs["briefs"],
        loss_analysis=inputs["loss_analysis"],
        control_structure=inputs["control_structure"],
        slots=create_slots(inputs["control_structure"]),
        controls=_controls(),
    )
    return request, inputs


def test_verifier_items_name_the_mechanisms_of_their_pattern() -> None:
    request, inputs = _routing_request()
    patterns = {item.obligation_id: item.attack_pattern_id for item in request.briefs}

    items = provider._mechanism_verification_items(request, inputs["routes"])

    refs = {
        patterns[route.obligation_id]: item.get("known_mechanism_refs")
        for route, item in zip(inputs["routes"], items, strict=True)
    }
    assert refs == {"AP-T6-08": ["user_claim"], "AP-T2-02": None}


def test_a_verifier_request_is_keyed_by_its_mechanisms_too() -> None:
    request, inputs = _routing_request()
    (item,) = provider._mechanism_verification_items(request, inputs["routes"][1:2])
    unlinked = {k: v for k, v in item.items() if k != "known_mechanism_refs"}

    assert provider._verification_key(item) != provider._verification_key(unlinked)


@pytest.mark.parametrize("stage", ["route", "verify"])
def test_the_routing_and_verifier_calls_record_the_mechanism_data(
    stage: str, tmp_path, monkeypatch
) -> None:
    request, inputs = _routing_request()
    seen: dict[str, Any] = {}

    def capture(**kwargs: Any) -> Any:
        seen.update(kwargs["prompt_template_hashes"])
        raise RuntimeError("captured")

    monkeypatch.setattr(provider, "call_with_policy", capture)
    adapter = ObligationAwareLLMAdapter(
        _RecordingClient(), run_dir=tmp_path, controls=_controls()
    )
    targeted = tuple(r for r in inputs["routes"] if r.disposition == "targeted")
    with pytest.raises(RuntimeError, match="captured"):
        if stage == "route":
            adapter.route(request)
        else:
            provider._ask_mechanism_verifier(adapter, request, targeted)

    assert seen == {
        **obligation_prompt_template_hashes(),
        provider.MECHANISM_DATA_HASH_KEY: bundled_mechanism_data_digest(),
    }
