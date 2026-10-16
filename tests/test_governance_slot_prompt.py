"""Slot filling for governance routes, and the pattern prompts it must not move."""

from __future__ import annotations

import hashlib
from types import SimpleNamespace

import pytest

from asago_scenario_generator.models.attack_pattern_chain import AttackPattern
from asago_scenario_generator.stpa.models.scenario_context import (
    ScenarioObligationConsideration,
)
from asago_scenario_generator.models.obligation_consideration import ObligationRoute
from asago_scenario_generator.stpa.obligation_aware.contracts import (
    IcaDeviationDraft,
    IcaFindingDraft,
    ObligationIcaDraft,
    SlotIcaDraft,
    SynthesisSlotRequest,
)
from asago_scenario_generator.stpa.obligation_aware.prompts import (
    build_structural_routing_prompts,
    build_synthesis_slot_prompts,
)
from asago_scenario_generator.stpa.obligation_aware.provider import (
    ObligationAwareLLMAdapter,
)
from asago_scenario_generator.stpa.obligation_aware.routing import build_neutral_briefs
from asago_scenario_generator.stpa.threat_enum.slot_creation import create_slots
from tests.helpers.obligation_factory import make_plan
from tests.helpers.projection_factory import get_test_raw_pattern
from tests.helpers.scripted_client import ScriptedClient
from tests.helpers.governance import _controls, _pattern_route, _setup
from tests.helpers.obligation_aware import (
    _control_structure,
    _loss_analysis,
    provider_slot_payload,
)

# Captured from 04a926bd, before any governance prompt text existed. The user
# digest was recaptured when slot prompts began naming each routed obligation
# with a short request-local handle. The system digest is the text recorded
# before the NOT_PROVIDED N/A sentence existed; the sentence was removed again
# because it raised the NOT_PROVIDED N/A share. The system digest was
# recaptured when the prompt began naming the identities a slot may cite, and
# again when a finding began naming one `governing_pair` and when
# `consideration_results` became an object keyed by obligation handle, and
# again when the pair became the `governing_pairs` array. The
# other digests are unchanged.
_GOLDEN_SLOT_SYSTEM = "1ee393a7d9379f7eb15e1f9950b39da4e4bc2cdc27dfb3e3566e0cd6280bd047"
_GOLDEN_SLOT_USER = "51f6875173344befda32d0a1fdbe879b7487e072808b8dafd2d89f9679c6f37a"
_GOLDEN_SLOT_USER_EMPTY = (
    "6a174dc144a7788395f2e38a60457edd891714dbd795c06411dad9616a4f9667"
)
# The routing system digest was recaptured when the routing prompt began
# describing the flat route form (null for fields a disposition does not use),
# and again when its examples stopped naming a NOT_PROVIDED slot and it began
# defining the four UCA types, and again when its example slot stopped
# matching a real slot.
_GOLDEN_ROUTING_SYSTEM = (
    "3cb0838594298426f080ac7bba9e1623b96e2e24eb6074fa8a1a88af60470b5c"
)
# The routing user digest was recaptured when slot IDs left the ID glossary for
# a UCA type legend, when routing stopped offering WRONG_DURATION slots that
# slot filling never analyses, and when the LAAF axis left the mapping set and
# so changed the obligation handles.
_GOLDEN_ROUTING_USER = (
    "d6f0b864a5e228ddee93a98c0a35313fb58cecd5f953f17826a7c5cf836ac6b8"
)


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def test_pattern_prompts_keep_their_bytes() -> None:
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    brief = build_neutral_briefs(make_plan(), (pattern,))[0]
    structure = _control_structure()
    slots = create_slots(structure)
    target_slots = [item for item in slots if item.responsibility == "RESP-1"]

    def slot_prompts(briefs, routes):
        return build_synthesis_slot_prompts(
            target_id="RESP-1",
            slots=target_slots,
            routed_briefs=briefs,
            routed_routes=routes,
            loss_analysis=_loss_analysis(),
            control_structure=structure,
        )

    system, user = slot_prompts((brief,), (_pattern_route(brief, slots[0]),))
    _, empty_user = slot_prompts((), ())
    routing_system, routing_user = build_structural_routing_prompts(
        briefs=(brief,),
        loss_analysis=_loss_analysis(),
        control_structure=structure,
        slots=slots,
    )

    assert _sha(system) == _GOLDEN_SLOT_SYSTEM
    assert _sha(user) == _GOLDEN_SLOT_USER
    assert _sha(empty_user) == _GOLDEN_SLOT_USER_EMPTY
    assert _sha(routing_system) == _GOLDEN_ROUTING_SYSTEM
    assert _sha(routing_user) == _GOLDEN_ROUTING_USER


def _governance_request(*, with_pattern: bool = False):
    briefs, _, loss, structure = _setup("risk-b")
    brief = briefs[0]
    slot = create_slots(structure)[0]
    route = ObligationRoute(
        obligation_id=brief.obligation_id,
        disposition="targeted",
        slot_ids=(slot.slot_id,),
        hazard_ids=("H-1",),
        constraint_ids=("SC-1",),
        rationale="the action changes the risky state",
        evidence=("CA-1-1: the action changes the risky state",),
    )
    routed_briefs, routed_routes = (brief,), (route,)
    if with_pattern:
        pattern = AttackPattern.model_validate(get_test_raw_pattern())
        other = build_neutral_briefs(make_plan(), (pattern,))[0]
        routed_briefs += (other,)
        routed_routes += (_pattern_route(other, slot),)
    return SynthesisSlotRequest(
        target_id="RESP-1",
        target_kind="responsibility",
        slots=(slot,),
        routed_briefs=routed_briefs,
        routed_routes=routed_routes,
        loss_analysis=loss,
        control_structure=structure,
        controls=_controls(),
    )


def _prompts(request):
    return build_synthesis_slot_prompts(
        target_id=request.target_id,
        slots=request.slots,
        routed_briefs=request.routed_briefs,
        routed_routes=request.routed_routes,
        loss_analysis=request.loss_analysis,
        control_structure=request.control_structure,
    )


def test_a_governance_question_carries_the_risk_and_no_attack_pattern() -> None:
    system, user = _prompts(_governance_request())

    assert "risk-b" in user
    assert "known_concern" not in user
    assert "mapping_strength" not in user
    assert "attack_pattern" not in user
    assert "governance risk" in system
    for field in ("reviewed_risk", "description", "obligation_handle"):
        assert field in system or field in user


def test_the_governance_paragraph_appears_only_with_a_governance_question() -> None:
    governance_system, _ = _prompts(_governance_request())
    mixed_system, mixed_user = _prompts(_governance_request(with_pattern=True))

    assert "governance risk" in governance_system
    assert "governance risk" in mixed_system
    assert "known_concern" in mixed_user
    assert (
        "governance risk"
        not in build_synthesis_slot_prompts(
            target_id="RESP-1",
            slots=create_slots(_control_structure()),
            routed_briefs=(),
            routed_routes=(),
            loss_analysis=_loss_analysis(),
            control_structure=_control_structure(),
        )[0]
    )


def test_the_provider_fills_a_slot_for_a_governance_route(tmp_path) -> None:
    request = _governance_request()
    brief = request.routed_briefs[0]
    slot = request.slots[0]
    draft = SlotIcaDraft(
        slot_id=slot.slot_id,
        is_na=False,
        findings=(
            IcaFindingDraft(
                deviation=IcaDeviationDraft(not_provided_context="the state is stale"),
                hazardous_context="the stale state reaches the process",
                loss_consequence="the protected operation is harmed",
                related_hazard_ids=("H-1",),
                related_constraint_ids=("SC-1",),
            ),
        ),
        consideration_results=(
            ObligationIcaDraft(
                obligation_handle="R1",
                disposition="finding",
                finding_indexes=(0,),
                rationale="the finding expresses the governance risk",
            ),
        ),
    )
    client = ScriptedClient(
        [{"filled_slots": [provider_slot_payload(draft)]}], model="governance-slot-test"
    )

    response = ObligationAwareLLMAdapter(
        client, run_dir=tmp_path, controls=_controls()
    ).fill(request)

    (pair,) = response.considerations
    assert pair.obligation_id == brief.obligation_id
    assert pair.disposition == "finding"
    assert pair.route_id == request.routed_routes[0].route_id
    assert len(client.prompts) == 1


def test_a_governance_finding_projects_to_a_governance_scenario_consideration() -> None:
    from asago_scenario_generator.pipeline.synthesis_scenarios import _findings_by_ica

    briefs, _, _, _ = _setup("risk-b")
    pair = SimpleNamespace(
        disposition="finding",
        obligation_id=briefs[0].obligation_id,
        rationale="",
        ica_ids=("ICA-A",),
    )

    (item,) = _findings_by_ica(briefs, (pair,))["ICA-A"]

    dumped = item.model_dump(mode="json")
    assert dumped["kind"] == "governance"
    assert dumped["risk_id"] == "risk-b"
    assert "attack_pattern_id" not in dumped
    assert item.finding_ica_id == "ICA-A"
    assert item.concise_concern


def test_a_pattern_consideration_keeps_its_serialized_keys() -> None:
    from asago_scenario_generator.stpa.models.scenario_context import (
        ScenarioObligationConsideration,
    )

    item = ScenarioObligationConsideration(
        obligation_id="OBL-1",
        attack_pattern_id="AP-1",
        attack_pattern_name="Pattern",
        concise_concern="Concern",
        disposition="finding",
        rationale="why",
        finding_ica_id="ICA-A",
    )

    assert sorted(item.model_dump(mode="json")) == [
        "attack_pattern_id",
        "attack_pattern_name",
        "concise_concern",
        "disposition",
        "finding_ica_id",
        "obligation_id",
        "rationale",
    ]


def test_the_stage5_view_names_a_governance_risk_without_a_pattern() -> None:
    from asago_scenario_generator.stpa.models.scenario_context import (
        ScenarioObligationConsideration,
    )
    from asago_scenario_generator.stpa.scenario_prod.stage5.prompt_view import (
        _stage5_taxonomy_considerations,
    )

    governance = ScenarioObligationConsideration(
        kind="governance",
        obligation_id="OBL-1",
        risk_id="risk-b",
        risk_name="Risk B",
        concise_concern="A reviewed risk",
        disposition="finding",
        rationale="why",
        finding_ica_id="ICA-A",
    )
    pattern = ScenarioObligationConsideration(
        obligation_id="OBL-2",
        attack_pattern_id="AP-1",
        attack_pattern_name="Pattern",
        concise_concern="Concern",
        disposition="finding",
        rationale="why",
    )
    context = SimpleNamespace(obligation_considerations=(governance, pattern))

    first, second = _stage5_taxonomy_considerations(context)

    assert first == {
        "risk_name": "Risk B",
        "concern": "A reviewed risk",
        "review_outcome": "finding",
        "review_reason": "why",
    }
    assert second["pattern_name"] == "Pattern"
    assert "risk_name" not in second


@pytest.mark.parametrize(
    "fields",
    (
        {"kind": "governance", "risk_id": "risk-b"},
        {
            "kind": "governance",
            "attack_pattern_id": "AP-1",
            "risk_id": "r",
            "risk_name": "n",
        },
        {"attack_pattern_id": "AP-1"},
        {"attack_pattern_id": "AP-1", "attack_pattern_name": "n", "risk_id": "r"},
        {},
    ),
)
def test_a_consideration_needs_exactly_the_identity_of_its_kind(fields) -> None:
    with pytest.raises(ValueError):
        ScenarioObligationConsideration(
            obligation_id="ob:v1:" + "a" * 64,
            concise_concern="c",
            disposition="finding",
            rationale="r",
            **fields,
        )
