"""The risk class sets what obligation matching and loss derivation judge.

A risk card's ``description`` is its class.  Its threat and consequence are
the source policy's example of that class.  Structural routing receives the
class next to the example; loss derivation labels the consequence as the
example and shows the in-boundary restatement Stage 1a's scope
classification recorded, falling back to the class description.  Every card
still feeds loss derivation.
"""

from __future__ import annotations

from unittest.mock import patch

import yaml

from asago_scenario_generator.models.attack_pattern_chain import AttackPattern
from asago_scenario_generator.models.risk_card import RiskCard
from asago_scenario_generator.stpa.obligation_aware.prompts import (
    build_structural_routing_prompts,
    project_obligation_question,
    project_obligation_routing_context,
)
from asago_scenario_generator.stpa.obligation_aware.routing import (
    build_neutral_briefs,
)
from asago_scenario_generator.stpa.system_model import run as run_module
from asago_scenario_generator.stpa.system_model.loss_analysis import (
    _compact_risk_card_evidence,
)
from asago_scenario_generator.stpa.system_model.loss_analysis import (
    derive_loss_analysis as real_derive_loss_analysis,
)
from asago_scenario_generator.stpa.system_model.risk_actionability import (
    ActionabilityDecision,
    RiskActionabilityEntry,
    RiskActionabilityRecord,
)
from asago_scenario_generator.stpa.system_model.risk_coverage_review import (
    _build_coverage_source_excerpts,
)
from asago_scenario_generator.stpa.system_model.run import run_sp1
from asago_scenario_generator.stpa.threat_enum.slot_creation import create_slots
from tests.helpers.obligation_aware import _control_structure, _loss_analysis
from tests.helpers.obligation_factory import make_plan
from tests.helpers.projection_factory import get_test_raw_pattern
from tests.helpers.stpa_builders import make_loss_analysis
from tests.stpa.sp1_helpers import setup_sp1_mock_client

_CLASS = "A reviewed risk used by planner tests."
_THREAT = "Staff paste company strategy into an outside chat tool."
_CONSEQUENCE = "Company strategy reaches the outside tool's provider."


def _brief(*, risk_description: str | None = None):
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    brief = build_neutral_briefs(make_plan(), (pattern,))[0]
    update = {"threat": _THREAT, "consequence": _CONSEQUENCE}
    if risk_description is not None:
        update["risk_description"] = risk_description
    return brief.model_copy(
        update={"risk_ref": brief.risk_ref.model_copy(update=update)}
    )


def _routed_risks(brief) -> list[dict]:
    structure = _control_structure()
    _, user = build_structural_routing_prompts(
        briefs=(brief,),
        loss_analysis=_loss_analysis(),
        control_structure=structure,
        slots=create_slots(structure),
    )
    block = user.split("Compact obligation questions:\n", 1)[1]
    block = block.split("Every obligation_handle is an opaque reference", 1)[0]
    return [row["reviewed_risk"] for row in yaml.safe_load(block)]


def test_routing_request_carries_the_class_next_to_the_policy_example() -> None:
    (risk,) = _routed_risks(_brief())

    assert risk["description"] == _CLASS
    assert risk["threat"] == _THREAT
    assert risk["consequence"] == _CONSEQUENCE


def test_a_risk_without_a_class_description_falls_back_to_its_name() -> None:
    (risk,) = _routed_risks(_brief(risk_description=" "))

    assert risk["description"] == risk["name"]


def test_only_the_routing_view_carries_the_class_description() -> None:
    brief = _brief()
    structure = _control_structure()

    (routed,) = project_obligation_routing_context(
        briefs=(brief,),
        loss_analysis=_loss_analysis(),
        control_structure=structure,
        slots=create_slots(structure),
    ).obligation_questions
    slot_view = project_obligation_question(brief).model_dump(mode="json")

    assert routed.reviewed_risk.description == _CLASS
    assert "description" not in slot_view["reviewed_risk"]


def _card(risk_id: str, *, consequence: str | None = None) -> RiskCard:
    return RiskCard(
        risk_id=risk_id,
        risk_name=f"Risk {risk_id}",
        risk_description=f"Class of {risk_id}.",
        taxonomy="test",
        confidence=0.9,
        grounding_confidence="high",
        consequence=consequence,
    )


def _entry(risk_id: str, decision: str, source: str = "model", **fields):
    return RiskActionabilityEntry(
        risk_id=risk_id,
        decision=ActionabilityDecision(decision),
        reason="Recorded.",
        source=source,
        **fields,
    )


def _record(*entries: RiskActionabilityEntry) -> RiskActionabilityRecord:
    return RiskActionabilityRecord(
        status="completed",
        call_count=1,
        counts={},
        entries=list(entries),
    )


_CARDS = [
    _card("risk-actionable", consequence="Staff disclose strategy to a provider."),
    _card("risk-outside"),
    _card("risk-fallback"),
    _card("risk-unrecorded", consequence="A policy example."),
]
_RECORD = _record(
    _entry(
        "risk-actionable",
        "actionable",
        system_action="The assistant's reply quotes an internal plan.",
        affected_stakeholder="The organization running the assistant.",
    ),
    _entry("risk-outside", "outside_boundary"),
    _entry("risk-fallback", "actionable", source="fallback"),
)


def test_an_actionable_card_shows_its_in_boundary_restatement() -> None:
    evidence = _compact_risk_card_evidence(_CARDS, _RECORD)

    assert evidence[0] == (
        "risk-actionable — Risk risk-actionable; "
        "class description: Class of risk-actionable.; "
        "in-boundary system action: The assistant's reply quotes an internal "
        "plan.; "
        "in-boundary affected stakeholder: The organization running the "
        "assistant.; "
        "policy example consequence: Staff disclose strategy to a provider."
    )


def test_other_cards_fall_back_to_their_class_description() -> None:
    evidence = _compact_risk_card_evidence(_CARDS, _RECORD)

    assert evidence[1:] == [
        "risk-outside — Risk risk-outside; class description: Class of risk-outside.",
        "risk-fallback — Risk risk-fallback; class description: Class of "
        "risk-fallback.",
        "risk-unrecorded — Risk risk-unrecorded; class description: Class of "
        "risk-unrecorded.; policy example consequence: A policy example.",
    ]


def test_every_card_feeds_loss_derivation_with_or_without_a_record() -> None:
    for record in (_RECORD, None, _record()):
        evidence = _compact_risk_card_evidence(_CARDS, record)

        assert [item.split(" — ", 1)[0] for item in evidence] == [
            card.risk_id for card in _CARDS
        ]
    assert not any(
        "in-boundary" in item for item in _compact_risk_card_evidence(_CARDS)
    )


def test_a_derived_run_shows_the_classifier_restatement_to_loss_derivation(
    tmp_path,
) -> None:
    client = setup_sp1_mock_client()
    received = []

    def spy(**kwargs):
        received.append(kwargs["risk_actionability"])
        return real_derive_loss_analysis(**kwargs)

    with patch.object(run_module, "derive_loss_analysis", side_effect=spy):
        run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=[_card("risk-1", consequence="A policy example.")],
            run_dir=tmp_path,
        )

    (record,) = received
    assert [entry.risk_id for entry in record.entries] == ["risk-1"]
    (risk_request,) = [
        call
        for call in client.calls
        if "## Organizational Risks" in call.user_prompt
        and "class description: Class of risk-1." in call.user_prompt
    ]
    assert (
        "risk-1 — Risk risk-1; class description: Class of risk-1.; "
        "in-boundary system action: The assistant's reply.; "
        "in-boundary affected stakeholder: The user.; "
        "policy example consequence: A policy example."
    ) in risk_request.user_prompt


def test_coverage_review_marks_the_consequence_as_the_policy_example() -> None:
    excerpts = _build_coverage_source_excerpts(
        make_loss_analysis(), [_card("risk-1", consequence="A policy example.")]
    )

    (consequence,) = [item for item in excerpts if item.text == "A policy example."]
    assert consequence.meaning == (
        "Exact supplied risk-card consequence for risk-1: the source policy's "
        "example of the risk class, not the class itself."
    )
