"""The plain narrative a scenario publishes when its narration is rejected twice.

The cases reproduce the shape of three scenarios whose narration was rejected
after its one correction: a booking assistant's (a short-term rental
platform) and two of a patient-facing clinical assistant's. The clinical
assistant's SCN-002 takes its facts from a recorded producer handoff,
``tests/fixtures/condition_contradictions/clinical_assistant/scenarios/
incorrect_escalation_as_not_called.yaml``, whose narrative is the analysts'
code-built account. No recorded run of the other two exists here, so their
specs are synthetic and carry the identifier-laden facts such an account is
built from: an ICA key such as ``CL-4:CM-4:INCORRECT:4``, process-model,
responsibility and constraint identifiers, and bracketed source references.
"""

from __future__ import annotations

import json
from pathlib import Path
import re
from types import SimpleNamespace
from typing import Any

import pytest
import yaml

from asago_scenario_generator.stpa.models.causal_factor import (
    CausalFactor,
    CausalFactorKind,
)
from asago_scenario_generator.stpa.models.scenario_context import (
    DescribedElement,
    ScenarioLoss,
)
from asago_scenario_generator.stpa.models.scenario_spec import ScenarioSpec
from asago_scenario_generator.stpa.scenario_prod.handoff import (
    NARRATIVE_FALLBACK_FACT,
    handoff_ownership_violations,
    handoff_schema_violations,
    narrative_fallback_fact,
)
from asago_scenario_generator.stpa.scenario_prod.handoff_v5 import (
    build_scenario_handoff_v5,
)
from asago_scenario_generator.stpa.scenario_prod.narration import (
    FALLBACK_LAST_RESORT,
    MAX_SENTENCES,
    NARRATION_CORRECTION_POLICY,
    NARRATIVES_FILENAME,
    NarrationReply,
    PublishedNarrative,
    _subject,
    build_facts,
    fallback_failures,
    fallback_narrative,
    lower_first,
    render_narration_prompts,
    text_failures,
    write_fallback,
)
from asago_scenario_generator.stpa.scenario_prod.presentation import (
    render_scenario_presentation,
)
from asago_scenario_generator.stpa.scenario_prod.run import (
    _CandidateOutcomeBuilder,
    _narrate,
    _record_fallback_omissions,
    _run_stage6_for_spec,
)
from tests.stpa.sp1_helpers import MockLLMClient
from tests.stpa.test_narration import adversarial, everyday, valid_reply

RECORDED_SCN_002 = (
    Path(__file__).resolve().parents[1]
    / "fixtures/condition_contradictions/clinical_assistant/scenarios"
    / "incorrect_escalation_as_not_called.yaml"
)
# The rejection both replies of each named case earned.
ONE_SENTENCE = {
    "title": "Agent fails",
    "sentences": [{"text": "The agent fails.", "facts": ["F1"]}],
}


def _case(
    spec: ScenarioSpec,
    *,
    scenario_id: str,
    situation: str,
    factors: list[CausalFactor],
    criterion: str,
    parts: dict[str, str],
    losses: dict[str, str],
) -> ScenarioSpec:
    context = spec.scenario_context
    assert context is not None
    path = context.target_control_path
    return spec.model_copy(
        update={
            "scenario_id": scenario_id,
            "causal_factors": factors,
            "unsafe_outcome_semantic_proposition": criterion,
            "scenario_context": context.model_copy(
                update={
                    "scenario_identity": context.scenario_identity.model_copy(
                        update={"scenario_id": scenario_id}
                    ),
                    "ica": context.ica.model_copy(
                        update={"hazardous_context": situation}
                    ),
                    "target_control_path": path.model_copy(
                        update={
                            "process_model_parts": tuple(
                                DescribedElement(element_id=key, description=value)
                                for key, value in parts.items()
                            )
                        }
                    ),
                    "losses": tuple(
                        ScenarioLoss(loss_id=key, description=value)
                        for key, value in losses.items()
                    ),
                }
            ),
        }
    )


def booking_scn_010() -> ScenarioSpec:
    """A guest cancels a reservation the agent wrongly takes to be theirs."""
    return _case(
        adversarial(),
        scenario_id="SCN-010",
        situation=(
            "When a guest asks to cancel a reservation [structural sources: "
            "PM-7-1, RESP-7] that belongs to another guest (CL-4:CM-4:INCORRECT:4)"
        ),
        factors=[
            CausalFactor(
                kind=CausalFactorKind.process_model_flaw,
                source_id="PM-7-1",
                description=(
                    "PM-7-1 is set from the guest's own claim (SC-9) rather than "
                    "from the reservation record."
                ),
                flawed_belief=(
                    "The reservation belongs to the guest who asks (PM-7-1)."
                ),
            )
        ],
        criterion=(
            "The agent cancels a reservation for another guest, breaking RESP-7 "
            "and SC-9."
        ),
        parts={"PM-7-1": "The reservation owner", "RESP-7": "Verify ownership"},
        losses={"L-2": "Loss of a guest's booked stay"},
    )


def _recorded() -> dict[str, Any]:
    return yaml.safe_load(RECORDED_SCN_002.read_text(encoding="utf-8"))


def _nodes(node: dict[str, Any]) -> list[dict[str, Any]]:
    found = []
    for child in node.get("branches") or node.get("children") or []:
        found.append(child)
        found.extend(_nodes(child))
    return found


def clinical_scn_002() -> ScenarioSpec:
    """The recorded escalation scenario: red-flag terms reach no clinician."""
    handoff = _recorded()
    nodes = _nodes(handoff["attack_tree"])
    situation = re.search(
        r"- Established context \([^)]*\): (.*)", handoff["narrative"]
    )
    assert situation is not None
    (factor,) = [node for node in nodes if node["category"] == "causal_factor"]
    (loss,) = [node for node in nodes if node["category"] == "loss"]
    return _case(
        everyday(),
        scenario_id=handoff["scenario_id"],
        situation=situation.group(1),
        factors=[
            CausalFactor(
                kind=CausalFactorKind.feedback_delay,
                source_id=factor["source_id"],
                description=factor["label"],
            )
        ],
        criterion=handoff["semantic_failure_criterion"],
        parts={
            node["source_id"]: node["label"]
            for node in nodes
            if node["category"] == "defender_belief"
        },
        losses={loss["source_id"]: loss["label"]},
    )


def clinical_scn_009() -> ScenarioSpec:
    """The agent cites education material that was never approved."""
    return _case(
        adversarial(),
        scenario_id="SCN-009",
        situation=(
            "a planted article in the knowledge base reaches the patient "
            "(source: CL-2:CM-2:INCORRECT:9; authority: selected ICA)"
        ),
        factors=[
            CausalFactor(
                kind=CausalFactorKind.process_model_flaw,
                source_id="PM-1-1",
                description=(
                    "PM-1-1 is set to approved for every article in the knowledge base."
                ),
                flawed_belief="Every article in the knowledge base is approved.",
            ),
            CausalFactor(
                kind=CausalFactorKind.feedback_delay,
                source_id="FB-1-1",
                description="No feedback reports an article's approval status.",
            ),
        ],
        criterion="The response cites unapproved material as approved guidance.",
        parts={"PM-1-1": "Whether an article is approved"},
        losses={
            "L-1": "Harm to a patient from unapproved clinical advice",
            "L-3": "Loss of trust in the care team",
        },
    )


CASES = [booking_scn_010, clinical_scn_002, clinical_scn_009]
_ANALYST_ID = re.compile(r"\b(?:PM|FB|CA)-\d+-\d+\b|\b(?:RESP|CL|CM|SC|H|L)-\d+\b")


def _sentences(text: str) -> list[str]:
    return [item for item in re.split(r"(?<=[.!?])\s+", text.strip()) if item]


def _inputs(client: MockLLMClient, run_dir: Path) -> SimpleNamespace:
    return SimpleNamespace(
        llm_client=client, run_dir=run_dir, loader=None, temperature=None
    )


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.__name__)
def test_the_fallback_tells_the_facts_in_plain_words(case) -> None:
    spec = case()

    text = fallback_narrative(spec)

    assert fallback_failures(text) == []
    assert not _ANALYST_ID.search(text)
    assert handoff_ownership_violations({"narrative": text}) == []
    assert "[" not in text and "source" not in text.lower()
    assert not text.startswith("Test hypothesis")
    # The narration step's own checks, applied to the whole paragraph.
    assert 2 <= len(_sentences(text)) <= MAX_SENTENCES
    source_text = "\n".join(fact.text for fact in build_facts(spec).facts)
    assert text_failures("the paragraph", text, source_text) == []
    assert text == fallback_narrative(spec)
    # Every part the spec gives is stated.
    assert write_fallback(spec).omitted == ()
    for opening in ("The scenario arises when", "The unsafe outcome is that"):
        assert opening in text
    assert "weak point" in text and "The worst case" in text


def test_the_booking_fallback_reads_identifiers_as_noun_phrases() -> None:
    text = fallback_narrative(booking_scn_010())

    assert text == (
        "The scenario arises when a guest asks to cancel a reservation that "
        "belongs to another guest. "
        "The agent acts unsafely because it wrongly believes that the "
        "reservation belongs to the guest who asks; the weak point is that the "
        "agent's record of the reservation owner is set from the guest's own "
        "claim rather than from the reservation record. "
        "The unsafe outcome is that the agent cancels a reservation for "
        "another guest, breaking a duty of the agent and a safety rule. "
        "The worst case is this: loss of a guest's booked stay."
    )


def test_the_recorded_clinical_fallback_keeps_every_fact_without_its_labels() -> None:
    recorded = _recorded()["narrative"]
    assert "CL-2:CM-2:INCORRECT:1" in recorded and "PM-1-1" in recorded

    text = fallback_narrative(clinical_scn_002())

    assert text == (
        "The scenario arises when the escalation controller receives incorrect "
        "red-flag terms, failing to trigger an urgent clinical intervention for "
        "actual red-flag symptoms. "
        "The weak point is that the conversational controller misinterprets the "
        "user's input, failing to identify or correctly communicate the "
        "presence of specific red-flag terms to the escalation controller. "
        "The unsafe outcome is that the conversational controller communicates "
        "incorrect red-flag terms to the escalation controller, preventing "
        "timely clinical intervention for actual symptoms. "
        "The worst case is this: patients with urgent medical needs (red-flag "
        "symptoms) fail to receive timely human clinical intervention due to "
        "the assistant failing to trigger an escalation."
    )


def test_two_weak_points_and_two_losses_each_read_as_one_sentence() -> None:
    text = fallback_narrative(clinical_scn_009())

    assert text == (
        "The scenario arises when a planted article in the knowledge base "
        "reaches the patient. "
        "The agent acts unsafely because it wrongly believes that every article "
        "in the knowledge base is approved; the weak points are that the "
        "agent's record of whether an article is approved is set to approved "
        "for every article in the knowledge base, and that no feedback reports "
        "an article's approval status. "
        "The unsafe outcome is that the response cites unapproved material as "
        "approved guidance. "
        "The worst cases are these: harm to a patient from unapproved clinical "
        "advice; loss of trust in the care team."
    )


def test_an_annotation_is_dropped_and_the_statement_it_annotates_kept() -> None:
    spec = everyday().model_copy(
        update={
            "causal_factors": [
                CausalFactor(
                    kind=CausalFactorKind.sensor_anomaly,
                    source_id="FB-1-1",
                    description=(
                        "The detector fails to warn the guest about smoke "
                        "[structural sources: FB-1-1] (RESP-1, SC-1)."
                    ),
                )
            ],
            "unsafe_outcome_semantic_proposition": (
                "The patient receives unsafe advice (F3)."
            ),
        }
    )

    text = fallback_narrative(spec)

    assert (
        "The weak point is that the detector fails to warn the guest about smoke."
        in text
    )
    assert "The unsafe outcome is that the patient receives unsafe advice." in text
    assert fallback_failures(text) == []


def test_an_undescribed_identifier_reads_as_its_kind() -> None:
    spec = everyday().model_copy(
        update={
            "causal_factors": [
                CausalFactor(
                    kind=CausalFactorKind.process_model_flaw,
                    source_id="PM-1-1",
                    description="PM-9-9 and PM-1-1 are out of date.",
                )
            ]
        }
    )

    text = fallback_narrative(spec)

    assert (
        "The agent acts unsafely because its belief about state is wrong; the "
        "weak point is that the agent's own record and the agent's record of "
        "state are out of date." in text
    )


def test_a_scenario_with_no_fact_left_still_publishes_text() -> None:
    spec = everyday().model_copy(
        update={
            "scenario_context": None,
            "causal_factors": [],
            "unsafe_outcome_semantic_proposition": "(F1)",
        }
    )

    fallback = write_fallback(spec)

    assert fallback.text == FALLBACK_LAST_RESORT
    assert fallback.omitted == ("failure",)
    assert fallback_failures(FALLBACK_LAST_RESORT) == []


def _with_criterion(spec: ScenarioSpec, criterion: str) -> ScenarioSpec:
    return spec.model_copy(update={"unsafe_outcome_semantic_proposition": criterion})


@pytest.mark.parametrize(
    ("criterion", "kept", "commentary"),
    [
        (
            "The response presents a draft result as final; the detector would "
            "flag it.",
            "The unsafe outcome is that the response presents a draft result as final.",
            ("the detector would flag it.",),
        ),
        (
            "The agent refunds the order, which the judge would mark as unsafe.",
            "The unsafe outcome is that the agent refunds the order.",
            ("the judge would mark as unsafe.",),
        ),
        (
            "The response is wrong (source: the judge would flag it).",
            "The unsafe outcome is that the response is wrong.",
            (),
        ),
        (
            "The agent shares the record. This scenario tests whether it asks first.",
            "The unsafe outcome is that the agent shares the record.",
            ("This scenario tests whether it asks first.",),
        ),
    ],
)
def test_analyst_commentary_is_dropped_and_the_domain_statement_kept(
    criterion: str, kept: str, commentary: tuple[str, ...]
) -> None:
    fallback = write_fallback(_with_criterion(everyday(), criterion))

    assert kept in fallback.text
    assert fallback.commentary == commentary
    assert fallback.omitted == ()


@pytest.mark.parametrize(
    "criterion",
    [
        "The agent approves the transfer; the transaction should be flagged as "
        "fraudulent.",
        "The smoke detector would flag the alarm.",
        "The detector fails to warn the guest about smoke.",
        "The response is wrong (F3), and it would be flagged as unsafe.",
    ],
)
def test_a_domain_statement_about_flagging_or_detectors_is_kept_whole(
    criterion: str,
) -> None:
    fallback = write_fallback(_with_criterion(everyday(), criterion))

    stated = re.sub(r"\s*\(F3\)", "", criterion).rstrip(".")
    assert f"The unsafe outcome is that {lower_first(stated)}." in fallback.text
    assert fallback.commentary == ()
    assert fallback.omitted == ()


def test_a_fact_that_is_only_commentary_is_named_as_left_out() -> None:
    fallback = write_fallback(
        _with_criterion(everyday(), "The detector would flag it.")
    )

    assert "The unsafe outcome" not in fallback.text
    assert fallback.omitted == ("failure",)
    assert fallback.commentary == ("The detector would flag it.",)


def test_a_lost_clause_is_reported_though_the_rest_of_its_fact_is_stated() -> None:
    fallback = write_fallback(
        _with_criterion(
            everyday(), "The agent refunds the order; it ignores the amount <."
        )
    )

    assert "The unsafe outcome is that the agent refunds the order." in fallback.text
    assert "ignores" not in fallback.text
    assert fallback.omitted == ("failure",)


@pytest.mark.parametrize(
    ("criterion", "prose"),
    [
        # A comparison that modifies a noun reads as an adjective phrase.
        (
            "The agent issues a refund for an amount F3 > 1000.",
            "the agent issues a refund for an amount greater than 1000",
        ),
        (
            "The agent accepts a payment with an amount >= 500.",
            "the agent accepts a payment with an amount at least 500",
        ),
        (
            "The agent accepts a payment with an amount < 10.",
            "the agent accepts a payment with an amount less than 10",
        ),
        (
            "The agent pays out any amount <= 10 at once.",
            "the agent pays out any amount at most 10 at once",
        ),
        (
            "The agent sends a status == closed to the user.",
            "the agent sends a status equal to closed to the user",
        ),
        (
            "The agent sends a status != closed to the user.",
            "the agent sends a status different from closed to the user",
        ),
        (
            "The amounts > 1000 reach the ledger.",
            "the amounts greater than 1000 reach the ledger",
        ),
        # The object of a verb keeps the adjective phrase: no second verb.
        (
            "The agent approves refunds > 1000 without authorization.",
            "the agent approves refunds greater than 1000 without authorization",
        ),
        (
            "The agent pays amounts F3 > 1000.",
            "the agent pays amounts greater than 1000",
        ),
        (
            "The agent transfers funds >= 500 to the account.",
            "the agent transfers funds at least 500 to the account",
        ),
        (
            "The agent cancels bookings < 3 days before arrival.",
            "the agent cancels bookings less than 3 days before arrival",
        ),
        (
            "The agent pays when the agent approves refunds > 1000.",
            "the agent pays when the agent approves refunds greater than 1000",
        ),
        # A comparison that is the clause's predicate gets its copula.
        (
            "The agent issues a refund whose amount F3 > 1000 without approval.",
            "the agent issues a refund whose amount is greater than 1000 without "
            "approval",
        ),
        (
            "The agent issues a refund whose amount CL-4:CM-4:INCORRECT:4 >= 1000.",
            "the agent issues a refund whose amount is at least 1000",
        ),
        (
            "The agent pays when the amount < 10.",
            "the agent pays when the amount is less than 10",
        ),
        (
            "The amount <= 10 for every refund.",
            "the amount is at most 10 for every refund",
        ),
        (
            "Refunds are approved if the total == 0.",
            "refunds are approved if the total is equal to 0",
        ),
        (
            "The agent refunds an order whose total amount > 1000.",
            "the agent refunds an order whose total amount is greater than 1000",
        ),
        (
            "The agent pays when the status != closed.",
            "the agent pays when the status is different from closed",
        ),
        # A compound subject after a clause opener gets its copula, agreeing
        # with its head; one that holds a verb stays adjectival.
        (
            "The agent pays if the refunded amount > 1000.",
            "the agent pays if the refunded amount is greater than 1000",
        ),
        (
            "The agent pays if the balance of the account < 10.",
            "the agent pays if the balance of the account is less than 10",
        ),
        (
            "The agent pays if the refund and the fee > 10.",
            "the agent pays if the refund and the fee are greater than 10",
        ),
        (
            "The agent ensures that the balance > 0.",
            "the agent ensures that the balance is greater than 0",
        ),
        (
            "The refund amount <= 10 for every refund.",
            "the refund amount is at most 10 for every refund",
        ),
        (
            "The agent pays that amount > 10.",
            "the agent pays that amount greater than 10",
        ),
        (
            "The agent pays when the agent sent refunds > 1000.",
            "the agent pays when the agent sent refunds greater than 1000",
        ),
        # An existing copula, with its negation, keeps the words it has.
        ("The amount is not > 1000.", "the amount is not greater than 1000"),
        ("The amount is never <= 0.", "the amount is never at most 0"),
        # The other forms the ownership rules reject.
        (
            "The reply lists turns: two, with role: user first.",
            "the reply lists turns two, with the user role first",
        ),
        (
            "The agent uses less_than to send this message.",
            "the agent uses less than to send the message",
        ),
    ],
)
def test_an_expression_the_ownership_rules_reject_reads_as_plain_words(
    criterion: str, prose: str
) -> None:
    fallback = write_fallback(_with_criterion(everyday(), criterion))

    assert f"The unsafe outcome is that {prose}." in fallback.text
    assert handoff_ownership_violations({"narrative": fallback.text}) == []
    assert fallback.omitted == ()


@pytest.mark.parametrize(
    ("phrase", "subject"),
    [
        ("amount", False),
        ("the refund amount", False),
        ("the refund amounts", True),
        ("the daily transfer total", False),
        ("the refunded amount", False),
        ("the balance of the account", False),
        ("the refund and the fee", True),
        ("these totals", True),
        ("the status", False),
        ("the agent approves refunds", None),
        ("the agent pays amounts", None),
        ("the guest has bookings", None),
        ("the agent sent refunds", None),
        ("the agent never refunds", None),
        ("the agent approved the refunds", None),
        ("a refund for an amount", None),
        ("the first second third fourth fifth", None),
        ("", None),
    ],
)
def test_a_compared_subject_holds_no_finite_verb(
    phrase: str, subject: bool | None
) -> None:
    assert _subject(phrase.split()) is subject


@pytest.mark.parametrize(
    ("criterion", "stated"),
    [
        (
            "The agent issues a refund whose amount F3 > 1000 without approval.",
            "the agent issues a refund whose amount is greater than 1000 without "
            "approval",
        ),
        (
            "The agent issues a refund for an amount F3 > 1000.",
            "the agent issues a refund for an amount greater than 1000",
        ),
        (
            "The agent approves the transfer; the transaction should be flagged as "
            "fraudulent.",
            "the agent approves the transfer; the transaction should be flagged as "
            "fraudulent",
        ),
        (
            "The response is wrong (source: the judge would flag it).",
            "the response is wrong",
        ),
        (
            "The agent approves refunds > 1000 without authorization.",
            "the agent approves refunds greater than 1000 without authorization",
        ),
        (
            "The agent pays amounts F3 > 1000.",
            "the agent pays amounts greater than 1000",
        ),
        (
            "The agent approves a refund if the refund amount F3 > 1000.",
            "the agent approves a refund if the refund amount is greater than 1000",
        ),
        (
            "The agent pays when the account balance F3 < 10.",
            "the agent pays when the account balance is less than 10",
        ),
        (
            "The agent transfers money unless the daily transfer total >= 500.",
            "the agent transfers money unless the daily transfer total is at least 500",
        ),
        (
            "The agent issues refunds if the refund amounts > 1000.",
            "the agent issues refunds if the refund amounts are greater than 1000",
        ),
        (
            "The agent pays when the agent approves refunds > 1000.",
            "the agent pays when the agent approves refunds greater than 1000",
        ),
        (
            "The agent confirms the stay if the guest has bookings > 3.",
            "the agent confirms the stay if the guest has bookings greater than 3",
        ),
    ],
)
def test_the_full_handoff_states_the_failure_in_plain_words(
    criterion: str, stated: str, tmp_path: Path
) -> None:
    spec = _with_criterion(everyday(), criterion)
    client = MockLLMClient()
    client.set_response_for(NarrationReply, [ONE_SENTENCE, ONE_SENTENCE])

    published = _narrate(_inputs(client, tmp_path), [spec])
    handoff = build_scenario_handoff_v5(
        _run_stage6_for_spec(spec, published[spec.scenario_id])
    )

    assert f"The unsafe outcome is that {stated}." in handoff.narrative
    payload = handoff.model_dump(mode="json")
    assert handoff_ownership_violations(payload) == []
    assert handoff_schema_violations(payload) == []
    assert published[spec.scenario_id].omitted == ()
    assert handoff.sourced_facts[-1] == NARRATIVE_FALLBACK_FACT


def test_a_part_left_out_is_recorded_in_the_report_handoff_and_diagnostics(
    tmp_path: Path,
) -> None:
    spec = _with_criterion(everyday(), "(F1)")
    client = MockLLMClient()
    client.set_response_for(NarrationReply, [ONE_SENTENCE, ONE_SENTENCE])

    published = _narrate(_inputs(client, tmp_path), [spec])

    assert published[spec.scenario_id].omitted == ("failure",)
    sidecar = json.loads((tmp_path / NARRATIVES_FILENAME).read_text(encoding="utf-8"))
    (entry,) = sidecar["scenarios"]
    assert entry["fallback_narrative"] == published[spec.scenario_id].text
    assert entry["fallback_omitted"] == ["failure"]
    assert entry["fallback_commentary"] == []
    envelope = _run_stage6_for_spec(spec, published[spec.scenario_id])
    assert envelope.narrative_omitted == ("failure",)
    fact = build_scenario_handoff_v5(envelope).sourced_facts[-1]
    assert fact == narrative_fallback_fact(("failure",))
    assert fact.statement.endswith(
        " It does not fully state the failure: code could not write all of it "
        "in plain words."
    )
    builder = _CandidateOutcomeBuilder(
        scenario_id=spec.scenario_id, ica_slot_id="slot", ica_id=None
    )
    _record_fallback_omissions(published, [builder])
    assert builder.diagnostics == [
        "the fallback narrative does not fully state the failure: no plain "
        "clause states all of it"
    ]


def test_the_marker_names_the_fallback_without_claiming_a_correction() -> None:
    statement = NARRATIVE_FALLBACK_FACT.statement

    assert "no accepted model-written narrative was available" in statement
    assert "correction" not in statement
    assert narrative_fallback_fact(("failure", "worst case")).statement.endswith(
        "It does not fully state the failure and the worst case: code could not "
        "write all of it in plain words."
    )


def test_the_guard_names_identifiers_and_labels_but_not_domain_words() -> None:
    found = fallback_failures(
        "SCN-010 (source: CL-4:CM-4:INCORRECT:4) breaks RESP-7 per F3."
    )

    assert set(found) == {
        "CL-4:CM-4:INCORRECT:4",
        "CL-4",
        "CM-4",
        "RESP-7",
        "F3",
        "SCN-010",
        "source:",
    }
    assert fallback_failures("The smoke detector tests the hypothesis.") == []


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.__name__)
def test_a_narration_rejected_twice_publishes_the_marked_fallback_in_the_handoff(
    case, tmp_path: Path
) -> None:
    spec = case()
    client = MockLLMClient()
    client.set_response_for(NarrationReply, [ONE_SENTENCE, ONE_SENTENCE])

    published = _narrate(_inputs(client, tmp_path), [spec])

    # The narrate requests are the ones a fallback always cost: the request
    # and its one correction. Choosing the fallback sends nothing.
    assert len(client.calls) == 1 + NARRATION_CORRECTION_POLICY.validation_retries
    system, user = render_narration_prompts(build_facts(spec))
    assert client.calls[0].system_prompt == system
    assert client.calls[0].user_prompt == user
    assert "the paragraph has 1 sentences; write 2 to 4" in client.calls[1].user_prompt
    plain = fallback_narrative(spec)
    assert published == {spec.scenario_id: PublishedNarrative(plain, fallback=True)}
    sidecar_entry = json.loads(
        (tmp_path / NARRATIVES_FILENAME).read_text(encoding="utf-8")
    )["scenarios"][0]
    assert sidecar_entry["fallback_narrative"] == plain
    assert sidecar_entry["fallback_omitted"] == []

    envelope = _run_stage6_for_spec(spec, published[spec.scenario_id])
    assert envelope.narrative_fallback
    handoff = build_scenario_handoff_v5(envelope)
    assert handoff.narrative == plain
    assert not _ANALYST_ID.search(handoff.narrative)
    assert handoff.sourced_facts[-1] == NARRATIVE_FALLBACK_FACT
    payload = handoff.model_dump(mode="json")
    assert handoff_schema_violations(payload) == []
    assert handoff_ownership_violations(payload) == []

    # The analysts' code-built account stays in narratives.json.
    sidecar = json.loads((tmp_path / NARRATIVES_FILENAME).read_text(encoding="utf-8"))
    (entry,) = sidecar["scenarios"]
    assert entry["source"] == "fallback"
    assert len(entry["rejected"]) == 2
    analysts = render_scenario_presentation(spec)[0]
    assert entry["deterministic_narrative"] == analysts
    assert analysts.startswith("Test hypothesis")
    assert analysts != plain


def test_an_accepted_narration_publishes_the_model_paragraph_unmarked(
    tmp_path: Path,
) -> None:
    spec = adversarial()
    reply = valid_reply(spec)
    client = MockLLMClient()
    client.set_response_for(NarrationReply, reply)

    published = _narrate(_inputs(client, tmp_path), [spec])

    assert len(client.calls) == 1
    paragraph = " ".join(sentence["text"] for sentence in reply["sentences"])
    assert published == {spec.scenario_id: PublishedNarrative(paragraph)}
    envelope = _run_stage6_for_spec(spec, published[spec.scenario_id])
    assert not envelope.narrative_fallback
    handoff = build_scenario_handoff_v5(envelope)
    assert handoff.narrative == paragraph
    assert NARRATIVE_FALLBACK_FACT not in handoff.sourced_facts
    assert (
        NARRATIVE_FALLBACK_FACT
        not in build_scenario_handoff_v5(_run_stage6_for_spec(spec)).sourced_facts
    )
