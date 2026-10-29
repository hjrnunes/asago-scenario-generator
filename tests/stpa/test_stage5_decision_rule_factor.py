"""A decision-rule factor: the controller's belief is right, its decision is wrong.

Stage 5 offers the selected controller as one more causal source, of kind
``INADEQUATE_CONTROL_ALGORITHM``. Such a factor is not a flawed belief, so the
belief step asks no belief for it: its entry is ``{"flawed_belief": null}``,
the handoff publishes ``process_model_belief: null``, the attack tree prints
no belief for it, and the narrative explains the action by the faulty decision
rule rather than by an incorrect belief. Every other kind still needs a
non-blank belief. Every test is offline and uses synthetic replies.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.models.causal_factor import (
    CausalFactor,
    CausalFactorKind,
    ProcessModelVariable,
    collect_source_ids,
    is_belief_flaw,
    namespace_for,
    validate_factor_sources,
)
from asago_scenario_generator.stpa.scenario_prod._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.scenario_prod.handoff import (
    ScenarioHandoffV5,
    verify_handoff_digest,
)
from asago_scenario_generator.stpa.scenario_prod.handoff_v5 import (
    build_scenario_handoff_v5,
)
from asago_scenario_generator.stpa.scenario_prod.narration import (
    AGENT_BELIEF,
    DECISION_RULE,
    NarrationReply,
    build_facts,
    narration_failures,
    render_narration_prompts,
    write_fallback,
)
from asago_scenario_generator.stpa.scenario_prod.run import run_sp3
from asago_scenario_generator.stpa.scenario_prod.stage5.belief_step import (
    BELIEFS_FILENAME,
    apply_beliefs,
    belief_failures,
    belief_reply_type,
    belief_request,
    render_belief_prompts,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.prompt_view import (
    build_context_bdi_prompts,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.shape_step import (
    ShapeProposal,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.sources import (
    _causal_source_choices,
)
from tests.helpers.belief_step import (
    RULE_EVIDENCE,
    RULE_HANDLE,
    decision_rule_belief_spec,
)
from tests.helpers.normal_authoring_wire import _wrong_timing_context
from tests.helpers.scenario_handoff_publication import (
    _functional_payload,
    _normal_semantics_payload,
    _published_handoff,
)
from tests.helpers.shape_step_call import DIRECT_REPLY
from tests.helpers.sp3_run import _make_ets
from tests.helpers.stpa_builders import make_cs, make_loss_analysis
from tests.stpa.helpers import make_minimal_control_structure
from tests.stpa.test_and_or_tree import nodes, tree_of
from tests.stpa.test_narration import adversarial
from tests.stpa.test_sp3_scenario_continuity import _coordination_context
from tests.stpa.test_scenario_handoff_v5 import SCHEMA, _envelope
from tests.stpa.test_stage5_belief_step import BELIEF as STEP_BELIEF
from tests.stpa.test_stage5_belief_step import BeliefClient

BELIEF = "The payment batch was already approved by the account holder."


def _spec(tmp_path: Path, *handles: str):
    return decision_rule_belief_spec(tmp_path, *handles)


# --- a factor that is not a belief flaw publishes no belief -----------------


def test_a_decision_rule_factor_is_accepted_with_a_null_belief(tmp_path) -> None:
    spec, structure = _spec(tmp_path, "cause_1", RULE_HANDLE)
    request = belief_request(spec, structure)
    reply = belief_reply_type(request).model_validate(
        {"cause_1": {"flawed_belief": BELIEF}, RULE_HANDLE: {"flawed_belief": None}}
    )

    assert belief_failures(reply, request) == []
    stated = apply_beliefs(spec, reply, request)
    rule = stated.causal_factors[1]
    assert rule.kind is CausalFactorKind.inadequate_control_algorithm
    assert rule.source_id == "RESP-1"
    assert rule.flawed_belief is None
    assert rule.process_model_variable is None
    assert stated.causal_factors[0].flawed_belief == BELIEF


# --- vocabulary and namespace -------------------------------------------------


def test_the_kind_cites_the_selected_controller_responsibility_or_link() -> None:
    assert CausalFactorKind.inadequate_control_algorithm.value == (
        "INADEQUATE_CONTROL_ALGORITHM"
    )
    assert namespace_for(CausalFactorKind.inadequate_control_algorithm) == "RESP or CL"
    for source_id in ("RESP-1", "CL-2"):
        CausalFactor(
            kind=CausalFactorKind.inadequate_control_algorithm,
            source_id=source_id,
            description="e",
        )
    with pytest.raises(ValidationError, match="RESP or CL namespace"):
        CausalFactor(
            kind=CausalFactorKind.inadequate_control_algorithm,
            source_id="CA-1-1",
            description="e",
        )


def test_only_the_decision_rule_kind_is_not_a_belief_flaw() -> None:
    assert {kind for kind in CausalFactorKind if not is_belief_flaw(kind)} == {
        CausalFactorKind.inadequate_control_algorithm
    }


def test_the_structure_supplies_responsibilities_as_decision_rule_sources() -> None:
    structure = make_minimal_control_structure()
    ids = collect_source_ids(structure)[CausalFactorKind.inadequate_control_algorithm]
    assert "RESP-1" in ids
    validate_factor_sources(
        structure,
        [
            CausalFactor(
                kind=CausalFactorKind.inadequate_control_algorithm,
                source_id="RESP-1",
                description="e",
            )
        ],
    )
    with pytest.raises(ValueError, match="RESP-99"):
        validate_factor_sources(
            structure,
            [
                CausalFactor(
                    kind=CausalFactorKind.inadequate_control_algorithm,
                    source_id="RESP-99",
                    description="e",
                )
            ],
        )


def test_stage5_offers_the_controller_last_so_other_handles_keep_their_numbers():
    choices = _causal_source_choices(_wrong_timing_context())
    assert [(item.handle, item.kind, item.source_id) for item in choices] == [
        ("cause_1", CausalFactorKind.process_model_flaw, "PM-1-1"),
        ("cause_2", CausalFactorKind.feedback_delay, "FB-1-1"),
        ("cause_3", CausalFactorKind.sensor_anomaly, "FB-1-1"),
        ("cause_4", CausalFactorKind.actuator_anomaly, "CA-1-1"),
        (RULE_HANDLE, CausalFactorKind.inadequate_control_algorithm, "RESP-1"),
    ]
    assert choices[-1].description == RESP_RULE


# The rule a decision-rule handle names: the controller, the control action
# its rule decides, and the unsafe-control-action type and hazardous context
# in which the rule selects the unsafe action, all from the analysis data.
RESP_RULE = (
    'Decision rule of the controller "Authorize bounded payment actions", which '
    'decides whether and how it provides "Authorize a bounded batch of payment '
    'actions". As a cause, this rule selects the unsafe action (WRONG_TIMING, '
    "meaning the action is provided too early, too late, or in an unsafe order) "
    "in the hazardous context where a compromised workflow requests bulk "
    "payment actions."
)
CL_RULE = (
    'Decision rule of the coordination link "Payment authorization and policy '
    'verification coordinate", which decides whether and how it provides '
    '"Synchronize payment policy state". As a cause, this rule selects the '
    "unsafe action (INCORRECT, meaning the action is provided, but its value, "
    "content, destination, or effect is unsafe) in the hazardous context where "
    "a manipulated policy state reaches payment authorization."
)


def _rule_entry(user: str) -> dict:
    """Return the decision-rule entry of the request's causal-source list."""
    section = user.split("## Allowed Causal-Factor Sources", 1)[1]
    start = section.index("- source_handle:")
    listed = yaml.safe_load(section[start : section.index("\n---", start)])
    (entry,) = [
        item for item in listed if item["source_type"] == "a controller decision rule"
    ]
    return entry


@pytest.mark.parametrize(
    ("context", "handle", "source_id", "rule"),
    [
        (_wrong_timing_context, RULE_HANDLE, "RESP-1", RESP_RULE),
        (_coordination_context, "cause_9", "CL-1", CL_RULE),
    ],
)
def test_the_stage5_request_describes_the_decision_rule_source(
    context, handle, source_id, rule
) -> None:
    built = context()
    (choice,) = [
        item
        for item in _causal_source_choices(built)
        if item.kind is CausalFactorKind.inadequate_control_algorithm
    ]
    assert (choice.handle, choice.source_id, choice.description) == (
        handle,
        source_id,
        rule,
    )
    _, user = build_context_bdi_prompts(built, TemplateLoader(PROMPTS_DIR))

    entry = _rule_entry(user)
    assert entry["source_handle"] == handle
    assert entry["description"] == rule
    assert entry["select_when"] == (
        "Select only when the controller's belief about the situation is correct "
        "and the rule it applies to that belief still selects the unsafe action; "
        "a wrong, missing, or stale belief belongs to the process-model belief "
        "instead. Reading a correct value does not by itself make the belief "
        "correct, because the controller may misinterpret the value or not "
        "retain it, and its belief is then wrong."
    )


# --- belief-step validation ---------------------------------------------------


def test_the_decision_rule_entry_only_accepts_a_null_belief(tmp_path) -> None:
    spec, structure = _spec(tmp_path, "cause_1", RULE_HANDLE)
    reply_type = belief_reply_type(belief_request(spec, structure))
    with pytest.raises(ValidationError):
        reply_type.model_validate(
            {
                "cause_1": {"flawed_belief": BELIEF},
                RULE_HANDLE: {"flawed_belief": BELIEF},
            }
        )
    with pytest.raises(ValidationError):
        reply_type.model_validate(
            {
                "cause_1": {"flawed_belief": BELIEF},
                RULE_HANDLE: {
                    "flawed_belief": None,
                    "process_model_variable": "none",
                    "missing_variable": "x",
                },
            }
        )
    schema = reply_type.model_json_schema()
    entry = schema["$defs"][schema["properties"][RULE_HANDLE]["$ref"].split("/")[-1]]
    assert entry["properties"]["flawed_belief"]["type"] == "null"
    assert entry["required"] == ["flawed_belief"]


def test_a_belief_flaw_factor_still_rejects_a_null_or_blank_belief(
    tmp_path,
) -> None:
    spec, structure = _spec(tmp_path, "cause_1", RULE_HANDLE)
    request = belief_request(spec, structure)
    reply_type = belief_reply_type(request)
    with pytest.raises(ValidationError):
        reply_type.model_validate(
            {"cause_1": {"flawed_belief": None}, RULE_HANDLE: {"flawed_belief": None}}
        )
    blank = reply_type.model_construct(
        cause_1=reply_type.model_fields["cause_1"].annotation.model_construct(
            flawed_belief="  "
        ),
        **{
            RULE_HANDLE: reply_type.model_fields[
                RULE_HANDLE
            ].annotation.model_construct(flawed_belief=None)
        },
    )
    assert belief_failures(blank, request) == [
        "cause_1: flawed_belief is blank; state what the controller wrongly takes "
        "to be true when it issues the unsafe action."
    ]


def test_a_stated_belief_on_a_decision_rule_factor_breaks_a_rule(tmp_path) -> None:
    spec, structure = _spec(tmp_path, "cause_1", RULE_HANDLE)
    request = belief_request(spec, structure)
    reply_type = belief_reply_type(request)
    stated = reply_type.model_construct(
        cause_1=reply_type.model_fields["cause_1"].annotation.model_construct(
            flawed_belief=BELIEF
        ),
        **{
            RULE_HANDLE: reply_type.model_fields[
                RULE_HANDLE
            ].annotation.model_construct(flawed_belief=BELIEF)
        },
    )
    assert belief_failures(stated, request) == [
        f"{RULE_HANDLE}: this factor is a faulty decision rule, not a flawed "
        "belief; set flawed_belief to null."
    ]


def test_the_belief_request_marks_the_decision_rule_factor(tmp_path) -> None:
    spec, structure = _spec(tmp_path, "cause_1", RULE_HANDLE)
    _, user = render_belief_prompts(spec, belief_request(spec, structure))
    assert (
        "flawed_belief: null; this factor is a faulty decision rule, not a flawed "
        "belief" in user
    )
    assert "source_type: a controller decision rule" in user


# --- publication, attack tree and narration -----------------------------------


def _rule_factor(spec) -> CausalFactor:
    return CausalFactor(
        kind=CausalFactorKind.inadequate_control_algorithm,
        source_id=spec.scenario_context.target_control_path.controller.element_id,
        description=RULE_EVIDENCE,
    )


def _rule_spec():
    """A scenario whose one factor is the controller's faulty decision rule."""
    spec = adversarial()
    return spec.model_copy(update={"causal_factors": [_rule_factor(spec)]})


def _mixed_spec():
    """A stated belief flaw beside a faulty decision rule."""
    spec = adversarial()
    stated = spec.causal_factors[0].model_copy(
        update={
            "flawed_belief": "The order on screen belongs to the caller.",
            "process_model_variable": ProcessModelVariable(
                pm_id="PM-1-1", description="Order ownership"
            ),
        }
    )
    return spec.model_copy(update={"causal_factors": [stated, _rule_factor(spec)]})


def test_the_handoff_publishes_a_null_belief_for_a_decision_rule() -> None:
    for spec, index in ((_rule_spec(), 0), (_mixed_spec(), 1)):
        handoff = build_scenario_handoff_v5(_envelope(spec))
        document = handoff.model_dump(mode="json")
        factor = document["causal_factors"][index]

        assert factor["source_id"] == "RESP-1"
        assert "process_model_belief" in factor
        assert factor["process_model_belief"] is None
        assert factor.get("process_model_variable") is None
        assert factor["flaw"] == RULE_EVIDENCE
        assert list(Draft202012Validator(SCHEMA).iter_errors(document)) == []
    mixed = build_scenario_handoff_v5(_envelope(_mixed_spec()))
    assert mixed.causal_factors[0].process_model_belief == (
        "The order on screen belongs to the caller."
    )


def test_the_attack_tree_prints_no_belief_for_a_decision_rule() -> None:
    found = nodes(tree_of(_rule_spec()))
    mixed = nodes(tree_of(_mixed_spec()))

    assert "belief" not in found["AT-WP-1"]
    assert found["AT-WP-1"]["label"] == RULE_EVIDENCE
    assert "belief" not in mixed["AT-WP-2"]
    assert mixed["AT-WP-1"]["belief"].startswith("The agent wrongly believes that ")
    path = build_scenario_handoff_v5(_envelope(_rule_spec())).model_dump(mode="json")[
        "attack_path"
    ]
    (weak,) = [item for item in path["conditions"] if item["category"] == "weak_point"]
    assert "belief" not in weak
    assert "None" not in json.dumps(path)


def test_the_narrate_facts_give_the_decision_rule_and_no_belief() -> None:
    facts = build_facts(_rule_spec())

    assert facts.rule_only
    assert not facts.stated_beliefs
    assert facts.ids_in((AGENT_BELIEF,)) == []
    assert [fact.text for fact in facts.facts if fact.category == DECISION_RULE] == [
        RULE_EVIDENCE
    ]
    assert ("the weak point", ("weak point", "agent belief", "decision rule")) in (
        facts.coverage
    )
    mixed = build_facts(_mixed_spec())
    assert not mixed.rule_only and mixed.stated_beliefs


def _narration(facts, reason: str, cite: list[str]) -> NarrationReply:
    return NarrationReply.model_validate(
        {
            "title": "A rule releases the batch",
            "sentences": [
                {"text": "A request arrives.", "facts": facts.ids_in(("situation",))},
                {"text": reason, "facts": cite},
                {"text": "The harm follows.", "facts": facts.ids_in(("hazard",))},
            ],
        }
    )


def _reason_failures(facts, reply: NarrationReply) -> list[str]:
    return [
        item
        for item in narration_failures(reply, facts)
        if "why the agent acts" in item or "false belief" in item
    ]


def test_the_narrative_explains_a_decision_rule_without_a_belief() -> None:
    facts = build_facts(_rule_spec())
    rule_ids = facts.ids_in((DECISION_RULE,))
    by_rule = "The agent acts because its rule releases any request in the queue."

    assert _reason_failures(facts, _narration(facts, by_rule, rule_ids)) == []
    assert (
        _reason_failures(
            facts,
            _narration(
                facts,
                "The agent acts because it correctly believes the request is unapproved "
                "yet its rule still releases it.",
                rule_ids,
            ),
        )
        == []
    )


def test_the_narrative_of_a_decision_rule_rejects_a_false_belief() -> None:
    facts = build_facts(_rule_spec())
    rule_ids = facts.ids_in((DECISION_RULE,))
    (rule_id,) = rule_ids

    assert _reason_failures(
        facts,
        _narration(
            facts,
            "The agent acts because it incorrectly believes the request is approved.",
            rule_ids,
        ),
    ) == [
        'sentence 2 attributes a false belief to the agent ("incorrectly '
        'believes"); its belief is correct here, so explain the action by its '
        "faulty decision rule"
    ]
    assert _reason_failures(
        facts, _narration(facts, "The agent releases the request.", rule_ids)
    ) == [
        'no sentence says why the agent acts, as in "because the rule it applies ..."'
    ]
    assert _reason_failures(
        facts,
        _narration(
            facts,
            "The agent acts because its rule releases it.",
            facts.ids_in(("situation",)),
        ),
    ) == [
        "the sentence that says why the agent acts cites no decision rule fact; "
        f"cite the one whose rule it states: {rule_id}"
    ]


def test_a_belief_flaw_beside_a_decision_rule_keeps_the_belief_rule() -> None:
    facts = build_facts(_mixed_spec())
    reasons = _reason_failures(
        facts,
        _narration(
            facts,
            "The agent acts because its rule releases it.",
            facts.ids_in((DECISION_RULE,)),
        ),
    )

    assert reasons == [
        'no sentence says why the agent acts, as in "because it incorrectly '
        'believes that ..."'
    ]


def test_only_a_rule_only_narrate_request_asks_for_the_rule() -> None:
    rule_system, rule_user = render_narration_prompts(build_facts(_rule_spec()))
    belief_system, belief_user = render_narration_prompts(build_facts(_mixed_spec()))

    assert "3. How that faulty rule comes into play:" in rule_system
    assert (
        "do not attribute a false belief, assumption, or impression to the agent"
        in " ".join(rule_system.split())
    )
    assert "No agent belief is false in this scenario." in rule_user
    assert "3. How that flawed belief arises:" in belief_system
    assert "faulty" not in belief_system + belief_user


def test_the_fallback_names_the_decision_rule_and_no_belief() -> None:
    text = write_fallback(_rule_spec()).text
    mixed = write_fallback(_mixed_spec()).text

    assert "The agent acts unsafely because it applies a faulty decision rule;" in text
    assert "believ" not in text
    assert (
        "because it wrongly believes that the order on screen belongs to the "
        "caller, and it applies a faulty decision rule;" in mixed
    )


def test_a_run_publishes_a_decision_rule_with_a_null_belief(tmp_path: Path) -> None:
    adversarial_reply = _normal_semantics_payload()
    rule = {
        "source_handle": RULE_HANDLE,
        "evidence": RULE_EVIDENCE,
        "temporal_condition": None,
        "evidence_status": "structural_failure",
    }
    adversarial_reply["causal_factors"].append(rule)
    functional_reply = _functional_payload()
    functional_reply["causal_factors"] = [rule]
    client = BeliefClient()
    client.set_response_queue([adversarial_reply, functional_reply])
    client.set_response_for(ShapeProposal, DIRECT_REPLY)

    result = run_sp3(
        llm_client=client,
        enriched_threat_set=_make_ets(num_threats=2),
        control_structure=make_cs(),
        loss_analysis=make_loss_analysis(),
        run_dir=tmp_path,
    )

    assert result.stage_errors == []
    sidecar = json.loads((tmp_path / BELIEFS_FILENAME).read_text(encoding="utf-8"))
    assert [entry["source"] for entry in sidecar["scenarios"]] == ["model"] * 2
    published = {
        scenario_id: _published_handoff(tmp_path, scenario_id)
        for scenario_id in ("SCN-001", "SCN-002")
    }
    for document in published.values():
        assert list(Draft202012Validator(SCHEMA).iter_errors(document)) == []
        verify_handoff_digest(ScenarioHandoffV5.model_validate(document))
        rule_factor = document["causal_factors"][-1]
        assert rule_factor["flaw"] == RULE_EVIDENCE
        assert rule_factor["process_model_belief"] is None
        assert "process_model_variable" not in rule_factor
    raw = (tmp_path / "scenarios" / "SCN-002.yaml").read_text(encoding="utf-8")
    assert "process_model_belief: null" in raw
    stated = published["SCN-001"]["causal_factors"][0]
    assert stated["process_model_belief"] == STEP_BELIEF


# Wordings that explain a decision-rule-only scenario by an invented false
# belief, assumption or impression; each must be rejected.
FALSE_BELIEF_REASONS = (
    "The agent acts because it holds a false belief that the request is approved.",
    "The agent acts because it has a wrong belief about the request's approval.",
    "The agent acts because it forms a mistaken assumption that the batch is approved.",
    "The agent acts because it operates on an incorrect understanding of the request.",
    "The agent acts because it acts on an erroneous impression that review happened.",
    "The agent acts because of its flawed assumption that the batch is approved.",
    "The agent acts because it mistakenly thinks the request is approved.",
    "The agent acts because it wrongly assumes the request is approved.",
    "The agent acts because it falsely concludes the request is approved.",
    "The agent acts because it erroneously believed the batch was approved.",
    "The agent acts because it believes, wrongly, that the batch is approved.",
    "The agent acts because it is under the mistaken impression that it is approved.",
    "The agent acts because it is under the impression that the batch is approved.",
    "The agent acts because it misbelieves that the batch is approved.",
    "The agent acts because it misjudges that the batch is approved.",
    "The agent acts because it misreads the review status as approved.",
    "The agent acts because it misinterprets the empty result as an approval.",
    "The agent acts because of a misconception that the batch is approved.",
    "The agent acts because it incorrectly perceives the batch as approved.",
    # A negation that governs another verb or clause does not deny the belief.
    "The agent acts because it does not question its false belief that the "
    "request is approved.",
    "The agent acts because, without checking, it wrongly assumes the request "
    "is approved.",
    "The agent acts because it never checks and wrongly assumes the batch is approved.",
    "The agent acts because it doesn't wait and wrongly concludes the batch is approved.",
    "The agent acts because no reviewer is present, so it holds a false belief "
    "that the batch is approved.",
    "The agent acts because it is not careful and is under the impression that "
    "the batch is approved.",
    # The agent, not its rule, is the subject of the belief verb.
    "The agent acts because it wrongly judges the request eligible for release.",
    "The agent acts because the agent, following its rule, wrongly assumes the "
    "batch is approved.",
    "The agent acts because it misjudges the batch as approved.",
    # A rule that is the object of the agent's verb, or that a preposition
    # governs, is not the subject of the belief verb.
    "The agent acts because it applies its rule then wrongly assumes the "
    "request is approved.",
    "The agent acts because it follows its rule and wrongly assumes the request "
    "is approved.",
    "The agent acts because it uses the threshold and then incorrectly concludes "
    "the batch is safe.",
    "The agent acts because under its policy it wrongly assumes the request is "
    "approved.",
    "The agent acts because it applies its rule, then wrongly assumes the request "
    "is approved.",
    "The agent acts because it checks the rule then mistakenly believes the "
    "batch is approved.",
    "The agent acts because, per its policy, it wrongly assumes the batch is approved.",
    "The agent acts because the agent uses rules then wrongly assumes the batch "
    "is approved.",
    "The agent acts because it relies on its logic and misjudges the batch as safe.",
    "The agent acts because it applies that rule then wrongly assumes the batch "
    "is approved.",
    "The agent acts because it applies its threshold and its rule then wrongly "
    "assumes the batch is approved.",
    "The agent acts because it uses the limit as its rule then wrongly assumes "
    "the batch is safe.",
    # A false-belief noun phrase counts whatever its subject: a rule holds no
    # belief.
    "The agent acts because its rule rests on a false assumption that small "
    "batches are approved.",
)

# Wordings that explain the action by the decision rule; each must pass.
RULE_REASONS = (
    "The agent acts because its rule releases any request in the queue.",
    "The agent acts because it correctly believes the request is unapproved "
    "but its rule still releases it.",
    "The agent acts because the decision rule wrongly treats an unapproved "
    "batch as releasable.",
    "The agent acts because its rule incorrectly allows any batch under the limit.",
    "The agent acts because its faulty decision rule releases the batch.",
    "The agent holds no false belief; it acts because its rule releases the batch.",
    "The agent acts because of its rule, not because of a mistaken assumption.",
    "The agent acts because its rule, rather than a false belief, releases the batch.",
    "The agent acts because its rule wrongly decides that the limit alone suffices.",
    # A rule, policy, logic, criterion or threshold as the subject of the
    # belief verb describes the faulty decision rule.
    "The agent acts because its rule incorrectly judges an unapproved request "
    "eligible for release.",
    "The agent acts because its rule wrongly concludes that any batch under the "
    "limit is safe.",
    "The agent acts because the decision rule incorrectly assumes every flagged "
    "request is safe.",
    "The agent acts because its policy logic wrongly infers approval from a low amount.",
    "The agent acts because its threshold wrongly judges small batches safe.",
    "The agent acts because its rule misjudges the risk of small batches.",
    "The agent releases the batch because it acts, and its rule wrongly assumes "
    "every small batch is safe.",
    "The request is released because the decision rule incorrectly assumes "
    "every flagged request is safe.",
    "The agent acts because its rule-based logic wrongly infers approval from "
    "the amount.",
    "The agent acts because the agent's rule still wrongly concludes that small "
    "batches are safe.",
    "Its rule wrongly assumes every small batch is safe, so the agent acts "
    "because of it.",
    "The agent acts; its policy wrongly judges small batches safe because of the rule.",
    "The agent acts because it believes that its rule wrongly assumes nothing "
    "about approval.",
    "The agent acts because its own decision rule wrongly assumes small batches "
    "are safe.",
    "The agent acts because, when its threshold incorrectly judges a batch safe, "
    "the batch is released.",
    # A negation that governs the false-belief wording itself denies it.
    "The agent does not wrongly assume anything; it acts because its rule "
    "releases the batch.",
    "The agent acts because of its rule and without any false belief.",
    "The agent acts because its rule, not a mistaken assumption, releases the batch.",
    "The agent isn't under any illusion; it acts because its rule releases the batch.",
)


@pytest.mark.parametrize("reason", FALSE_BELIEF_REASONS)
def test_a_decision_rule_narrative_rejects_any_false_belief_wording(reason) -> None:
    facts = build_facts(_rule_spec())
    failures = _reason_failures(
        facts, _narration(facts, reason, facts.ids_in((DECISION_RULE,)))
    )

    assert any(item.startswith("sentence 2 ") for item in failures), failures
    assert all("false belief" in item for item in failures), failures


@pytest.mark.parametrize("reason", RULE_REASONS)
def test_a_decision_rule_narrative_accepts_rule_wording(reason) -> None:
    facts = build_facts(_rule_spec())

    assert (
        _reason_failures(
            facts, _narration(facts, reason, facts.ids_in((DECISION_RULE,)))
        )
        == []
    )


def test_a_decision_rule_title_rejects_a_false_belief() -> None:
    facts = build_facts(_rule_spec())
    reply = _narration(
        facts,
        "The agent acts because its rule releases the batch.",
        facts.ids_in((DECISION_RULE,)),
    ).model_copy(update={"title": "The agent wrongly assumes the batch is approved"})

    assert [item for item in _reason_failures(facts, reply)] == [
        'the title attributes a false belief to the agent ("wrongly assumes"); its '
        "belief is correct here, so explain the action by its faulty decision rule"
    ]
