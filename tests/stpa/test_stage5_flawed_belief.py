"""Stated flawed beliefs behind ``--flawed-belief stated``.

With the flag on, every Stage 5 causal factor states what the controller
wrongly takes to be true and names the process-model variable that holds it
(or a gap). Code fills the variable of process-model factors and of feedback
factors whose updated variable is on the path; the model chooses the rest.
Downstream, the agent-belief fact, the and-or weak point and the v5 causal
factor carry the stated belief. With the flag off nothing changes. Every test
is offline and uses synthetic replies.
"""

from __future__ import annotations

import copy
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from asago_scenario_generator.pipeline.synthesis_types import SynthesisInputs
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.models.causal_factor import (
    CausalFactor,
    CausalFactorKind,
    ProcessModelVariable,
)
from asago_scenario_generator.stpa.scenario_prod._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.scenario_prod.and_or_tree import AttackTreeFormat
from asago_scenario_generator.stpa.scenario_prod.handoff import (
    HandoffFormat,
    ScenarioHandoffV5,
    handoff_ownership_violations,
    verify_handoff_digest,
)
from asago_scenario_generator.stpa.scenario_prod.narration import (
    AGENT_BELIEF,
    NarrationReply,
    build_facts,
    narration_failures,
    render_narration_prompts,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.feedback import (
    _normal_validation_retry_feedback,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.flawed_belief import (
    FlawedBeliefFrame,
    FlawedBeliefMode,
    VariableChoice,
    build_flawed_belief_frame,
    flawed_belief_findings,
    validate_flawed_beliefs,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.generate import (
    generate_bdi_for_context,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.issues import (
    ExactIssueError,
    IssueCode,
    issues_of,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.prompt_view import (
    build_context_bdi_prompts,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.schema import (
    _scenario_semantics_payload_type,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.sources import (
    _causal_source_choices,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.shape_step import (
    ShapeProposal,
)
from asago_scenario_generator.stpa.scenario_prod.run import run_sp3
from tests.helpers.normal_authoring_wire import (
    _normal_payload,
    _wrong_timing_assembly,
    _wrong_timing_context,
)
from tests.helpers.scenario_handoff_publication import (
    _functional_payload,
    _normal_semantics_payload,
    _published_handoff,
)
from tests.helpers.shape_step_call import DIRECT_REPLY
from tests.helpers.sp3_run import _make_ets
from tests.helpers.stpa_builders import make_cs, make_loss_analysis
from tests.stpa.sp1_helpers import MockLLMClient
from tests.stpa.test_and_or_tree import nodes, tree_of
from tests.stpa.test_narration import adversarial
from tests.stpa.test_scenario_handoff_v5 import SCHEMA, fields_of

BELIEF = "The payment batch was already approved by the account holder."
CA_BELIEF = "The account holder asked for this exact batch of payments."
GAP = "Whether the account holder approved the batch"


def _frame() -> tuple[FlawedBeliefFrame, Any, Any]:
    context = _wrong_timing_context()
    assembly = _wrong_timing_assembly(context)
    choices = _causal_source_choices(context)
    return (
        build_flawed_belief_frame(choices, context, assembly.control_structure),
        context,
        assembly,
    )


def _stated(factor: dict, belief: str, variable: str | None, missing: str | None):
    return {
        **factor,
        "flawed_belief": belief,
        "process_model_variable": variable,
        "missing_variable": missing,
    }


def _stated_payload() -> dict:
    """A PM factor (code fills its variable) and a CA factor with a gap."""
    payload = _normal_payload()
    payload["causal_factors"] = [
        _stated(payload["causal_factors"][0], BELIEF, None, None),
        _stated(
            {
                "source_handle": "cause_4",
                "evidence": "The action runs the whole batch without a check.",
                "temporal_condition": None,
                "evidence_status": "structural_failure",
            },
            CA_BELIEF,
            "none",
            GAP,
        ),
    ]
    payload["attacker_bdi"]["intentions"][0]["source_handles"] = ["cause_1", "cause_4"]
    return payload


def _generate(tmp_path: Path, *replies: dict, stated: bool = True):
    client = MockLLMClient()
    client.set_response_queue(list(replies))
    context = _wrong_timing_context()
    result = generate_bdi_for_context(
        client,
        context,
        tmp_path,
        assembly=_wrong_timing_assembly(context),
        stated_beliefs=stated,
    )
    return client, result


# --- frame --------------------------------------------------------------------


def test_code_fills_the_variable_of_pm_and_on_path_feedback_sources() -> None:
    frame, _, _ = _frame()

    assert frame.variables == (
        VariableChoice("variable_1", "PM-1-1", "Recent payment-action count", ()),
    )
    # cause_1 is the PM, cause_2 and cause_3 its feedback; cause_4 is the CA.
    assert dict(frame.fixed) == {
        "cause_1": "variable_1",
        "cause_2": "variable_1",
        "cause_3": "variable_1",
    }


def test_the_model_chooses_for_feedback_whose_variable_is_off_the_path() -> None:
    context = _wrong_timing_context()
    structure = _wrong_timing_assembly(context).control_structure
    responsibility = structure.responsibilities[0]
    moved = responsibility.model_copy(
        update={
            "feedback_channels": [
                channel.model_copy(update={"updates": "PM-9-9"})
                for channel in responsibility.feedback_channels
            ]
        }
    )
    structure = structure.model_copy(update={"responsibilities": [moved]})

    frame = build_flawed_belief_frame(
        _causal_source_choices(context), context, structure
    )

    assert dict(frame.fixed) == {"cause_1": "variable_1"}


# --- request ------------------------------------------------------------------


def test_off_requests_carry_no_belief_field_or_variable_section() -> None:
    context = _wrong_timing_context()
    loader = TemplateLoader(PROMPTS_DIR)
    off = build_context_bdi_prompts(context, loader)
    schema = _scenario_semantics_payload_type(4).model_json_schema()

    assert off == build_context_bdi_prompts(context, loader, flawed_beliefs=None)
    for prompt in off:
        assert "flawed_belief" not in prompt
        assert "Process-Model Variables" not in prompt
    assert "flawed_belief" not in str(schema)


def test_stated_requests_show_the_variables_and_who_fills_each_one() -> None:
    frame, context, _ = _frame()
    system, user = (
        " ".join(prompt.split())
        for prompt in build_context_bdi_prompts(
            context, TemplateLoader(PROMPTS_DIR), flawed_beliefs=frame
        )
    )

    assert "`flawed_belief` is what the controller wrongly takes to be true" in system
    assert "set `process_model_variable` to `none`" in system
    assert "## Process-Model Variables" in user
    assert "variable_handle: variable_1" in user
    assert "description: Recent payment-action count" in user
    assert user.count("filled by code (variable_1)") == 3
    assert user.count("your choice: the handle of the listed variable") == 1
    assert "Select only when the flawed belief is about this variable" in user
    assert "a belief that no listed process-model variable holds" in user
    for identifier in ("PM-1-1", "FB-1-1"):
        assert identifier not in user


def test_the_stated_schema_requires_the_belief_fields_on_every_branch() -> None:
    model = _scenario_semantics_payload_type(4, belief_variable_count=1)
    schema = model.model_json_schema()
    branches = [
        definition
        for name, definition in schema["$defs"].items()
        if "CausalFactorDraft" in name
    ]

    assert len(branches) == 3
    for branch in branches:
        assert {"flawed_belief", "process_model_variable", "missing_variable"} <= set(
            branch["required"]
        )
        assert branch["properties"]["process_model_variable"]["anyOf"][0]["enum"] == [
            "variable_1",
            "none",
        ]
    payload = _stated_payload()
    payload["causal_factors"][1]["process_model_variable"] = "variable_2"
    with pytest.raises(ValidationError):
        model.model_validate(payload)


# --- validation ---------------------------------------------------------------


def _draft_factors(*factors: dict) -> Any:
    model = _scenario_semantics_payload_type(4, belief_variable_count=1)
    payload = _stated_payload()
    payload["causal_factors"] = list(factors)
    payload["attacker_bdi"]["intentions"][0]["source_handles"] = [
        item["source_handle"] for item in factors
    ]
    return model.model_validate(payload).causal_factors


def _findings(*factors: dict) -> list[str]:
    frame, context, _ = _frame()
    choices = {choice.handle: choice for choice in _causal_source_choices(context)}
    return flawed_belief_findings(_draft_factors(*factors), frame, choices)


def _pm(belief: str, variable: str | None = None, missing: str | None = None):
    return _stated(_stated_payload()["causal_factors"][0], belief, variable, missing)


def _ca(belief: str, variable: str | None, missing: str | None):
    return _stated(_stated_payload()["causal_factors"][1], belief, variable, missing)


def test_a_valid_reply_breaks_no_rule() -> None:
    assert _findings(*_stated_payload()["causal_factors"]) == []


@pytest.mark.parametrize(
    ("factor", "expected"),
    [
        (
            _pm("The count for PM-1-1 is low."),
            "causal_factors[0] (cause_1): flawed_belief contains the identifier "
            "PM-1-1; state the belief in domain words.",
        ),
        (
            _pm("The cause_2 feedback is current."),
            "causal_factors[0] (cause_1): flawed_belief contains the identifier "
            "cause_2; state the belief in domain words.",
        ),
        (
            _pm("The recent payment-action count."),
            "causal_factors[0] (cause_1): flawed_belief only names a variable or "
            "source description; state the wrong value the controller takes to be "
            "true in this scenario.",
        ),
        (
            _pm("The flawed belief concerns: recent payment-action count"),
            "causal_factors[0] (cause_1): flawed_belief only names a variable or "
            "source description; state the wrong value the controller takes to be "
            "true in this scenario.",
        ),
        (
            _pm(BELIEF, "none"),
            "causal_factors[0] (cause_1): code fills this factor's variable; set "
            "process_model_variable and missing_variable to null.",
        ),
        (
            _pm(BELIEF, "variable_1", GAP),
            "causal_factors[0] (cause_1): code fills this factor's variable; set "
            "process_model_variable and missing_variable to null.",
        ),
        (
            _ca(CA_BELIEF, None, None),
            "causal_factors[0] (cause_4): process_model_variable is null; choose "
            "one of variable_1, none.",
        ),
        (
            _ca(CA_BELIEF, "none", " "),
            "causal_factors[0] (cause_4): process_model_variable is none, so "
            "missing_variable must describe the variable the controller would "
            "need to hold the belief.",
        ),
        (
            _ca(CA_BELIEF, "none", "The RESP-1 approval flag"),
            "causal_factors[0] (cause_4): missing_variable contains the identifier "
            "RESP-1; describe the variable in domain words.",
        ),
        (
            _ca(CA_BELIEF, "none", "recent payment-action count"),
            "causal_factors[0] (cause_4): missing_variable describes the listed "
            "variable variable_1; choose variable_1 instead of none.",
        ),
        (
            _ca(CA_BELIEF, "variable_1", GAP),
            "causal_factors[0] (cause_4): process_model_variable names a listed "
            "variable, so set missing_variable to null.",
        ),
    ],
)
def test_each_rule_names_the_factor_and_the_fix(factor: dict, expected: str) -> None:
    assert _findings(factor) == [expected]


@pytest.mark.parametrize(
    "factor",
    [
        _pm(BELIEF, "variable_1"),
        _pm(BELIEF, None, " "),
        _ca(CA_BELIEF, "variable_1", " "),
    ],
)
def test_a_value_that_agrees_with_code_breaks_no_rule(factor: dict) -> None:
    assert _findings(factor) == []


INQUIRY = VariableChoice(
    "variable_1",
    "PM-1-1",
    "Nature of the patient's inquiry (values: diagnostic/prescriptive request; "
    "red-flag symptom identified; general educational inquiry) "
    "(evidence: argument:ask_clinical_question.question)",
    (
        "diagnostic/prescriptive request",
        "red-flag symptom identified",
        "general educational inquiry",
    ),
)
NAMES_ONLY = (
    "causal_factors[0] (cause_1): flawed_belief only names a variable or source "
    "description; state the wrong value the controller takes to be true in this "
    "scenario."
)


@pytest.mark.parametrize(
    ("belief", "expected"),
    [
        ("The patient's inquiry is a general educational inquiry.", []),
        ("The inquiry is a red-flag symptom identified.", []),
        ("Nature of the patient's inquiry", [NAMES_ONLY]),
        (
            "The patient's inquiry is a diagnostic/prescriptive request or a "
            "general educational inquiry.",
            [NAMES_ONLY],
        ),
    ],
)
def test_a_belief_may_pick_one_value_the_description_lists(
    belief: str, expected: list[str]
) -> None:
    """The description spells out its values; picking one states a value."""
    _, context, _ = _frame()
    frame = FlawedBeliefFrame(variables=(INQUIRY,), fixed=(("cause_1", "variable_1"),))
    choices = {choice.handle: choice for choice in _causal_source_choices(context)}
    choices["cause_1"] = replace(choices["cause_1"], description=INQUIRY.description)

    findings = flawed_belief_findings(_draft_factors(_pm(belief)), frame, choices)

    assert findings == expected


def test_one_error_names_every_broken_rule() -> None:
    frame, context, _ = _frame()
    model = _scenario_semantics_payload_type(4, belief_variable_count=1)
    payload = _stated_payload()
    payload["causal_factors"][0]["flawed_belief"] = "Recent payment-action count"
    payload["causal_factors"][1]["process_model_variable"] = None
    draft = model.model_validate(payload)

    with pytest.raises(ExactIssueError) as caught:
        validate_flawed_beliefs(
            draft.causal_factors, frame, _causal_source_choices(context)
        )

    (issue,) = issues_of(caught.value)
    assert issue.code is IssueCode.flawed_belief_invalid
    assert issue.detail.splitlines() == [
        "stated flawed beliefs break these rules:",
        "- causal_factors[0] (cause_1): flawed_belief only names a variable or "
        "source description; state the wrong value the controller takes to be "
        "true in this scenario.",
        "- causal_factors[1] (cause_4): process_model_variable is null; choose "
        "one of variable_1, none.",
    ]


def test_the_correction_names_the_code_and_the_variable_handles() -> None:
    frame, context, _ = _frame()
    feedback = _normal_validation_retry_feedback(
        context, _causal_source_choices(context), flawed_beliefs=frame
    )
    text = feedback(ExactIssueError(IssueCode.flawed_belief_invalid, "x"))

    assert "- flawed_belief_invalid: fix every listed causal factor" in text
    assert "Available process_model_variable values are variable_1, none.\n" in text
    off = _normal_validation_retry_feedback(context, _causal_source_choices(context))
    assert "process_model_variable" not in off(ValueError("x"))


# --- compile ------------------------------------------------------------------


def test_a_valid_reply_compiles_the_belief_and_variable_onto_each_factor(
    tmp_path: Path,
) -> None:
    client, (spec, error) = _generate(tmp_path, _stated_payload())

    assert error is None
    assert len(client.calls) == 1
    pm, ca = spec.causal_factors
    assert (pm.kind, pm.flawed_belief) == (CausalFactorKind.process_model_flaw, BELIEF)
    assert pm.process_model_variable == ProcessModelVariable(
        pm_id="PM-1-1", description="Recent payment-action count"
    )
    assert (ca.source_id, ca.flawed_belief) == ("CA-1-1", CA_BELIEF)
    assert ca.process_model_variable == ProcessModelVariable(
        pm_id=None, description=GAP
    )


def test_a_broken_reply_gets_one_correction_with_every_rule(tmp_path: Path) -> None:
    broken = _stated_payload()
    broken["causal_factors"][0]["process_model_variable"] = "none"
    broken["causal_factors"][1]["flawed_belief"] = "Uses FB-1-1 data."

    client, (spec, error) = _generate(tmp_path, broken, _stated_payload())

    assert error is None and spec.causal_factors[0].flawed_belief == BELIEF
    correction = client.calls[1].user_prompt
    assert "flawed_belief_invalid: stated flawed beliefs break these rules:\n" in (
        correction
    )
    assert "- causal_factors[0] (cause_1): code fills this factor's variable" in (
        correction
    )
    assert "- causal_factors[1] (cause_4): flawed_belief contains the identifier " in (
        correction
    )


def test_off_keeps_the_factor_without_belief_fields(tmp_path: Path) -> None:
    _, (spec, error) = _generate(tmp_path, _normal_payload(), stated=False)

    assert error is None
    factor = spec.causal_factors[0]
    assert factor.flawed_belief is None and factor.process_model_variable is None
    assert "flawed_belief" not in factor.model_dump_json()
    assert "process_model_variable" not in factor.model_dump_json()


# --- downstream ---------------------------------------------------------------


def _stated_spec(variable: ProcessModelVariable | None = None):
    spec = adversarial()
    factor = spec.causal_factors[0].model_copy(
        update={
            "flawed_belief": "The order on screen belongs to the caller.",
            "process_model_variable": variable
            or ProcessModelVariable(pm_id="PM-1-1", description="Order ownership"),
        }
    )
    return spec.model_copy(update={"causal_factors": [factor]})


def test_the_agent_belief_fact_states_the_belief_and_its_variable() -> None:
    facts = build_facts(_stated_spec())

    beliefs = [fact.text for fact in facts.facts if fact.category == AGENT_BELIEF]
    assert beliefs == [
        "The agent wrongly believes that the order on screen belongs to the "
        "caller. The belief concerns: order ownership."
    ]
    assert facts.stated_beliefs


def test_a_gap_fact_states_the_belief_alone() -> None:
    gap = ProcessModelVariable(pm_id=None, description="Who owns the order")
    facts = build_facts(_stated_spec(gap))

    assert [f.text for f in facts.facts if f.category == AGENT_BELIEF] == [
        "The agent wrongly believes that the order on screen belongs to the caller."
    ]


def _reply(facts, cite_belief: bool) -> NarrationReply:
    belief = facts.ids_in((AGENT_BELIEF,))
    weak = facts.ids_in(("weak point",))
    return NarrationReply.model_validate(
        {
            "title": "A wrong owner",
            "sentences": [
                {
                    "text": "The agent acts because it incorrectly believes the "
                    "order is the caller's.",
                    "facts": (belief if cite_belief else []) + weak,
                },
                {"text": "The harm follows.", "facts": facts.ids_in(("hazard",))},
            ],
        }
    )


def test_the_narrate_rule_requires_the_reason_to_cite_a_belief_fact() -> None:
    facts = build_facts(_stated_spec())
    (belief_id,) = facts.ids_in((AGENT_BELIEF,))
    rule = (
        "the sentence that says why the agent acts cites no agent belief fact; "
        f"cite the one whose belief it states: {belief_id}"
    )

    assert rule in narration_failures(_reply(facts, False), facts)
    assert rule not in narration_failures(_reply(facts, True), facts)
    off = build_facts(adversarial())
    assert not any(
        "cites no agent belief fact" in item
        for item in narration_failures(_reply(off, False), off)
    )


def test_the_narrate_request_names_the_belief_fact_only_when_stated() -> None:
    stated = build_facts(_stated_spec())
    (belief_id,) = stated.ids_in((AGENT_BELIEF,))
    _, user = render_narration_prompts(stated)
    _, off = render_narration_prompts(build_facts(adversarial()))

    assert user.endswith(
        'The sentence that says why the agent acts ("because it incorrectly '
        'believes\nthat ...") cites the agent belief fact whose belief it states: '
        f"{belief_id}.\n"
    )
    assert "cites the agent belief fact" not in off


def test_the_weak_point_carries_the_belief_and_its_variable_or_gap() -> None:
    found = nodes(tree_of(_stated_spec()))
    gap = nodes(
        tree_of(_stated_spec(ProcessModelVariable(pm_id=None, description="Owner")))
    )

    assert found["AT-WP-1"]["belief"] == (
        "The agent wrongly believes that the order on screen belongs to the "
        "caller. Process-model variable: order ownership."
    )
    assert gap["AT-WP-1"]["belief"] == (
        "The agent wrongly believes that the order on screen belongs to the "
        "caller. No process-model variable; missing: owner."
    )
    assert list(found) == list(nodes(tree_of(adversarial())))


def test_the_v5_factor_publishes_the_belief_and_the_variable() -> None:
    fields = fields_of(_stated_spec())
    gap = fields_of(_stated_spec(ProcessModelVariable(pm_id=None, description="Who")))

    assert fields["causal_factors"][0]["process_model_belief"] == (
        "The order on screen belongs to the caller."
    )
    assert fields["causal_factors"][0]["process_model_variable"] == {
        "id": "PM-1-1",
        "description": "Order ownership",
    }
    assert gap["causal_factors"][0]["process_model_variable"] == {
        "id": None,
        "description": "Who",
    }
    assert "process_model_variable" not in fields_of(adversarial())["causal_factors"][0]


# --- run ----------------------------------------------------------------------


def _with_beliefs(payload: dict) -> dict:
    payload = copy.deepcopy(payload)
    payload["causal_factors"] = [
        _stated(item, BELIEF, None, None) for item in payload["causal_factors"]
    ]
    return payload


def test_a_stated_run_publishes_the_beliefs_through_to_the_handoff(
    tmp_path: Path,
) -> None:
    client = MockLLMClient()
    client.set_response_queue(
        [
            _with_beliefs(_normal_semantics_payload()),
            _with_beliefs(_functional_payload()),
        ]
    )
    client.set_response_for(ShapeProposal, DIRECT_REPLY)

    result = run_sp3(
        llm_client=client,
        enriched_threat_set=_make_ets(num_threats=2),
        control_structure=make_cs(),
        loss_analysis=make_loss_analysis(),
        run_dir=tmp_path,
        handoff_format=HandoffFormat.V5,
        attack_tree_format=AttackTreeFormat.AND_OR,
        flawed_belief=FlawedBeliefMode.STATED,
    )

    assert result.stage_errors == []
    assert "## Process-Model Variables" in client.calls[0].user_prompt
    for scenario_id in ("SCN-001", "SCN-002"):
        document = _published_handoff(tmp_path, scenario_id)
        assert list(Draft202012Validator(SCHEMA).iter_errors(document)) == []
        assert handoff_ownership_violations(document) == []
        verify_handoff_digest(ScenarioHandoffV5.model_validate(document))
        for factor in document["causal_factors"]:
            assert factor["process_model_belief"] == BELIEF
            assert factor["process_model_variable"]["id"].startswith("PM-")
        weak_points = [
            node
            for node in nodes(document["attack_tree"]).values()
            if node["node_id"].startswith("AT-WP-")
        ]
        assert weak_points and all(
            node["belief"].startswith("The agent wrongly believes that ")
            for node in weak_points
        )


def test_stated_requires_v5() -> None:
    with pytest.raises(ValueError, match="flawed_belief=stated requires"):
        run_sp3(
            llm_client=MockLLMClient(),
            enriched_threat_set=_make_ets(num_threats=1),
            control_structure=make_cs(),
            loss_analysis=make_loss_analysis(),
            run_dir=Path("/nonexistent"),
            flawed_belief=FlawedBeliefMode.STATED,
        )


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"flawed_belief": "on"}, "flawed_belief must be off or stated"),
        ({"flawed_belief": "stated"}, "flawed_belief stated requires handoff_format"),
    ],
)
def test_the_synthesis_request_checks_the_flag(changes, message) -> None:
    with pytest.raises(ValueError, match=message):
        SynthesisInputs.__post_init__(
            type(
                "Probe", (), {"use_case": "x", "max_workers": 1, **_DEFAULTS, **changes}
            )()
        )


_DEFAULTS = {
    "narration_mode": "off",
    "attack_tree_format": "flat",
    "handoff_format": "v4",
    "model_gherkin": "off",
    "flawed_belief": "off",
}


def test_causal_factor_rejects_a_variable_outside_the_pm_namespace() -> None:
    with pytest.raises(ValidationError):
        ProcessModelVariable(pm_id="FB-1-1", description="x")
    factor = CausalFactor(
        kind=CausalFactorKind.process_model_flaw,
        source_id="PM-1-1",
        description="d",
    )
    assert (
        factor.model_dump()
        == CausalFactor.model_validate(factor.model_dump()).model_dump()
    )
