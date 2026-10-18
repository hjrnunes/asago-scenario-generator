"""The stated-belief step behind ``--flawed-belief separate``.

Stage 5 sends what ``off`` sends; then one request per Stage 5 spec states
each causal factor's flawed belief and, where code does not fill it, the
process-model variable that holds it or the variable the controller lacks.
Code checks the reply with the ``stated`` rules and never repairs it; a reply
that breaks a rule or does not decode earns one correction, and any remaining
failure leaves the spec unchanged. Every test is offline and uses a fake
client.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from asago_scenario_generator.pipeline import synthesis
from asago_scenario_generator.stpa.infra.llm import _json_schema_response_format
from asago_scenario_generator.stpa.infra.provider_record import (
    LiveRequestBudgetError,
)
from asago_scenario_generator.stpa.models.causal_factor import ProcessModelVariable
from asago_scenario_generator.stpa.scenario_prod.and_or_tree import AttackTreeFormat
from asago_scenario_generator.stpa.scenario_prod.handoff import (
    HandoffFormat,
    ScenarioHandoffV5,
    handoff_ownership_violations,
    verify_handoff_digest,
)
from asago_scenario_generator.stpa.scenario_prod.narration import (
    AGENT_BELIEF,
    build_facts,
    render_narration_prompts,
)
from asago_scenario_generator.stpa.scenario_prod.presentation import (
    render_scenario_summary,
)
from asago_scenario_generator.stpa.scenario_prod.run import run_sp3
from asago_scenario_generator.stpa.scenario_prod.stage5.belief_step import (
    BELIEF_MAX_COMPLETION_TOKENS,
    BELIEF_STAGE,
    BELIEF_STEP,
    BELIEFS_FILENAME,
    StatedBeliefReply,
    apply_belief_step,
    belief_failures,
    belief_reply_type,
    belief_request,
    render_belief_prompts,
    state_beliefs,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.flawed_belief import (
    FlawedBeliefMode,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.shape_step import (
    ShapeProposal,
)
from tests.helpers.belief_step import CA_EVIDENCE, belief_spec
from tests.helpers.scenario_handoff_publication import (
    _functional_payload,
    _normal_semantics_payload,
    _published_handoff,
)
from tests.helpers.shape_step_call import DIRECT_REPLY
from tests.helpers.sp3_run import _make_ets
from tests.helpers.stpa_builders import make_cs, make_loss_analysis
from tests.stpa.sp1_helpers import MockLLMClient
from tests.stpa.test_and_or_tree import invoke_generate, nodes, tree_of
from tests.stpa.test_scenario_handoff_v5 import SCHEMA

BELIEF = "The payment batch was already approved by the account holder."
CA_BELIEF = "The account holder asked for this exact batch of payments."
GAP = "Whether the account holder approved the batch"


def _valid() -> dict[str, Any]:
    return {
        "cause_1": {"flawed_belief": BELIEF},
        "cause_4": {
            "flawed_belief": CA_BELIEF,
            "process_model_variable": "none",
            "missing_variable": GAP,
        },
    }


def reply_for(response_format: type) -> dict[str, Any]:
    """Return a reply that keeps every rule for any request's handles."""
    reply: dict[str, Any] = {}
    for handle, info in response_format.model_fields.items():
        fields = info.annotation.model_fields
        reply[handle] = (
            {"flawed_belief": BELIEF}
            if "process_model_variable" not in fields
            else {
                "flawed_belief": CA_BELIEF,
                "process_model_variable": "none",
                "missing_variable": GAP,
            }
        )
    return reply


class BeliefClient(MockLLMClient):
    """A fake client whose belief replies fit each request's handles."""

    def __init__(
        self, belief: Callable[[type], Any] | None = reply_for, **kwargs: Any
    ) -> None:
        super().__init__(**kwargs)
        self.belief = belief

    def complete(self, system_prompt: str, user_prompt: str, **kwargs: Any) -> Any:
        response_format = kwargs.get("response_format")
        if (
            self.belief is not None
            and isinstance(response_format, type)
            and issubclass(response_format, StatedBeliefReply)
        ):
            self.set_response_for(response_format, self.belief(response_format))
        return super().complete(system_prompt, user_prompt, **kwargs)


@pytest.fixture
def spec_and_structure(tmp_path: Path):
    return belief_spec(tmp_path / "stage5")


def _state(spec_and_structure, tmp_path: Path, client: MockLLMClient):
    spec, structure = spec_and_structure
    return state_beliefs(
        spec, llm_client=client, run_dir=tmp_path, control_structure=structure
    )


# --- request ------------------------------------------------------------------


def test_each_factor_keeps_its_stage5_handle_and_code_fills_the_pm_variable(
    spec_and_structure,
) -> None:
    spec, structure = spec_and_structure
    request = belief_request(spec, structure)

    assert [(index, choice.handle) for index, choice in request.listed] == [
        (0, "cause_1"),
        (1, "cause_4"),
    ]
    assert request.frame.variable_handles == ("variable_1",)
    assert dict(request.frame.fixed) == {"cause_1": "variable_1"}


def test_the_user_prompt_lists_the_account_factors_and_variables(
    spec_and_structure,
) -> None:
    spec, structure = spec_and_structure
    _, user = render_belief_prompts(spec, belief_request(spec, structure))

    assert user.startswith(
        "## Scenario account\n\n" + render_scenario_summary(spec)[0] + "\n\n---\n"
    )
    assert (
        "- source_handle: cause_1\n"
        "  source_type: a process-model belief or state\n"
        "  source_description: Recent payment-action count\n"
        "  factor_description: The selected authorization state can remain stale.\n"
        "  process_model_variable: filled by code (variable_1); give only "
        "flawed_belief\n"
    ) in user
    assert "- source_handle: cause_4\n" in user
    assert f"  factor_description: {CA_EVIDENCE}\n" in user
    assert user.count("your choice: the handle of the listed variable") == 1
    assert user.endswith(
        "- variable_handle: variable_1\n"
        "  description: Recent payment-action count\n"
        "  values: []\n\n"
    )
    factors = user.split("## Causal Factors", 1)[1]
    for identifier in ("PM-1-1", "CA-1-1"):
        assert identifier not in factors


def test_the_shape_and_dedup_inputs_do_not_read_the_belief_fields(
    spec_and_structure,
) -> None:
    spec, _ = spec_and_structure
    factor = spec.causal_factors[0].model_copy(
        update={
            "flawed_belief": BELIEF,
            "process_model_variable": ProcessModelVariable(
                pm_id="PM-1-1", description="Recent payment-action count"
            ),
        }
    )
    stated = spec.model_copy(update={"causal_factors": [factor]})
    plain = spec.model_copy(update={"causal_factors": [spec.causal_factors[0]]})

    assert render_scenario_summary(stated)[0] == render_scenario_summary(plain)[0]


# --- schema -------------------------------------------------------------------


def test_the_schema_is_closed_with_one_entry_per_listed_handle(
    spec_and_structure,
) -> None:
    spec, structure = spec_and_structure
    model = belief_reply_type(belief_request(spec, structure))
    schema = _json_schema_response_format(model)["json_schema"]["schema"]

    assert schema["required"] == ["cause_1", "cause_4"]
    assert schema["additionalProperties"] is False
    fixed = schema["$defs"]["_FixedBelief"]
    chosen = schema["$defs"]["_ChosenBeliefV1"]
    assert fixed["required"] == ["flawed_belief"] == list(fixed["properties"])
    assert fixed["additionalProperties"] is False and "description" not in fixed
    assert chosen["required"] == [
        "flawed_belief",
        "process_model_variable",
        "missing_variable",
    ]
    assert chosen["properties"]["process_model_variable"]["enum"] == [
        "variable_1",
        "none",
    ]
    assert chosen["additionalProperties"] is False
    assert model.model_validate(_valid())


@pytest.mark.parametrize(
    "change",
    [
        lambda reply: reply.pop("cause_4"),
        lambda reply: reply.update({"cause_2": {"flawed_belief": BELIEF}}),
        lambda reply: reply["cause_1"].update({"process_model_variable": None}),
        lambda reply: reply["cause_4"].update({"process_model_variable": "variable_2"}),
        lambda reply: reply["cause_4"].update({"process_model_variable": None}),
        lambda reply: reply["cause_4"].pop("missing_variable"),
        lambda reply: reply["cause_4"].update({"flawed_belief": ""}),
    ],
    ids=[
        "missing-handle",
        "extra-handle",
        "variable-on-code-filled",
        "unknown-variable",
        "null-variable",
        "missing-field",
        "empty-belief",
    ],
)
def test_the_schema_rejects_a_reply_outside_the_listed_factors(
    spec_and_structure, change
) -> None:
    spec, structure = spec_and_structure
    model = belief_reply_type(belief_request(spec, structure))
    reply = _valid()
    change(reply)

    with pytest.raises(ValidationError):
        model.model_validate(reply)


# --- validation ---------------------------------------------------------------


def _failures(spec_and_structure, **entries: dict) -> list[str]:
    spec, structure = spec_and_structure
    request = belief_request(spec, structure)
    reply = belief_reply_type(request).model_validate({**_valid(), **entries})
    return belief_failures(reply, request)


def test_a_valid_reply_breaks_no_rule(spec_and_structure) -> None:
    assert _failures(spec_and_structure) == []


def _ca(belief: str, variable: str, missing: str | None) -> dict:
    return {
        "cause_4": {
            "flawed_belief": belief,
            "process_model_variable": variable,
            "missing_variable": missing,
        }
    }


@pytest.mark.parametrize(
    ("entries", "expected"),
    [
        (
            {"cause_1": {"flawed_belief": "The count for PM-1-1 is low."}},
            "cause_1: flawed_belief contains the identifier PM-1-1; state the "
            "belief in domain words.",
        ),
        (
            {"cause_1": {"flawed_belief": "The cause_2 feedback is current."}},
            "cause_1: flawed_belief contains the identifier cause_2; state the "
            "belief in domain words.",
        ),
        (
            {"cause_1": {"flawed_belief": " "}},
            "cause_1: flawed_belief is blank; state what the controller wrongly "
            "takes to be true when it issues the unsafe action.",
        ),
        (
            {"cause_1": {"flawed_belief": "The account holder approved RESP-6."}},
            "cause_1: flawed_belief contains the identifier RESP-6; state the "
            "belief in domain words.",
        ),
        (
            _ca(CA_BELIEF, "none", " "),
            "cause_4: process_model_variable is none, so missing_variable must "
            "describe the variable the controller would need to hold the belief.",
        ),
        (
            _ca(CA_BELIEF, "none", None),
            "cause_4: process_model_variable is none, so missing_variable must "
            "describe the variable the controller would need to hold the belief.",
        ),
        (
            _ca(CA_BELIEF, "none", "The RESP-1 approval flag"),
            "cause_4: missing_variable contains the identifier RESP-1; describe "
            "the variable in domain words.",
        ),
        (
            _ca(CA_BELIEF, "none", "recent payment-action count"),
            "cause_4: missing_variable describes the listed variable variable_1; "
            "choose variable_1 instead of none.",
        ),
        (
            _ca(CA_BELIEF, "variable_1", GAP),
            "cause_4: process_model_variable names a listed variable, so set "
            "missing_variable to null.",
        ),
    ],
)
def test_each_stated_rule_names_the_handle_and_the_fix(
    spec_and_structure, entries: dict, expected: str
) -> None:
    assert _failures(spec_and_structure, **entries) == [expected]


@pytest.mark.parametrize(
    "entries",
    [
        {"cause_1": {"flawed_belief": "The recent payment-action count."}},
        _ca("Authorize a bounded batch of payment actions", "none", GAP),
    ],
)
def test_code_leaves_to_the_model_whether_a_belief_states_a_value(
    spec_and_structure, entries: dict
) -> None:
    assert _failures(spec_and_structure, **entries) == []


@pytest.mark.parametrize(
    "entries",
    [_ca(CA_BELIEF, "variable_1", None), _ca(CA_BELIEF, "variable_1", " ")],
)
def test_a_listed_variable_with_a_null_or_blank_gap_breaks_no_rule(
    spec_and_structure, entries: dict
) -> None:
    assert _failures(spec_and_structure, **entries) == []


# --- the step -----------------------------------------------------------------


def test_a_valid_reply_states_each_factor_belief_and_variable(
    spec_and_structure, tmp_path: Path
) -> None:
    client = MockLLMClient()
    client.set_response_queue([_valid()])

    outcome = _state(spec_and_structure, tmp_path, client)

    assert (outcome.source, outcome.requests, outcome.rejected) == ("model", 1, [])
    assert outcome.reason is None
    pm, ca = outcome.spec.causal_factors
    assert pm.flawed_belief == BELIEF
    assert pm.process_model_variable == ProcessModelVariable(
        pm_id="PM-1-1", description="Recent payment-action count"
    )
    assert ca.flawed_belief == CA_BELIEF
    assert ca.process_model_variable == ProcessModelVariable(
        pm_id=None, description=GAP
    )
    spec, _ = spec_and_structure
    assert (
        outcome.spec.model_copy(update={"causal_factors": spec.causal_factors}) == spec
    )
    (call,) = client.calls
    assert call.max_completion_tokens == BELIEF_MAX_COMPLETION_TOKENS
    assert issubclass(call.response_format, StatedBeliefReply)
    (record,) = [
        json.loads(line) for line in (tmp_path / "calls.jsonl").read_text().splitlines()
    ]
    assert (record["stage"], record["step"]) == (BELIEF_STAGE, BELIEF_STEP)
    assert record["scenario_id"] == spec.scenario_id
    assert record["slot_id"] == spec.threat_source.ica_slot_id


def test_the_belief_is_stripped_and_a_chosen_variable_resolves(
    spec_and_structure, tmp_path: Path
) -> None:
    client = MockLLMClient()
    client.set_response_queue(
        [
            {
                "cause_1": {"flawed_belief": f"  {BELIEF}  "},
                "cause_4": {
                    "flawed_belief": CA_BELIEF,
                    "process_model_variable": "variable_1",
                    "missing_variable": None,
                },
            }
        ]
    )

    outcome = _state(spec_and_structure, tmp_path, client)

    pm, ca = outcome.spec.causal_factors
    assert pm.flawed_belief == BELIEF
    assert ca.process_model_variable == ProcessModelVariable(
        pm_id="PM-1-1", description="Recent payment-action count"
    )


def test_a_broken_reply_gets_one_correction_with_every_rule(
    spec_and_structure, tmp_path: Path
) -> None:
    broken = {**_valid(), **_ca("Uses FB-1-1 data.", "variable_1", GAP)}
    client = MockLLMClient()
    client.set_response_queue([broken, _valid()])

    outcome = _state(spec_and_structure, tmp_path, client)

    assert outcome.source == "model" and outcome.requests == 2
    assert outcome.rejected == [
        (
            "cause_4: flawed_belief contains the identifier FB-1-1; state the "
            "belief in domain words.",
            "cause_4: process_model_variable names a listed variable, so set "
            "missing_variable to null.",
        )
    ]
    correction = client.calls[1].user_prompt
    assert client.calls[1].system_prompt == client.calls[0].system_prompt
    assert correction.startswith(client.calls[0].user_prompt)
    assert (
        "Code rejected the prior reply. Return the whole reply again with every "
        "listed problem fixed."
    ) in correction
    assert "Prior structured response to correct in place:" in correction
    assert "stated flawed beliefs break these rules:\n" in correction
    assert "- cause_4: flawed_belief contains the identifier FB-1-1" in correction
    assert '"$defs"' not in correction


def test_a_reply_that_breaks_a_rule_twice_leaves_the_spec_unchanged(
    spec_and_structure, tmp_path: Path
) -> None:
    broken = {**_valid(), "cause_1": {"flawed_belief": "Uses PM-1-1."}}
    client = MockLLMClient()
    client.set_response_queue([broken, broken])

    outcome = _state(spec_and_structure, tmp_path, client)

    assert outcome.source == "none" and outcome.spec is None
    assert outcome.requests == 2 and len(outcome.rejected) == 2
    assert "contains the identifier PM-1-1" in (outcome.reason or "")


def test_an_undecodable_reply_gets_one_decode_correction(
    spec_and_structure, tmp_path: Path
) -> None:
    client = MockLLMClient()
    client.set_response_queue(['{"cause_1": {"flawed_belief": "The pay', _valid()])

    outcome = _state(spec_and_structure, tmp_path, client)

    assert outcome.source == "model" and outcome.requests == 2
    correction = client.calls[1].user_prompt
    assert "Code could not decode the prior reply as JSON" in correction
    assert "Code rejected the prior reply" not in correction
    assert '```json\n{"cause_1": {"flawed_belief": "The pay\n```' in correction


def test_a_schema_failure_gets_the_rejection_correction(
    spec_and_structure, tmp_path: Path
) -> None:
    client = MockLLMClient()
    client.set_response_queue([{"cause_1": {"flawed_belief": BELIEF}}, _valid()])

    outcome = _state(spec_and_structure, tmp_path, client)

    assert outcome.source == "model" and outcome.requests == 2
    assert "Code rejected the prior reply" in client.calls[1].user_prompt
    assert outcome.rejected == []


@pytest.mark.parametrize(
    "error",
    [
        RuntimeError("connection reset"),
        LiveRequestBudgetError("the budget of 0 live request(s) is spent"),
    ],
    ids=["provider-error", "budget-refusal"],
)
def test_a_failed_or_refused_call_leaves_the_spec_unchanged(
    spec_and_structure, tmp_path: Path, error: Exception
) -> None:
    client = MockLLMClient()
    client.set_exception_for(StatedBeliefReply, error)

    outcome = _state(spec_and_structure, tmp_path, client)

    assert len(client.calls) == 1
    assert outcome.source == "none" and outcome.spec is None
    assert str(error) in (outcome.reason or "")


def test_a_spec_without_context_sends_no_request(
    spec_and_structure, tmp_path: Path
) -> None:
    spec, structure = spec_and_structure
    client = MockLLMClient()

    outcome = state_beliefs(
        spec.model_copy(update={"scenario_context": None}),
        llm_client=client,
        run_dir=tmp_path,
        control_structure=structure,
    )

    assert client.calls == []
    assert (outcome.source, outcome.requests) == ("none", 0)
    assert "carries no scenario context" in (outcome.reason or "")


def test_the_step_returns_specs_in_order_and_writes_the_sidecar(
    spec_and_structure, tmp_path: Path
) -> None:
    spec, structure = spec_and_structure
    second = spec.model_copy(update={"scenario_id": "SCN-002"})
    client = MockLLMClient()
    client.set_response_queue([_valid(), "not json", "still not json"])

    specs = apply_belief_step(
        [spec, second],
        llm_client=client,
        run_dir=tmp_path,
        control_structure=structure,
    )

    assert specs[0].causal_factors[0].flawed_belief == BELIEF
    assert specs[1] is second
    sidecar = json.loads((tmp_path / BELIEFS_FILENAME).read_text(encoding="utf-8"))
    assert list(sidecar) == ["stage", "step", "scenarios"]
    assert (sidecar["stage"], sidecar["step"]) == (BELIEF_STAGE, BELIEF_STEP)
    first, failed = sidecar["scenarios"]
    assert list(first) == ["scenario_id", "source", "requests", "rejected", "reason"]
    assert first == {
        "scenario_id": spec.scenario_id,
        "source": "model",
        "requests": 1,
        "rejected": [],
        "reason": None,
    }
    assert (failed["scenario_id"], failed["source"]) == ("SCN-002", "none")
    assert failed["requests"] == 2 and failed["reason"]


# --- the run ------------------------------------------------------------------


def _run(run_dir: Path, client: MockLLMClient | None = None, **kwargs: Any):
    client = client or BeliefClient()
    client.set_response_queue([_normal_semantics_payload(), _functional_payload()])
    client.set_response_for(ShapeProposal, DIRECT_REPLY)
    result = run_sp3(
        llm_client=client,
        enriched_threat_set=_make_ets(num_threats=2),
        control_structure=make_cs(),
        loss_analysis=make_loss_analysis(),
        run_dir=run_dir,
        handoff_format=HandoffFormat.V5,
        attack_tree_format=AttackTreeFormat.AND_OR,
        **kwargs,
    )
    return result, client


def _requests(client: MockLLMClient, *, beliefs: bool = False) -> list[Any]:
    return [
        (call.system_prompt, call.user_prompt, call.response_format.__name__)
        for call in client.calls
        if issubclass(call.response_format, StatedBeliefReply) is beliefs
    ]


def _files(run_dir: Path) -> dict[str, bytes]:
    return {
        path.name: path.read_bytes()
        for path in sorted((run_dir / "scenarios").glob("SCN-*"))
    }


SEPARATE = {"flawed_belief": FlawedBeliefMode.SEPARATE}


def test_a_separate_run_publishes_the_beliefs_through_to_the_handoff(
    tmp_path: Path,
) -> None:
    _, off_client = _run(tmp_path / "off")
    result, client = _run(tmp_path / "separate", **SEPARATE)

    assert result.stage_errors == []
    # Stage 5 and the shape step send exactly what off sends.
    assert _requests(client) == _requests(off_client)
    beliefs = _requests(client, beliefs=True)
    assert len(beliefs) == 2
    # Both Stage 5 requests, then one belief request per spec, then shape.
    kinds = [call.response_format for call in client.calls]
    assert [issubclass(kind, StatedBeliefReply) for kind in kinds[:4]] == [
        False,
        False,
        True,
        True,
    ]
    assert kinds[4] is ShapeProposal
    run_dir = tmp_path / "separate"
    sidecar = json.loads((run_dir / BELIEFS_FILENAME).read_text(encoding="utf-8"))
    assert [entry["scenario_id"] for entry in sidecar["scenarios"]] == [
        "SCN-001",
        "SCN-002",
    ]
    assert {entry["source"] for entry in sidecar["scenarios"]} == {"model"}
    for scenario_id in ("SCN-001", "SCN-002"):
        document = _published_handoff(run_dir, scenario_id)
        assert list(Draft202012Validator(SCHEMA).iter_errors(document)) == []
        assert handoff_ownership_violations(document) == []
        verify_handoff_digest(ScenarioHandoffV5.model_validate(document))
        for factor in document["causal_factors"]:
            assert factor["process_model_belief"] in (BELIEF, CA_BELIEF)
            assert factor["process_model_variable"]["description"]
        weak_points = [
            node
            for node in nodes(document["attack_tree"]).values()
            if node["node_id"].startswith("AT-WP-")
        ]
        assert weak_points and all(
            node["belief"].startswith("The agent wrongly believes that ")
            for node in weak_points
        )
    (adversarial,) = result.scenario_specs
    facts = build_facts(adversarial)
    stated = [fact.text for fact in facts.facts if fact.category == AGENT_BELIEF]
    assert stated and all(
        text.startswith("The agent wrongly believes that ") for text in stated
    )
    assert facts.stated_beliefs
    _, narrate_user = render_narration_prompts(facts)
    assert "cites the agent belief fact whose belief it states" in narrate_user
    assert any(
        node.get("belief", "").startswith("The agent wrongly believes that ")
        for node in nodes(tree_of(adversarial)).values()
    )


@pytest.mark.parametrize(
    "error",
    [
        RuntimeError("connection reset"),
        LiveRequestBudgetError("the budget of 0 live request(s) is spent"),
    ],
    ids=["provider-error", "budget-refusal"],
)
def test_a_separate_run_whose_belief_calls_fail_publishes_what_off_publishes(
    tmp_path: Path, error: Exception
) -> None:
    _, off_client = _run(tmp_path / "off")
    client = BeliefClient(belief=None)
    client.set_exception_for(StatedBeliefReply, error)

    result, _ = _run(tmp_path / "failed", client, **SEPARATE)

    assert result.stage_errors == []
    assert _requests(client) == _requests(off_client)
    assert _files(tmp_path / "failed") == _files(tmp_path / "off")
    for name in ("testability.yaml", "condition-families.yaml"):
        off_path = tmp_path / "off" / name
        if off_path.exists():
            assert (tmp_path / "failed" / name).read_bytes() == off_path.read_bytes()
    sidecar = json.loads((tmp_path / "failed" / BELIEFS_FILENAME).read_text())
    assert [entry["source"] for entry in sidecar["scenarios"]] == ["none"] * 2
    assert all(str(error) in entry["reason"] for entry in sidecar["scenarios"])


@pytest.mark.parametrize("mode", [FlawedBeliefMode.OFF, FlawedBeliefMode.STATED])
def test_off_and_stated_send_no_belief_request_and_write_no_sidecar(
    tmp_path: Path, mode: FlawedBeliefMode
) -> None:
    _, client = _run(tmp_path, flawed_belief=mode)

    assert _requests(client, beliefs=True) == []
    assert not (tmp_path / BELIEFS_FILENAME).exists()


# --- flags --------------------------------------------------------------------


def test_separate_requires_v5() -> None:
    with pytest.raises(ValueError, match="flawed_belief=separate requires"):
        run_sp3(
            llm_client=MockLLMClient(),
            enriched_threat_set=_make_ets(num_threats=1),
            control_structure=make_cs(),
            loss_analysis=make_loss_analysis(),
            run_dir=Path("/nonexistent"),
            flawed_belief=FlawedBeliefMode.SEPARATE,
        )


def test_the_inputs_check_the_separate_value(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="flawed_belief separate requires"):
        synthesis.SynthesisInputs(
            use_case="u", output_dir=tmp_path, flawed_belief="separate"
        )
    inputs = synthesis.SynthesisInputs(
        use_case="u", output_dir=tmp_path, handoff_format="v5", flawed_belief="separate"
    )
    assert FlawedBeliefMode(inputs.flawed_belief) is FlawedBeliefMode.SEPARATE


def test_the_cli_separate_reaches_the_inputs(tmp_path: Path) -> None:
    result, captured = invoke_generate(
        tmp_path, ["--handoff-format", "v5", "--flawed-belief", "separate"]
    )

    assert result.exit_code == 0, result.output
    assert captured[0].flawed_belief == "separate"


@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        (["--flawed-belief", "separate"], "separate requires --handoff-format v5"),
        (["--flawed-belief", "stated"], "stated requires --handoff-format v5"),
        (["--flawed-belief", "on"], "must be off, stated or separate"),
    ],
    ids=["separate-v4", "stated-v4", "unknown"],
)
def test_the_cli_rejects_a_bad_flawed_belief(
    tmp_path: Path, arguments: list[str], message: str
) -> None:
    result, captured = invoke_generate(tmp_path, arguments)

    assert result.exit_code != 0
    assert "--flawed-belief" in result.output
    assert message in " ".join(result.output.split())
    assert captured == []
