"""Offline acceptance handlers for the Phase 4 grounded authoring call."""

from __future__ import annotations

import json
from pathlib import Path

from runtime_shared import _tempfile

from asago_scenario_generator.stpa.scenario_prod.authoring import (
    AuthoredUnsafeObservation,
    AuthoringResponse,
    CandidateAuthoringOutcome,
    author_candidate_scenarios,
    load_oracle_templates,
    render_oracle_text,
    synthesize_authored_enumeration,
    system_prompt_text,
)
from tests.stpa.sp1_helpers import MockLLMClient
from tests.stpa.test_authored_assembly import (
    _accepted,
    _project,
    _spec_for,
)
from tests.stpa.test_authoring_validation import (
    STATE,
    _accepted_model,
    _candidate,
    _draft,
    _minimal_control_structure,
    _observations,
    _profile,
    _session,
    _structure,
)

FEATURE_ID = "stpa_grounded_authoring"


def _response_payload() -> str:
    """Return the mock wire response: one valid draft, one unknown tool."""
    invalid_oracle = AuthoredUnsafeObservation(
        kind="tool_argument",
        tool="delete_order",
        argument="order_id",
        operator="equals",
        value="ORD-201",
    )
    payload = {
        "scenarios": [
            json.loads(_draft().model_dump_json()),
            json.loads(_draft(oracle=invalid_oracle).model_dump_json()),
        ]
    }
    return json.dumps(payload)


def _read_calls(run_dir: Path) -> list[dict]:
    calls_file = run_dir / "calls.jsonl"
    if not calls_file.exists():
        return []
    return [json.loads(line) for line in calls_file.read_text().splitlines()]


def _given_candidate(world, step, examples):
    del step, examples
    world.ga_dir = Path(_tempfile.mkdtemp(prefix="grounded_authoring_"))
    world.ga_client = MockLLMClient()
    world.ga_client.set_response_for(AuthoringResponse, _response_payload())
    world.ga_outcome = None
    return True, ""


def _when_authoring_runs(world, step, examples):
    del step, examples
    world.ga_outcome = author_candidate_scenarios(
        world.ga_client,
        _candidate(),
        profile=_profile(),
        observations=_observations(),
        structure=_structure(),
        control_structure=_minimal_control_structure(),
        capability_profile=None,
        run_dir=world.ga_dir,
        temperature=0.4,
        has_content_surface=False,
        session=_session(),
        subject_model=_accepted_model(),
    )
    return True, ""


def _then_one_call(world, step, examples):
    del step, examples
    assert len(world.ga_client.calls) == 1
    entries = _read_calls(world.ga_dir)
    authored = [entry for entry in entries if entry.get("stage") == "stage_5_authoring"]
    assert len(authored) == 1
    assert authored[0]["step"] == "SC-1:process_refund"
    assert authored[0]["success"] is True
    return True, ""


def _then_accepted(world, step, examples):
    del step, examples
    outcome = world.ga_outcome
    assert len(outcome.accepted) == 1
    accepted = outcome.accepted[0]
    assert accepted.uca_type.value == "INCORRECT"
    assert accepted.reaches_target_via.value == "user_message"
    return True, ""


def _then_rejected(world, step, examples):
    del step, examples
    outcome = world.ga_outcome
    assert len(outcome.rejected) == 1
    _draft_rejected, rejection = outcome.rejected[0]
    assert rejection.reason == "tool_mismatch"
    # No repair: exactly one logged call survives the rejection.
    assert len(_read_calls(world.ga_dir)) == 1
    return True, ""


def _given_templates(world, step, examples):
    del step, examples
    world.ga_templates = load_oracle_templates()
    return True, ""


_ORACLE_RENDER_ARGS = {
    "tool_argument": dict(
        tool="process_refund",
        argument="order_id",
        operator="equals",
        value="ORD-201",
    ),
    "tool_absent": dict(
        tool="process_refund",
        trigger="the whitelist miss instructs escalation",
    ),
    "tool_order": dict(
        tool="process_refund",
        argument="order_id",
        operator="equals",
        value="ORD-104",
        reference_tool="lookup_order",
    ),
    "response_claim": dict(
        proposition="The response fabricates a late-fee percentage."
    ),
}


def _when_templates_render(world, step, examples):
    del step, examples
    world.ga_rendered = {
        kind: render_oracle_text(kind, **args)
        for kind, args in _ORACLE_RENDER_ARGS.items()
    }
    return True, ""


def _then_deterministic_sentences(world, step, examples):
    del step, examples
    for kind, text in world.ga_rendered.items():
        assert text.strip(), f"{kind} rendered an empty oracle"
        assert render_oracle_text(kind, **_ORACLE_RENDER_ARGS[kind]) == text, (
            f"{kind} must render deterministically"
        )
    assert "process_refund" in world.ga_rendered["tool_argument"]
    assert "ORD-201" in world.ga_rendered["tool_argument"]
    assert "lookup_order" in world.ga_rendered["tool_order"]
    return True, ""


def _then_unknown_kind_fails(world, step, examples):
    del step, examples
    raised = False
    try:
        render_oracle_text("no_such_kind", value="x")
    except ValueError:
        raised = True
    assert raised, "an unknown oracle kind must fail closed"
    return True, ""


def _given_accepted_scenario(world, step, examples):
    del step, examples
    world.ga_control_structure = _minimal_control_structure()
    world.ga_accepted = _accepted()
    return True, ""


def _when_enumeration_synthesizes(world, step, examples):
    del step, examples
    enumeration, bundles = synthesize_authored_enumeration(
        (
            CandidateAuthoringOutcome(
                candidate=world.ga_accepted.candidate,
                accepted=(world.ga_accepted,),
            ),
        ),
        _structure(),
        world.ga_control_structure,
    )
    world.ga_enumeration = enumeration
    world.ga_bundles = bundles
    return True, ""


def _then_accepted_slot(world, step, examples):
    del step, examples
    slot = next(
        item
        for item in world.ga_enumeration.slots
        if item.slot_id == "RESP-1:CA-1-2:INCORRECT"
    )
    assert len(slot.icas) == 1
    ica = slot.icas[0]
    assert world.ga_bundles[ica.ica_id].accepted is world.ga_accepted
    return True, ""


def _then_other_slots_unresolved(world, step, examples):
    del step, examples
    resolved = {item.slot_id for item in world.ga_enumeration.slots if item.icas}
    assert resolved == {"RESP-1:CA-1-2:INCORRECT"}
    assert all(not item.is_na for item in world.ga_enumeration.slots), (
        "unresolved authored slots are never recorded as N/A decisions"
    )
    return True, ""


def _when_assembly_builds_spec(world, step, examples):
    del step, examples
    spec, enumeration = _spec_for(world.ga_accepted, world.ga_control_structure)
    world.ga_spec = spec
    world.ga_enumeration = enumeration
    return True, ""


def _then_condition_pinned(world, step, examples):
    del step, examples
    condition = world.ga_spec.unsafe_outcome_condition
    assert condition.control_action_id == "CA-1-2"
    assert condition.property == "order_id"
    assert condition.operator == "equals"
    assert condition.expected == "ORD-201"
    return True, ""


def _then_adversary_reach(world, step, examples):
    del step, examples
    assert world.ga_spec.adversary is not None
    assert world.ga_spec.adversary.reaches_target_via.value == "user_message"
    return True, ""


def _then_projection_valid(world, step, examples):
    del step, examples
    projection = _project(
        world.ga_spec, world.ga_control_structure, world.ga_enumeration
    )
    assert projection.execution_contract.action_kind.value == "tool_call"
    assert projection.scenario_id == "SCN-001"
    return True, ""


def _given_prompt_templates(world, step, examples):
    del step, examples
    world.ga_system_prompt = system_prompt_text()
    from asago_scenario_generator.stpa.scenario_prod.authoring import (
        build_authoring_user_prompt,
    )

    world.ga_user_prompt = build_authoring_user_prompt(
        _candidate(),
        state=STATE,
        observation_records=tuple(
            record
            for record in _observations().prompt_records()
            if record["observation_ref"] != "TARGET-STATE"
        ),
        session=_session(),
        subject_model=_accepted_model(),
        profile=_profile(),
    )
    rule_log = (
        Path(__file__).resolve().parents[2]
        / "data"
        / "prompts"
        / "authoring-rule-log.md"
    )
    world.ga_rule_log = rule_log.read_text(encoding="utf-8")
    return True, ""


def _when_system_prompt_renders(world, step, examples):
    del step, examples
    world.ga_prompt_length = len(world.ga_system_prompt)
    return True, ""


def _then_prompt_budget(world, step, examples):
    del step, examples
    assert world.ga_prompt_length <= 3000
    return True, ""


def _then_prompt_schema(world, step, examples):
    del step, examples
    # The closed output schema lives in the user prompt; the system prompt
    # carries only the prose rules.
    for kind in (
        "tool_argument",
        "tool_absent",
        "tool_order",
        "response_claim",
    ):
        assert kind in world.ga_user_prompt
    for unsupported in ("tool_called", "paired_response"):
        assert unsupported not in world.ga_user_prompt
    return True, ""


def register(api):
    """Register the Phase 4 grounded authoring acceptance steps."""
    api.register(
        r"^a target-derived structure with one relevant constraint-action "
        r"candidate$",
        _given_candidate,
    )
    api.register(
        r"^a mock provider returning one valid draft and one draft naming an "
        r"unobserved tool$",
        _given_candidate,
    )
    api.register(
        r"^the grounded authoring call runs for the candidate$",
        _when_authoring_runs,
    )
    api.register(
        r"^exactly one model call is recorded for the candidate$",
        _then_one_call,
    )
    api.register(
        r"^the valid scenario is accepted with the synthesized deviation "
        r"category$",
        _then_accepted,
    )
    api.register(
        r"^the invalid scenario is rejected with a typed reason and no repair "
        r"call$",
        _then_rejected,
    )
    api.register(
        r"^the committed oracle template table$",
        _given_templates,
    )
    api.register(
        r"^the oracle text renders for every supported kind$",
        _when_templates_render,
    )
    api.register(
        r"^each kind renders one deterministic sentence from its validated "
        r"values$",
        _then_deterministic_sentences,
    )
    api.register(
        r"^an unknown oracle kind fails closed$",
        _then_unknown_kind_fails,
    )
    api.register(
        r"^one accepted authored scenario for the refund action$",
        _given_accepted_scenario,
    )
    api.register(
        r"^one accepted tool_argument authored scenario$",
        _given_accepted_scenario,
    )
    api.register(
        r"^the ICA enumeration synthesizes from the accepted scenarios$",
        _when_enumeration_synthesizes,
    )
    api.register(
        r"^the accepted scenario occupies the process_refund INCORRECT slot$",
        _then_accepted_slot,
    )
    api.register(
        r"^every other slot in the deterministic universe stays "
        r"typed-unresolved$",
        _then_other_slots_unresolved,
    )
    api.register(
        r"^the deterministic assembly builds the contextual scenario spec$",
        _when_assembly_builds_spec,
    )
    api.register(
        r"^the unsafe condition pins the exact argument and expected value$",
        _then_condition_pinned,
    )
    api.register(
        r"^the adversary reaches the target via the user message$",
        _then_adversary_reach,
    )
    api.register(
        r"^the v2 execution projection validates offline with a tool_call "
        r"action kind$",
        _then_projection_valid,
    )
    api.register(
        r"^the committed authoring prompt templates$",
        _given_prompt_templates,
    )
    api.register(
        r"^the authoring system prompt renders$",
        _when_system_prompt_renders,
    )
    api.register(
        r"^the rendered system prompt is at most 3000 characters$",
        _then_prompt_budget,
    )
    api.register(
        r"^the prompt schema names only the four supported oracle kinds$",
        _then_prompt_schema,
    )
