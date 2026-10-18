"""scenario-handoff-v5 behind ``--handoff-format v5``.

v5 keeps every v4 field and adds the UCA, actor, causal factors,
preconditions, procedure and worst case threat, each derived by code from the
scenario spec. v4 stays the default and byte-identical. Every test is offline.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from asago_scenario_generator.models.canonical import compute_framed_digest
from asago_scenario_generator.pipeline import synthesis
from asago_scenario_generator.pipeline.model_runtime import ModelRuntime
from asago_scenario_generator.pipeline.synthesis_defaults import _default_scenarios
from asago_scenario_generator.report.run_data import _read_scenarios
from asago_scenario_generator.stpa.models.attack_shape import AttackShape, TurnPurpose
from asago_scenario_generator.stpa.models.scenario_spec import ScenarioSpec
from asago_scenario_generator.stpa.scenario_prod.assembly import assemble_envelope
from asago_scenario_generator.stpa.scenario_prod.handoff import (
    HANDOFF_DIGEST_DOMAIN_V5,
    HANDOFF_SCHEMA_VERSION_V4,
    HANDOFF_SCHEMA_VERSION_V5,
    HandoffFormat,
    ScenarioHandoffV4,
    ScenarioHandoffV5,
    build_scenario_handoff,
    handoff_model_for,
    handoff_ownership_violations,
    handoff_payload_digest,
    handoff_schema_violations,
    verify_handoff_digest,
)
from asago_scenario_generator.stpa.scenario_prod.handoff_v5 import (
    build_scenario_handoff_v5,
    uca_type,
    v5_fields,
)
from asago_scenario_generator.stpa.scenario_prod.narration import (
    NarrationMode,
    NarrationReply,
)
from asago_scenario_generator.stpa.scenario_prod.presentation import (
    render_scenario_presentation,
)
from asago_scenario_generator.stpa.scenario_prod.run import _narrate, run_sp3
from asago_scenario_generator.stpa.scenario_prod.stage5.shape_step import (
    ShapeProposal,
)
from tests.helpers.scenario_handoff_publication import (
    _functional_payload,
    _normal_semantics_payload,
    _published_handoff,
)
from tests.helpers.shape_step_call import DIRECT_REPLY
from tests.helpers.sp3_run import _make_ets
from tests.helpers.stpa_builders import make_cs, make_loss_analysis
from tests.helpers.synthesis_fixture import final_ica_result
from tests.stpa.sp1_helpers import MockLLMClient
from tests.stpa.test_and_or_tree import invoke_generate
from tests.stpa.test_scenario_handoff_v4_kit import _generator
from tests.stpa.test_narration import (
    INDIRECT,
    _inputs,
    adversarial,
    everyday,
    valid_reply,
)

ROOT = Path(__file__).resolve().parents[2]
CONTRACT_ROOT = ROOT / "data/contracts/scenario-handoff"
KIT = CONTRACT_ROOT / "handoff-v5"
SCHEMA = json.loads((KIT / "schema.json").read_text(encoding="utf-8"))

PERSISTENCE = {"id": "AML.TA0006", "name": "Persistence"}
EXECUTION = {"id": "AML.TA0005", "name": "Execution"}
TOOL_DATA_POISONING = {"id": "AML.T0099", "name": "AI Agent Tool Data Poisoning"}
INDIRECT_INJECTION = {"id": "AML.T0051.001", "name": "LLM Prompt Injection: Indirect"}
DIRECT_INJECTION = {"id": "AML.T0051.000", "name": "LLM Prompt Injection: Direct"}
THREAD_POISONING = {"id": "AML.T0080.001", "name": "AI Agent Context Poisoning: Thread"}

DIRECT = AttackShape.model_validate(
    {
        **DIRECT_REPLY,
        "threat_label": None,
        "source": "stage5_validated",
        "downgrade_reason": None,
    }
)
FORGED = AttackShape.model_validate(
    {
        "channel": "forged_transcript",
        "turn_count": 3,
        "turn_plan": [
            {"position": 1, "speaker": "forged_assistant", "purpose": "forged_history"},
            {
                "position": 2,
                "speaker": "forged_tool_result",
                "purpose": "forged_history",
            },
            {"position": 3, "speaker": "attacker_user", "purpose": "request_action"},
        ],
        "indirect": None,
        "threat_label": "forged_transcript_threat",
        "source": "stage5_validated",
        "downgrade_reason": None,
    }
)


def shaped(shape: AttackShape) -> ScenarioSpec:
    return adversarial().model_copy(update={"attack_shape": shape})


def fields_of(spec: ScenarioSpec) -> dict[str, Any]:
    """The v5 fields as the handoff publishes them."""
    handoff = build_scenario_handoff_v5(_envelope(spec))
    return {
        key: value
        for key, value in handoff.model_dump(mode="json", exclude_none=True).items()
        if key in V5_KEYS
    }


V5_KEYS = (
    "uca",
    "actor",
    "causal_factors",
    "preconditions",
    "procedure",
    "worst_case_threat",
)


def _envelope(spec: ScenarioSpec, narrative: str | None = None) -> Any:
    rendered, tree, gherkin = render_scenario_presentation(spec)
    return assemble_envelope(
        scenario_id=spec.scenario_id,
        scenario_spec=spec,
        narrative=narrative or rendered,
        attack_tree=tree,
        gherkin_spec=gherkin,
        gherkin_raw=gherkin.to_feature_text(),
    )


def steps(fields: dict[str, Any]) -> list[tuple]:
    return [
        (s["step_id"], s["leads_to"], s["tactic"], s["technique"], s["channel"])
        for s in fields["procedure"]
    ]


# --- derivation ---------------------------------------------------------------


def test_an_indirect_scenario_plants_the_item_then_reads_it() -> None:
    fields = fields_of(adversarial())

    assert fields["preconditions"] == [
        "A third party has planted an order content item (record ORD-201) in "
        "what lookup_order returns.",
        "belief",
    ]
    assert steps(fields) == [
        ("S00", ["S01"], PERSISTENCE, TOOL_DATA_POISONING, "tool_data"),
        ("S01", ["S02"], EXECUTION, INDIRECT_INJECTION, "user_turn"),
        ("S02", [], EXECUTION, INDIRECT_INJECTION, "user_turn"),
    ]
    assert [step["description"] for step in fields["procedure"]] == [
        "A third party plants an order content item (record ORD-201) in what "
        "lookup_order returns.",
        "The benign user asks the agent to read the planted item through lookup_order.",
        "The benign user follows up on what the planted item says.",
    ]
    assert fields["actor"] == {
        "profile": "a third party acting through content",
        "goal": "Learns another customer's order.",
    }


def test_an_indirect_scenario_names_the_benign_users_actor() -> None:
    relation = INDIRECT.indirect.party_relation.model_copy(
        update={"benign_user_actor_ref": "CUST001"}
    )
    indirect = INDIRECT.indirect.model_copy(update={"party_relation": relation})
    spec = shaped(INDIRECT.model_copy(update={"indirect": indirect}))

    assert fields_of(spec)["preconditions"][1] == "The benign user acts as CUST001."


def test_a_direct_scenario_has_user_turns_and_no_planted_item() -> None:
    fields = fields_of(shaped(DIRECT))

    assert fields["preconditions"] == ["belief"]
    assert steps(fields) == [
        ("S00", ["S01"], EXECUTION, DIRECT_INJECTION, "user_turn"),
        ("S01", [], EXECUTION, DIRECT_INJECTION, "user_turn"),
    ]


def test_a_forged_scenario_poisons_the_thread_then_asks() -> None:
    fields = fields_of(shaped(FORGED))

    assert steps(fields) == [
        ("S00", ["S01"], PERSISTENCE, THREAD_POISONING, "forged_history"),
        ("S01", ["S02"], PERSISTENCE, THREAD_POISONING, "forged_history"),
        ("S02", [], EXECUTION, DIRECT_INJECTION, "user_turn"),
    ]


def test_a_step_without_a_technique_has_a_null_tactic_and_technique() -> None:
    shape = INDIRECT.model_copy(
        update={
            "turn_plan": [
                INDIRECT.turn_plan[0],
                INDIRECT.turn_plan[1].model_copy(
                    update={"purpose": TurnPurpose.APPLY_PRESSURE}
                ),
            ]
        }
    )

    last = fields_of(shaped(shape))["procedure"][-1]

    assert (last["tactic"], last["technique"]) == (None, None)


def test_a_functional_scenario_has_no_actor_preconditions_or_procedure() -> None:
    fields = fields_of(everyday())

    assert fields["actor"] is None
    assert fields["preconditions"] == []
    assert fields["procedure"] == []
    assert fields["uca"]["statement"] == "Unsafe control action"
    assert fields["causal_factors"] == [
        {
            "source_id": "FB-1-1",
            "process_model_belief": None,
            "flaw": "Feedback is delayed.",
        }
    ]
    assert fields["worst_case_threat"] == "Loss."


def test_the_uca_comes_from_the_selected_ica_and_its_hazards() -> None:
    assert fields_of(adversarial())["uca"] == {
        "source": "RESP-1",
        "type": "too-early-too-late-or-out-of-order",
        "control_action": "Action",
        "context": "Context",
        "statement": "Unsafe control action",
        "hazards": [{"hazard_id": "H-1", "description": "Hazard"}],
    }


@pytest.mark.parametrize(
    ("suffix", "expected"),
    [
        ("NOT_PROVIDED", "not-providing-causes-hazard"),
        ("INCORRECT", "providing-causes-hazard"),
        ("WRONG_TIMING", "too-early-too-late-or-out-of-order"),
        ("WRONG_DURATION", "stopped-too-soon-or-applied-too-long"),
    ],
)
def test_each_ica_slot_suffix_names_its_handbook_uca_type(
    suffix: str, expected: str
) -> None:
    assert uca_type(f"RESP-1:CA-1-1:{suffix}") == expected


def test_an_unknown_ica_slot_suffix_fails() -> None:
    with pytest.raises(ValueError, match="unknown UCA type 'TOO_LATE'"):
        uca_type("RESP-1:CA-1-1:TOO_LATE")


def test_a_factor_names_the_belief_of_its_process_model_part() -> None:
    spec = adversarial()
    factor = spec.causal_factors[0].model_copy(update={"source_id": "PM-1-1"})
    spec = spec.model_copy(update={"causal_factors": [factor, spec.causal_factors[0]]})

    assert fields_of(spec)["causal_factors"] == [
        {
            "source_id": "PM-1-1",
            "process_model_belief": "State",
            "flaw": "Feedback is delayed.",
        },
        {
            "source_id": "FB-1-1",
            "process_model_belief": None,
            "flaw": "Feedback is delayed.",
        },
    ]


def test_preconditions_skip_blank_and_repeated_beliefs() -> None:
    spec = shaped(DIRECT)
    spec = spec.model_copy(
        update={
            "attacker_bdi": spec.attacker_bdi.model_copy(
                update={
                    "beliefs": ["One.", " ", "One.", "Two [structural sources: PM-1-1]"]
                }
            )
        }
    )

    assert fields_of(spec)["preconditions"] == ["One.", "Two"]


def test_the_worst_case_threat_joins_each_loss_as_a_sentence() -> None:
    spec = adversarial()
    context = spec.scenario_context
    losses = [
        context.losses[0].model_copy(update={"description": "Money is lost"}),
        context.losses[0].model_copy(
            update={"loss_id": "L-2", "description": "Trust ends."}
        ),
    ]
    spec = spec.model_copy(
        update={"scenario_context": context.model_copy(update={"losses": losses})}
    )

    assert v5_fields(spec)["worst_case_threat"] == "Money is lost. Trust ends."


def test_a_missing_source_fails_instead_of_publishing_blank_text() -> None:
    spec = adversarial()
    context = spec.scenario_context
    blank_loss = context.model_copy(
        update={"losses": [context.losses[0].model_copy(update={"description": " "})]}
    )

    with pytest.raises(ValueError, match="needs the scenario context"):
        v5_fields(spec.model_copy(update={"scenario_context": None}))
    with pytest.raises(ValueError, match="needs an adversary"):
        v5_fields(spec.model_copy(update={"adversary": None}))
    with pytest.raises(ValueError, match="worst_case_threat has no source text"):
        v5_fields(spec.model_copy(update={"scenario_context": blank_loss}))
    with pytest.raises(ValueError, match="needs causal factors"):
        v5_fields(spec.model_copy(update={"causal_factors": []}))


# --- envelope -----------------------------------------------------------------


@pytest.mark.parametrize(
    "make",
    [adversarial, everyday, lambda: shaped(DIRECT), lambda: shaped(FORGED)],
    ids=["indirect", "functional", "direct", "forged"],
)
def test_a_v5_handoff_passes_the_kit_schema_ownership_and_digest(make) -> None:
    document = build_scenario_handoff_v5(_envelope(make())).model_dump(
        mode="json", exclude_none=True
    )

    assert document["schema_version"] == HANDOFF_SCHEMA_VERSION_V5
    assert list(Draft202012Validator(SCHEMA).iter_errors(document)) == []
    assert handoff_schema_violations(document) == []
    assert handoff_ownership_violations(document) == []
    verify_handoff_digest(ScenarioHandoffV5.model_validate(document))


def test_the_v5_digest_uses_its_own_domain() -> None:
    document = build_scenario_handoff_v5(_envelope(adversarial())).model_dump(
        mode="json", exclude_none=True
    )
    unsigned = {k: v for k, v in document.items() if k != "content_digest"}

    assert HANDOFF_DIGEST_DOMAIN_V5 == "scenario-handoff-v5"
    assert document["content_digest"] == compute_framed_digest(
        HANDOFF_DIGEST_DOMAIN_V5, unsigned
    )
    assert handoff_payload_digest(unsigned) == document["content_digest"]


def test_v5_keeps_every_v4_field_and_value() -> None:
    envelope = _envelope(adversarial())
    v4 = build_scenario_handoff(envelope).model_dump(mode="json", exclude_none=True)
    v5 = build_scenario_handoff_v5(envelope).model_dump(mode="json", exclude_none=True)

    assert list(v5)[: len(v4)] == list(v4)
    assert list(v5)[len(v4) :] == list(V5_KEYS)
    assert {key for key in v4 if v4[key] != v5[key]} == {
        "schema_version",
        "sourced_facts",
        "content_digest",
    }
    assert v5["sourced_facts"][-1]["source"] == (
        f"producer handoff contract {HANDOFF_SCHEMA_VERSION_V5}"
    )


def test_the_schema_version_selects_the_model() -> None:
    assert handoff_model_for({"schema_version": HANDOFF_SCHEMA_VERSION_V4}) is (
        ScenarioHandoffV4
    )
    assert handoff_model_for({"schema_version": HANDOFF_SCHEMA_VERSION_V5}) is (
        ScenarioHandoffV5
    )
    with pytest.raises(ValueError, match="unsupported"):
        handoff_model_for({"schema_version": "scenario-handoff-v9"})


def test_a_v4_document_with_v5_fields_is_rejected() -> None:
    document = build_scenario_handoff_v5(_envelope(adversarial())).model_dump(
        mode="json", exclude_none=True
    )
    document["schema_version"] = HANDOFF_SCHEMA_VERSION_V4

    with pytest.raises(ValidationError):
        ScenarioHandoffV4.model_validate(document)


# --- kit ----------------------------------------------------------------------


def _kit(relative: str) -> dict:
    return json.loads((KIT / relative).read_text(encoding="utf-8"))


def test_the_v5_schema_file_is_the_models_schema_byte_for_byte() -> None:
    rendered = json.dumps(ScenarioHandoffV5.model_json_schema(), indent=2) + "\n"

    assert (KIT / "schema.json").read_text(encoding="utf-8") == rendered


def test_the_v5_kit_holds_the_v4_fixture_names_and_more_invalid_cases() -> None:
    v4 = CONTRACT_ROOT / "handoff-v4"
    names = {path.name for path in (KIT / "valid").glob("*.json")}
    invalid = {path.name for path in (KIT / "invalid").glob("*.json")}
    stated = {"adversarial-stated-beliefs.json", "functional-stated-belief.json"}

    assert names == {path.name for path in (v4 / "valid").glob("*.json")} | stated
    assert {path.name for path in (v4 / "invalid").glob("*.json")} < invalid
    assert set(_kit("expected-violations.json")) == {f"invalid/{n}" for n in invalid}


@pytest.mark.parametrize(
    "path", sorted((KIT / "valid").glob("*.json")), ids=lambda path: path.name
)
def test_each_valid_v5_fixture_passes_every_check(path: Path) -> None:
    payload = json.loads(path.read_text(encoding="utf-8"))

    assert payload["schema_version"] == HANDOFF_SCHEMA_VERSION_V5
    assert list(Draft202012Validator(SCHEMA).iter_errors(payload)) == []
    assert handoff_schema_violations(payload) == []
    assert handoff_ownership_violations(payload) == []
    verify_handoff_digest(ScenarioHandoffV5.model_validate(payload))
    digests = _kit("canonical-digests.json")
    assert digests["handoff_digests"][f"valid/{path.name}"] == payload["content_digest"]


@pytest.mark.parametrize(
    "path", sorted((KIT / "invalid").glob("*.json")), ids=lambda path: path.name
)
def test_each_invalid_v5_fixture_is_rejected_with_its_recorded_codes(
    path: Path,
) -> None:
    payload = json.loads(path.read_text(encoding="utf-8"))
    found = handoff_ownership_violations(payload) + handoff_schema_violations(payload)

    assert found
    assert _kit("expected-violations.json")[f"invalid/{path.name}"] == found


@pytest.mark.parametrize(
    ("name", "codes"),
    [
        ("v5-uca-type-not-enumerated", ["schema_violation:uca"]),
        ("v5-actor-null-on-adversarial", ["schema_violation:<root>"]),
        ("v5-actor-on-functional", ["schema_violation:<root>"]),
        ("v5-procedure-leads-to-wrong", ["schema_violation:<root>"]),
        ("v5-procedure-channel-not-enumerated", ["schema_violation:procedure"]),
        ("v5-causal-factor-belief-missing", ["schema_violation:causal_factors"]),
        ("v5-worst-case-threat-blank", ["schema_violation:worst_case_threat"]),
    ],
)
def test_the_v5_rules_reject_their_cases(name: str, codes: list[str]) -> None:
    payload = _kit(f"invalid/{name}.json")

    assert handoff_schema_violations(payload) == codes


def test_the_lock_pins_v4_at_the_top_and_lists_v5() -> None:
    lock = json.loads((CONTRACT_ROOT / "CONTRACT.lock").read_text(encoding="utf-8"))

    assert lock["handoff_schema_version"] == HANDOFF_SCHEMA_VERSION_V4
    assert lock["additional_versions"] == [
        {
            "digest_domain": HANDOFF_DIGEST_DOMAIN_V5,
            "handoff_schema_version": HANDOFF_SCHEMA_VERSION_V5,
            "kit": "handoff-v5",
            "metadata_fields": [
                name
                for name in ScenarioHandoffV5.model_fields
                if name not in lock["representations"]
            ],
        }
    ]
    assert any(name.startswith("handoff-v5/") for name in lock["files"])


def test_the_generator_rebuilds_the_v5_kit_byte_for_byte(tmp_path: Path) -> None:
    module = _generator(tmp_path)
    shutil.rmtree(module.ROOT / "handoff-v5")

    module.main()

    for path in sorted(KIT.rglob("*")):
        if path.is_file():
            rebuilt = module.ROOT / "handoff-v5" / path.relative_to(KIT)
            assert rebuilt.read_bytes() == path.read_bytes(), path.name
    assert (module.ROOT / "CONTRACT.lock").read_bytes() == (
        CONTRACT_ROOT / "CONTRACT.lock"
    ).read_bytes()


# --- run ----------------------------------------------------------------------


def _publish(run_dir: Path, **kwargs: Any) -> Any:
    client = MockLLMClient()
    client.set_response_queue([_normal_semantics_payload(), _functional_payload()])
    client.set_response_for(ShapeProposal, DIRECT_REPLY)
    result = run_sp3(
        llm_client=client,
        enriched_threat_set=_make_ets(num_threats=2),
        control_structure=make_cs(),
        loss_analysis=make_loss_analysis(),
        run_dir=run_dir,
        **kwargs,
    )
    return result, client


def test_a_v5_run_publishes_valid_v5_handoffs(tmp_path: Path) -> None:
    result, _ = _publish(tmp_path, handoff_format=HandoffFormat.V5)

    assert result.stage_errors == []
    kinds = set()
    for scenario_id in ("SCN-001", "SCN-002"):
        document = _published_handoff(tmp_path, scenario_id)
        kinds.add(document["kind"])
        assert document["schema_version"] == HANDOFF_SCHEMA_VERSION_V5
        assert list(Draft202012Validator(SCHEMA).iter_errors(document)) == []
        assert handoff_ownership_violations(document) == []
        verify_handoff_digest(ScenarioHandoffV5.model_validate(document))
    assert kinds == {"adversarial", "functional"}
    scenarios = _read_scenarios(tmp_path)
    assert all(isinstance(item, ScenarioHandoffV5) for item in scenarios.values())


def test_the_default_format_is_v4_byte_for_byte(tmp_path: Path) -> None:
    _, default_client = _publish(tmp_path / "default")
    _publish(tmp_path / "v4", handoff_format=HandoffFormat.V4)
    _, v5_client = _publish(tmp_path / "v5", handoff_format=HandoffFormat.V5)

    assert default_client.calls == v5_client.calls
    for scenario_id in ("SCN-001", "SCN-002"):
        for name in (f"{scenario_id}.yaml", f"{scenario_id}.feature"):
            assert (tmp_path / "default/scenarios" / name).read_bytes() == (
                tmp_path / "v4/scenarios" / name
            ).read_bytes()
        assert (tmp_path / "v5/scenarios" / f"{scenario_id}.feature").read_bytes() == (
            tmp_path / "default/scenarios" / f"{scenario_id}.feature"
        ).read_bytes()
        v4 = _published_handoff(tmp_path / "default", scenario_id)
        v5 = _published_handoff(tmp_path / "v5", scenario_id)
        assert v4["schema_version"] == HANDOFF_SCHEMA_VERSION_V4
        # A functional actor is null, which reads the same as v4's absent key.
        expected = {"schema_version", "sourced_facts", "content_digest", *V5_KEYS}
        if v5["kind"] == "functional":
            expected.discard("actor")
        assert {key for key in v5 if v4.get(key) != v5[key]} == expected


def test_a_v5_handoff_narrative_is_the_accepted_paragraph_alone(
    tmp_path: Path,
) -> None:
    spec = adversarial()
    client = MockLLMClient()
    client.set_response_for(NarrationReply, valid_reply(spec))

    published = _narrate(
        _inputs(NarrationMode.HANDOFF, client, tmp_path / "v5"),
        [spec],
        paragraph_only=True,
    )

    paragraph = " ".join(item["text"] for item in valid_reply(spec)["sentences"])
    assert published == {"SCN-001": paragraph}


def test_v4_keeps_the_full_writeup_as_the_handoff_narrative(tmp_path: Path) -> None:
    spec = adversarial()
    client = MockLLMClient()
    client.set_response_for(NarrationReply, valid_reply(spec))

    published = _narrate(_inputs(NarrationMode.HANDOFF, client, tmp_path), [spec])

    assert published["SCN-001"].startswith("Test hypothesis")
    assert "Steps (ATLAS case-study procedure):" in published["SCN-001"]


# --- plumbing -----------------------------------------------------------------


def test_the_inputs_reject_an_unknown_handoff_format(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="handoff_format"):
        synthesis.SynthesisInputs(
            use_case="u", output_dir=tmp_path, handoff_format="v6"
        )


@pytest.mark.parametrize("value", ["v4", "v5"])
def test_the_inputs_handoff_format_reaches_run_sp3(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    captured: dict = {}

    def _fake_run_sp3(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace(
            stage_errors=[],
            scenario_specs=[],
            scenario_envelopes=[],
            candidate_outcomes=(),
            functional_test_specs=[],
        )

    monkeypatch.setattr(
        "asago_scenario_generator.stpa.scenario_prod.run.run_sp3", _fake_run_sp3
    )
    monkeypatch.setattr(
        "asago_scenario_generator.stpa.threat_enum.catalog_enrichment.enrich_threats",
        lambda *a, **k: SimpleNamespace(structural_threats=[]),
    )
    monkeypatch.setattr(
        "asago_scenario_generator.stpa.pipeline.llm_config.resolve_llm_client",
        lambda *a, **k: (MockLLMClient(), "test-profile"),
    )
    inputs = synthesis.SynthesisInputs(
        use_case="u", output_dir=tmp_path, handoff_format=value
    )
    _default_scenarios(
        ica_enumeration=final_ica_result(),
        control_structure=SimpleNamespace(),
        loss_analysis=make_loss_analysis(),
        inputs=inputs,
        capability_profile=None,
        output_dir=tmp_path,
        model_runtime=ModelRuntime.for_inputs(inputs),
    )

    assert captured["handoff_format"] is HandoffFormat(value)


@pytest.mark.parametrize(
    ("arguments", "expected"),
    [([], "v4"), (["--handoff-format", "v5"], "v5")],
    ids=["default", "v5"],
)
def test_the_cli_handoff_format_reaches_the_inputs(
    tmp_path: Path, arguments: list[str], expected: str
) -> None:
    result, captured = invoke_generate(tmp_path, arguments)

    assert result.exit_code == 0, result.output
    assert captured[0].handoff_format == expected


def test_the_cli_rejects_an_unknown_handoff_format(tmp_path: Path) -> None:
    result, captured = invoke_generate(tmp_path, ["--handoff-format", "v6"])

    assert result.exit_code != 0
    assert "--handoff-format" in result.output
    assert captured == []
