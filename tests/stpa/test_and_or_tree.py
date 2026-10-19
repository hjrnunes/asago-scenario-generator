"""The and-or-tree-v1 attack tree behind ``--attack-tree-format and-or``.

Code renders the tree from the scenario spec: the root is the hazard, an OR
joins this scenario to the run's other scenarios that share a hazard, and
this scenario is an ordered AND of its conditions, steps, unsafe action, and
observable failure. Every test is offline.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest
from jsonschema import Draft202012Validator

from asago_scenario_generator.cli import app
from asago_scenario_generator.pipeline import synthesis
from asago_scenario_generator.pipeline.model_runtime import ModelRuntime
from asago_scenario_generator.pipeline.synthesis_defaults import _default_scenarios
from asago_scenario_generator.report.scenario_panels import panel_stats, tree_panel
from asago_scenario_generator.stpa.models.attack_shape import AttackShape
from asago_scenario_generator.stpa.models.scenario_spec import ScenarioSpec
from asago_scenario_generator.stpa.scenario_prod.and_or_tree import (
    AttackTreeFormat,
    build_sibling_index,
    render_and_or_tree,
)
from asago_scenario_generator.stpa.scenario_prod.handoff import (
    ScenarioHandoffV4,
    build_scenario_handoff,
    handoff_ownership_violations,
    verify_handoff_digest,
)
from asago_scenario_generator.stpa.scenario_prod.assembly import assemble_envelope
from asago_scenario_generator.stpa.scenario_prod.narration import (
    ATLAS_DIRECT_INJECTION,
    ATLAS_INDIRECT_INJECTION,
    ATLAS_TOOL_DATA_POISONING,
)
from asago_scenario_generator.stpa.scenario_prod.presentation import (
    render_scenario_presentation,
)
from asago_scenario_generator.stpa.scenario_prod.run import run_sp3
from asago_scenario_generator.stpa.scenario_prod.stage5.shape_step import (
    ShapeProposal,
)
from asago_scenario_generator.stpa.scenario_prod.tree_sources import (
    AND_OR_TREE_FORMAT,
)
from asago_scenario_generator.stpa.scenario_prod.validators import (
    validate_and_or_tree_structure,
    validate_tree_factor_evidence_coverage,
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
from tests.cli_helpers import PlainCliRunner
from tests.stpa.test_narration import adversarial, everyday

SCHEMA = ScenarioHandoffV4.model_json_schema()
DIRECT = AttackShape.model_validate(
    {
        **DIRECT_REPLY,
        "threat_label": None,
        "source": "stage5_validated",
        "downgrade_reason": None,
    }
)


def tree_of(spec: ScenarioSpec, *others: ScenarioSpec) -> dict[str, Any]:
    flat = render_scenario_presentation(spec)[1]
    return render_and_or_tree(spec, flat, build_sibling_index([spec, *others]))


def nodes(tree: dict[str, Any]) -> dict[str, dict[str, Any]]:
    found: dict[str, dict[str, Any]] = {}
    stack = [tree["root"]]
    while stack:
        node = stack.pop()
        found[node["node_id"]] = node
        stack.extend(node.get("children", []))
    return found


def child_ids(node: dict[str, Any]) -> list[str]:
    return [child["node_id"] for child in node.get("children", [])]


def renamed(spec: ScenarioSpec, scenario_id: str, criterion: str) -> ScenarioSpec:
    return spec.model_copy(
        update={
            "scenario_id": scenario_id,
            "unsafe_outcome_semantic_proposition": criterion,
        }
    )


def with_hazards(spec: ScenarioSpec, *hazards: tuple[str, str]) -> ScenarioSpec:
    context = spec.scenario_context
    template = context.hazards[0]
    return spec.model_copy(
        update={
            "scenario_context": context.model_copy(
                update={
                    "hazards": [
                        template.model_copy(
                            update={"hazard_id": hazard_id, "description": text}
                        )
                        for hazard_id, text in hazards
                    ]
                }
            )
        }
    )


def pm_factor(spec: ScenarioSpec) -> ScenarioSpec:
    """Make the factor name the defender belief's process-model part."""
    factor = spec.causal_factors[0].model_copy(update={"source_id": "PM-1-1"})
    belief = spec.defender_bdi.beliefs[0].model_copy(
        update={"vulnerability": "The state is stale."}
    )
    return spec.model_copy(
        update={
            "causal_factors": [factor],
            "defender_bdi": spec.defender_bdi.model_copy(update={"beliefs": [belief]}),
        }
    )


# --- tree builder -------------------------------------------------------------


def test_an_indirect_attack_is_an_ordered_and_under_the_hazard() -> None:
    spec = adversarial()
    tree = tree_of(spec)

    assert tree["format"] == AND_OR_TREE_FORMAT
    assert tree["relation"] == "and-or"
    assert tree["relation_basis"] == "scenario_structure"
    assert "branches" not in tree and "relation_evidence" not in tree
    flat = render_scenario_presentation(spec)[1]
    for key in ("framing", "kind", "criterion", "lineage", "loss_scenario", "leaves"):
        assert tree[key] == flat[key]
    root = tree["root"]
    assert (root["type"], root["category"]) == ("goal", "hazard")
    assert root["source_ids"] == ["H-1"]
    assert [item["source_id"] for item in root["hazards"]] == ["H-1"]
    assert [item["source_id"] for item in root["losses"]] == ["L-1"]
    found = nodes(tree)
    assert child_ids(root) == ["AT-OR"]
    assert found["AT-OR"]["operator"] == "OR" and "ordered" not in found["AT-OR"]
    assert child_ids(found["AT-OR"]) == ["AT-SCN"]
    scenario = found["AT-SCN"]
    assert (scenario["operator"], scenario["ordered"]) == ("AND", True)
    assert scenario["this_scenario"] is True and scenario["scenario_id"] == "SCN-001"
    assert scenario["label"] == spec.unsafe_outcome_semantic_proposition
    assert scenario["attacker"] == {
        "profile": "a third party acting through content",
        "goal": "Learns another customer's order.",
        "plan": ["intent"],
    }
    assert child_ids(scenario) == ["AT-COND", "AT-STEPS", "AT-UCA", "AT-FAIL"]
    assert "ordered" not in found["AT-COND"]
    assert child_ids(found["AT-COND"]) == ["AT-SIT", "AT-ASM-1", "AT-WP-1"]
    weak = found["AT-WP-1"]
    assert (weak["source_id"], weak["label"]) == ("FB-1-1", "Feedback is delayed.")
    assert weak["evidence_status"] == spec.causal_factors[0].evidence_status.value
    assert "belief" not in weak
    steps = found["AT-STEPS"]
    assert steps["ordered"] is True
    assert [found[i]["technique_id"] for i in child_ids(steps)] == [
        ATLAS_TOOL_DATA_POISONING[0],
        ATLAS_INDIRECT_INJECTION[0],
        ATLAS_INDIRECT_INJECTION[0],
    ]
    assert found["AT-STEP-1"]["asset"] == "lookup_order"
    assert "asset" not in found["AT-STEP-2"]
    action = found["AT-UCA"]
    assert action["label"] == spec.scenario_context.ica.exact_ica_text
    assert action["source_ids"] == ["RESP-1", "CA-1-1"]
    assert [item["source_id"] for item in action["violates"]] == ["SC-1"]
    assert found["AT-FAIL"]["label"] == spec.unsafe_outcome_semantic_proposition
    for node in found.values():
        assert node["authority"] == "proposed_hypothesis"
        if node["type"] in ("condition", "action", "reference"):
            assert "children" not in node


def test_a_direct_attack_has_no_plant_step_and_no_asset() -> None:
    tree = tree_of(adversarial().model_copy(update={"attack_shape": DIRECT}))

    found = nodes(tree)
    steps = [found[i] for i in child_ids(found["AT-STEPS"])]
    assert [step["technique_id"] for step in steps] == [ATLAS_DIRECT_INJECTION[0]] * 2
    assert all("asset" not in step for step in steps)


def test_an_adversarial_spec_without_a_shape_uses_the_default_shape() -> None:
    tree = tree_of(adversarial().model_copy(update={"attack_shape": None}))

    assert child_ids(nodes(tree)["AT-STEPS"]) == ["AT-STEP-1"]


def test_an_everyday_scenario_has_no_attacker_assumptions_or_steps() -> None:
    tree = tree_of(everyday())

    found = nodes(tree)
    assert "attacker" not in found["AT-SCN"]
    assert child_ids(found["AT-SCN"]) == ["AT-COND", "AT-UCA", "AT-FAIL"]
    assert child_ids(found["AT-COND"]) == ["AT-SIT", "AT-WP-1"]
    assert not any(node_id.startswith(("AT-ASM", "AT-STEP")) for node_id in found)


def test_a_weak_point_carries_the_defender_belief_it_names() -> None:
    found = nodes(tree_of(pm_factor(adversarial())))

    assert found["AT-WP-1"]["belief"] == (
        "The flawed belief concerns: state. Flaw: The state is stale."
    )


def test_two_hazards_root_at_the_first_and_list_both() -> None:
    spec = with_hazards(adversarial(), ("H-1", "First hazard"), ("H-2", "Second"))
    tree = tree_of(spec)

    root = tree["root"]
    assert root["label"] == "First hazard"
    assert root["source_ids"] == ["H-1", "H-2"]
    assert root["hazards"] == [
        {"source_id": "H-1", "label": "First hazard"},
        {"source_id": "H-2", "label": "Second"},
    ]


def test_other_scenarios_that_share_a_hazard_are_references_in_id_order() -> None:
    spec = with_hazards(adversarial(), ("H-1", "First"), ("H-2", "Second"))
    second_hazard_only = with_hazards(
        renamed(everyday(), "SCN-009", "Everyday failure."), ("H-2", "Second")
    )
    both = renamed(adversarial(), "SCN-003", "Another attack.")
    unrelated = with_hazards(
        renamed(adversarial(), "SCN-002", "Unrelated."), ("H-7", "Other")
    )

    tree = tree_of(spec, second_hazard_only, both, unrelated)

    found = nodes(tree)
    assert child_ids(found["AT-OR"]) == ["AT-SCN", "AT-ALT-1", "AT-ALT-2"]
    assert [
        (found[i]["scenario_id"], found[i]["label"], found[i]["type"])
        for i in ("AT-ALT-1", "AT-ALT-2")
    ] == [
        ("SCN-003", "SCN-003", "reference"),
        ("SCN-009", "SCN-009", "reference"),
    ]
    assert validate_and_or_tree_structure(tree, "SCN-001").passed
    text = json.dumps(tree)
    for criterion in ("Another attack.", "Everyday failure.", "Unrelated."):
        assert criterion not in text


def test_the_sibling_index_holds_scenario_ids_by_hazard() -> None:
    spec = with_hazards(adversarial(), ("H-1", "First"), ("H-2", "Second"))
    other = with_hazards(renamed(everyday(), "SCN-002", "x"), ("H-2", "Second"))

    assert build_sibling_index([other, spec]) == {
        "H-1": ["SCN-001"],
        "H-2": ["SCN-001", "SCN-002"],
    }


def test_an_unsupported_structural_id_in_free_text_is_replaced() -> None:
    spec = adversarial()
    spec = spec.model_copy(
        update={
            "attacker_bdi": spec.attacker_bdi.model_copy(
                update={"beliefs": ["The agent trusts CA-9-9."]}
            )
        }
    )
    tree = tree_of(spec)

    assert nodes(tree)["AT-ASM-1"]["label"] == (
        "The agent trusts [unsupported source omitted]."
    )
    assert "source_uncertainty" in tree
    assert validate_tree_factor_evidence_coverage(tree, spec).passed


# --- validators ---------------------------------------------------------------


def test_the_built_trees_pass_both_validators() -> None:
    for spec in (adversarial(), everyday(), pm_factor(adversarial())):
        tree = tree_of(spec, renamed(everyday(), "SCN-005", "Other."))
        assert validate_and_or_tree_structure(tree, spec.scenario_id).passed
        assert validate_tree_factor_evidence_coverage(tree, spec).passed


def test_a_flat_tree_passes_the_structural_validator_untouched() -> None:
    flat = render_scenario_presentation(adversarial())[1]

    assert validate_and_or_tree_structure(flat, "SCN-001").passed


def _broken(change) -> list[str]:
    tree = copy.deepcopy(tree_of(adversarial(), renamed(everyday(), "SCN-002", "x")))
    change(tree, nodes(tree))
    return validate_and_or_tree_structure(tree, "SCN-001").errors


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda t, n: n["AT-UCA"].update(node_id="AT-FAIL"), "not unique"),
        (lambda t, n: n["AT-UCA"].update(node_id="UCA"), "AT- node_id"),
        (lambda t, n: n["AT-OR"].update(operator="XOR"), "must be AND or OR"),
        (lambda t, n: n["AT-STEPS"].update(children=[]), "at least one child"),
        (lambda t, n: n["AT-OR"].update(ordered=True), "only on an AND"),
        (lambda t, n: n["AT-FAIL"].update(children=[]), "must not carry children"),
        (lambda t, n: n["AT-ALT-1"].update(scenario_id="SCN-001"), "names this"),
        (lambda t, n: n["AT-UCA"].update(operator="AND"), "is not an operator"),
        (lambda t, n: n["AT-UCA"].update(type="step"), "unknown type"),
        (lambda t, n: t["root"].update(type="operator", operator="OR"), "goal"),
        (lambda t, n: n["AT-SCN"].pop("this_scenario"), "exactly one node"),
        (lambda t, n: t.update(root="text"), "node mapping"),
    ],
    ids=[
        "duplicate-id",
        "id-prefix",
        "unknown-operator",
        "childless-operator",
        "ordered-or",
        "leaf-children",
        "self-reference",
        "operator-on-leaf",
        "unknown-type",
        "root-not-goal",
        "no-own-scenario",
        "root-string",
    ],
)
def test_the_structural_validator_rejects_a_broken_tree(change, message) -> None:
    errors = _broken(change)

    assert any(message in error for error in errors), errors


def test_factor_coverage_requires_a_weak_point_of_this_scenario() -> None:
    spec = adversarial()
    tree = tree_of(spec)
    found = nodes(tree)
    found["AT-COND"]["children"] = [
        child for child in found["AT-COND"]["children"] if child["node_id"] != "AT-WP-1"
    ]
    # The factor's id and text elsewhere in the tree do not count.
    found["AT-FAIL"]["label"] = "FB-1-1: Feedback is delayed."

    result = validate_tree_factor_evidence_coverage(tree, spec)

    assert not result.passed
    assert "FB-1-1" in result.errors[0]


def test_factor_coverage_rejects_an_unsupported_bridge_in_an_and_or_tree() -> None:
    spec = adversarial()
    tree = tree_of(spec)
    nodes(tree)["AT-SIT"]["label"] = "Context reached through CA-9-9."

    result = validate_tree_factor_evidence_coverage(tree, spec)

    assert not result.passed
    assert "CA-9-9" in result.errors[0]


def test_another_scenarios_criterion_stays_out_of_this_tree() -> None:
    spec = adversarial()
    tree = tree_of(spec, renamed(everyday(), "SCN-002", "It calls CA-9-9."))

    assert "CA-9-9" not in json.dumps(tree)
    assert validate_tree_factor_evidence_coverage(tree, spec).passed


def test_flat_factor_coverage_stays_strict() -> None:
    spec = adversarial()
    flat = render_scenario_presentation(spec)[1]
    flat["leaves"] = []
    flat["branches"] = []

    assert not validate_tree_factor_evidence_coverage(flat, spec).passed


# --- report -------------------------------------------------------------------


def test_the_report_renders_an_and_or_tree_as_an_outline() -> None:
    tree = tree_of(adversarial(), renamed(everyday(), "SCN-002", "Other."))

    panel = tree_panel(tree)

    assert panel.preview == "14 nodes · 1 other scenario · weak point FB-1-1"
    body = str(panel.body)
    for text in ("AT-SCN", "AT-STEP-1", "AT-ALT-1", "AND, in order", "OR", "AML.T0099"):
        assert text in body
    assert body.index("AT-COND") < body.index("AT-STEPS") < body.index("AT-FAIL")


def test_panel_stats_counts_an_and_or_tree_as_not_flat() -> None:
    run = SimpleNamespace(
        scenarios={"SCN-001": SimpleNamespace(attack_tree=tree_of(adversarial()))},
        features={},
    )

    assert panel_stats(run).flat == 0
    assert panel_stats(run).and_or == 1


# --- handoff ------------------------------------------------------------------


def _handoff(spec: ScenarioSpec, tree: dict[str, Any]) -> dict[str, Any]:
    narrative, _, gherkin = render_scenario_presentation(spec)
    envelope = assemble_envelope(
        scenario_id=spec.scenario_id,
        scenario_spec=spec,
        narrative=narrative,
        attack_tree=tree,
        gherkin_spec=gherkin,
        gherkin_raw=gherkin.to_feature_text(),
    )
    return build_scenario_handoff(envelope).model_dump(mode="json")


@pytest.mark.parametrize(
    "make", [adversarial, everyday], ids=["adversarial", "everyday"]
)
def test_an_and_or_handoff_passes_ownership_model_and_schema(make) -> None:
    spec = make()
    document = _handoff(spec, tree_of(spec, renamed(everyday(), "SCN-002", "x")))

    assert handoff_ownership_violations(document) == []
    assert list(Draft202012Validator(SCHEMA).iter_errors(document)) == []
    verify_handoff_digest(ScenarioHandoffV4.model_validate(document))


def test_the_digest_covers_the_and_or_tree() -> None:
    spec = adversarial()
    flat = _handoff(spec, render_scenario_presentation(spec)[1])
    and_or = _handoff(spec, tree_of(spec))

    assert flat["content_digest"] != and_or["content_digest"]
    assert {key for key in flat if flat[key] != and_or[key]} == {
        "attack_tree",
        "content_digest",
    }


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


def test_an_and_or_run_publishes_valid_trees_that_name_each_other(
    tmp_path: Path,
) -> None:
    result, client = _publish(tmp_path, attack_tree_format=AttackTreeFormat.AND_OR)

    assert result.stage_errors == []
    assert result.validation_errors == []
    assert client.call_count == 3
    for own, other in (("SCN-001", "SCN-002"), ("SCN-002", "SCN-001")):
        document = _published_handoff(tmp_path, own)
        assert list(Draft202012Validator(SCHEMA).iter_errors(document)) == []
        assert handoff_ownership_violations(document) == []
        verify_handoff_digest(ScenarioHandoffV4.model_validate(document))
        tree = document["attack_tree"]
        assert tree["format"] == AND_OR_TREE_FORMAT
        assert validate_and_or_tree_structure(tree, own).passed
        references = [
            node["scenario_id"]
            for node in nodes(tree).values()
            if node["type"] == "reference"
        ]
        assert references == [other]


def test_the_format_changes_only_the_tree_and_the_digest(tmp_path: Path) -> None:
    _, flat_client = _publish(tmp_path / "flat")
    _, and_or_client = _publish(
        tmp_path / "and-or", attack_tree_format=AttackTreeFormat.AND_OR
    )
    _publish(tmp_path / "explicit-flat", attack_tree_format=AttackTreeFormat.FLAT)

    assert flat_client.calls == and_or_client.calls
    for scenario_id in ("SCN-001", "SCN-002"):
        flat = _published_handoff(tmp_path / "flat", scenario_id)
        and_or = _published_handoff(tmp_path / "and-or", scenario_id)
        assert {key for key in flat if flat[key] != and_or[key]} == {
            "attack_tree",
            "content_digest",
        }
        for name in (f"{scenario_id}.yaml", f"{scenario_id}.feature"):
            assert (tmp_path / "flat" / "scenarios" / name).read_bytes() == (
                tmp_path / "explicit-flat" / "scenarios" / name
            ).read_bytes()


# --- plumbing -----------------------------------------------------------------


def test_the_inputs_reject_an_unknown_tree_format(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="attack_tree_format"):
        synthesis.SynthesisInputs(
            use_case="u", output_dir=tmp_path, attack_tree_format="tree"
        )


@pytest.mark.parametrize("value", ["flat", "and-or"])
def test_the_inputs_format_reaches_run_sp3(
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
        use_case="u", output_dir=tmp_path, attack_tree_format=value
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

    assert captured["attack_tree_format"] is AttackTreeFormat(value)


def invoke_generate(tmp_path: Path, extra: list[str]) -> tuple[Any, list[Any]]:
    for name in ("risk.json", "facts.json", "mapping.tsv"):
        (tmp_path / name).write_text("{}", encoding="utf-8")
    arguments = [
        "generate",
        "--use-case",
        "a system",
        "--risk-extraction",
        str(tmp_path / "risk.json"),
        "--qualification-facts",
        str(tmp_path / "facts.json"),
        "--sssom",
        str(tmp_path / "mapping.tsv"),
        "--output-dir",
        str(tmp_path / "out"),
        *extra,
    ]
    captured: list[Any] = []

    def capture(inputs: Any, adapter: Any) -> SimpleNamespace:
        captured.append(inputs)
        return SimpleNamespace(
            output_dir=tmp_path,
            artifact_paths={"taxonomy-obligation-plan.yaml": tmp_path / "p.yaml"},
            report_path=None,
            run_status="completed",
        )

    with (
        patch(
            "asago_scenario_generator.data.loaders.load_reviewed_risk_extraction",
            return_value=(),
        ),
        patch(
            "asago_scenario_generator.pipeline.synthesis.run_synthesis",
            side_effect=capture,
        ),
    ):
        return PlainCliRunner().invoke(app, arguments), captured


@pytest.mark.parametrize(
    ("arguments", "expected"),
    [([], "flat"), (["--attack-tree-format", "and-or"], "and-or")],
    ids=["default", "and-or"],
)
def test_the_cli_flag_reaches_the_inputs(
    tmp_path: Path, arguments: list[str], expected: str
) -> None:
    result, captured = invoke_generate(tmp_path, arguments)

    assert result.exit_code == 0, result.output
    assert captured[0].attack_tree_format == expected


def test_the_cli_rejects_an_unknown_tree_format(tmp_path: Path) -> None:
    result, captured = invoke_generate(tmp_path, ["--attack-tree-format", "tree"])

    assert result.exit_code != 0
    assert "--attack-tree-format" in result.output
    assert captured == []


def test_generate_help_lists_the_tree_format_flag() -> None:
    result = PlainCliRunner().invoke(app, ["generate", "--help"])

    assert result.exit_code == 0
    assert "--attack-tree-format" in result.stdout


def test_a_belief_flaw_that_repeats_the_weak_point_is_left_out() -> None:
    spec = pm_factor(adversarial())
    belief = spec.defender_bdi.beliefs[0].model_copy(
        update={"vulnerability": "Feedback is delayed."}
    )
    spec = spec.model_copy(
        update={
            "defender_bdi": spec.defender_bdi.model_copy(update={"beliefs": [belief]})
        }
    )

    assert nodes(tree_of(spec))["AT-WP-1"]["belief"] == (
        "The flawed belief concerns: state."
    )


def test_a_belief_flaw_that_says_not_selected_is_left_out() -> None:
    spec = pm_factor(adversarial())
    belief = spec.defender_bdi.beliefs[0].model_copy(
        update={"vulnerability": "Not selected as a causal factor here."}
    )
    spec = spec.model_copy(
        update={
            "defender_bdi": spec.defender_bdi.model_copy(update={"beliefs": [belief]})
        }
    )

    assert nodes(tree_of(spec))["AT-WP-1"]["belief"] == (
        "The flawed belief concerns: state."
    )
