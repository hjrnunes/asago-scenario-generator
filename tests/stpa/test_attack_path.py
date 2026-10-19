"""The ``attack-path-v1`` path a v5 handoff carries in place of the attack tree.

Code reduces the scenario's and-or tree to the path; no request depends on it.
Every test is offline.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from asago_scenario_generator.stpa.scenario_prod.attack_path import (
    ATTACK_PATH_FORMAT,
    attack_path_errors,
    other_scenario_ids,
    path_node_id,
    path_node_ids,
    reduce_to_attack_path,
)
from asago_scenario_generator.stpa.scenario_prod.handoff import (
    AttackPath,
    ScenarioHandoffV4,
    ScenarioHandoffV5,
    build_scenario_handoff,
    handoff_ownership_violations,
    handoff_schema_violations,
)
from asago_scenario_generator.stpa.scenario_prod.handoff_v5 import (
    build_scenario_handoff_v5,
)
from tests.stpa.test_narration import adversarial, everyday
from tests.stpa.test_scenario_handoff_v5 import (
    SCHEMA,
    _envelope,
    _kit,
)

ROOT = Path(__file__).resolve().parents[2]
V4_SCHEMA = ROOT / "data/contracts/scenario-handoff/handoff-v4/schema.json"


def _tree(spec: Any) -> dict[str, Any]:
    return _envelope(spec).attack_tree


def _nodes(node: dict[str, Any]) -> list[dict[str, Any]]:
    found = [node]
    for child in node.get("children", []):
        found.extend(_nodes(child))
    return found


# --- reduction ----------------------------------------------------------------


def test_the_path_ids_swap_the_prefix_and_name_the_root_the_hazard() -> None:
    assert path_node_id("AT-WP-1") == "AP-WP-1"
    assert path_node_id("AT-STEP-3") == "AP-STEP-3"
    assert path_node_id("AT-ROOT") == "AP-HAZ"
    with pytest.raises(ValueError, match="AT-"):
        path_node_id("AP-WP-1")


def test_an_adversarial_tree_reduces_to_its_scenarios_route() -> None:
    tree = _tree(adversarial())
    path = reduce_to_attack_path(tree)

    assert path["format"] == ATTACK_PATH_FORMAT
    assert list(path) == [
        "format",
        "attacker",
        "conditions",
        "steps",
        "unsafe_action",
        "observable_failure",
        "hazard",
    ]
    assert path["unsafe_action"]["node_id"] == "AP-UCA"
    assert path["observable_failure"]["node_id"] == "AP-FAIL"
    assert path["hazard"]["node_id"] == "AP-HAZ"
    assert path["steps"]
    assert [step["node_id"] for step in path["steps"]] == [
        f"AP-STEP-{n}" for n in range(1, len(path["steps"]) + 1)
    ]
    assert all(
        node["node_id"].startswith("AP-")
        for node in (*path["conditions"], *path["steps"])
    )


def test_the_path_keeps_the_trees_text_and_sources() -> None:
    tree = _tree(adversarial())
    path = reduce_to_attack_path(tree)
    tree_nodes = {node["node_id"]: node for node in _nodes(tree["root"])}

    for node in (*path["conditions"], *path["steps"]):
        original = tree_nodes["AT-" + node["node_id"][len("AP-") :]]
        assert node["label"] == original["label"]
    weak = [n for n in path["conditions"] if n["category"] == "weak_point"]
    assert weak
    for node in weak:
        original = tree_nodes["AT-" + node["node_id"][len("AP-") :]]
        assert node["source_ids"] == [original["source_id"]]
        assert node["evidence_status"] == original["evidence_status"]


def test_a_functional_tree_reduces_to_a_path_without_attacker_or_steps() -> None:
    path = reduce_to_attack_path(_tree(everyday()))

    assert "attacker" not in path
    assert path["steps"] == []
    assert path["unsafe_action"]["node_id"] == "AP-UCA"


def test_the_path_names_no_other_scenario_and_drops_the_or() -> None:
    siblings_tree = copy.deepcopy(_tree(adversarial()))
    reference = {
        "node_id": "AT-SCN-SCN-009",
        "type": "reference",
        "scenario_id": "SCN-009",
        "label": "Another way to the hazard.",
    }
    siblings_tree["root"]["children"][0].setdefault("children", []).append(reference)
    assert other_scenario_ids(siblings_tree) == ["SCN-009"]

    text = json.dumps(reduce_to_attack_path(siblings_tree))
    assert "SCN-009" not in text
    assert "AT-" not in text


def test_the_reduction_is_pure() -> None:
    tree = _tree(adversarial())
    before = copy.deepcopy(tree)

    assert reduce_to_attack_path(tree) == reduce_to_attack_path(tree)
    assert tree == before


def test_the_reduction_carries_the_trees_source_uncertainty() -> None:
    tree = copy.deepcopy(_tree(adversarial()))
    tree["source_uncertainty"] = "A source outside the path."

    assert reduce_to_attack_path(tree)["source_uncertainty"] == (
        "A source outside the path."
    )
    assert "source_uncertainty" not in reduce_to_attack_path(_tree(adversarial()))


@pytest.mark.parametrize(
    "damage",
    [
        lambda tree: tree.update(format="flat"),
        lambda tree: tree.update(root=None),
        lambda tree: [node.pop("this_scenario", None) for node in _nodes(tree["root"])],
    ],
    ids=["format", "root", "no-scenario"],
)
def test_a_tree_that_is_not_an_and_or_tree_does_not_reduce(damage: Any) -> None:
    tree = copy.deepcopy(_tree(adversarial()))
    damage(tree)

    with pytest.raises(ValueError):
        reduce_to_attack_path(tree)


# --- Stage-7 check ------------------------------------------------------------


def _factor_ids(handoff: ScenarioHandoffV5) -> list[str]:
    return [factor.source_id for factor in handoff.causal_factors]


def test_a_reduced_path_passes_the_stage_7_check() -> None:
    handoff = build_scenario_handoff_v5(_envelope(adversarial()))
    path = handoff.attack_path.model_dump(mode="json", exclude_none=True)

    assert attack_path_errors(path, _factor_ids(handoff)) == []
    assert path_node_ids(path)[-3:] == ["AP-UCA", "AP-FAIL", "AP-HAZ"]


def test_the_check_names_a_duplicate_or_a_foreign_id() -> None:
    handoff = build_scenario_handoff_v5(_envelope(adversarial()))
    path = handoff.attack_path.model_dump(mode="json", exclude_none=True)
    path["conditions"][0]["node_id"] = "AT-SIT"
    path["steps"].append(dict(path["steps"][0]))

    errors = attack_path_errors(path, _factor_ids(handoff))

    assert any("AT-SIT needs an AP-" in error for error in errors)
    assert any("not unique" in error for error in errors)


def test_the_check_wants_one_weak_point_per_causal_factor() -> None:
    handoff = build_scenario_handoff_v5(_envelope(adversarial()))
    path = handoff.attack_path.model_dump(mode="json", exclude_none=True)

    errors = attack_path_errors(path, [*_factor_ids(handoff), "CA-9-9"])

    assert len(errors) == 1
    assert "one weak point per causal factor" in errors[0]


# --- the v5 model and its schema ----------------------------------------------


def _document() -> dict[str, Any]:
    return build_scenario_handoff_v5(_envelope(adversarial())).model_dump(
        mode="json", exclude_none=True
    )


def test_a_v5_handoff_carries_the_path_where_v4_carries_the_tree() -> None:
    envelope = _envelope(adversarial())
    v4 = build_scenario_handoff(envelope).model_dump(mode="json", exclude_none=True)
    v5 = _document()

    assert list(v4).index("attack_tree") == list(v5).index("attack_path")
    assert "attack_tree" not in v5
    assert v5["attack_path"] == reduce_to_attack_path(envelope.attack_tree)


def test_the_path_model_is_closed_and_typed() -> None:
    path = _document()["attack_path"]

    assert (
        AttackPath.model_validate(path).model_dump(mode="json", exclude_none=True)
        == path
    )
    for damage in (
        lambda p: p.update(extra=1),
        lambda p: p["conditions"][0].update(authority="proposed_hypothesis"),
        lambda p: p["conditions"][0].update(node_id="AT-SIT"),
        lambda p: p["unsafe_action"].update(node_id="AP-FAIL"),
        lambda p: p["hazard"].update(node_id="AP-ROOT"),
        lambda p: p.update(format="and-or-tree-v1"),
    ):
        broken = copy.deepcopy(path)
        damage(broken)
        with pytest.raises(ValidationError):
            AttackPath.model_validate(broken)


def test_a_v5_document_with_a_tree_or_without_a_path_is_rejected() -> None:
    document = _document()
    with_tree = {**document, "attack_tree": {"format": "and-or-tree-v1"}}
    without_path = {k: v for k, v in document.items() if k != "attack_path"}

    for broken in (with_tree, without_path):
        assert list(Draft202012Validator(SCHEMA).iter_errors(broken))
        assert handoff_schema_violations(broken)
        with pytest.raises(ValidationError):
            ScenarioHandoffV5.model_validate(broken)


def test_a_v4_document_with_a_path_is_rejected() -> None:
    document = _document()
    document["schema_version"] = "scenario-handoff-v4"

    with pytest.raises(ValidationError):
        ScenarioHandoffV4.model_validate(document)


def test_the_published_document_passes_the_schema_and_ownership_scan() -> None:
    document = _document()

    assert list(Draft202012Validator(SCHEMA).iter_errors(document)) == []
    assert handoff_schema_violations(document) == []
    assert handoff_ownership_violations(document) == []


def test_the_v4_schema_is_still_the_v4_models_schema() -> None:
    assert V4_SCHEMA.read_text(encoding="utf-8") == (
        json.dumps(ScenarioHandoffV4.model_json_schema(), indent=2) + "\n"
    )


def test_the_kit_holds_the_path_cases() -> None:
    expected = _kit("expected-violations.json")

    assert expected["invalid/schema-attack-path-not-object.json"] == [
        "schema_violation:attack_path"
    ]
    assert expected["invalid/v5-attack-tree-present.json"] == [
        "schema_violation:attack_tree"
    ]
    assert expected["invalid/v5-attack-path-unknown-key.json"] == [
        "schema_violation:attack_path"
    ]
