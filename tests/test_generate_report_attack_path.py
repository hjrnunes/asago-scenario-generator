"""The attack path in the report: its panel, the hazard view, and the Attack Flow files.

``klarna-and-or`` holds seven v5 handoffs that carry attack paths;
``klarna-and-or-v4`` holds the same scenarios as v4 handoffs that carry the
and-or trees the paths reduce from.
"""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
from typing import Any

import pytest

from asago_scenario_generator.report import attack_flow, hazard_view
from asago_scenario_generator.report.generate_report import write_report
from asago_scenario_generator.report.run_data import load_run
from asago_scenario_generator.report.scenario_panels import scenario_panels
from tests.helpers.generate_report_fixture import copy_run, edit_yaml

FIXTURES = Path(__file__).parent / "fixtures" / "generate_report"
HAZARDS = ("H-2", "H-5", "H-9", "H-10")


def copy(tmp_path: Path, name: str, fixture: str) -> Path:
    target = tmp_path / name
    shutil.copytree(FIXTURES / fixture, target)
    return target


def panels(output: Path, scenario: str) -> dict:
    return {p.key: p for p in scenario_panels(load_run(output), scenario)}


def section(html: str, section_id: str) -> str:
    match = re.search(rf'<section id="{section_id}">.*?</section>', html, re.S)
    assert match is not None, section_id
    return match.group(0)


def flow(output: Path, hazard_id: str) -> dict[str, Any]:
    path = output / "report" / "attack-flow" / f"{hazard_id}.json"
    return json.loads(path.read_text(encoding="utf-8"))


# --- the panel ------------------------------------------------------------------


def test_a_v5_scenario_has_an_attack_path_panel_in_place_of_the_tree(
    tmp_path: Path,
) -> None:
    run = load_run(copy(tmp_path, "v5", "klarna-and-or"))

    for scenario in run.scenarios:
        assert [p.key for p in scenario_panels(run, scenario)] == [
            "narrative",
            "path",
            "gherkin",
        ]
        assert scenario_panels(run, scenario)[1].title == "Attack path"


def test_the_path_reads_attacker_then_five_numbered_parts(tmp_path: Path) -> None:
    p = panels(copy(tmp_path, "v5", "klarna-and-or"), "SCN-027")["path"]

    body = str(p.body)
    labels = re.findall(r"<dt>(.*?)</dt>", body)
    assert labels == [
        "Attacker",
        "1 Conditions",
        "2 Attack steps",
        "3 Unsafe action",
        "4 Observable failure",
        "5 Hazard",
    ]
    assert p.preview == "3 conditions · 3 attack steps · weak point CA-1-5"
    assert "AML.T0099 AI Agent Tool Data Poisoning" in body
    assert "asset lookup_order" in body
    assert "Violates" in body and '<span class="chip">SC-8</span>' in body
    assert "Safe outcome:" in body
    assert '<span class="chip">L-9</span>' in body
    assert '<span class="chip">CA-1-5</span>' in body


def test_the_path_shows_no_node_id_framing_or_format_note(tmp_path: Path) -> None:
    for fixture in ("klarna-and-or", "klarna-and-or-v4"):
        body = str(panels(copy(tmp_path, fixture, fixture), "SCN-027")["path"].body)

        assert not re.search(r"\bA[TP]-[A-Z]", body)
        assert "Proposed causal hypothesis" not in body
        assert "Format " not in body
        assert "proposed hypothesis" not in body


def test_a_weak_point_shows_its_belief_and_evidence_status(tmp_path: Path) -> None:
    output = copy(tmp_path, "v5", "klarna-and-or")

    def believe(y: dict) -> None:
        weak = [
            n for n in y["attack_path"]["conditions"] if n["category"] == "weak_point"
        ]
        weak[0]["belief"] = "The agent wrongly believes the plan is the customer's."

    edit_yaml(output / "scenarios" / "SCN-027.yaml", believe)

    body = str(panels(output, "SCN-027")["path"].body)

    assert "<b>Belief</b> The agent wrongly believes the plan is the customer" in body
    assert "Evidence status:" in body and "structural failure" in body


def test_a_functional_path_has_no_attacker_and_shows_none_for_its_steps(
    tmp_path: Path,
) -> None:
    p = panels(copy(tmp_path, "v5", "klarna-and-or"), "SCN-001")["path"]

    body = str(p.body)
    labels = re.findall(r"<dt>(.*?)</dt>", body)
    assert labels == [
        "1 Conditions",
        "2 Attack steps",
        "3 Unsafe action",
        "4 Observable failure",
        "5 Hazard",
    ]
    assert "<dt>2 Attack steps</dt><dd>None</dd>" in body
    assert "0 attack steps" in p.preview


def test_an_adversarial_path_keeps_its_steps_row_as_a_list(tmp_path: Path) -> None:
    body = str(panels(copy(tmp_path, "v5", "klarna-and-or"), "SCN-027")["path"].body)

    assert "<dt>2 Attack steps</dt><dd><ol><li>A third party plants" in body
    assert "<dd>None</dd>" not in body


def test_a_v4_and_or_tree_gets_the_same_panel_plus_the_other_scenarios(
    tmp_path: Path,
) -> None:
    v5 = panels(copy(tmp_path, "v5", "klarna-and-or"), "SCN-027")["path"]
    v4 = panels(copy(tmp_path, "v4", "klarna-and-or-v4"), "SCN-027")["path"]

    line = '<p class="nm">Other scenarios that reach the same hazard: SCN-042, SCN-043.</p>'
    assert str(v4.body) == line + str(v5.body)
    assert (v4.key, v4.title, v4.preview) == (v5.key, v5.title, v5.preview)
    assert "Other scenarios" not in str(v5.body)


def test_the_flat_tree_panel_loses_only_its_framing_sentence(tmp_path: Path) -> None:
    body = str(panels(copy_run(tmp_path), "SCN-001")["tree"].body)

    assert "Proposed causal hypothesis" not in body
    assert "Loss scenario:" in body
    assert "Relations are flat" in body


def test_a_tree_the_reduction_cannot_read_falls_back_to_the_outline(
    tmp_path: Path,
) -> None:
    output = copy(tmp_path, "v4", "klarna-and-or-v4")
    edit_yaml(
        output / "scenarios" / "SCN-027.yaml",
        lambda y: y["attack_tree"]["root"].update(children=[]),
    )

    p = panels(output, "SCN-027")["tree"]

    assert p.title == "Attack tree"


# --- the narrative panel --------------------------------------------------------


def test_a_v5_narrative_renders_as_its_paragraph_with_a_clipped_preview(
    tmp_path: Path,
) -> None:
    run = load_run(copy(tmp_path, "v5", "klarna-and-or"))
    narrative = run.scenarios["SCN-027"].narrative

    p = panels(copy(tmp_path, "again", "klarna-and-or"), "SCN-027")["narrative"]

    assert str(p.body) == f"<p>{narrative}</p>"
    assert p.preview.endswith("…") and len(p.preview) <= 111
    assert narrative.startswith(p.preview.removesuffix("…"))
    assert "sourced claim" not in p.preview


def test_a_short_v5_narrative_previews_whole(tmp_path: Path) -> None:
    output = copy(tmp_path, "v5", "klarna-and-or")
    edit_yaml(
        output / "scenarios" / "SCN-027.yaml",
        lambda y: y.update(narrative="The assistant acts on a planted item."),
    )

    p = panels(output, "SCN-027")["narrative"]

    assert p.preview == "The assistant acts on a planted item."


def test_the_structured_narrative_has_no_opening_paragraph(tmp_path: Path) -> None:
    body = str(panels(copy_run(tmp_path), "SCN-004")["narrative"].body)

    assert not body.startswith("<p")
    assert "Test hypothesis" not in body
    assert "Claims without an authority note" not in body
    assert "authority proposed_hypothesis" not in body


# --- the scenario intro ---------------------------------------------------------


def test_the_intro_of_a_v5_run_counts_its_attack_paths(tmp_path: Path) -> None:
    output = copy(tmp_path, "v5", "klarna-and-or")

    write_report(output)

    intro = section((output / "report/index.html").read_text(), "scenarios")
    assert "7 of 7 scenarios carry an attack path" in intro


# --- the hazard view and the Attack Flow files ---------------------------------


def hazard_text(output: Path) -> str:
    html = section((output / "report/index.html").read_text(), "hazards")
    return re.sub(r'<span class="nid">[^<]*</span>', "", html)


def shape(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    """Return a bundle's objects with every id replaced by its position."""
    objects = bundle["objects"]
    position = {item["id"]: f"#{n}" for n, item in enumerate(objects)}
    position[bundle["id"]] = "#bundle"

    def swap(value: Any) -> Any:
        if isinstance(value, str):
            return position.get(value, value)
        if isinstance(value, list):
            return [swap(item) for item in value]
        if isinstance(value, dict):
            return {key: swap(item) for key, item in value.items()}
        return value

    return [swap(item) for item in objects]


def render_with_tree_subtrees(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, Path]:
    """Render the v5 run from its paths, then again from the trees they reduce from.

    The second render swaps in the ``AT-SCN`` subtree of each scenario's v4
    twin, so everything else (the unsafe control action, the ATLAS tactics)
    stays the v5 run's own.
    """
    v5 = copy(tmp_path, "v5", "klarna-and-or")
    trees = {
        scenario_id: hazard_view._tree_subtree(scenario.attack_tree)
        for scenario_id, scenario in load_run(
            copy(tmp_path, "v4", "klarna-and-or-v4")
        ).scenarios.items()
    }
    write_report(v5, "report")
    from_trees = copy(tmp_path, "trees", "klarna-and-or")
    with monkeypatch.context() as patch:
        patch.setattr(hazard_view, "scenario_subtree", lambda s: trees[s.scenario_id])
        patch.setattr(attack_flow, "scenario_subtree", lambda s: trees[s.scenario_id])
        write_report(from_trees, "report")
    return v5, from_trees


def test_the_hazard_view_of_a_v5_run_differs_only_in_node_ids(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    v5, from_trees = render_with_tree_subtrees(tmp_path, monkeypatch)

    assert hazard_text(v5) == hazard_text(from_trees)
    nodes = re.findall(
        r'<span class="nid">([^<]*)</span>',
        section((v5 / "report/index.html").read_text(), "hazards"),
    )
    assert nodes and all(node.startswith("AP-") for node in nodes)


def test_an_attack_flow_of_a_v5_run_equals_the_tree_flow_up_to_ids(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    v5, from_trees = render_with_tree_subtrees(tmp_path, monkeypatch)

    changed = 0
    for hazard_id in HAZARDS:
        new, old = flow(v5, hazard_id), flow(from_trees, hazard_id)
        assert shape(new) == shape(old), hazard_id
        changed += {o["id"] for o in new["objects"]} != {
            o["id"] for o in old["objects"]
        }
    assert changed == len(HAZARDS)
