"""The attack path in the report: its panel, the hazard view, and the Attack Flow files.

``klarna-and-or`` holds seven v5 handoffs that carry attack paths.
"""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
from typing import Any


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
    body = str(panels(copy(tmp_path, "v5", "klarna-and-or"), "SCN-027")["path"].body)

    assert not re.search(r"\bA[TP]-[A-Z]", body)
    assert "Proposed causal hypothesis" not in body
    assert "Format " not in body
    assert "proposed hypothesis" not in body
    assert "Other scenarios" not in body


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


def test_the_hazard_view_names_the_path_node_ids(tmp_path: Path) -> None:
    output = copy(tmp_path, "v5", "klarna-and-or")

    write_report(output)

    nodes = re.findall(
        r'<span class="nid">([^<]*)</span>',
        section((output / "report/index.html").read_text(), "hazards"),
    )
    assert nodes and all(node.startswith("AP-") for node in nodes)
    assert hazard_text(output).count("Any one of these scenarios") == len(HAZARDS)


def test_each_reached_hazard_has_an_attack_flow(tmp_path: Path) -> None:
    output = copy(tmp_path, "v5", "klarna-and-or")

    write_report(output)

    for hazard_id in HAZARDS:
        assert flow(output, hazard_id)["type"] == "bundle"
