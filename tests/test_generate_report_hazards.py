"""The hazard view, its Attack Flow files, and the process-model gap list."""

from __future__ import annotations

import html
import json
import re
import shutil
from pathlib import Path
from typing import Any

import pytest
import yaml

from asago_scenario_generator.pipeline.synthesis_persist import _render_report
from asago_scenario_generator.report.attack_flow import (
    EXTENSION_DEFINITION,
    EXTENSION_ID,
    attack_flow_bundle,
)
from asago_scenario_generator.report.generate_report import build_report, write_report
from asago_scenario_generator.report.hazard_view import hazard_groups
from asago_scenario_generator.report.process_model_gaps import (
    GAPS_FILE,
    gaps_section,
    handoff_documents,
    process_model_gaps,
    write_process_model_gaps,
)
from asago_scenario_generator.report.run_data import load_run
from tests.helpers.generate_report_fixture import body_rows, copy_run, edit_yaml

AND_OR = Path(__file__).parent / "fixtures" / "generate_report" / "klarna-and-or"
AND_OR_V4 = Path(__file__).parent / "fixtures" / "generate_report" / "klarna-and-or-v4"
REACHED = {
    "H-2": ("SCN-001", "SCN-032"),
    "H-5": ("SCN-020", "SCN-021"),
    "H-9": ("SCN-027", "SCN-042"),
    "H-10": ("SCN-005", "SCN-032"),
}


def copy_and_or(tmp_path: Path, name: str = "output") -> Path:
    """Copy the v5 run, whose scenarios carry attack paths."""
    target = tmp_path / name
    shutil.copytree(AND_OR, target)
    return target


def copy_and_or_v4(tmp_path: Path, name: str = "output") -> Path:
    """Copy the same run as v4 handoffs, whose scenarios carry and-or trees."""
    target = tmp_path / name
    shutil.copytree(AND_OR_V4, target)
    return target


def section_html(html: str, section_id: str) -> str:
    match = re.search(rf'<section id="{section_id}">.*?</section>', html, re.S)
    assert match is not None, section_id
    return match.group(0)


def flow(output: Path, hazard_id: str) -> dict[str, Any]:
    path = output / "report" / "attack-flow" / f"{hazard_id}.json"
    return json.loads(path.read_text(encoding="utf-8"))


# --- hazard view ---------------------------------------------------------------


def test_the_view_is_off_by_default(tmp_path: Path) -> None:
    default = copy_and_or(tmp_path, "default")
    explicit = copy_and_or(tmp_path, "explicit")

    write_report(default)
    write_report(explicit, "off")

    html = (default / "report" / "index.html").read_text(encoding="utf-8")
    assert 'id="hazards"' not in html
    assert not (default / "report" / "attack-flow").exists()
    assert html == (explicit / "report" / "index.html").read_text(encoding="utf-8")


def test_an_unknown_view_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="hazard_view must be one of off, report"):
        write_report(copy_and_or(tmp_path), "hazards")


def test_each_scenario_appears_under_every_hazard_it_names(tmp_path: Path) -> None:
    run = load_run(copy_and_or(tmp_path))

    groups = {g.hazard_id: g.scenario_ids for g in hazard_groups(run)}

    assert [g.hazard_id for g in hazard_groups(run)] == [f"H-{n}" for n in range(1, 11)]
    assert {h: s for h, s in groups.items() if s} == REACHED


def test_the_report_view_shows_a_tree_per_reached_hazard(tmp_path: Path) -> None:
    output = copy_and_or(tmp_path)

    write_report(output, "report")

    html = (output / "report" / "index.html").read_text(encoding="utf-8")
    hazards = section_html(html, "hazards")
    assert html.index('id="hazards"') < html.index('<section id="scenarios"')
    assert body_rows(hazards, "hazards-table") == 10
    assert "4 of 10 hazards have a published scenario" in hazards
    assert "1 scenario names more than one and appears under each" in hazards
    for hazard_id, scenario_ids in REACHED.items():
        detail = re.search(
            rf'<details id="hazard-{hazard_id}".*?</details>', hazards, re.S
        ).group(0)
        assert f'href="attack-flow/{hazard_id}.json"' in detail
        assert "Any one of these scenarios reaches the hazard" in detail
        for scenario_id in scenario_ids:
            assert f'<a href="#{scenario_id}">{scenario_id}</a>' in detail
    assert 'id="hazard-H-1"' not in hazards
    assert "duplicate of SCN-019" in hazards
    assert "analytical only" in hazards


def test_one_broken_tree_costs_only_its_hazards(tmp_path: Path) -> None:
    output = copy_and_or_v4(tmp_path)

    def drop_scenario_node(handoff: dict) -> None:
        handoff["attack_tree"]["root"]["children"] = []

    edit_yaml(output / "scenarios" / "SCN-027.yaml", drop_scenario_node)
    write_report(output, "report")

    hazards = section_html(
        (output / "report" / "index.html").read_text(encoding="utf-8"), "hazards"
    )
    assert "H-9 could not be rendered" in hazards
    assert 'id="hazard-H-2"' in hazards
    written = sorted(p.name for p in (output / "report" / "attack-flow").iterdir())
    assert written == ["H-10.json", "H-2.json", "H-5.json"]


def test_the_scenario_intro_counts_and_or_trees(tmp_path: Path) -> None:
    output = copy_and_or_v4(tmp_path)

    write_report(output)

    scenarios = section_html(
        (output / "report" / "index.html").read_text(encoding="utf-8"), "scenarios"
    )
    assert "7 of 7 attack trees are AND/OR trees" in scenarios
    assert "are flat" not in scenarios


def test_the_scenario_intro_counts_attack_paths_in_a_v5_run(tmp_path: Path) -> None:
    output = copy_and_or(tmp_path)

    write_report(output)

    scenarios = section_html(
        (output / "report" / "index.html").read_text(encoding="utf-8"), "scenarios"
    )
    assert "7 of 7 scenarios carry an attack path" in scenarios
    assert "have exactly one weak point" in scenarios
    assert "attack trees are" not in scenarios


def test_the_flat_scenario_intro_is_unchanged(tmp_path: Path) -> None:
    output = copy_run(tmp_path)

    write_report(output)

    html = (output / "report" / "index.html").read_text(encoding="utf-8")
    assert "8 of 8 attack trees are flat, with no AND or OR between nodes" in html


def test_the_page_stays_within_its_size_budget(tmp_path: Path) -> None:
    output = copy_and_or(tmp_path)

    write_report(output, "report")

    html = (output / "report" / "index.html").read_text(encoding="utf-8")
    assert len(html.encode()) / 7 * 100 <= 5_000_000


# --- Attack Flow ---------------------------------------------------------------


def test_one_flow_file_per_reached_hazard(tmp_path: Path) -> None:
    output = copy_and_or(tmp_path)

    write_report(output, "report")

    written = sorted(p.name for p in (output / "report" / "attack-flow").iterdir())
    assert written == sorted(f"{h}.json" for h in REACHED)


def test_a_flow_is_a_well_formed_attack_tree(tmp_path: Path) -> None:
    output = copy_and_or(tmp_path)
    write_report(output, "report")

    bundle = flow(output, "H-10")

    objects = {item["id"]: item for item in bundle["objects"]}
    assert bundle["type"] == "bundle"
    assert bundle["objects"][0] == EXTENSION_DEFINITION
    (attack_flow,) = [o for o in objects.values() if o["type"] == "attack-flow"]
    assert attack_flow["scope"] == "attack-tree"
    for item in objects.values():
        assert item.get("created_by_ref", item["id"]) in objects
        for key in ("effect_refs", "on_true_refs", "start_refs"):
            for ref in item.get(key) or []:
                assert ref in objects, (item["id"], key, ref)
        if item["type"].startswith("attack-"):
            assert item["extensions"] == {EXTENSION_ID: {"extension_type": "new-sdo"}}
        if item["type"] == "attack-operator":
            assert len(item["effect_refs"]) == 1
            assert objects[item["effect_refs"][0]]["type"] == "attack-action"
    targets = {
        ref
        for item in objects.values()
        for key in ("effect_refs", "on_true_refs")
        for ref in item.get(key) or []
    }
    roots = [
        i
        for i, o in objects.items()
        if o["type"] == "attack-action" and not o.get("effect_refs")
    ]
    assert [objects[i]["name"] for i in roots] == [
        "H-10: The assistant provides details or information that are not on the "
        "approved information whitelist."
    ]
    leaves = [
        i
        for i, o in objects.items()
        if o["type"] in ("attack-action", "attack-condition") and i not in targets
    ]
    assert attack_flow["start_refs"] == leaves
    operators = sorted(o["operator"] for o in objects.values() if "operator" in o)
    assert operators == ["AND", "AND", "OR"]


def test_a_flow_chains_the_steps_to_the_unsafe_action(tmp_path: Path) -> None:
    output = copy_and_or(tmp_path)
    write_report(output, "report")

    objects = {item["id"]: item for item in flow(output, "H-9")["objects"]}

    by_name = {o.get("name", ""): o for o in objects.values()}
    first = by_name["SCN-027 step 1: AI Agent Tool Data Poisoning"]
    assert first["technique_id"] == "AML.T0099"
    assert first["tactic_id"] == "AML.TA0006"
    chain = [first]
    while objects[chain[-1]["effect_refs"][0]]["type"] == "attack-action":
        chain.append(objects[chain[-1]["effect_refs"][0]])
    assert len(chain) == 4
    assert chain[-1]["name"].startswith("SCN-027 unsafe control action: RESP-1 ")
    assert "Violates SC-8" in chain[-1]["description"]
    assert objects[chain[-1]["effect_refs"][0]]["operator"] == "AND"


def test_a_flow_is_the_same_on_every_render(tmp_path: Path) -> None:
    first = copy_and_or(tmp_path, "first")
    second = copy_and_or(tmp_path, "second")

    write_report(first, "report")
    write_report(second, "report")

    for hazard_id in REACHED:
        name = f"report/attack-flow/{hazard_id}.json"
        assert (first / name).read_bytes() == (second / name).read_bytes()
        assert (first / name).read_bytes().endswith(b"}\n")


def test_a_hazard_without_a_scenario_has_no_flow(tmp_path: Path) -> None:
    run = load_run(copy_and_or(tmp_path))
    (empty,) = [g for g in hazard_groups(run) if g.hazard_id == "H-1"]

    with pytest.raises(ValueError, match="H-1 has no published scenario"):
        attack_flow_bundle(run, empty)


# --- process-model gaps --------------------------------------------------------


def linked(documents: dict[str, dict]) -> dict[str, dict]:
    """Give each causal factor a variable: SCN-001 and SCN-027 hold gaps."""
    for scenario_id, document in documents.items():
        for factor in document.get("causal_factors") or []:
            gap = scenario_id in ("SCN-027", "SCN-001")
            factor["process_model_variable"] = {
                "id": None if gap else "PM-1-1",
                "description": f"{scenario_id} needs this variable" if gap else "held",
            }
    return documents


def test_no_gap_list_without_the_field(tmp_path: Path) -> None:
    output = copy_and_or(tmp_path)

    write_report(output, "report")

    assert process_model_gaps(load_run(output), handoff_documents(output)) is None
    assert not (output / "report" / GAPS_FILE).exists()
    assert 'id="gaps"' not in (output / "report" / "index.html").read_text()


def test_the_gap_list_groups_gaps_by_controller(tmp_path: Path) -> None:
    output = copy_and_or(tmp_path)
    documents = linked(handoff_documents(output))

    gaps = process_model_gaps(load_run(output), documents)

    factors = sum(len(d.get("causal_factors") or []) for d in documents.values())
    assert gaps["format"] == "process-model-gaps-v1"
    assert gaps["summary"] == {"factors": factors, "linked": factors - 2, "gaps": 2}
    assert [c["controller"] for c in gaps["controllers"]] == ["CL-1", "RESP-1"]
    assert gaps["controllers"][1]["description"]
    (gap,) = gaps["controllers"][1]["gaps"]
    assert gap == {
        "scenario_id": "SCN-027",
        "source_id": "CA-1-5",
        "belief": None,
        "missing_variable": "SCN-027 needs this variable",
    }


def test_the_gap_list_is_written_and_rendered(tmp_path: Path) -> None:
    output = copy_and_or(tmp_path)
    run = load_run(output)
    gaps = process_model_gaps(run, linked(handoff_documents(output)))
    (output / "report").mkdir()

    path = write_process_model_gaps(output / "report", gaps)
    html, _ = build_report(run, "off", gaps)

    assert yaml.safe_load(path.read_text(encoding="utf-8")) == gaps
    section = section_html(str(html), "gaps")
    assert body_rows(section, "gaps-table") == 2
    assert '<a href="#SCN-027">SCN-027</a>' in section
    assert section == str(gaps_section(gaps))
    assert str(html).index('id="gaps"') < str(html).index('<section id="scenarios"')


def test_a_link_gap_names_both_endpoints_and_the_variable_owner(
    tmp_path: Path,
) -> None:
    output = copy_and_or(tmp_path)
    run = load_run(output)

    gaps = process_model_gaps(run, linked(handoff_documents(output)))

    link, responsibility = gaps["controllers"]
    descriptions = {
        item.resp_id: item.description for item in run.structure.responsibilities
    }
    (cl_1,) = run.structure.coordination_links
    assert list(link) == [
        "controller",
        "kind",
        "description",
        "endpoints",
        "shared_variable",
        "gaps",
    ]
    assert link["kind"] == "coordination_link"
    assert link["description"] == cl_1.description
    assert link["endpoints"] == [
        {"id": "RESP-1", "description": descriptions["RESP-1"]},
        {"id": "RESP-2", "description": descriptions["RESP-2"]},
    ]
    assert link["shared_variable"] == {"id": "PM-2-2", "owner": "RESP-2"}
    assert [gap["scenario_id"] for gap in link["gaps"]] == ["SCN-001"]
    assert responsibility["kind"] == "responsibility"
    assert "endpoints" not in responsibility
    assert "shared_variable" not in responsibility


def test_a_controller_missing_from_the_structure_is_unknown(tmp_path: Path) -> None:
    output = copy_and_or(tmp_path)
    documents = linked(handoff_documents(output))
    documents["SCN-027"]["uca"]["source"] = "RESP-9"

    gaps = process_model_gaps(load_run(output), documents)

    unknown = next(c for c in gaps["controllers"] if c["controller"] == "RESP-9")
    assert unknown["kind"] == "unknown" and unknown["description"] is None
    assert "not in control-structure.yaml" in str(gaps_section(gaps))


def test_a_link_row_names_the_endpoints_and_owner_before_the_link(
    tmp_path: Path,
) -> None:
    output = copy_and_or(tmp_path)
    run = load_run(output)
    gaps = process_model_gaps(run, linked(handoff_documents(output)))

    section = str(gaps_section(gaps))

    start = section.index("Link from <code>RESP-1</code>")
    cell = section[start : section.index("</td>", start)]
    assert cell.index("to <code>RESP-2</code>") < cell.index(
        "shared variable <code>PM-2-2</code> owned by <code>RESP-2</code>."
    )
    link_description = run.structure.coordination_links[0].description
    assert cell.endswith(f". {html.escape(link_description, quote=True)}")
    assert body_rows(section, "gaps-table") == 2


# --- publication ---------------------------------------------------------------


def test_the_published_report_carries_the_view(tmp_path: Path) -> None:
    output = copy_and_or(tmp_path)

    index = _render_report(output)

    assert index is not None and 'id="hazards"' in index.read_text(encoding="utf-8")
    assert (output / "report" / "attack-flow" / "H-9.json").exists()
