"""The scenario as written: narrative, attack tree, and Gherkin panels."""

from __future__ import annotations

from pathlib import Path

from asago_scenario_generator.report.run_data import load_run
from asago_scenario_generator.report.scenario_panels import (
    panel_stats,
    scenario_panels,
)
from tests.helpers.generate_report_fixture import copy_run, edit_yaml


def panels(output: Path, scenario: str) -> dict:
    run = load_run(output)
    return {p.key: p for p in scenario_panels(run, scenario)}


def test_every_scenario_has_three_panels_in_a_fixed_order(tmp_path: Path) -> None:
    run = load_run(copy_run(tmp_path))

    for scenario in run.scenarios:
        assert [p.key for p in scenario_panels(run, scenario)] == [
            "narrative",
            "tree",
            "gherkin",
        ]


def test_an_attack_narrative_previews_actor_channel_and_turns(tmp_path: Path) -> None:
    p = panels(copy_run(tmp_path), "SCN-001")["narrative"]

    assert (
        p.preview == "a third party acting through content · indirect channel · 2 turns"
    )


def test_narrative_turns_become_a_numbered_list(tmp_path: Path) -> None:
    body = str(panels(copy_run(tmp_path), "SCN-001")["narrative"].body)

    assert "<ol><li>The benign user asks the agent to read the planted item" in body
    assert "<dt>Actor</dt>" in body


def test_an_everyday_check_previews_sourced_claims_and_the_factor(
    tmp_path: Path,
) -> None:
    p = panels(copy_run(tmp_path), "SCN-004")["narrative"]

    assert p.preview.startswith("18 sourced claims · factor: ")


def test_an_unselected_vulnerability_reads_as_not_a_causal_factor(
    tmp_path: Path,
) -> None:
    body = str(panels(copy_run(tmp_path), "SCN-004")["narrative"].body)

    assert "not a causal factor here" in body
    assert "Not selected as a causal factor" not in body
    assert "fails to verify if the target order" in body


def test_the_default_authority_is_stated_once_not_on_every_claim(
    tmp_path: Path,
) -> None:
    body = str(panels(copy_run(tmp_path), "SCN-004")["narrative"].body)

    assert body.count("Claims without an authority note are proposed hypotheses.") == 1
    assert "authority proposed_hypothesis" not in body


def test_a_line_the_parser_does_not_know_renders_as_plain_text(tmp_path: Path) -> None:
    output = copy_run(tmp_path)
    edit_yaml(
        output / "scenarios" / "SCN-001.yaml",
        lambda y: y.update(narrative=y["narrative"] + "\nA surprising line <b>x</b>"),
    )

    body = str(panels(output, "SCN-001")["narrative"].body)

    assert "A surprising line &lt;b&gt;x&lt;/b&gt;" in body


def test_the_tree_groups_nodes_by_category_and_names_the_leaf(tmp_path: Path) -> None:
    p = panels(copy_run(tmp_path), "SCN-001")["tree"]

    assert " nodes in 2 branches" in p.preview
    assert "AT-CONTROLLER" not in p.preview
    assert "Belief" in str(p.body)
    assert "leaf" in str(p.body)
    assert "Relations are flat" in str(p.body)


def test_a_node_that_repeats_another_nodes_text_is_dimmed_and_names_it(
    tmp_path: Path,
) -> None:
    output = copy_run(tmp_path)

    def repeat(y: dict) -> None:
        children = y["attack_tree"]["branches"][0]["children"]
        children[1]["label"] = children[0]["label"]

    edit_yaml(output / "scenarios" / "SCN-001.yaml", repeat)

    body = str(panels(output, "SCN-001")["tree"].body)

    assert "same text as AT-DB-1" in body


def test_a_non_default_authority_and_a_source_uncertainty_note_are_shown(
    tmp_path: Path,
) -> None:
    output = copy_run(tmp_path)

    def mark(y: dict) -> None:
        node = y["attack_tree"]["branches"][0]["children"][0]
        node["authority"] = "reviewed_fact"
        node["source_uncertainty"] = "the source was paraphrased"

    edit_yaml(output / "scenarios" / "SCN-001.yaml", mark)

    body = str(panels(output, "SCN-001")["tree"].body)

    assert "authority reviewed_fact" in body
    assert "the source was paraphrased" in body


def test_gherkin_comes_from_the_feature_file_and_says_it_agrees(tmp_path: Path) -> None:
    p = panels(copy_run(tmp_path), "SCN-004")["gherkin"]

    assert "SCN-004.feature" in str(p.body)
    assert "The two agree." in str(p.body)
    assert '<span class="gk">Feature:</span>' in str(p.body)
    assert "differs" not in p.preview


def test_a_feature_file_that_differs_from_the_yaml_block_is_flagged(
    tmp_path: Path,
) -> None:
    output = copy_run(tmp_path)
    path = output / "scenarios" / "SCN-004.feature"
    path.write_text(path.read_text().replace("Then ", "Then also ", 1))

    p = panels(output, "SCN-004")["gherkin"]

    assert "differs from YAML" in p.preview
    assert "It differs from the YAML block." in str(p.body)


def test_without_a_feature_file_the_yaml_block_is_rendered(tmp_path: Path) -> None:
    output = copy_run(tmp_path)
    (output / "scenarios" / "SCN-004.feature").unlink()

    p = panels(output, "SCN-004")["gherkin"]

    assert "No feature file; rendered from the YAML" in str(p.body)
    assert "Scenario:" in str(p.body)


def test_the_stats_count_flat_trees_single_leaf_trees_and_matching_features(
    tmp_path: Path,
) -> None:
    stats = panel_stats(load_run(copy_run(tmp_path)))

    assert (stats.trees, stats.flat, stats.single_leaf) == (8, 8, 6)
    assert (stats.features, stats.matching) == (8, 8)
