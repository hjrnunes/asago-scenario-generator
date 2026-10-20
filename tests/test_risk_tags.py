"""Risk tags shared across a name-merged group, and the handoff's OWASP references.

Policy coverage merges risks that several taxonomies list under one name; the
scenario handoff reads the same tags, so the two cannot disagree.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from asago_scenario_generator.pipeline import synthesis
from asago_scenario_generator.pipeline.synthesis_defaults import _default_scenarios
from asago_scenario_generator.report.risk_tags import merged_risk_tags
from asago_scenario_generator.stpa.models.loss_analysis import RiskDisposition
from asago_scenario_generator.stpa.scenario_prod.handoff import (
    HandoffTaxonomyInputs,
    HandoffTaxonomyRef,
)
from tests.helpers.stpa_builders import make_loss_analysis
from tests.helpers.synthesis import _FakeAdapters, _runtime
from tests.helpers.synthesis_fixture import final_ica_result, synthesis_inputs
from tests.test_policy_coverage import analysis, build, by_id, card, mapping, risk_loss

EXCESSIVE_AGENCY = "llm032026-excessive-agency"
TOOL_MISUSE = "asi02-tool-misuse-and-exploitation"


def _row(subject_id: str, object_id: str, object_source: str):
    return mapping(object_id, object_source).model_copy(
        update={"subject_id": subject_id}
    )


def test_merged_siblings_share_their_tags() -> None:
    cards = [card("one", "Same name (IBM, 2024)", "a"), card("two", "same  NAME", "b")]
    sssom = [_row("one", EXCESSIVE_AGENCY, "owasp-llm-2026")]

    tags = merged_risk_tags(cards, sssom)

    expected = (
        {
            "scheme": "owasp-llm-2026",
            "id": EXCESSIVE_AGENCY,
            "label": "OWASP LLM03:2026 Excessive Agency",
        },
    )
    assert tags == {"one": expected, "two": expected}


def test_policy_coverage_tags_equal_merged_risk_tags() -> None:
    cards = [
        card("credo-risk-021", "False or misleading information", "credo-ucf"),
        card("mit-3.1", "False  or Misleading Information ", "mit-ai-risk-repository"),
        card("r-a", "Alpha risk"),
        card("r-z", "Another risk"),
    ]
    sssom = [
        _row("mit-3.1", "llm072026-misinformation", "owasp-llm-2026"),
        _row("credo-risk-021", "nist-confabulation", "nist-ai-rmf"),
        _row("mit-3.1", "nist-confabulation", "nist-ai-rmf"),
        _row("r-a", TOOL_MISUSE, "owasp-asi-2026"),
    ]
    document = build(
        cards=cards,
        sssom=sssom,
        loss_analysis=analysis(
            [risk_loss("L-1", "Wrong answers", ["mit-3.1"])],
            [
                RiskDisposition(
                    risk_ref="mit-3.1", disposition="cited", loss_ids=["L-1"]
                )
            ],
        ),
    )

    merged = merged_risk_tags(cards, sssom)

    assert len(document["risks"]) == 3
    for risk in document["risks"]:
        for risk_id in risk["merged_ids"]:
            assert list(merged[risk_id]) == risk["tags"]
    assert len(by_id(document)["credo-risk-021"]["tags"]) == 2
    assert merged["r-z"] == ()


def test_a_no_match_row_gives_no_tag() -> None:
    cards = [card("one", "One")]
    denied = _row("one", EXCESSIVE_AGENCY, "owasp-llm-2026").model_copy(
        update={"predicate_id": "skos:noMatch"}
    )
    no_term = _row("one", "sssom:NoTermFound", "owasp-llm-2026").model_copy(
        update={"predicate_id": "skos:noMatch"}
    )

    assert merged_risk_tags(cards, [denied, no_term]) == {"one": ()}


@pytest.mark.parametrize(
    "source",
    [
        "OWASP-LLM-2.0",
        "owasp_llm_2025",
        "https://genai.owasp.org/llm-top-10/2025",
        "OWASP-ASI-2025",
    ],
)
def test_a_differently_spelled_stale_owasp_source_is_refused(source: str) -> None:
    with pytest.raises(ValueError, match="not a current scheme") as caught:
        merged_risk_tags([card("one", "One")], [_row("one", "x", source)])

    assert source in str(caught.value)


def test_an_unknown_object_id_names_its_risk() -> None:
    with pytest.raises(ValueError, match="'nist-confabulations'") as caught:
        merged_risk_tags(
            [card("one", "One")],
            [_row("other-risk", "nist-confabulations", "nist-ai-rmf")],
        )

    assert "'other-risk'" in str(caught.value)


def _sssom_file(path: Path, rows: list[tuple[str, str, str]]) -> Path:
    header = (
        "subject_id\tsubject_source\tpredicate_id\tobject_id\tobject_source\t"
        "mapping_justification\n"
    )
    body = "".join(
        f"{subject}\tibm\tskos:relatedMatch\t{object_id}\t{source}\tx\n"
        for subject, object_id, source in rows
    )
    path.write_text(header + body, encoding="utf-8")
    return path


def test_default_scenarios_hand_sp3_each_losss_owasp_references(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, object] = {}
    monkeypatch.setattr(
        "asago_scenario_generator.stpa.threat_enum.catalog_enrichment.enrich_threats",
        lambda *a, **k: SimpleNamespace(structural_threats=[]),
    )
    monkeypatch.setattr(
        "asago_scenario_generator.stpa.scenario_prod.run.run_sp3",
        lambda **kwargs: captured.update(kwargs) or "sp3",
    )
    sssom = _sssom_file(
        tmp_path / "risks.sssom.tsv",
        [
            ("r-1", EXCESSIVE_AGENCY, "owasp-llm-2026"),
            ("r-1", "nist-confabulation", "nist-ai-rmf"),
            ("r-2", TOOL_MISUSE, "owasp-asi-2026"),
        ],
    )
    loss_analysis = make_loss_analysis()
    first = loss_analysis.risk_card_losses[0].model_copy(
        update={"source_risk_cards": ["r-1", "r-2"]}
    )
    unmapped = first.model_copy(update={"loss_id": "L-2", "source_risk_cards": ["r-3"]})
    loss_analysis = loss_analysis.model_copy(
        update={"risk_card_losses": [first, unmapped]}
    )
    inputs = synthesis.SynthesisInputs(
        use_case="u",
        output_dir=tmp_path,
        risk_cards=(
            {"risk_id": "r-1", "risk_name": "One"},
            {"risk_id": "r-2", "risk_name": "Two"},
            {"risk_id": "r-3", "risk_name": "Three"},
        ),
        sssom_path=sssom,
    )

    _default_scenarios(
        ica_enumeration=final_ica_result(),
        control_structure=SimpleNamespace(),
        loss_analysis=loss_analysis,
        inputs=inputs,
        capability_profile=None,
        output_dir=tmp_path,
        model_runtime=_runtime(object()),
    )

    taxonomy = captured["handoff_taxonomy"]
    assert isinstance(taxonomy, HandoffTaxonomyInputs)
    assert taxonomy.atlas_release == "2026.05"
    assert taxonomy.references_by_loss[first.loss_id] == (
        HandoffTaxonomyRef(
            scheme="owasp-asi",
            edition="2026",
            id="ASI02",
            name="Tool Misuse & Exploitation",
        ),
        HandoffTaxonomyRef(
            scheme="owasp-llm", edition="2026", id="LLM03", name="Excessive Agency"
        ),
    )
    assert taxonomy.references_by_loss["L-2"] == ()


def test_a_bad_row_for_another_targets_risk_stops_the_run_before_any_model_call(
    tmp_path: Path,
) -> None:
    sssom = _sssom_file(
        tmp_path / "shared.sssom.tsv",
        [
            ("risk-a", EXCESSIVE_AGENCY, "owasp-llm-2026"),
            ("other-target-risk", "nist-confabulations", "nist-ai-rmf"),
        ],
    )
    adapters = _FakeAdapters(calls=[])

    with pytest.raises(ValueError) as caught:
        synthesis.run_synthesis(
            synthesis_inputs(tmp_path / "run", sssom_path=sssom), adapters
        )

    assert adapters.calls == []
    assert not (tmp_path / "run" / "provider-calls.jsonl").exists()
    message = str(caught.value)
    assert f"{sssom}:3:" in message
    assert "'other-target-risk'" in message
    assert "'nist-confabulations'" in message


def test_the_handoff_references_reuse_the_rows_checked_at_load(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, object] = {}
    monkeypatch.setattr(
        "asago_scenario_generator.stpa.threat_enum.catalog_enrichment.enrich_threats",
        lambda *a, **k: SimpleNamespace(structural_threats=[]),
    )
    monkeypatch.setattr(
        "asago_scenario_generator.stpa.scenario_prod.run.run_sp3",
        lambda **kwargs: captured.update(kwargs) or "sp3",
    )
    sssom = _sssom_file(
        tmp_path / "risks.sssom.tsv", [("r-1", EXCESSIVE_AGENCY, "owasp-llm-2026")]
    )
    inputs = synthesis.SynthesisInputs(
        use_case="u",
        output_dir=tmp_path,
        risk_cards=({"risk_id": "r-1", "risk_name": "One"},),
        sssom_path=sssom,
    )
    sssom.unlink()
    loss = (
        make_loss_analysis()
        .risk_card_losses[0]
        .model_copy(update={"source_risk_cards": ["r-1"]})
    )

    _default_scenarios(
        ica_enumeration=final_ica_result(),
        control_structure=SimpleNamespace(),
        loss_analysis=make_loss_analysis().model_copy(
            update={"risk_card_losses": [loss]}
        ),
        inputs=inputs,
        capability_profile=None,
        output_dir=tmp_path,
        model_runtime=_runtime(object()),
    )

    taxonomy = captured["handoff_taxonomy"]
    assert [ref.id for ref in taxonomy.references_by_loss[loss.loss_id]] == ["LLM03"]
