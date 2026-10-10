"""policy-coverage.json: which policy risks reached scenarios, and where the rest dropped."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from asago_scenario_generator.data.sssom import SSSOMMapping
from asago_scenario_generator.models.risk_card import MitigationRef, RiskCard
from asago_scenario_generator.report.policy_coverage import (
    SCHEMA_VERSION,
    build_policy_coverage,
    display_name,
    harm_title,
)
from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossAnalysis,
    LossProvenance,
    RiskDisposition,
    SecurityConstraint,
)
from asago_scenario_generator.stpa.system_model.risk_actionability import (
    RiskActionabilityEntry,
    RiskActionabilityRecord,
)


def card(
    risk_id: str, name: str, taxonomy: str = "ibm-risk-atlas", **extra: Any
) -> RiskCard:
    return RiskCard(
        risk_id=risk_id,
        risk_name=name,
        risk_description=f"About {name}.",
        taxonomy=taxonomy,
        confidence=0.9,
        grounding_confidence="high",
        **extra,
    )


def analysis(losses: list[Loss], dispositions: list[RiskDisposition]) -> LossAnalysis:
    anchor = Loss(
        loss_id="L-99", description="Anchor.", provenance=LossProvenance.use_case
    )
    kept = [*losses] or [anchor]
    return LossAnalysis(
        risk_card_losses=[x for x in kept if x.provenance == LossProvenance.risk_card],
        use_case_losses=[x for x in kept if x.provenance != LossProvenance.risk_card],
        hazards=[
            Hazard(hazard_id="H-1", description="h", related_losses=[kept[0].loss_id])
        ],
        security_constraints=[
            SecurityConstraint(constraint_id="SC-1", rule="r", related_hazards=["H-1"])
        ],
        risk_dispositions=dispositions,
    )


def risk_loss(loss_id: str, description: str, cards: list[str]) -> Loss:
    return Loss(
        loss_id=loss_id,
        description=description,
        provenance=LossProvenance.risk_card,
        source_risk_cards=cards,
    )


def decisions(**by_risk: tuple[str, str]) -> RiskActionabilityRecord:
    entries = [
        RiskActionabilityEntry(risk_id=rid, decision=d, reason=why, source="model")
        for rid, (d, why) in by_risk.items()
    ]
    return RiskActionabilityRecord(
        status="completed", call_count=1, counts={}, entries=entries
    )


def build(**overrides: Any) -> dict[str, Any]:
    cards = overrides.pop(
        "cards",
        [
            card("r-a", "Alpha risk"),
            card("r-b", "Beta risk"),
            card("r-c", "Gamma risk"),
            card("r-d", "Delta risk"),
            card("r-e", "Epsilon risk"),
        ],
    )
    values: dict[str, Any] = {
        "cards": cards,
        "sssom": [],
        "actionability": decisions(
            **{
                "r-a": ("actionable", "in scope"),
                "r-b": ("actionable", "in scope"),
                "r-c": ("outside_boundary", "People decide this, not the assistant."),
                "r-d": ("not_applicable", "No images are produced."),
                "r-e": ("actionable", "in scope"),
            }
        ),
        "loss_analysis": analysis(
            [
                risk_loss("L-1", "Customers lose money due to errors", ["r-a"]),
                risk_loss("L-2", "Data leaks via the chat", ["r-b"]),
            ],
            [
                RiskDisposition(risk_ref="r-a", disposition="cited", loss_ids=["L-1"]),
                RiskDisposition(risk_ref="r-b", disposition="cited", loss_ids=["L-2"]),
                RiskDisposition(
                    risk_ref="r-e",
                    disposition="not_applicable",
                    reason="Copyright cannot arise here.",
                ),
            ],
        ),
        "scenario_ids_by_loss": {"L-1": ["SCN-002", "SCN-001"]},
        "source": None,
    }
    values.update(overrides)
    return build_policy_coverage(**values)


def by_id(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {risk["risk_id"]: risk for risk in document["risks"]}


def test_a_cited_risk_with_a_written_scenario_covers_scenarios() -> None:
    risks = by_id(build())

    assert risks["r-a"]["coverage"] == "scenarios"
    assert risks["r-a"]["reason"] is None
    assert risks["r-a"]["loss_ids"] == ["L-1"]


def test_a_cited_risk_whose_loss_has_no_scenario_is_not_reached() -> None:
    risks = by_id(build())

    assert risks["r-b"]["coverage"] == "not_reached"
    assert risks["r-b"]["reason"]["step"] == "scenario_writing"


def test_the_boundary_decision_supplies_the_reason_of_an_outside_risk() -> None:
    risks = by_id(build())

    assert risks["r-c"]["coverage"] == "outside_boundary"
    assert risks["r-c"]["reason"] == {
        "code": "boundary_decision:outside_boundary",
        "text": "People decide this, not the assistant.",
        "step": "boundary_decision",
    }
    assert risks["r-d"]["coverage"] == "not_applicable"
    assert risks["r-d"]["reason"]["step"] == "boundary_decision"


def test_a_loss_analysis_disposition_outranks_the_boundary_decision() -> None:
    risks = by_id(build())

    assert risks["r-e"]["coverage"] == "not_applicable"
    assert risks["r-e"]["reason"] == {
        "code": "loss_analysis:not_applicable",
        "text": "Copyright cannot arise here.",
        "step": "loss_analysis",
    }


def test_a_cited_risk_stays_covered_even_when_the_boundary_called_it_outside() -> None:
    actionability = decisions(**{"r-a": ("outside_boundary", "later cited")})

    risks = by_id(build(actionability=actionability))

    assert risks["r-a"]["coverage"] == "scenarios"


def test_harms_list_the_scenarios_written_for_each_loss_in_order() -> None:
    harms = {harm["loss_id"]: harm for harm in build()["harms"]}

    assert harms["L-1"]["scenario_ids"] == ["SCN-001", "SCN-002"]
    assert harms["L-1"]["risk_ids"] == ["r-a"]
    assert harms["L-2"]["scenario_ids"] == []
    assert harms["L-1"]["provenance"] == "risk_card"


def test_a_use_case_harm_cites_no_risk() -> None:
    use_case = Loss(
        loss_id="L-3",
        description="Merchants lose money.",
        provenance=LossProvenance.use_case,
    )
    document = build(
        loss_analysis=analysis(
            [risk_loss("L-1", "Customers lose money", ["r-a"]), use_case],
            [RiskDisposition(risk_ref="r-a", disposition="cited", loss_ids=["L-1"])],
        ),
        scenario_ids_by_loss={"L-3": ["SCN-009"]},
    )

    harm = {h["loss_id"]: h for h in document["harms"]}["L-3"]

    assert harm["risk_ids"] == []
    assert harm["scenario_ids"] == ["SCN-009"]
    assert harm["provenance"] == "use_case"


def test_risks_that_share_a_normalized_name_merge_and_keep_every_id_and_source() -> (
    None
):
    cards = [
        card("credo-risk-021", "False or misleading information", "credo-ucf"),
        card("mit-3.1", "False  or Misleading Information ", "mit-ai-risk-repository"),
        card("r-z", "Another risk"),
    ]
    document = build(
        cards=cards,
        actionability=decisions(),
        loss_analysis=analysis(
            [risk_loss("L-1", "Wrong answers", ["mit-3.1"])],
            [
                RiskDisposition(
                    risk_ref="mit-3.1", disposition="cited", loss_ids=["L-1"]
                )
            ],
        ),
        scenario_ids_by_loss={"L-1": ["SCN-001"]},
    )

    merged = by_id(document)["credo-risk-021"]

    assert len(document["risks"]) == 2
    assert merged["merged_ids"] == ["credo-risk-021", "mit-3.1"]
    assert merged["sources"] == ["credo-ucf", "mit-ai-risk-repository"]
    assert merged["coverage"] == "scenarios"
    assert merged["loss_ids"] == ["L-1"]
    assert document["policy"]["entry_count"] == 3
    assert document["policy"]["risk_count"] == 2
    harm = document["harms"][0]
    assert harm["risk_ids"] == ["credo-risk-021"]


def test_a_merged_risk_takes_the_best_coverage_and_its_reason() -> None:
    cards = [card("one", "Same name", "a"), card("two", "Same name", "b")]
    document = build(
        cards=cards,
        actionability=decisions(
            one=("outside_boundary", "outside reason"),
            two=("not_applicable", "na reason"),
        ),
        loss_analysis=analysis([], []),
    )

    merged = document["risks"][0]

    assert merged["coverage"] == "not_applicable"
    assert merged["reason"]["text"] == "na reason"


def test_display_name_drops_a_trailing_citation_only() -> None:
    assert (
        display_name("Overreliance (Slattery et al., 2024; IBM, 2024)")
        == "Overreliance"
    )
    assert display_name("Misuse (of tools)") == "Misuse (of tools)"


def test_tags_come_from_nist_and_owasp_mappings_only() -> None:
    sssom = [
        SSSOMMapping(
            subject_id="r-a",
            subject_source="ibm",
            predicate_id="skos:relatedMatch",
            object_id="llm092025-misinformation",
            object_source="owasp-llm-2.0",
            mapping_justification="x",
        ),
        SSSOMMapping(
            subject_id="r-a",
            subject_source="ibm",
            predicate_id="skos:relatedMatch",
            object_id="nist-confabulation",
            object_source="nist-ai-rmf",
            mapping_justification="x",
        ),
        SSSOMMapping(
            subject_id="r-a",
            subject_source="ibm",
            predicate_id="skos:relatedMatch",
            object_id="ail-hate",
            object_source="ailuminate-v1.0",
            mapping_justification="x",
        ),
    ]

    tags = by_id(build(sssom=sssom))["r-a"]["tags"]

    assert tags == [
        {
            "scheme": "nist-ai-rmf",
            "id": "nist-confabulation",
            "label": "NIST Confabulation",
        },
        {
            "scheme": "owasp-llm-2.0",
            "id": "llm092025-misinformation",
            "label": "OWASP LLM09 Misinformation",
        },
    ]


def test_mitigations_keep_their_ids_sources_and_text() -> None:
    cards = [
        card(
            "r-a",
            "Alpha risk",
            mitigations=[
                MitigationRef(
                    mitigation_id="aiuc1-a002", description="Do X.", source="aiuc1"
                )
            ],
        )
    ]

    risk = by_id(build(cards=cards))["r-a"]

    assert risk["mitigations"] == [
        {"id": "aiuc1-a002", "source": "aiuc1", "text": "Do X."}
    ]


def test_the_policy_block_counts_entries_and_names_the_document() -> None:
    document = build(
        source={
            "risk_extraction": "extraction.json",
            "digest": "ab" * 32,
            "documents": ["p.pdf"],
        }
    )

    assert document["schema_version"] == SCHEMA_VERSION == "policy-coverage-v1"
    assert document["rule"] == "loss-source-risk-cards"
    assert document["policy"] == {
        "risk_extraction": "extraction.json",
        "digest": "ab" * 32,
        "documents": ["p.pdf"],
        "entry_count": 5,
        "risk_count": 5,
    }


def test_harm_title_is_the_first_clause_of_the_description() -> None:
    assert (
        harm_title("Klarna suffers penalties due to wrong answers.")
        == "Klarna suffers penalties"
    )
    assert harm_title("Plain sentence.") == "Plain sentence"


def test_the_document_is_the_same_on_every_build() -> None:
    assert build() == build()


CONTRACT = (
    Path(__file__).resolve().parents[1]
    / "data/contracts/policy-coverage/policy-coverage-v1"
)


def validator() -> Draft202012Validator:
    return Draft202012Validator(json.loads((CONTRACT / "schema.json").read_text()))


def test_a_built_document_validates_against_the_contract_schema() -> None:
    document = build(
        source={"risk_extraction": "x.json", "digest": "a" * 64, "documents": ["p.pdf"]}
    )

    assert list(validator().iter_errors(document)) == []


def test_a_document_without_a_source_validates_with_null_provenance() -> None:
    assert list(validator().iter_errors(build())) == []


def test_the_contract_example_validates() -> None:
    example = json.loads((CONTRACT / "valid/minimal.json").read_text())

    assert list(validator().iter_errors(example)) == []


def test_a_risk_without_scenarios_must_carry_a_reason() -> None:
    document = build()
    by_id(document)["r-c"]["reason"] = None

    assert list(validator().iter_errors(document)) != []
