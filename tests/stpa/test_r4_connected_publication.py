"""R4 regressions for the normal semantic presentation seam."""

from __future__ import annotations

import re

from asago_scenario_generator.stpa.models.scenario_spec import (
    Adversary,
    AdversaryKind,
    AttackerBDI,
    DefenderBelief,
    DefenderDesire,
    DefenderIntention,
)
from asago_scenario_generator.stpa.models.scenario_context import DescribedElement
from asago_scenario_generator.stpa.scenario_prod.presentation import (
    render_scenario_summary,
)
from asago_scenario_generator.stpa.scenario_prod.validators import (
    validate_tree_factor_evidence_coverage,
)
from tests.helpers.stpa_producer_seams import _spec


def test_normal_publication_connects_selected_criterion_and_exact_bdi_sources():
    spec = _spec()

    narrative, tree, gherkin = render_scenario_summary(spec)

    criterion = spec.unsafe_outcome_semantic_proposition
    assert criterion is not None
    assert criterion in narrative
    assert criterion in str(tree)
    assert criterion in gherkin.to_feature_text()
    for text in ("belief", "desire", "intent", "Feedback is delayed."):
        assert text in narrative
    for source_id in ("PM-1-1", "FB-1-1", "CA-1-1", "H-1", "SC-1", "L-1"):
        assert source_id in narrative
        assert source_id in str(tree)
    factor_node = tree["branches"][1]["children"][0]
    assert factor_node["evidence_status"] == "structural_failure"
    assert "source_uncertainty" not in tree
    assert gherkin.then_expected == ["Then the system should preserve SC-1: Constraint"]


def test_relevant_bdi_mutation_changes_publication_without_changing_lineage():
    original = _spec()
    changed = original.model_copy(
        update={
            "defender_bdi": original.defender_bdi.model_copy(
                update={
                    "beliefs": [
                        DefenderBelief(
                            pm_id="PM-1-1",
                            content="Changed state belief",
                            vulnerability="Changed vulnerability",
                        )
                    ]
                }
            )
        }
    )

    original_narrative, original_tree, original_gherkin = render_scenario_summary(
        original
    )
    changed_narrative, changed_tree, changed_gherkin = render_scenario_summary(changed)

    assert changed_narrative != original_narrative
    assert "Changed state belief" in changed_narrative
    assert "Changed vulnerability" in changed_narrative
    assert changed_tree["lineage"] == original_tree["lineage"]
    assert changed_gherkin.scenario == original_gherkin.scenario


def test_selected_criterion_mutation_reaches_each_normal_representation():
    original = _spec()
    changed = original.model_copy(
        update={
            "unsafe_outcome_semantic_proposition": (
                "The response exposes the selected protected record."
            )
        }
    )

    original_rendered = render_scenario_summary(original)
    changed_rendered = render_scenario_summary(changed)

    for representation in changed_rendered:
        assert "The response exposes the selected protected record." in str(
            representation
        )
    assert all(
        "The response exposes the selected protected record." not in str(representation)
        for representation in original_rendered
    )


def test_unrelated_catalog_metadata_does_not_change_semantic_publication():
    original = _spec()
    changed = original.model_copy(
        update={
            "catalog_context": [
                {
                    "catalog": "ATLAS",
                    "id": "AML.T9999",
                    "name": "Unrelated bookkeeping label",
                    "confidence": "low",
                }
            ]
        }
    )

    assert render_scenario_summary(original) == render_scenario_summary(changed)


def test_unsupported_factor_relation_remains_explicitly_flat():
    _narrative, tree, _gherkin = render_scenario_summary(_spec())

    assert tree["relation"] == "flat"
    assert tree["relation_evidence"] == "typed_relation_not_supplied"
    assert "AND" not in str(tree)
    assert "OR" not in str(tree)


def test_no_context_legacy_spec_keeps_fallback_lineage_and_steps():
    spec = _spec().model_copy(
        update={
            "scenario_context": None,
            "unsafe_outcome_semantic_proposition": None,
        }
    )

    narrative, tree, gherkin = render_scenario_summary(spec)

    assert "Loss scenario" in narrative
    assert tree["lineage"]["control_action_id"] == "CA-1-1"
    assert tree["lineage"]["loss_ids"] == []
    assert gherkin.given == [
        "Given the proposed process-model hypothesis references PM-1-1"
    ]


def test_multiple_grounded_defender_items_keep_exact_indexes_and_constraints():
    spec = _spec()
    defender = spec.defender_bdi.model_copy(
        update={
            "beliefs": [
                *spec.defender_bdi.beliefs,
                DefenderBelief(pm_id="PM-1-2", content="Schema", vulnerability=""),
            ],
            "desires": [
                DefenderDesire(
                    resp_id="RESP-1",
                    content="Controller",
                    constraint_id="SC-1",
                ),
                DefenderDesire(resp_id="RESP-1", content="Review"),
            ],
            "intentions": [
                *spec.defender_bdi.intentions,
                DefenderIntention(ca_id="CA-1-2", content="Validate"),
            ],
        }
    )
    spec = spec.model_copy(update={"defender_bdi": defender})

    _narrative, tree, _gherkin = render_scenario_summary(spec)

    children = tree["branches"][0]["children"]
    assert [node["node_id"] for node in children[:5]] == [
        "AT-DB-1",
        "AT-DB-2",
        "AT-DD-1",
        "AT-DD-2",
        "AT-DI-1",
    ]
    assert children[2]["source_ids"] == ["RESP-1", "SC-1"]
    assert children[5]["source_id"] == "CA-1-2"
    assert "source: RESP-1, SC-1" in _narrative


def test_synthetic_lineage_node_ids_do_not_look_like_lineage_citations():
    """Presentation indexes must not become undeclared SC/H/L citations."""
    _narrative, tree, _gherkin = render_scenario_summary(_spec())
    node_ids = {
        node["node_id"]
        for branch in tree["branches"]
        for node in branch["children"]
        if "node_id" in node
    }

    assert "AT-CONSTRAINT-1" in node_ids
    assert "AT-HAZARD-1" in node_ids
    assert "AT-LOSS-1" in node_ids
    assert not any(re.search(r"\b(?:SC|H|L)-\d+\b", node_id) for node_id in node_ids)


def test_unsupported_structural_text_is_sanitized_without_tree_evidence():
    spec = _spec().model_copy(
        update={
            "unsafe_outcome_semantic_proposition": (
                "The response fails through unsupported CA-9-9 evidence."
            )
        }
    )

    _narrative, tree, _gherkin = render_scenario_summary(spec)

    assert "CA-9-9" not in tree["criterion"]
    assert tree["source_uncertainty"]


def test_tree_allows_a_unique_responsibility_source_in_actor_evidence():
    spec = _spec()
    context = spec.scenario_context
    assert context is not None
    path = context.target_control_path.model_copy(
        update={
            "responsibility": DescribedElement(
                element_id="RESP-9",
                description="Additional responsible controller",
            )
        }
    )
    context = context.model_copy(update={"target_control_path": path})
    attacker = spec.attacker_bdi.model_copy(
        update={"beliefs": ["The actor knows RESP-9"]}
    )
    spec = spec.model_copy(
        update={"scenario_context": context, "attacker_bdi": attacker}
    )

    _narrative, tree, _gherkin = render_scenario_summary(spec)

    actor_belief = tree["branches"][1]["children"][-3]
    assert "RESP-9" in actor_belief["label"]


def test_grounded_secondary_defender_intention_is_accepted_as_tree_evidence():
    spec = _spec()
    defender = spec.defender_bdi.model_copy(
        update={
            "intentions": [
                *spec.defender_bdi.intentions,
                DefenderIntention(
                    ca_id="CA-1-2",
                    content="Validate the selected parameters.",
                ),
            ]
        }
    )
    spec = spec.model_copy(update={"defender_bdi": defender})

    _narrative, tree, _gherkin = render_scenario_summary(spec)

    validation = validate_tree_factor_evidence_coverage(tree, spec)
    assert validation.passed, validation.errors
    assert "CA-1-2" in str(tree)


def test_functional_publication_keeps_structural_causality_without_attacker():
    spec = _spec().model_copy(
        update={
            "adversary": Adversary(
                kind=AdversaryKind.none,
                gain="No one gains from the unsafe outcome.",
                reaches_target_via=None,
            ),
            "attacker_bdi": AttackerBDI(beliefs=[], desires=[], intentions=[]),
        }
    )

    narrative, tree, gherkin = render_scenario_summary(spec)
    rendered = "\n".join((narrative, str(tree), gherkin.to_feature_text())).lower()

    assert "functional" in rendered
    assert "defender" in rendered
    assert "attacker" not in rendered
    assert "pm-1-1" in rendered
    assert "ca-1-1" in rendered
    assert "h-1" in rendered
    assert "l-1" in rendered
