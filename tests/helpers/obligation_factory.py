"""Factories for valid typed taxonomy-obligation planner inputs.

The obligation tests intentionally enter through the public typed planner
contract.  Candidate records are derived from the real projection fixture;
the helper never invents candidate IDs, resource bindings, or persisted rows.
"""

from __future__ import annotations

from typing import Any

from asago_scenario_generator.models.attack_pattern_chain import AttackPattern
from asago_scenario_generator.models.attack_pattern_contracts import TaxonomyPin
from asago_scenario_generator.models.risk_card import RiskCard
from asago_scenario_generator.pipeline.obligation_contracts import (
    QualificationFactsInput,
    TaxonomyObligationInputs,
    compute_mapping_bundle_digest,
)
from asago_scenario_generator.pipeline.obligation_planner import (
    plan_taxonomy_obligations,
)
from asago_scenario_generator.pipeline.projection_contracts import ProjectionBudget

from tests.helpers.projection_factory import (
    get_projected_candidate,
    get_test_raw_pattern,
    get_test_snapshot,
)


def make_inputs(
    *,
    risk_ids: tuple[str, ...] = ("risk-a",),
    pattern: AttackPattern | None = None,
    capability_snapshot: Any | None = None,
    include_mapping: bool = True,
    mappings: list[dict[str, Any]] | None = None,
    catalog_pins: dict[str, Any] | None = None,
    mapping_pins: dict[str, Any] | None = None,
) -> TaxonomyObligationInputs:
    """Build complete authoritative planner input from shared test fixtures."""
    pattern = pattern or AttackPattern.model_validate(get_test_raw_pattern())
    snapshot = capability_snapshot or get_test_snapshot()
    candidate = get_projected_candidate()

    if mappings is None:
        mappings = (
            [
                {
                    "source_id": risk_id,
                    "target_id": pattern.id,
                    "relation": "exact_match",
                    "confidence": 1.0,
                }
                for risk_id in risk_ids
            ]
            if include_mapping
            else []
        )

    atlas_context = pattern.canonical_chain.taxonomy_context.atlas
    default_catalog_pins = {
        "atlas": TaxonomyPin(
            release=atlas_context.release,
            digest=candidate.projection.catalog_pin,
        )
    }
    default_mapping_pins = {
        "sssom": TaxonomyPin(
            release=atlas_context.release,
            digest=pattern.canonical_chain.taxonomy_context.mapping_set_digest,
        ),
        "obligation_edges": TaxonomyPin(
            release="obligation-mapping-bundle-v1",
            digest=compute_mapping_bundle_digest(mappings, []),
        ),
    }
    qualification_facts = QualificationFactsInput.model_validate(list(snapshot.facts))
    payload: dict[str, Any] = {
        "risk_cards": [
            RiskCard(
                risk_id=risk_id,
                risk_name=f"Risk {risk_id}",
                risk_description="A reviewed risk used by planner tests.",
                taxonomy="ibm-risk-atlas",
                confidence=1.0,
                grounding_confidence="high",
            )
            for risk_id in risk_ids
        ],
        "capability_snapshot": snapshot,
        "attack_pattern_catalog": [pattern],
        "cross_taxonomy_mappings": mappings,
        "sssom_mappings": [],
        "catalog_pins": catalog_pins or default_catalog_pins,
        "mapping_pins": mapping_pins or default_mapping_pins,
        "qualification_facts": qualification_facts,
        "projection_budget": ProjectionBudget(
            max_candidates=100,
            max_derivation_work=4096,
        ),
        "compatibility_policy": {"allow_legacy_keyword_matches": False},
    }
    return TaxonomyObligationInputs.model_validate(payload)


def make_plan(**kwargs: Any) -> Any:
    """Plan complete typed inputs through the public planner seam."""
    return plan_taxonomy_obligations(make_inputs(**kwargs))
