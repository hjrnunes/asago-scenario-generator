"""Shared offline builders for typed obligation-plan acceptance fixtures."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from asago_scenario_generator.pipeline.obligation_contracts import (
    compute_mapping_bundle_digest,
)


def typed_authoritative_fixture() -> tuple[Any, dict[str, Any], Any]:
    """Return the authoritative projection fixture used by contract tests."""
    from tests.helpers.projection_factory import (
        get_projected_candidate,
        get_test_raw_pattern,
        get_test_snapshot,
    )

    return get_projected_candidate(), get_test_raw_pattern(), get_test_snapshot()


def jsonable(value: Any) -> Any:
    """Convert typed fixture values to JSON for the file adapter."""
    if hasattr(value, "model_dump"):
        return jsonable(value.model_dump(mode="json"))
    if isinstance(value, dict):
        return {key: jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [jsonable(item) for item in value]
    return value


def typed_pin_payload(
    raw_pattern: dict[str, Any] | None = None,
    snapshot: Any | None = None,
    cross_taxonomy_mappings: Any = (),
    sssom_mappings: Any = (),
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Capture catalog and mapping pins from an authoritative fixture."""
    candidate, default_pattern, default_snapshot = typed_authoritative_fixture()
    raw_pattern = raw_pattern or default_pattern
    snapshot = snapshot or default_snapshot
    context = raw_pattern["canonical_chain"]["taxonomy_context"]
    if raw_pattern == default_pattern and snapshot == default_snapshot:
        catalog_digest = candidate.projection.catalog_pin
    else:
        from asago_scenario_generator.pipeline.projection import (
            ProjectionBudget,
            project_authoritative_candidates,
        )
        from asago_scenario_generator.pipeline.projection_qualification import (
            compute_authoritative_catalog_pin,
        )
        from tests.helpers.projection_factory import get_test_resolver

        resolver = get_test_resolver()
        catalog_digest = compute_authoritative_catalog_pin([raw_pattern], resolver)
        batch = project_authoritative_candidates(
            [raw_pattern],
            resolver,
            snapshot,
            budget=ProjectionBudget(max_candidates=100),
        )
        if batch.candidates:
            catalog_digest = batch.candidates[0].projection.catalog_pin
    return (
        {
            "atlas": {
                "release": context["atlas"]["release"],
                "digest": catalog_digest,
            }
        },
        {
            "sssom": {
                "release": context["atlas"]["release"],
                "digest": context["mapping_set_digest"],
            },
            "obligation_edges": {
                "release": "obligation-mapping-bundle-v1",
                "digest": compute_mapping_bundle_digest(
                    cross_taxonomy_mappings, sssom_mappings
                ),
            },
        },
    )


def typed_expected_candidate() -> Any:
    """Return the candidate derived from the authoritative fixture."""
    return typed_authoritative_fixture()[0]


def typed_default_qualification(snapshot: Any | None = None) -> dict[str, Any]:
    """Build qualification facts with the shared content-integrity digest."""
    if snapshot is None:
        _candidate, _raw_pattern, snapshot = typed_authoritative_fixture()
    facts = [item.model_dump(mode="json") for item in snapshot.facts]
    from asago_scenario_generator.pipeline.obligation_contracts import (
        QualificationFactsInput,
    )

    return QualificationFactsInput(facts=facts).model_dump(mode="json")


def typed_risk_card(risk_id: str) -> dict[str, Any]:
    """Return a reviewed risk-card fixture for the typed planner seam."""
    return {
        "risk_id": risk_id,
        "risk_name": f"Risk {risk_id}",
        "risk_description": "A reviewed risk used by acceptance contract tests.",
        "taxonomy": "ibm-risk-atlas",
        "confidence": 1.0,
        "grounding_confidence": "high",
        "evidence": [],
        "mitigations": [],
    }


def typed_pattern_variant(pattern_id: str) -> dict[str, Any]:
    """Return a repinned full authoritative pattern for identity tests."""
    from asago_scenario_generator.models.attack_pattern import (
        compute_chain_semantic_digest,
    )

    _candidate, raw_pattern, _snapshot = typed_authoritative_fixture()
    variant = deepcopy(raw_pattern)
    variant["id"] = pattern_id
    variant["canonical_chain"]["pattern_id"] = pattern_id
    variant["canonical_chain"]["semantic_digest"] = compute_chain_semantic_digest(
        variant["canonical_chain"]
    )
    return variant


def typed_payload(
    *,
    risk_ids: tuple[str, ...] = ("risk-a",),
    pattern_id: str | None = "AP-T1-01",
    catalog_pin: str | None = None,
    mapping_pin: str | None = None,
    pattern_record: dict[str, Any] | None = None,
    capability_snapshot: Any | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the normative TaxonomyObligationInputs mapping fixture."""
    _candidate, raw_pattern, default_snapshot = typed_authoritative_fixture()
    actual_pattern_id = raw_pattern["id"]
    if pattern_id is None:
        selected_pattern: dict[str, Any] | None = None
    elif pattern_record is not None:
        selected_pattern = deepcopy(pattern_record)
    elif pattern_id == actual_pattern_id:
        selected_pattern = deepcopy(raw_pattern)
    else:
        selected_pattern = typed_pattern_variant(pattern_id)

    selected_snapshot = capability_snapshot or default_snapshot
    mappings = [
        {
            "source_id": risk_id,
            "target_id": pattern_id,
            "relation": "exact",
            "evidence": ["reviewed-risk-card-mapping"],
        }
        for risk_id in risk_ids
        if pattern_id is not None
    ]
    actual_catalog_pin, actual_mapping_pin = typed_pin_payload(
        selected_pattern or raw_pattern,
        selected_snapshot,
        mappings,
        [],
    )
    payload: dict[str, Any] = {
        "risk_cards": [typed_risk_card(risk_id) for risk_id in risk_ids],
        "capability_snapshot": selected_snapshot,
        "attack_pattern_catalog": (
            [selected_pattern] if selected_pattern is not None else []
        ),
        "cross_taxonomy_mappings": mappings,
        "sssom_mappings": [],
        "catalog_pins": {
            "atlas": {
                "release": catalog_pin or actual_catalog_pin["atlas"]["release"],
                "digest": actual_catalog_pin["atlas"]["digest"],
            }
        },
        "mapping_pins": {
            "sssom": {
                "release": mapping_pin or actual_mapping_pin["sssom"]["release"],
                "digest": actual_mapping_pin["sssom"]["digest"],
            },
            "obligation_edges": actual_mapping_pin["obligation_edges"],
        },
        "qualification_facts": typed_default_qualification(selected_snapshot),
        "projection_budget": {"max_candidates": 100, "max_derivation_work": 4096},
        "compatibility_policy": {"allow_legacy_keyword_matches": False},
    }
    if extra:
        payload.update(extra)
    return payload


def typed_input_model(payload: dict[str, Any]) -> Any:
    """Validate one mapping through the public typed input model."""
    from asago_scenario_generator.pipeline.obligation_contracts import (
        TaxonomyObligationInputs,
    )

    return TaxonomyObligationInputs.model_validate(payload)
