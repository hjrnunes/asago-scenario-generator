"""Canonical separation of scenario and projected-step ATLAS identity scopes."""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from typing import Any

from asago_scenario_generator.models.projection_envelope import ProjectionEnvelopeBlock
from asago_scenario_generator.models.scenario import (
    ScenarioEnvelope,
    TechniqueScopeEvidence,
)

_NARRATIVE_TECHNIQUE_RE = re.compile(r"\[?(AML\.T\d{4}(?:\.\d{3})?)\]?")


def stable_unique(values: Iterable[str]) -> list[str]:
    """Return non-empty string values once, preserving first-seen order."""
    return list(dict.fromkeys(str(value) for value in values if str(value)))


def scenario_classification_ids(
    pinned_technique_ids: Sequence[str] | None,
    seed_atlas_technique_ids: Sequence[str],
) -> list[str]:
    """Resolve qualified pins, falling back to the legacy seed classification."""
    source = pinned_technique_ids or seed_atlas_technique_ids
    return stable_unique(source)


def projected_step_mapping_ids(block: ProjectionEnvelopeBlock) -> list[str]:
    """Collect exact ATLAS IDs declared by selected projected steps."""
    return stable_unique(
        technique_id
        for projected in block.projected_mappings
        if projected.scope == "step"
        and projected.mapping.taxonomy == "ATLAS"
        and projected.mapping.decision == "exact"
        for technique_id in projected.mapping.ids
    )


def projected_step_mapping_ids_by_step(
    block: ProjectionEnvelopeBlock,
) -> dict[str, frozenset[str]]:
    """Return exact ATLAS mapping membership for each selected projected step."""
    selected = set(block.selected_step_ids)
    result = {step_id: set() for step_id in block.selected_step_ids}
    for projected in block.projected_mappings:
        if (
            projected.scope != "step"
            or projected.step_id not in selected
            or projected.mapping.taxonomy != "ATLAS"
            or projected.mapping.decision != "exact"
        ):
            continue
        result[projected.step_id].update(projected.mapping.ids)
    return {step_id: frozenset(ids) for step_id, ids in result.items()}


def narrative_reference_ids(narrative: Any) -> list[str]:
    """Extract stable ATLAS references from provider-authored narrative text."""
    texts: list[str] = []
    summary = getattr(narrative, "summary", None)
    if summary:
        texts.append(str(summary))
    for step in getattr(narrative, "steps", ()):
        for field_name in ("action", "effect"):
            value = getattr(step, field_name, None)
            if value:
                texts.append(str(value))
    return stable_unique(
        match.group(1)
        for text in texts
        for match in _NARRATIVE_TECHNIQUE_RE.finditer(text)
    )


def build_technique_scope_evidence(
    *,
    pinned_technique_ids: Sequence[str] | None,
    seed_atlas_technique_ids: Sequence[str],
    projection: ProjectionEnvelopeBlock,
    narrative: Any,
) -> TechniqueScopeEvidence:
    """Build explicit evidence for a newly assembled scenario envelope."""
    return TechniqueScopeEvidence(
        scenario_classification_ids=scenario_classification_ids(
            pinned_technique_ids, seed_atlas_technique_ids
        ),
        projected_step_mapping_ids=projected_step_mapping_ids(projection),
        narrative_reference_ids=narrative_reference_ids(narrative),
    )


def resolved_technique_scope_evidence(
    scenario: ScenarioEnvelope,
) -> TechniqueScopeEvidence:
    """Read explicit evidence or derive named scopes from a legacy envelope."""
    if scenario.technique_scope_evidence is not None:
        return scenario.technique_scope_evidence
    return TechniqueScopeEvidence(
        scenario_classification_ids=stable_unique(
            scenario.faceting.taxonomy_chain.atlas_technique_ids or ()
        ),
        projected_step_mapping_ids=stable_unique(
            scenario.attack_tree.collect_technique_ids()
        ),
        narrative_reference_ids=narrative_reference_ids(scenario.narrative),
        legacy_derived=True,
    )
