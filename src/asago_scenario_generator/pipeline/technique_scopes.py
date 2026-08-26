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


def _mapping_targets_selected_step(projected: Any, selected: set[str]) -> bool:
    """Whether a projected mapping targets a selected step with exact ATLAS identity."""
    return (
        projected.scope == "step"
        and projected.step_id in selected
        and projected.mapping.taxonomy == "ATLAS"
        and projected.mapping.decision == "exact"
    )


def projected_step_mapping_ids_by_step(
    block: ProjectionEnvelopeBlock,
) -> dict[str, frozenset[str]]:
    """Return exact ATLAS mapping membership for each selected projected step."""
    selected = set(block.selected_step_ids)
    result = {step_id: set() for step_id in block.selected_step_ids}
    for projected in block.projected_mappings:
        if not _mapping_targets_selected_step(projected, selected):
            continue
        result[projected.step_id].update(projected.mapping.ids)
    return {step_id: frozenset(ids) for step_id, ids in result.items()}


def _step_reference_texts(step: Any) -> list[str]:
    """Collect action/effect text from one narrative step."""
    texts: list[str] = []
    for field_name in ("action", "effect"):
        value = getattr(step, field_name, None)
        if value:
            texts.append(str(value))
    return texts


def _narrative_reference_texts(narrative: Any) -> list[str]:
    """Collect summary/action/effect text for ATLAS reference extraction."""
    texts: list[str] = []
    summary = getattr(narrative, "summary", None)
    if summary:
        texts.append(str(summary))
    for step in getattr(narrative, "steps", ()):
        texts.extend(_step_reference_texts(step))
    return texts


def narrative_reference_ids(narrative: Any) -> list[str]:
    """Extract stable ATLAS references from provider-authored narrative text."""
    return stable_unique(
        match.group(1)
        for text in _narrative_reference_texts(narrative)
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


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-26T11:34:14Z","module_hash":"1ff2fc663f94af0769c51970f191c34dfdcd9178b50fc9f80e68263f4336367b","source_sha256":"f93146f3c07e8e7fc1a99df69a2942e4b43a9edce0e0a1c44dd8afbb217b1e85","functions":[{"id":"func/stable_unique","name":"stable_unique","line":18,"end_line":20,"hash":"9f489fae2c3b22f478e12cbae71e37fea1bbe4d366377cb9a43e6abc089c81f1"},{"id":"func/scenario_classification_ids","name":"scenario_classification_ids","line":23,"end_line":29,"hash":"f88eef4121cfb84f4dccbb677d1643fad11a52e9461369b2f1076a09331ea08f"},{"id":"func/projected_step_mapping_ids","name":"projected_step_mapping_ids","line":32,"end_line":41,"hash":"b7761931a20439b126e67da556f6a4dfd28a0059c5d89edb062442c47a4c89f8"},{"id":"func/_mapping_targets_selected_step","name":"_mapping_targets_selected_step","line":44,"end_line":51,"hash":"567b51da9b84fbef4aec28db13ed9f6c2bd532d48a9ef5c3b66bff476874de52"},{"id":"func/projected_step_mapping_ids_by_step","name":"projected_step_mapping_ids_by_step","line":54,"end_line":64,"hash":"fc41d4d80dd7c6b4345f2593170140d6bbd97862c6785cf19616d69d8f58a702"},{"id":"func/_step_reference_texts","name":"_step_reference_texts","line":67,"end_line":74,"hash":"49f7e9fa9944bdb2cd88b6545568f346907d9cfb3e90c0365626d53d76c9592f"},{"id":"func/_narrative_reference_texts","name":"_narrative_reference_texts","line":77,"end_line":85,"hash":"822c3d8fe8b4e62fa6d34977b421e880b68e07985f376b227261c6ba4dc4590a"},{"id":"func/narrative_reference_ids","name":"narrative_reference_ids","line":88,"end_line":94,"hash":"1b39362b42744aa85114801cf73a5a6588c33fbd9f4cd5fe44962d15eaab3a10"},{"id":"func/build_technique_scope_evidence","name":"build_technique_scope_evidence","line":97,"end_line":111,"hash":"63b18ee4425e9dbe747ebd31207fdd9ddd5f9fa18de7892387265d82f99097d5"},{"id":"func/resolved_technique_scope_evidence","name":"resolved_technique_scope_evidence","line":114,"end_line":129,"hash":"76b3316d78a31b984dde8653398e1760e5cd55243e7746e8b06323423dd61a3d"}]}
# mutate4py-manifest-end
