"""Deterministic source-influence provenance qualification.

Qualifies the typed source-influence provenance block persisted on a
scenario envelope (see ``models.source_influence_provenance``): every
projected attack-tree leaf and narrative step must link to the declared
threat sources, mitigations, and capability constraints, and the declared
source universe must be fully referenced.  Qualification is deterministic,
offline, and fails closed:

- ``missing_source_provenance`` — an artifact link omits a source type;
- ``unknown_source_reference`` — a link references a source outside the
  declared universe;
- ``provenance_projected_step_mismatch`` — a link claims a projected step
  the artifact does not realize;
- ``orphaned_source_provenance`` — a declared source is never referenced;
- ``unreferenced_source_influence_artifact`` — no artifact carrying a
  projected step has a provenance link.

Coverage metrics (projected-leaf, narrative-step, and source-reference
fractions plus orphaned/unreferenced counts) are recomputed on every
qualification so persisted metadata can be verified for staleness.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from asago_scenario_generator.models.attack_tree import GateType, AttackTreeNode
from asago_scenario_generator.models.source_influence_provenance import (
    CoverageFraction,
    SourceInfluenceArtifactElement,
    SourceInfluenceArtifactKind,
    SourceInfluenceArtifactLink,
    SourceInfluenceMetrics,
    SourceInfluenceProvenanceBlock,
    SourceInfluenceQualification,
    SourceInfluenceSourceRef,
    SourceInfluenceSourceType,
    SourceInfluenceViolation,
    SourceInfluenceViolationCode,
)

if TYPE_CHECKING:
    from asago_scenario_generator.models.scenario import (
        NarrativeLayer,
        ScenarioEnvelope,
    )

EMPTY_METRICS = SourceInfluenceMetrics(
    projected_leaf_coverage=CoverageFraction(numerator=0, denominator=0),
    narrative_step_coverage=CoverageFraction(numerator=0, denominator=0),
    source_reference_coverage=CoverageFraction(numerator=0, denominator=0),
    orphaned_source_count=0,
    unreferenced_artifact_count=0,
)
"""Metrics for the vacuous pass of an envelope without a provenance block."""

__all__ = [
    "EMPTY_METRICS",
    "make_source_influence_provenance_block",
    "qualify_source_influence_provenance",
    "validate_source_influence_provenance",
]


# ---------------------------------------------------------------------------#
# Qualification engine
# ---------------------------------------------------------------------------#


def _canonical_declared_sources(
    declared_sources: Sequence[SourceInfluenceSourceRef],
) -> tuple[SourceInfluenceSourceRef, ...]:
    """Deduplicate declared source records by (type, id), preserving order.

    The scenario-level source universe stores each typed record exactly
    once; duplicate declarations collapse into the first occurrence.
    """
    seen: set[tuple[SourceInfluenceSourceType, str]] = set()
    result: list[SourceInfluenceSourceRef] = []
    for ref in declared_sources:
        key = (ref.source_type, ref.source_id)
        if key in seen:
            continue
        seen.add(key)
        result.append(ref)
    return tuple(result)


def _step_mismatch_violation(
    kind: SourceInfluenceArtifactKind,
    artifact_id: str,
    claimed_step_id: str,
    realized_step_ids: tuple[str, ...],
) -> SourceInfluenceViolation:
    """Violation for a link claiming a projected step the artifact lacks."""
    return SourceInfluenceViolation(
        code=SourceInfluenceViolationCode.provenance_projected_step_mismatch,
        detail=(
            f"{kind.value} '{artifact_id}' provenance link claims projected "
            f"step '{claimed_step_id}' but the artifact realizes "
            f"{realized_step_ids}"
        ),
        artifact_id=artifact_id,
        projected_step_id=claimed_step_id,
    )


def _unknown_reference_violation(
    kind: SourceInfluenceArtifactKind,
    artifact_id: str,
    ref: SourceInfluenceSourceRef,
) -> SourceInfluenceViolation:
    """Violation for a link referencing a source outside the universe."""
    return SourceInfluenceViolation(
        code=SourceInfluenceViolationCode.unknown_source_reference,
        detail=(
            f"{kind.value} '{artifact_id}' references source '{ref.source_id}' "
            f"which is not declared in the source-influence provenance "
            f"universe"
        ),
        source_type=ref.source_type,
        source_id=ref.source_id,
        artifact_id=artifact_id,
    )


def _missing_source_type_violations(
    kind: SourceInfluenceArtifactKind,
    artifact_id: str,
    present_types: set[SourceInfluenceSourceType],
) -> list[SourceInfluenceViolation]:
    """Violations for every source type a link omits."""
    return [
        SourceInfluenceViolation(
            code=SourceInfluenceViolationCode.missing_source_provenance,
            detail=(
                f"{kind.value} '{artifact_id}' provenance omits source type "
                f"'{source_type.value}'"
            ),
            source_type=source_type,
            artifact_id=artifact_id,
        )
        for source_type in SourceInfluenceSourceType
        if source_type not in present_types
    ]


def _orphaned_source_violations(
    declared: Sequence[SourceInfluenceSourceRef],
    referenced_ids: set[tuple[SourceInfluenceSourceType, str]],
) -> list[SourceInfluenceViolation]:
    """Violations for declared source records never referenced by any link."""
    violations: list[SourceInfluenceViolation] = []
    for ref in declared:
        if (ref.source_type, ref.source_id) not in referenced_ids:
            violations.append(
                SourceInfluenceViolation(
                    code=SourceInfluenceViolationCode.orphaned_source_provenance,
                    detail=(
                        f"declared source '{ref.source_id}' is not referenced "
                        f"by any projected leaf or narrative step link"
                    ),
                    source_type=ref.source_type,
                    source_id=ref.source_id,
                )
            )
    return violations


def _unreferenced_step_violations(
    selected_step_ids: Sequence[str],
    linked_steps: set[str],
) -> list[SourceInfluenceViolation]:
    """Violations for projected steps no linked artifact realizes."""
    violations: list[SourceInfluenceViolation] = []
    for step_id in selected_step_ids:
        if step_id not in linked_steps:
            violations.append(
                SourceInfluenceViolation(
                    code=SourceInfluenceViolationCode.unreferenced_source_influence_artifact,
                    detail=(
                        f"no projected leaf or narrative step artifact "
                        f"realizing projected step '{step_id}' carries "
                        f"source-influence provenance links"
                    ),
                    projected_step_id=step_id,
                )
            )
    return violations


def _deduplicate_violations(
    violations: Sequence[SourceInfluenceViolation],
) -> list[SourceInfluenceViolation]:
    """Deduplicate violations by identity-bearing fields, preserving order."""
    seen: set[tuple[str, str, str | None, str | None, str | None]] = set()
    unique: list[SourceInfluenceViolation] = []
    for violation in violations:
        key = (
            violation.code.value,
            violation.source_type.value if violation.source_type else "",
            violation.source_id,
            violation.artifact_id,
            violation.projected_step_id,
        )
        if key not in seen:
            seen.add(key)
            unique.append(violation)
    return unique


def _qualify_artifact_link(
    *,
    element: SourceInfluenceArtifactElement,
    link: SourceInfluenceArtifactLink,
    kind: SourceInfluenceArtifactKind,
    declared_ids: set[tuple[SourceInfluenceSourceType, str]],
    violations: list[SourceInfluenceViolation],
    referenced_ids: set[tuple[SourceInfluenceSourceType, str]],
) -> None:
    """Qualify one artifact link, appending its typed violations."""
    if link.projected_step_id not in element.projected_step_ids:
        violations.append(
            _step_mismatch_violation(
                kind,
                element.artifact_id,
                link.projected_step_id,
                element.projected_step_ids,
            )
        )
    present_types: set[SourceInfluenceSourceType] = set()
    for ref in link.source_refs:
        present_types.add(ref.source_type)
        key = (ref.source_type, ref.source_id)
        if key not in declared_ids:
            violations.append(
                _unknown_reference_violation(kind, element.artifact_id, ref)
            )
        else:
            referenced_ids.add(key)
    violations.extend(
        _missing_source_type_violations(kind, element.artifact_id, present_types)
    )


def _qualify_artifact_kind(
    *,
    elements: Sequence[SourceInfluenceArtifactElement],
    links_by_id: dict[str, SourceInfluenceArtifactLink],
    kind: SourceInfluenceArtifactKind,
    declared_ids: set[tuple[SourceInfluenceSourceType, str]],
    violations: list[SourceInfluenceViolation],
    referenced_ids: set[tuple[SourceInfluenceSourceType, str]],
    linked_steps: set[str],
) -> tuple[int, int]:
    """Qualify one artifact kind; return (covered count, unreferenced count)."""
    covered_count = 0
    unreferenced_count = 0
    for element in elements:
        link = links_by_id.get(element.artifact_id)
        if link is None:
            unreferenced_count += 1
            continue
        if link.source_refs:
            covered_count += 1
        linked_steps.update(element.projected_step_ids)
        _qualify_artifact_link(
            element=element,
            link=link,
            kind=kind,
            declared_ids=declared_ids,
            violations=violations,
            referenced_ids=referenced_ids,
        )
    return covered_count, unreferenced_count


def qualify_source_influence_provenance(
    *,
    selected_step_ids: Sequence[str],
    declared_sources: Sequence[SourceInfluenceSourceRef],
    leaf_elements: Sequence[SourceInfluenceArtifactElement],
    narrative_elements: Sequence[SourceInfluenceArtifactElement],
    leaf_links: Sequence[SourceInfluenceArtifactLink],
    narrative_links: Sequence[SourceInfluenceArtifactLink],
) -> SourceInfluenceQualification:
    """Qualify artifact provenance links against the declared source universe.

    Args:
        selected_step_ids: Projected step IDs from the canonical projection.
        declared_sources: Scenario-level declared source records (deduped).
        leaf_elements: Projected attack-tree leaf elements that realize steps.
        narrative_elements: Narrative step elements that realize steps.
        leaf_links: Provenance links attached to the leaf elements.
        narrative_links: Provenance links attached to the narrative elements.

    Returns:
        A deterministic :class:`SourceInfluenceQualification` carrying the
        typed violations, coverage metrics, and pass/fail status.  Links
        naming artifact elements that do not exist in the supplied element
        sets are ignored.
    """
    declared = _canonical_declared_sources(declared_sources)
    declared_ids = {(ref.source_type, ref.source_id) for ref in declared}

    # Keep the two persisted link collections hermetic.  ``artifact_kind`` is
    # part of the serialized contract, so a link placed in the wrong
    # collection must not qualify an artifact by ID alone.  It is treated as
    # absent and consequently produces the normal fail-closed
    # ``unreferenced_source_influence_artifact`` violation.
    leaf_links_by_id = {
        link.artifact_id: link
        for link in leaf_links
        if link.artifact_kind is SourceInfluenceArtifactKind.projected_leaf
    }
    narrative_links_by_id = {
        link.artifact_id: link
        for link in narrative_links
        if link.artifact_kind is SourceInfluenceArtifactKind.narrative_step
    }

    violations: list[SourceInfluenceViolation] = []
    referenced_ids: set[tuple[SourceInfluenceSourceType, str]] = set()
    linked_steps: set[str] = set()

    leaf_covered, leaf_unreferenced = _qualify_artifact_kind(
        elements=leaf_elements,
        links_by_id=leaf_links_by_id,
        kind=SourceInfluenceArtifactKind.projected_leaf,
        declared_ids=declared_ids,
        violations=violations,
        referenced_ids=referenced_ids,
        linked_steps=linked_steps,
    )
    narrative_covered, narrative_unreferenced = _qualify_artifact_kind(
        elements=narrative_elements,
        links_by_id=narrative_links_by_id,
        kind=SourceInfluenceArtifactKind.narrative_step,
        declared_ids=declared_ids,
        violations=violations,
        referenced_ids=referenced_ids,
        linked_steps=linked_steps,
    )
    violations.extend(_orphaned_source_violations(declared, referenced_ids))
    violations.extend(_unreferenced_step_violations(selected_step_ids, linked_steps))
    if leaf_unreferenced + narrative_unreferenced and not any(
        violation.code
        == SourceInfluenceViolationCode.unreferenced_source_influence_artifact
        for violation in violations
    ):
        violations.append(
            SourceInfluenceViolation(
                code=SourceInfluenceViolationCode.unreferenced_source_influence_artifact,
                detail=(
                    "one or more generated artifacts have no source-influence "
                    "provenance link"
                ),
                projected_step_id=next(iter(linked_steps), None),
            )
        )
    unique = _deduplicate_violations(violations)

    source_numerator = len(referenced_ids & declared_ids)
    metrics = SourceInfluenceMetrics(
        projected_leaf_coverage=CoverageFraction(
            numerator=leaf_covered, denominator=len(leaf_elements)
        ),
        narrative_step_coverage=CoverageFraction(
            numerator=narrative_covered, denominator=len(narrative_elements)
        ),
        source_reference_coverage=CoverageFraction(
            numerator=source_numerator, denominator=len(declared)
        ),
        orphaned_source_count=len(declared) - source_numerator,
        unreferenced_artifact_count=leaf_unreferenced + narrative_unreferenced,
    )

    return SourceInfluenceQualification(
        valid=not unique,
        status="pass" if not unique else "fail",
        violations=tuple(unique),
        metrics=metrics,
    )


def make_source_influence_provenance_block(
    *,
    declared_sources: Sequence[SourceInfluenceSourceRef],
    leaf_links: Sequence[SourceInfluenceArtifactLink],
    narrative_links: Sequence[SourceInfluenceArtifactLink],
    qualification: SourceInfluenceQualification,
) -> SourceInfluenceProvenanceBlock:
    """Persist a qualification as the envelope's typed provenance block.

    The declared source universe is stored deduplicated exactly once;
    links and the computed metrics/status are stored as given.
    """
    return SourceInfluenceProvenanceBlock(
        declared_sources=_canonical_declared_sources(declared_sources),
        leaf_links=tuple(leaf_links),
        narrative_links=tuple(narrative_links),
        metrics=qualification.metrics,
        status=qualification.status,
    )


# ---------------------------------------------------------------------------#
# Envelope-level fail-closed validation
# ---------------------------------------------------------------------------#


def _leaf_nodes(root: AttackTreeNode) -> list[AttackTreeNode]:
    """Collect all LEAF nodes from a tree, depth-first."""
    if root.gate == GateType.LEAF:
        return [root]
    leaves: list[AttackTreeNode] = []
    for child in root.children or ():
        leaves.extend(_leaf_nodes(child))
    return leaves


def _artifact_elements(
    leaves: Sequence[AttackTreeNode],
    narrative: NarrativeLayer | None,
) -> tuple[
    tuple[SourceInfluenceArtifactElement, ...],
    tuple[SourceInfluenceArtifactElement, ...],
]:
    """Derive leaf and narrative artifact elements from the envelope artifacts.

    Only leaves that realize at least one projected step are provenance
    participants; narrative steps always carry projected step IDs on
    scenarios with a projection block.
    """
    leaf_elements = tuple(
        SourceInfluenceArtifactElement(
            artifact_id=leaf.id,
            projected_step_ids=tuple(leaf.projected_step_ids),
        )
        for leaf in leaves
        if leaf.projected_step_ids
    )
    narrative_elements = tuple(
        SourceInfluenceArtifactElement(
            artifact_id=str(step.step_number),
            projected_step_ids=tuple(step.projected_step_ids),
        )
        for step in (narrative.steps if narrative is not None else ())
    )
    return leaf_elements, narrative_elements


def validate_source_influence_provenance(
    envelope: ScenarioEnvelope,
) -> SourceInfluenceQualification:
    """Validate an envelope's persisted source-influence provenance block.

    An envelope without a provenance block passes vacuously (nothing is
    declared, so nothing can be orphaned or unreferenced).  When a block
    is present, the qualification is recomputed from the envelope's actual
    artifacts and compared with the persisted metrics and status: stale
    or tampered persisted metadata raises ``ValueError`` (fail closed),
    and violations are returned for the publish gate to reject.

    Only a typed :class:`SourceInfluenceProvenanceBlock` is treated as a
    persisted block.  Anything else (``None`` or a stand-in such as a
    ``MagicMock`` on adapter paths that patch the projection-traceability
    gate to pass) qualifies vacuously, matching the envelope-validator
    convention of the traceability gate.

    Raises:
        ValueError: When the persisted metrics/status disagree with the
            recomputed deterministic qualification.
    """
    block: SourceInfluenceProvenanceBlock | None = envelope.source_influence_provenance
    if not isinstance(block, SourceInfluenceProvenanceBlock):
        return SourceInfluenceQualification(
            valid=True,
            status="pass",
            violations=(),
            metrics=EMPTY_METRICS,
        )
    leaves = (
        _leaf_nodes(envelope.attack_tree.root)
        if envelope.attack_tree is not None
        else []
    )
    leaf_elements, narrative_elements = _artifact_elements(leaves, envelope.narrative)
    result = qualify_source_influence_provenance(
        selected_step_ids=tuple(envelope.projection.selected_step_ids),
        declared_sources=block.declared_sources,
        leaf_elements=leaf_elements,
        narrative_elements=narrative_elements,
        leaf_links=block.leaf_links,
        narrative_links=block.narrative_links,
    )
    if result.metrics != block.metrics:
        raise ValueError(
            "persisted source-influence provenance metrics are inconsistent "
            "with the envelope artifacts; the provenance block was mutated "
            "after qualification"
        )
    if result.status != block.status:
        raise ValueError(
            "persisted source-influence qualification status is inconsistent "
            "with the envelope artifacts; the provenance block was mutated "
            "after qualification"
        )
    return result


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-20T11:16:38Z","module_hash":"0291486799b560bf3dbf39eedf530c86720199f191f73cd26e2f7f76d5d81b33","functions":[{"id":"func/_canonical_declared_sources","name":"_canonical_declared_sources","line":72,"end_line":88,"hash":"b9a00c7e6bd7beb5c47466e564c652621484fbdcf27abf9b2d1baf2e84a05f12"},{"id":"func/_step_mismatch_violation","name":"_step_mismatch_violation","line":91,"end_line":107,"hash":"910915c0595828b12fa871dd85d6f6935f2169b8397fbd4cf588fb7fddf68b34"},{"id":"func/_unknown_reference_violation","name":"_unknown_reference_violation","line":110,"end_line":126,"hash":"b16aaeafb540dd93c221879953f4817f07a8461f9928f7570f8b4d6384b58e7d"},{"id":"func/_missing_source_type_violations","name":"_missing_source_type_violations","line":129,"end_line":147,"hash":"81125a677959945961e9792a991bda8a5e22047e4020dfbcf0113f2a2a1c984f"},{"id":"func/_orphaned_source_violations","name":"_orphaned_source_violations","line":150,"end_line":169,"hash":"822115276c1c8d9a754b1ea96f27127bd1b271bccea5a51d698ae4b4569c65b2"},{"id":"func/_unreferenced_step_violations","name":"_unreferenced_step_violations","line":172,"end_line":191,"hash":"39957fd6a788d4814a49a086152429efdb3011f7ea6f19d9dd77732cd179137f"},{"id":"func/_deduplicate_violations","name":"_deduplicate_violations","line":194,"end_line":211,"hash":"d373fcc8afc9609c4d0dedac996dd95c7ba747b29128ba829ecd6f34c66996b8"},{"id":"func/_qualify_artifact_link","name":"_qualify_artifact_link","line":214,"end_line":245,"hash":"3b21b0b8d74c6f1c08a3c8d96f64b0fbbe287ff12b2df5e902400bc26283384c"},{"id":"func/_qualify_artifact_kind","name":"_qualify_artifact_kind","line":248,"end_line":277,"hash":"9348e2315184873e2e93c5d9b98aefc9ac6011c3a4a2c753159c744b79e4abaa"},{"id":"func/qualify_source_influence_provenance","name":"qualify_source_influence_provenance","line":280,"end_line":385,"hash":"85f758c8f14d609b83ebbe94f92d042e12ae2378b0d1bc84f6bfbc67e45851cf"},{"id":"func/make_source_influence_provenance_block","name":"make_source_influence_provenance_block","line":388,"end_line":406,"hash":"3986f497ac369623a46d441c412dec1865090e4dd4c3c85f0eb4c4d34a1fe31f"},{"id":"func/_leaf_nodes","name":"_leaf_nodes","line":414,"end_line":421,"hash":"26aedc3ed6f56c264246772ae913e079c8a2fe536567ac43ecb8044e65e2cac4"},{"id":"func/_artifact_elements","name":"_artifact_elements","line":424,"end_line":452,"hash":"eaffc62ec34144115bf56ab34367c817f439547a90bfa29c91973342dd23cd33"},{"id":"func/validate_source_influence_provenance","name":"validate_source_influence_provenance","line":455,"end_line":511,"hash":"9e1559ddc0de4b40a2341b5284c65e9b2499c544e55bbeea3f74dbb144245d95"}]}
# mutate4py-manifest-end
