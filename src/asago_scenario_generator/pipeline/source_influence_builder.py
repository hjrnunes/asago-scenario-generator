"""Deterministic source-influence provenance assembly for the generate path.

The generate path always attaches a typed
:class:`SourceInfluenceProvenanceBlock` to every admitted scenario
envelope (QA-TSIP contract; see the QA procedures for taxonomy source
influence).  This module assembles that block deterministically from the
data already flowing through generation — never from an LLM:

- **Threat sources** derive from the seed's risk inputs: the primary
  ``threat_id`` followed by ``agentic_threat_ids``, deduplicated in
  order (``threat:T12``).
- **Mitigations** derive from the committed OWASP Agentic Threats
  taxonomy: every mitigation playbook (``mitigation:playbook-N``) whose
  ``mitigates`` list intersects the declared threat IDs.
- **Capability constraints** derive from the capability profile's KC
  sub-codes (``constraint:KCX-MAGENT``, ``constraint:KC1.1``, ...).

Artifact links are built from the same elements the qualification engine
derives from the envelope (projected attack-tree leaves and narrative
steps that realize projected steps).  Every artifact link carries the
full declared source universe, so a complete envelope always qualifies
``pass`` and the finalization gate enforces fail-closed behavior for
stale, tampered, or incomplete blocks.

When no leaf and no narrative element realizes projected steps, there is
nothing to link and no block is attached (the envelope passes vacuously);
on the real generate path projection traceability guarantees at least one
realizing element per selected step, so admitted envelopes always carry a
block.
"""

from __future__ import annotations

import functools
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

from asago_scenario_generator.data.paths import DATA_ROOT
from asago_scenario_generator.models.source_influence_provenance import (
    SourceInfluenceArtifactElement,
    SourceInfluenceArtifactKind,
    SourceInfluenceArtifactLink,
    SourceInfluenceProvenanceBlock,
    SourceInfluenceSourceRef,
    SourceInfluenceSourceType,
)
from asago_scenario_generator.pipeline.source_influence import (
    artifact_elements,
    leaf_nodes,
    make_source_influence_provenance_block,
    qualify_source_influence_provenance,
)

if TYPE_CHECKING:
    from asago_scenario_generator.models.attack_tree import AttackTree
    from asago_scenario_generator.models.scenario import NarrativeLayer
    from asago_scenario_generator.pipeline.projection_contracts import (
        CapabilityFactSnapshot,
    )
    from asago_scenario_generator.pipeline.seeds import ScenarioSeed

__all__ = [
    "assemble_source_influence_provenance",
    "declared_source_records",
]

_DEFAULT_THREATS_PATH = (
    DATA_ROOT
    / "taxonomies"
    / "owasp-agentic-threats"
    / "owasp-agentic-threats-v1.1.yaml"
)


@functools.lru_cache(maxsize=4)
def _load_threat_playbooks_cached(path: str) -> tuple[tuple[str, tuple[str, ...]], ...]:
    """Load ``(playbook_id, mitigates)`` records from the threats taxonomy.

    Playbooks are sorted by ID so the derived mitigation universe is
    deterministic for a given threat set.
    """
    with open(path) as handle:
        data = yaml.safe_load(handle)
    return tuple(
        (item["id"], tuple(item.get("mitigates", ())))
        for item in sorted(
            data.get("playbooks", ()), key=lambda entry: entry.get("id", "")
        )
    )


def _dedupe_source_refs(
    source_type: SourceInfluenceSourceType,
    source_ids: Sequence[str],
) -> tuple[SourceInfluenceSourceRef, ...]:
    """Deduplicate pre-formatted source IDs into typed source records.

    First occurrence wins so callers can order inputs deliberately
    (e.g. primary threat first).
    """
    refs: list[SourceInfluenceSourceRef] = []
    seen: set[str] = set()
    for source_id in source_ids:
        if source_id in seen:
            continue
        seen.add(source_id)
        refs.append(
            SourceInfluenceSourceRef(source_type=source_type, source_id=source_id)
        )
    return tuple(refs)


def _threat_source_refs(
    threat_ids: Sequence[str],
) -> tuple[SourceInfluenceSourceRef, ...]:
    """Deduplicate threat IDs (primary first) into typed threat sources."""
    return _dedupe_source_refs(
        SourceInfluenceSourceType.threat_source,
        (f"threat:{threat_id}" for threat_id in threat_ids),
    )


def _mitigation_source_refs(
    threat_ids: Sequence[str],
    threats_path: str | Path | None,
) -> tuple[SourceInfluenceSourceRef, ...]:
    """Derive mitigation sources from playbooks mitigating the threats."""
    path = Path(threats_path) if threats_path is not None else _DEFAULT_THREATS_PATH
    threat_set = set(threat_ids)
    return tuple(
        SourceInfluenceSourceRef(
            source_type=SourceInfluenceSourceType.mitigation,
            source_id=f"mitigation:{playbook_id}",
        )
        for playbook_id, mitigates in _load_threat_playbooks_cached(str(path))
        if threat_set & set(mitigates)
    )


def _constraint_source_refs(
    kc_subcodes: Sequence[str],
) -> tuple[SourceInfluenceSourceRef, ...]:
    """Derive capability-constraint sources from the profile KC sub-codes."""
    return _dedupe_source_refs(
        SourceInfluenceSourceType.capability_constraint,
        (f"constraint:{kc}" for kc in kc_subcodes),
    )


def declared_source_records(
    *,
    seed: ScenarioSeed,
    capability_snapshot: CapabilityFactSnapshot,
    threats_path: str | Path | None = None,
) -> tuple[SourceInfluenceSourceRef, ...]:
    """Derive the declared source universe for one generated scenario.

    Threat sources come from the seed's risk inputs (primary ``threat_id``
    first, then ``agentic_threat_ids``), mitigations from the committed
    OWASP Agentic Threats playbooks, and capability constraints from the
    profile's KC sub-codes.  Every record is deterministic and typed.
    """
    threat_ids: list[str] = [seed.threat_id, *seed.agentic_threat_ids]
    return tuple(
        [
            *_threat_source_refs(threat_ids),
            *_mitigation_source_refs(threat_ids, threats_path),
            *_constraint_source_refs(capability_snapshot.profile.kc_subcodes),
        ]
    )


def _links_for_elements(
    elements: Sequence[SourceInfluenceArtifactElement],
    kind: SourceInfluenceArtifactKind,
    refs: tuple[SourceInfluenceSourceRef, ...],
) -> tuple[SourceInfluenceArtifactLink, ...]:
    """Build one full-universe provenance link per artifact element."""
    return tuple(
        SourceInfluenceArtifactLink(
            artifact_kind=kind,
            artifact_id=element.artifact_id,
            projected_step_id=element.projected_step_ids[0],
            source_refs=refs,
        )
        for element in elements
    )


def assemble_source_influence_provenance(
    *,
    seed: ScenarioSeed,
    capability_snapshot: CapabilityFactSnapshot,
    attack_tree: AttackTree | None,
    narrative: NarrativeLayer | None,
    selected_step_ids: Sequence[str],
    threats_path: str | Path | None = None,
) -> SourceInfluenceProvenanceBlock | None:
    """Assemble and qualify the provenance block for the generate path.

    The declared source universe is derived from the seed, capability
    snapshot, and committed threats taxonomy; artifact links are derived
    from the actual projected attack-tree leaves and narrative steps —
    the same elements the qualification engine derives from the envelope,
    so the persisted metrics always re-qualify consistently.

    Returns:
        The typed provenance block (status ``pass`` on the real generate
        path, where artifacts fully realize the projection), or ``None``
        when no leaf or narrative element realizes projected steps.
    """
    declared = declared_source_records(
        seed=seed,
        capability_snapshot=capability_snapshot,
        threats_path=threats_path,
    )
    leaves = leaf_nodes(attack_tree.root) if attack_tree is not None else []
    leaf_elements, narrative_elements = artifact_elements(leaves, narrative)
    if not leaf_elements and not narrative_elements:
        return None

    leaf_links = _links_for_elements(
        leaf_elements, SourceInfluenceArtifactKind.projected_leaf, declared
    )
    narrative_links = _links_for_elements(
        narrative_elements, SourceInfluenceArtifactKind.narrative_step, declared
    )
    result = qualify_source_influence_provenance(
        selected_step_ids=tuple(selected_step_ids),
        declared_sources=declared,
        leaf_elements=leaf_elements,
        narrative_elements=narrative_elements,
        leaf_links=leaf_links,
        narrative_links=narrative_links,
    )
    return make_source_influence_provenance_block(
        declared_sources=declared,
        leaf_links=leaf_links,
        narrative_links=narrative_links,
        qualification=result,
    )


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-20T15:28:32Z","module_hash":"14f88f4e67230e0dc3def1bc4d79d1e37f8e31f57da05b914fa2629bad830cd8","functions":[{"id":"func/_load_threat_playbooks_cached","name":"_load_threat_playbooks_cached","line":77,"end_line":90,"hash":"e96d4b649c526ff3d157532ad7577cbdbb720fee2cf5f1e578a22e16b895e984"},{"id":"func/_dedupe_source_refs","name":"_dedupe_source_refs","line":93,"end_line":111,"hash":"f982c5716f3ffe85722562e884b5c1829758fcb29c5b4105bcae47d38b3e30b5"},{"id":"func/_threat_source_refs","name":"_threat_source_refs","line":114,"end_line":121,"hash":"012634033713dfd2cddf4b492b3a2be7eafc785bac3d5cbbf956f2c40a3b39e3"},{"id":"func/_mitigation_source_refs","name":"_mitigation_source_refs","line":124,"end_line":138,"hash":"bc9e5427041785a151d315e17b1b4f2ec9dedc2336bf7311a5d3f87da2bcdeb6"},{"id":"func/_constraint_source_refs","name":"_constraint_source_refs","line":141,"end_line":148,"hash":"4ad7a4519ccb7183c2a50dd1ad27203ed36e368dc2673bacd7da4b7fd8e2702c"},{"id":"func/declared_source_records","name":"declared_source_records","line":151,"end_line":171,"hash":"98db596fc30be3efbe8ed7ced48ab3a11b4bdbd3148a30bcd45589f1ad5855eb"},{"id":"func/_links_for_elements","name":"_links_for_elements","line":174,"end_line":188,"hash":"0231ffdf47c4820050d17f3245f28b966a2d08901b1d02b55f2db8965e1362b3"},{"id":"func/assemble_source_influence_provenance","name":"assemble_source_influence_provenance","line":191,"end_line":242,"hash":"4d356db8b0e7c543b18b3738a8a5ede1af75075524b9f0da89677034a7ecc728"}]}
# mutate4py-manifest-end
