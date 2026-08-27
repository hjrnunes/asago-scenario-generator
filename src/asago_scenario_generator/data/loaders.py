"""Taxonomy data loaders for asago-scenario-generator.

Loads each taxonomy data file into typed structures for use in the
scenario generation pipeline.
"""

from __future__ import annotations

import functools
import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Callable

import yaml

from asago_scenario_generator.data.paths import DATA_ROOT
from asago_scenario_generator.data.sssom import SSSOMMapping, load_sssom
from asago_scenario_generator.models import EvidenceSpan, MitigationRef, RiskCard


class _UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects same-scope duplicate mapping keys."""


def _construct_unique_mapping(
    loader: _UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise ValueError(f"duplicate YAML key: {key}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


def load_yaml_strict(content: bytes | str) -> Any:
    """Safely parse YAML while rejecting duplicate mapping keys."""
    return yaml.load(content, Loader=_UniqueKeyLoader)


def load_agentic_threats(path: str | Path) -> dict[str, Any]:
    """Load OWASP Agentic Threats YAML and return threats keyed by ID.

    Args:
        path: Path to owasp-agentic-threats-v1.1.yaml

    Returns:
        Dict mapping threat IDs (e.g. "T2") to their full threat dicts.
    """
    with open(path) as f:
        data = yaml.safe_load(f)
    return data["threats"]


def load_atlas_techniques(path: str | Path) -> dict[str, Any]:
    """Load MITRE ATLAS YAML and return techniques keyed by ID.

    Args:
        path: Path to ATLAS-2026.05.yaml

    Returns:
        Dict mapping technique IDs (e.g. "AML.T0000") to their full dicts.
    """
    with open(path) as f:
        data = yaml.safe_load(f)
    return data["techniques"]


def load_cross_taxonomy_mappings(path: str | Path) -> dict[str, Any]:
    """Load cross-taxonomy-mappings.yaml.

    Args:
        path: Path to cross-taxonomy-mappings.yaml

    Returns:
        The full parsed YAML as a dict.
    """
    with open(path) as f:
        return yaml.safe_load(f)


_DEFAULT_KC_THREAT_MAPPING_PATH = (
    DATA_ROOT / "taxonomies" / "mappings" / "kc-threat-mapping.yaml"
)


@functools.lru_cache(maxsize=16)
def _load_document_cached(
    path_str: str | None, default_path: str, parser: Callable
) -> Any:
    """Internal cached document loader (string path for hashability)."""
    document_path = Path(path_str) if path_str else Path(default_path)
    with open(document_path) as f:
        return parser(f)


def load_kc_threat_mapping(
    path: str | Path | None = None,
) -> dict[str, Any]:
    """Load KC sub-code to threat mapping YAML.

    Args:
        path: Path to kc-threat-mapping.yaml. Defaults to the bundled file.

    Returns:
        The full parsed YAML as a dict with keys: metadata,
        kc_subcodes, kc_to_threats, threat_to_kc_subcodes, hitl.
    """
    return _load_document_cached(
        str(path) if path else None,
        str(_DEFAULT_KC_THREAT_MAPPING_PATH),
        yaml.safe_load,
    )


def _parse_evidence(raw: dict) -> EvidenceSpan:
    """Convert a policy-mapper evidence dict to an EvidenceSpan.

    The policy-mapper format uses 'document' and 'cross_encoder_score'
    while our model uses 'source' and 'relevance'.
    """
    return EvidenceSpan(
        text=raw["text"],
        source=raw.get("document"),
        relevance=raw.get("cross_encoder_score"),
    )


def _parse_mitigation(raw: dict) -> MitigationRef:
    """Convert a policy-mapper mitigation dict to a MitigationRef.

    The policy-mapper format uses 'action_id'/'action_name'/'description'
    while our model uses 'mitigation_id'/'description'.
    """
    return MitigationRef(
        mitigation_id=raw.get("action_id"),
        description=raw.get("description", raw.get("action_name", "")),
        source=raw.get("source"),
    )


def _risk_extraction_records(data: Any) -> Any:
    """The risk records of a policy-mapper document (dict or raw list)."""
    if isinstance(data, dict):
        return data.get("risks", data)
    return data


def _risk_card_from_raw(r: dict) -> RiskCard:
    """Convert one policy-mapper risk dict to a RiskCard."""
    evidence = [_parse_evidence(e) for e in r.get("evidence", [])]
    mitigations = [_parse_mitigation(m) for m in r.get("mitigations", [])]
    return RiskCard(
        risk_id=r["risk_id"],
        risk_name=r["risk_name"],
        risk_description=r["risk_description"],
        taxonomy=r["taxonomy"],
        confidence=r["confidence"],
        grounding_confidence=r["grounding_confidence"],
        evidence=evidence,
        scores=r.get("scores"),
        mitigations=mitigations,
        threat=r.get("threat"),
        threat_source=r.get("threat_source"),
        vulnerability=r.get("vulnerability"),
        consequence=r.get("consequence"),
        impact=r.get("impact"),
    )


def load_risk_extraction(path: str | Path) -> list[RiskCard]:
    """Load a policy-mapper risk-extraction.json, filtering to IBM Risk Atlas.

    Reads the JSON file, filters to entries with taxonomy == "ibm-risk-atlas",
    and returns them as a list of RiskCard Pydantic models.

    Args:
        path: Path to a risk-extraction.json file.

    Returns:
        List of RiskCard instances for ibm-risk-atlas entries only.
    """
    with open(path) as f:
        data = json.load(f)
    risks_raw = _risk_extraction_records(data)
    return [
        _risk_card_from_raw(r)
        for r in risks_raw
        if r.get("taxonomy") == "ibm-risk-atlas"
    ]


_DEFAULT_ATTACK_PATTERNS_DIR = DATA_ROOT / "taxonomies" / "attack-patterns"

_DEFAULT_ATTACK_PATTERNS_PATH = _DEFAULT_ATTACK_PATTERNS_DIR / "attack-patterns.yaml"


def _load_single_attack_patterns_file(p: Path) -> dict[str, dict]:
    """Load a single attack patterns YAML file and return its patterns dict."""
    with open(p) as f:
        data = yaml.safe_load(f)
    return dict(data.get("patterns", {}))


def load_attack_patterns(
    path: str | Path | None = None,
) -> dict[str, dict]:
    """Load abstract attack patterns YAML, keyed by pattern ID.

    When ``path`` is given, loads just that single file.  When ``path``
    is ``None``, globs all ``attack-patterns*.yaml`` files from the
    default directory and merges their ``patterns`` dicts into one.

    Merging fails loudly on duplicate pattern IDs across files: a pinned
    catalog must not silently overwrite one record with another.

    Returns:
        Dict mapping pattern IDs (e.g. 'AP-T7-01') to their full pattern dicts.

    Raises:
        ValueError: If the merged files declare the same pattern ID.
    """
    if path is not None:
        return _load_single_attack_patterns_file(Path(path))

    # Glob all matching files from the default directory
    files = sorted(_DEFAULT_ATTACK_PATTERNS_DIR.glob("attack-patterns*.yaml"))
    if not files:
        # Fallback: try the exact default path (raises FileNotFoundError if missing)
        return _load_single_attack_patterns_file(_DEFAULT_ATTACK_PATTERNS_PATH)
    return _merge_pattern_files(files)


def _merge_pattern_files(files: list[Path]) -> dict[str, dict]:
    """Merge pattern dicts, failing loudly on duplicate pattern IDs."""
    merged: dict[str, dict] = {}
    origins: dict[str, Path] = {}
    for f in files:
        for pattern_id, pattern in _load_single_attack_patterns_file(f).items():
            if pattern_id in merged:
                raise ValueError(
                    f"duplicate attack pattern id {pattern_id!r} across "
                    f"merged files: {origins[pattern_id]} and {f}"
                )
            merged[pattern_id] = pattern
            origins[pattern_id] = f
    return merged


def build_threat_to_patterns_index(
    patterns: dict[str, dict],
) -> dict[str, list[str]]:
    """Build threat_id -> list of pattern IDs index."""
    index: dict[str, list[str]] = defaultdict(list)
    for pid, pattern in patterns.items():
        index[pattern["threat_id"]].append(pid)
    return dict(index)


_DEFAULT_ATTACK_PATTERNS_SSSOM_PATH = (
    _DEFAULT_ATTACK_PATTERNS_DIR / "attack-patterns.sssom.tsv"
)


def load_attack_pattern_provenance(
    path: str | Path | None = None,
) -> list[SSSOMMapping]:
    """Load attack-pattern SSSOM TSV provenance file(s).

    When ``path`` is given, loads just that single file.  When ``path``
    is ``None``, globs all ``attack-patterns*.sssom.tsv`` files from the
    default directory and concatenates their mappings.

    Args:
        path: Path to the .sssom.tsv file. Defaults to globbing the
              attack-patterns directory.

    Returns:
        List of SSSOMMapping instances.
    """
    if path is not None:
        return load_sssom(Path(path))

    # Glob all matching SSSOM files from the default directory
    files = sorted(_DEFAULT_ATTACK_PATTERNS_DIR.glob("attack-patterns*.sssom.tsv"))
    if not files:
        # Fallback: try the exact default path (raises FileNotFoundError if missing)
        return load_sssom(_DEFAULT_ATTACK_PATTERNS_SSSOM_PATH)

    merged: list[SSSOMMapping] = []
    for f in files:
        merged.extend(load_sssom(f))
    return merged


def build_pattern_provenance_index(
    mappings: list[SSSOMMapping],
) -> dict[str, dict[str, list[str]]]:
    """Build a nested index of pattern provenance by source.

    Returns:
        Dict mapping pattern IDs to dicts of object_source -> list of
        object IDs.  Example::

            {
                "AP-T7-01": {
                    "laaf": ["S1", "M3"],
                    "mitre-atlas": ["AML.T0054", "AML.T0015", "AML.T0053"],
                },
                ...
            }
    """
    index: dict[str, dict[str, list[str]]] = {}
    for m in mappings:
        pid = m.subject_id
        src = m.object_source
        if pid not in index:
            index[pid] = {}
        if src not in index[pid]:
            index[pid][src] = []
        if m.object_id not in index[pid][src]:
            index[pid][src].append(m.object_id)
    return index


# ---------------------------------------------------------------------------
# Attack Goals Taxonomy
# ---------------------------------------------------------------------------

_ATTACK_GOALS_TAXONOMY_PATH = (
    DATA_ROOT / "taxonomies" / "attack-goals" / "attack-goals.json"
)


def load_attack_goals_taxonomy(
    path: Path | None = None,
) -> dict[str, Any]:
    """Load the attack goals taxonomy JSON file.

    Returns the parsed taxonomy dict with 'version' and 'categories' keys.
    Results are cached per unique path.
    """
    return _load_document_cached(
        str(path) if path else None, str(_ATTACK_GOALS_TAXONOMY_PATH), json.load
    )


# ---------------------------------------------------------------------------
# Threat-goal affinity map
# ---------------------------------------------------------------------------

_THREAT_GOAL_AFFINITY_PATH = (
    DATA_ROOT / "taxonomies" / "attack-goals" / "threat-goal-affinity.yaml"
)


@functools.lru_cache(maxsize=4)
def _load_threat_goal_affinity_cached(
    path_str: str | None,
) -> dict[str, dict[str, list[str]]]:
    """Internal cached loader — takes a string path for hashability."""
    affinity_path = Path(path_str) if path_str else _THREAT_GOAL_AFFINITY_PATH
    with open(affinity_path) as f:
        data = yaml.safe_load(f)
    return data["affinities"]


def load_threat_goal_affinity(
    path: Path | None = None,
) -> dict[str, dict[str, list[str]]]:
    """Load the threat-goal affinity YAML map.

    Returns a dict keyed by threat ID (e.g. 'T1') whose values are dicts
    with keys 'primary', 'secondary', 'excluded' — each a list of category IDs.
    Results are cached per unique path.
    """
    return _load_threat_goal_affinity_cached(str(path) if path else None)
