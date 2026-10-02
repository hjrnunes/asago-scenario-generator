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


def _risk_extraction_records(data: Any) -> Any:
    """The risk records of a policy-mapper document (dict or raw list)."""
    if isinstance(data, dict):
        return data.get("risks", data)
    return data


def _reviewed_evidence_from_raw(raw: dict[str, Any]) -> EvidenceSpan:
    """Project one reviewed evidence span as the Phase 1 input builder does.

    Policy-mapper's ``cross_encoder_score`` is a ranking score, not the
    reviewed evidence relevance field consumed by the closed obligation
    contract.  In particular, preserving a missing/``null`` ``relevance``
    value is part of the Phase 1 input identity.
    """
    return EvidenceSpan(
        text=raw.get("text", ""),
        source=raw.get("document") or raw.get("source"),
        relevance=raw.get("relevance"),
    )


def _reviewed_mitigation_from_raw(raw: dict[str, Any]) -> MitigationRef:
    """Project one reviewed mitigation using the Phase 1 field precedence."""
    return MitigationRef(
        mitigation_id=raw.get("mitigation_id") or raw.get("action_id"),
        description=(
            raw.get("description")
            or raw.get("action_description")
            or raw.get("action_name")
            or ""
        ),
        source=raw.get("source"),
    )


def _reviewed_risk_card_from_raw(raw: dict[str, Any]) -> RiskCard:
    """Project a raw reviewed record without applying the IBM taxonomy filter."""
    return RiskCard(
        risk_id=raw["risk_id"],
        risk_name=raw.get("risk_name", ""),
        risk_description=raw.get("risk_description", ""),
        taxonomy=raw.get("taxonomy", ""),
        confidence=raw.get("confidence", 0.0),
        grounding_confidence=raw.get("grounding_confidence", "low"),
        evidence=[
            _reviewed_evidence_from_raw(item) for item in raw.get("evidence", [])
        ],
        scores=raw.get("scores"),
        mitigations=[
            _reviewed_mitigation_from_raw(item) for item in raw.get("mitigations", [])
        ],
        threat=raw.get("threat"),
        threat_source=raw.get("threat_source"),
        vulnerability=raw.get("vulnerability"),
        consequence=raw.get("consequence"),
        impact=raw.get("impact"),
    )


def load_reviewed_risk_extraction(path: str | Path) -> list[RiskCard]:
    """Load every reviewed risk record with the closed Phase 1 projection.

    Unlike :func:`load_risk_extraction`, this synthesis-only loader does not
    filter by taxonomy.  The obligation planner receives the complete
    reviewed risk set so its identity can be checked against a supplied typed
    snapshot.  The existing filtered loader remains unchanged for ``generate``
    compatibility.
    """
    with open(path) as f:
        data = json.load(f)
    risks_raw = _risk_extraction_records(data)
    return [_reviewed_risk_card_from_raw(r) for r in risks_raw]


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


# ---------------------------------------------------------------------------
# Attack Goals Taxonomy
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Threat-goal affinity map
# ---------------------------------------------------------------------------
