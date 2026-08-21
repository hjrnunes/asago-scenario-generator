"""Loader, semantic validator, and deterministic digest for catalog lineage.

The catalog-lineage artifact
(``data/taxonomies/attack-patterns/catalog-lineage.yaml``) is the final,
versioned, machine-readable record of how each of the 71 legacy
attack-pattern source records maps to resulting authoritative patterns for
the canonical chain-authoring waves.  It is validated against the closed
Draft 2020-12 schema at ``data/schemas/catalog-lineage.yaml`` plus the
semantic gates in :func:`validate_catalog_lineage`:

- exactly 71 unique historical source entries, each with internally
  coherent source facts (file, threat, evidence tier/count, kill-chain
  count) drawn from artifact data alone;
- the source-catalog content pin (:func:`compute_source_catalog_digest`)
  commits the exact canonicalized historical loader records at the recorded
  ``source_git_revision``; the artifact carries the pin durably while the
  recompute-and-compare audit lives in the explicit
  :func:`verify_catalog_lineage_source_snapshot`, so normal validation
  stays green after the live catalog migrates through the authoring waves;
- taxonomy pins match the production resolver (ATLAS-only; LAAF absent);
- every proposed exact ATLAS id exists in the production resolver — with the
  schema requiring nonblank operational-identity rationale and evidence so
  membership alone is never semantic approval;
- every ``AML.CSxxxx Snn`` case-step citation in a mapping's evidence is
  checked against the pinned ATLAS case-study relationships: the cited case
  and steps must exist, and an unhedged citation (no ``analogue`` /
  ``adapted`` / ``retag`` marker in its evidence segment) must cite at least
  one step whose pinned ``employs`` relationship assigns exactly the mapped
  technique.  Deliberate definition-level divergences must be explicitly
  marked and explained instead of asserting source assignment;
- disposition/resulting invariants: retired and deferred sources carry no
  resulting record; resulting ids are unique and collision-free against the
  existing catalog unless they continue their own source id; split sources
  map explicitly to two or more resulting ids;
- overlap groups have one explicit resolution covering all members.

The release digest (:func:`compute_catalog_lineage_digest`) is a
deterministic semantic digest: every string is NFC-normalized, object keys
are emitted in sorted order, and every array is framed as a sorted set, so
the digest is insensitive to key order and array order but sensitive to any
content change.  Only ``release.semantic_digest`` itself is excluded.

The source-catalog pin is a separate deterministic digest over the
canonicalized attack-pattern loader records (NFC-normalized strings, sorted
object keys, order-preserving arrays because kill-chain order is semantic),
framed per declaring file under a versioned domain.  It pins loader-record
content, not source YAML bytes, and it commits the historical baseline the
decisions were made against: ``source_catalog_context.source_git_revision``
records the authoritative original catalog revision.  Later authoring waves
change the live catalog (converted kill chains removed, split-derived ids
added); :func:`validate_catalog_lineage` therefore never consults the live
catalog, and creation-time/source-audit verification is the explicit
:func:`verify_catalog_lineage_source_snapshot` against a catalog supplied
from that pinned revision.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator

from asago_scenario_generator.data.canonical import (
    _canonical_json,
    _nfc,
    _normalize,
)

_DEFAULT_LINEAGE_PATH = (
    Path(__file__).resolve().parents[3]
    / "data"
    / "taxonomies"
    / "attack-patterns"
    / "catalog-lineage.yaml"
)
_DEFAULT_SCHEMA_PATH = (
    Path(__file__).resolve().parents[3] / "data" / "schemas" / "catalog-lineage.yaml"
)
# Pinned ATLAS source; kept in sync with taxonomy_pins._DEFAULT_ATLAS_PATH.
_DEFAULT_ATLAS_PATH = (
    Path(__file__).resolve().parents[3]
    / "data"
    / "taxonomies"
    / "atlas"
    / "ATLAS-2026.05.yaml"
)
_LINEAGE_DOMAIN = "asago-scenario-generator:catalog-lineage:v1"
_SOURCE_CATALOG_DOMAIN = "asago-scenario-generator:attack-pattern-catalog:v1"
SOURCE_CATALOG_CANONICALIZATION = "asago-scenario-generator:attack-pattern-records:v1"

_FINAL_DISPOSITIONS = frozenset(
    {"retain", "narrow", "split", "supersede", "retire", "defer"}
)

# Markers that make a case-step citation hedged: the mapping deliberately
# diverges from the pinned relationship and says so in the evidence segment.
_HEDGE_TOKENS = ("analogue", "adapted", "retag")
_CASE_STEP_RE = re.compile(r"AML\.(CS\d{4})\s+((?:S\d{2})(?:\s*[-/,]\s*S?\d{2})*)")
_STEP_NUMBER_RE = re.compile(r"\d{2}")


def load_catalog_lineage(path: str | Path | None = None) -> dict[str, Any]:
    """Load the catalog-lineage artifact as a plain dict (no validation)."""
    lineage_path = Path(path) if path is not None else _DEFAULT_LINEAGE_PATH
    with open(lineage_path) as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise TypeError(f"catalog lineage {lineage_path} is not a mapping")
    return data


def load_catalog_lineage_schema(path: str | Path | None = None) -> dict[str, Any]:
    """Load the closed Draft 2020-12 schema for the artifact."""
    schema_path = Path(path) if path is not None else _DEFAULT_SCHEMA_PATH
    with open(schema_path) as f:
        schema = yaml.safe_load(f)
    if not isinstance(schema, dict):
        raise TypeError(f"catalog lineage schema {schema_path} is not a mapping")
    Draft202012Validator.check_schema(schema)
    return schema


def compute_catalog_lineage_digest(artifact: dict[str, Any]) -> str:
    """Deterministic semantic digest over normalized artifact content.

    Excludes only ``release.semantic_digest``.  NFC-normalized; object key
    order and array order are normalized away; framed under a versioned
    domain so the digest never collides with other pinned content.
    """
    if not isinstance(artifact, dict):
        raise TypeError("catalog lineage artifact must be a mapping")
    release = artifact.get("release")
    if not isinstance(release, dict) or "semantic_digest" not in release:
        raise ValueError("catalog lineage artifact lacks release.semantic_digest")
    stripped = {
        **artifact,
        "release": {k: v for k, v in release.items() if k != "semantic_digest"},
    }
    payload = (
        _LINEAGE_DOMAIN.encode()
        + b"\0"
        + _canonical_json(_normalize(stripped)).encode("utf-8")
    )
    return hashlib.sha256(payload).hexdigest()


def _normalize_record(value: Any) -> Any:
    """Canonicalize a loader record for the source-catalog pin.

    Unlike the lineage digest normalization, array order is preserved:
    kill-chain step order is semantic.  Object key order is normalized away
    by the canonical-JSON sort; strings are NFC-normalized; non-JSON scalar
    values (for example YAML dates) are stringified deterministically.
    """
    if isinstance(value, dict):
        return {str(k): _normalize_record(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_normalize_record(item) for item in value]
    if isinstance(value, str):
        return _nfc(value)
    if value is None or isinstance(value, bool | int | float):
        return value
    return str(value)


def compute_source_catalog_digest(
    patterns: Mapping[str, Mapping[str, Any]],
    owners: Mapping[str, str],
    manifest: list[str],
) -> str:
    """Deterministic content pin over the production source catalog records.

    ``patterns`` is the production catalog from
    :func:`asago_scenario_generator.data.loaders.load_attack_patterns`; ``owners``
    maps every catalog id to its declaring attack-patterns file;
    ``manifest`` is the expected ordered file list.  Each record is framed
    with its id under its declaring file so reassignment, deletion, or any
    same-count content edit (description, evidence source, kill-chain
    action or technique) changes the digest.
    """
    unowned = sorted(set(patterns) - set(owners))
    if unowned:
        raise ValueError(f"source catalog ids without a declaring file: {unowned}")
    undeclared = sorted(set(owners.values()) - set(manifest))
    if undeclared:
        raise ValueError(f"owners reference files outside the manifest: {undeclared}")
    files = []
    for filename in manifest:
        records = sorted(
            (
                pid,
                _canonical_json(_normalize_record(patterns[pid])),
            )
            for pid, owner in owners.items()
            if owner == filename
        )
        files.append(
            {
                "file": filename,
                "records": [[pid, blob] for pid, blob in records],
            }
        )
    framed = {
        "canonicalization": SOURCE_CATALOG_CANONICALIZATION,
        "files": files,
    }
    payload = (
        _SOURCE_CATALOG_DOMAIN.encode()
        + b"\0"
        + _canonical_json(framed).encode("utf-8")
    )
    return hashlib.sha256(payload).hexdigest()


def load_atlas_case_step_index(
    path: str | Path | None = None,
) -> dict[str, dict[str, frozenset[str]]]:
    """Pinned ATLAS case-step index: case id -> step id -> employed techniques.

    Drawn from the ``employs`` relationships of the pinned ATLAS source.
    Case studies remain provenance, never mapping authority; this index
    exists so citations of them can be checked for semantic consistency.
    """
    atlas_path = Path(path) if path is not None else _DEFAULT_ATLAS_PATH
    with open(atlas_path) as f:
        data = yaml.safe_load(f)
    index: dict[str, dict[str, frozenset[str]]] = {}
    for case_id, bundle in (data.get("relationships") or {}).items():
        if not isinstance(case_id, str) or not case_id.startswith("AML.CS"):
            continue
        steps: dict[str, set[str]] = {}
        for employs in (bundle or {}).get("employs") or []:
            step_id = employs.get("step-id")
            target = employs.get("target")
            if isinstance(step_id, str) and isinstance(target, str):
                steps.setdefault(step_id, set()).add(target)
        if steps:
            index[case_id] = {sid: frozenset(t) for sid, t in steps.items()}
    return index


def _parse_step_expr(expr: str) -> list[str]:
    """Expand a citation step expression like ``S01``, ``S01/S04``, ``S05-S09``."""
    steps: list[str] = []
    for part in re.split(r"\s*[/,]\s*", expr):
        lo, dash, hi = part.partition("-")
        if dash:
            bounds = _STEP_NUMBER_RE.findall(lo + hi)
            if len(bounds) != 2:
                raise ValueError(f"unparseable case-step range {part!r}")
            start, end = int(bounds[0]), int(bounds[1])
            steps.extend(f"S{n:02d}" for n in range(start, end + 1))
        else:
            (number,) = _STEP_NUMBER_RE.findall(part)
            steps.append(f"S{int(number):02d}")
    return steps


def _mapping_citation_errors(
    record_id: str,
    mapping_id: str,
    evidence: str,
    case_steps: Mapping[str, Mapping[str, frozenset[str]]],
) -> list[str]:
    """Check every ``AML.CSxxxx Snn`` citation in one mapping's evidence.

    The evidence string is split into ``;``-separated segments; a segment
    carrying a hedge token (``analogue``/``adapted``/``retag``) declares a
    deliberate definition-level divergence and is exempt from the
    assignment check.  Every citation — hedged or not — must reference a
    case and steps that exist in the pinned ATLAS relationships; an
    unhedged citation must cite at least one step whose pinned ``employs``
    relationship assigns exactly the mapped technique.
    """
    errors: list[str] = []
    for segment in evidence.split(";"):
        citations = list(_CASE_STEP_RE.finditer(segment))
        if not citations:
            continue
        hedged = any(token in segment.lower() for token in _HEDGE_TOKENS)
        for match in citations:
            case_id, step_expr = f"AML.{match.group(1)}", match.group(2)
            label = f"{case_id} {step_expr}"
            if case_id not in case_steps:
                errors.append(
                    f"{record_id} mapping {mapping_id}: cited case {case_id} "
                    "is absent from the pinned ATLAS relationships"
                )
                continue
            try:
                steps = _parse_step_expr(step_expr)
            except ValueError as exc:
                errors.append(f"{record_id} mapping {mapping_id}: {exc}")
                continue
            unknown = [s for s in steps if s not in case_steps[case_id]]
            if unknown:
                errors.append(
                    f"{record_id} mapping {mapping_id}: citation {label} "
                    f"references steps {unknown} absent from {case_id} in the "
                    "pinned ATLAS relationships"
                )
                continue
            if hedged:
                continue
            if not any(mapping_id in case_steps[case_id][s] for s in steps):
                employed = sorted({t for s in steps for t in case_steps[case_id][s]})
                errors.append(
                    f"{record_id} mapping {mapping_id}: unhedged citation "
                    f"{label} asserts source assignment, but the pinned "
                    f"relationships there employ {employed}, not "
                    f"{mapping_id}; correct the citation or explicitly mark "
                    "the deliberate divergence as analogue/adapted/retag"
                )
    return errors


def _split_pattern_id(pattern_id: str) -> tuple[str, int]:
    """Split ``AP-T<fam>-<NN>`` into its threat family and sequence number."""
    fam, _, nn = pattern_id.removeprefix("AP-T").partition("-")
    return fam, int(nn)


def _mapping_ids(resulting: dict[str, Any]) -> list[str]:
    ids = [m["id"] for m in resulting["atlas_chain_mappings"]]
    ids.extend(m["id"] for m in resulting["atlas_step_mappings"])
    return ids


def _evidence_tier(pattern: Mapping[str, Any]) -> str:
    """Mutually exclusive evidence tier for a loader record."""
    evidence = pattern.get("evidence") or []
    if any(e.get("type") == "direct_demonstration" for e in evidence):
        return "direct_demonstration"
    if evidence:
        return "enrichment"
    if pattern.get("kill_chain"):
        return "kill_chain_only"
    return "none"


def _check_source_entry_coherence(entry: Mapping[str, Any]) -> None:
    """Artifact-internal coherence of one source entry's recorded facts.

    Replaces any live-catalog comparison: the tier must be consistent with
    the recorded evidence/kill-chain counts, so the entry is self-attesting.
    """
    pid = entry["source_pattern_id"]
    tier = entry["evidence_tier"]
    evidence_count = entry["evidence_count"]
    legacy_steps = entry["legacy_kill_chain_steps"]
    coherent = {
        "direct_demonstration": evidence_count >= 1,
        "enrichment": evidence_count >= 1,
        "kill_chain_only": evidence_count == 0 and legacy_steps >= 1,
        "none": evidence_count == 0 and legacy_steps == 0,
    }[tier]
    if not coherent:
        raise ValueError(
            f"catalog lineage entry {pid} is internally incoherent: "
            f"evidence_tier={tier!r} with evidence_count={evidence_count} "
            f"and legacy_kill_chain_steps={legacy_steps}"
        )


def validate_catalog_lineage(
    artifact: dict[str, Any],
    *,
    resolver: Any,
    case_steps: Mapping[str, Mapping[str, frozenset[str]]],
    schema: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Schema-validate and semantically qualify the immutable lineage artifact.

    Validation is durable: it draws on artifact data, the taxonomy resolver,
    and the pinned ATLAS case-step index only — never the mutable live
    attack-pattern catalog, so it stays green after later authoring waves
    migrate that catalog.  ``resolver`` implements the production
    ``TaxonomyResolver`` protocol (``taxonomy_context`` + ``contains``);
    ``case_steps`` is the pinned ATLAS case-step index from
    :func:`load_atlas_case_step_index`, required for the mapping-citation
    gate.  Creation-time/source-audit comparison against the historical
    catalog is the explicit :func:`verify_catalog_lineage_source_snapshot`.
    Returns the artifact on success; raises ``ValueError`` (or
    ``jsonschema.ValidationError``) on any breach.
    """
    schema = schema if schema is not None else load_catalog_lineage_schema()
    Draft202012Validator(schema).validate(artifact)

    # Taxonomy pins must match the production resolver exactly.
    context = artifact["taxonomy_context"]
    expected = resolver.taxonomy_context
    if context["laaf"] is not None:
        raise ValueError("catalog lineage taxonomy_context.laaf must be null for v1")
    if (
        context["atlas"]["release"] != expected.atlas.release
        or context["atlas"]["digest"] != expected.atlas.digest
        or context["mapping_set_digest"] != expected.mapping_set_digest
        or expected.laaf is not None
    ):
        raise ValueError(
            "catalog lineage taxonomy pins do not match the production resolver"
        )

    # The source-catalog pin is checked for internal coherence only; the
    # recompute-and-compare audit against the historical catalog is the
    # explicit snapshot verifier (creation-time/source-audit use).
    pin = artifact["source_catalog_context"]
    if pin["canonicalization"] != SOURCE_CATALOG_CANONICALIZATION:
        raise ValueError(
            "catalog lineage source catalog canonicalization "
            f"{pin['canonicalization']!r} is not {SOURCE_CATALOG_CANONICALIZATION!r}"
        )
    sources = artifact["sources"]
    if pin["record_count"] != len(sources):
        raise ValueError(
            f"catalog lineage source catalog record_count {pin['record_count']} "
            f"does not match the {len(sources)} source entries"
        )
    manifest = pin["file_manifest"]
    if manifest != sorted(manifest):
        raise ValueError("catalog lineage source catalog manifest is not sorted")
    declared_files = set(manifest)
    for entry in sources:
        if entry["source_file"] not in declared_files:
            raise ValueError(
                f"catalog lineage entry {entry['source_pattern_id']} "
                f"source_file={entry['source_file']!r} is not in the source "
                "catalog manifest"
            )

    # The disposition vocabulary keys are exactly the closed disposition enum.
    if set(artifact["disposition_vocabulary"]) != _FINAL_DISPOSITIONS:
        raise ValueError(
            "disposition_vocabulary keys diverge from the closed vocabulary"
        )

    source_ids = [entry["source_pattern_id"] for entry in sources]
    if len(set(source_ids)) != len(source_ids):
        raise ValueError("duplicate source_pattern_id in catalog lineage sources")

    # Source-entry facts must be internally coherent (self-attesting).
    by_id = {entry["source_pattern_id"]: entry for entry in sources}
    for entry in sources:
        _check_source_entry_coherence(entry)

    # Overlap groups: unique ids, one resolution, members are sources, and
    # membership is consistent with the per-entry overlap_group references.
    groups = artifact["overlap_groups"]
    group_ids = [g["group_id"] for g in groups]
    if len(set(group_ids)) != len(group_ids):
        raise ValueError("duplicate overlap group_id in catalog lineage")
    member_to_group: dict[str, str] = {}
    for group in groups:
        for member in group["members"]:
            if member not in by_id:
                raise ValueError(
                    f"overlap group {group['group_id']} member {member} is not a source"
                )
            if member in member_to_group:
                raise ValueError(
                    f"overlap member {member} appears in more than one group"
                )
            member_to_group[member] = group["group_id"]
    for entry in sources:
        referenced = entry["overlap_group"]
        pid = entry["source_pattern_id"]
        if referenced is None:
            if pid in member_to_group:
                raise ValueError(
                    f"overlap group {member_to_group[pid]} lists {pid} but the "
                    "source entry references no group"
                )
            continue
        if referenced not in set(group_ids):
            raise ValueError(
                f"source {pid} references unknown overlap group {referenced}"
            )
        if member_to_group.get(pid) != referenced:
            raise ValueError(
                f"source {pid} references overlap group {referenced} but is "
                "not listed as a member"
            )

    # Resulting records: uniqueness, collision-freedom against the 71
    # historical source ids, disposition rules, resolver membership for
    # every proposed exact ATLAS id, and pinned case-step citation
    # consistency for every mapping.
    catalog_ids = set(source_ids)
    resulting_ids: list[str] = []
    citation_errors: list[str] = []
    for entry in sources:
        pid = entry["source_pattern_id"]
        disposition = entry["disposition"]
        resulting = entry["resulting_patterns"]
        if disposition in ("retire", "defer"):
            if resulting:
                raise ValueError(
                    f"{disposition} source {pid} carries resulting patterns"
                )
            continue
        if disposition in ("retain", "narrow", "supersede"):
            expected_ids = {pid} if disposition != "supersede" else None
            for record in resulting:
                rid = record["pattern_id"]
                if expected_ids is not None and rid != pid:
                    raise ValueError(
                        f"{disposition} source {pid} resulting id {rid} must "
                        "continue its source id"
                    )
        for record in resulting:
            rid = record["pattern_id"]
            if rid in catalog_ids and rid != pid:
                raise ValueError(
                    f"resulting id {rid} from source {pid} collides with an "
                    "existing catalog id"
                )
            if record["source_file"] not in _SOURCE_FILES:
                raise ValueError(f"resulting id {rid} has an unknown source_file")
            if record["source_file"] != entry["source_file"]:
                raise ValueError(
                    f"resulting id {rid} from source {pid} is owned by "
                    f"{record['source_file']!r}, not the source file "
                    f"{entry['source_file']!r}"
                )
            for atlas_id in _mapping_ids(record):
                if not resolver.contains("ATLAS", atlas_id):
                    raise ValueError(
                        f"resulting id {rid} proposes unknown ATLAS id {atlas_id}"
                    )
            for mapping in (
                record["atlas_chain_mappings"] + record["atlas_step_mappings"]
            ):
                citation_errors.extend(
                    _mapping_citation_errors(
                        rid, mapping["id"], mapping["evidence"], case_steps
                    )
                )
            resulting_ids.append(rid)
    if len(set(resulting_ids)) != len(resulting_ids):
        raise ValueError("duplicate resulting pattern id across catalog lineage")
    if citation_errors:
        raise ValueError(
            "catalog lineage case-step citation inconsistencies:\n  - "
            + "\n  - ".join(citation_errors)
        )

    # Split-derived ids must follow the deterministic naming strategy: split
    # sources are processed in ascending source id order; the first resulting
    # record (causal mechanism order) continues the source id; each subsequent
    # record takes the lowest unused NN in the source threat family across the
    # merged catalog plus ids already allocated to earlier splits.
    family_used: dict[str, set[int]] = {}
    for cid in catalog_ids:
        fam, nn = _split_pattern_id(cid)
        family_used.setdefault(fam, set()).add(nn)
    for entry in sorted(sources, key=lambda e: e["source_pattern_id"]):
        if entry["disposition"] != "split":
            continue
        pid = entry["source_pattern_id"]
        fam, _ = _split_pattern_id(pid)
        results = entry["resulting_patterns"]
        if results[0]["pattern_id"] != pid:
            raise ValueError(
                f"split source {pid} first resulting id "
                f"{results[0]['pattern_id']!r} must continue the source id "
                "in causal mechanism order"
            )
        used = family_used[fam]
        for record in results[1:]:
            nn = 1
            while nn in used:
                nn += 1
            expected = f"AP-T{fam}-{nn:02d}"
            if record["pattern_id"] != expected:
                raise ValueError(
                    f"split source {pid} derived id {record['pattern_id']!r} "
                    f"must be the lowest unused family id {expected!r}"
                )
            used.add(nn)

    # Release digest must recompute deterministically.
    recorded = artifact["release"]["semantic_digest"]
    recomputed = compute_catalog_lineage_digest(artifact)
    if recorded != recomputed:
        raise ValueError(
            f"catalog lineage digest mismatch: recorded {recorded} != recomputed {recomputed}"
        )
    return artifact


def verify_catalog_lineage_source_snapshot(
    artifact: dict[str, Any],
    *,
    patterns: Mapping[str, Mapping[str, Any]],
    owners: Mapping[str, str],
    schema: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Creation-time/source-audit verification against the historical catalog.

    Explicit opt-in counterpart to :func:`validate_catalog_lineage`: the
    caller supplies the attack-pattern catalog (``patterns`` from
    :func:`asago_scenario_generator.data.loaders.load_attack_patterns`) and per-file
    ownership loaded from the artifact's pinned
    ``source_catalog_context.source_git_revision`` — the authoritative
    original catalog baseline the decisions were made against.  Verifies:

    - the source-catalog content pin recomputes from the supplied records
      (so any same-count content edit is detected);
    - the pinned manifest, record count, and canonicalization match the
      supplied catalog;
    - exactly the supplied catalog ids appear as sources, once each;
    - every source entry's recorded facts (source file, threat, evidence
      tier/count, legacy kill-chain count) match the supplied records.

    Returns the artifact on success; raises ``ValueError`` (or
    ``jsonschema.ValidationError``) on any breach.
    """
    schema = schema if schema is not None else load_catalog_lineage_schema()
    Draft202012Validator(schema).validate(artifact)

    pin = artifact["source_catalog_context"]
    if pin["canonicalization"] != SOURCE_CATALOG_CANONICALIZATION:
        raise ValueError(
            "catalog lineage source catalog canonicalization "
            f"{pin['canonicalization']!r} is not {SOURCE_CATALOG_CANONICALIZATION!r}"
        )
    manifest = pin["file_manifest"]
    actual_files = sorted({owners[pid] for pid in patterns})
    if sorted(manifest) != actual_files:
        raise ValueError(
            f"catalog lineage source catalog manifest {sorted(manifest)} does "
            f"not match the supplied declaring files {actual_files}"
        )
    if pin["record_count"] != len(patterns):
        raise ValueError(
            f"catalog lineage source catalog record_count {pin['record_count']} "
            f"does not match the supplied catalog size {len(patterns)}"
        )
    recomputed_pin = compute_source_catalog_digest(patterns, owners, manifest)
    if pin["digest"] != recomputed_pin:
        raise ValueError(
            "catalog lineage source catalog digest mismatch: recorded "
            f"{pin['digest']} != recomputed {recomputed_pin} (supplied records "
            "must come from the pinned source_git_revision "
            f"{pin['source_git_revision']})"
        )

    sources = artifact["sources"]
    source_ids = [entry["source_pattern_id"] for entry in sources]
    if len(set(source_ids)) != len(source_ids):
        raise ValueError("duplicate source_pattern_id in catalog lineage sources")
    if set(source_ids) != set(patterns):
        missing = sorted(set(patterns) - set(source_ids))
        extra = sorted(set(source_ids) - set(patterns))
        raise ValueError(
            f"catalog lineage sources diverge from the supplied catalog; "
            f"missing={missing} extra={extra}"
        )

    # Source-entry facts must match the supplied historical loader records.
    by_id = {entry["source_pattern_id"]: entry for entry in sources}
    for pid, pattern in patterns.items():
        entry = by_id[pid]
        mismatches = {
            "threat_id": (entry["threat_id"], pattern["threat_id"]),
            "evidence_tier": (entry["evidence_tier"], _evidence_tier(pattern)),
            "evidence_count": (
                entry["evidence_count"],
                len(pattern.get("evidence") or []),
            ),
            "legacy_kill_chain_steps": (
                entry["legacy_kill_chain_steps"],
                len(pattern.get("kill_chain") or []),
            ),
        }
        for field, (claimed, actual) in mismatches.items():
            if claimed != actual:
                raise ValueError(
                    f"catalog lineage entry {pid} {field}={claimed!r} "
                    f"does not match the supplied catalog value {actual!r}"
                )
        if entry["source_file"] != owners[pid]:
            raise ValueError(
                f"catalog lineage entry {pid} source_file={entry['source_file']!r} "
                f"does not match the declaring file {owners[pid]!r}"
            )
    return artifact


_SOURCE_FILES = frozenset(
    {
        "attack-patterns.yaml",
        "attack-patterns-agentic-only.yaml",
        "attack-patterns-atlas-derived.yaml",
        "attack-patterns-comms-human-supply.yaml",
        "attack-patterns-halluc-intent.yaml",
        "attack-patterns-memory-tool.yaml",
    }
)
