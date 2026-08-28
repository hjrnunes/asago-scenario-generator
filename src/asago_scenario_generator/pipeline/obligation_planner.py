"""Deterministic offline taxonomy obligation planner."""

from __future__ import annotations

import json
from typing import Any

from asago_scenario_generator.models.obligation_plan import (
    CandidateRecord,
    ObligationPlanSummary,
    ObligationProjectionDisposition,
    QualificationTraceItem,
    TaxonomyObligation,
    TaxonomyObligationPlan,
    TaxonomyObligationSnapshot,
    compute_sha256,
)

_DEFAULT_CATALOG_PIN = "atlas-2026.05"
_DEFAULT_MAPPING_PIN = "sssom-v1"
_REDACTED = "[REDACTED]"

# Legacy single "disposition" strings mapped to their default (scope,
# qualification, projection) dispositions. A None component leaves that
# disposition to its explicit or kind-derived resolution below.
_LEGACY_DISPOSITION_DEFAULTS: dict[str, tuple[str | None, str, str | None]] = {
    "governance-only": ("governance_only", "not_attempted", "not_attempted"),
    "governance_only": ("governance_only", "not_attempted", "not_attempted"),
    "gated": ("capability_excluded", "not_attempted", "not_attempted"),
    "missing-template": (None, "missing_evidence", None),
    "missing_evidence": (None, "missing_evidence", None),
    "infeasible": (None, "structurally_infeasible", None),
    "unsupported": (None, "structurally_infeasible", None),
    "structurally_infeasible": (None, "structurally_infeasible", None),
    "contradictory_evidence": (None, "contradictory_evidence", None),
    "generated": (None, "ready", None),
    "ready": (None, "ready", None),
    "not_attempted": (None, "not_attempted", None),
}

# Relationship-kind substrings that force an excluded or governance scope.
_KIND_EXCLUSION_SUBSTRINGS = ("gated", "capability")
_KIND_GOVERNANCE_SUBSTRINGS = ("governance", "orphan")

# Relationship-kind substrings mapped to their qualification disposition, in
# evaluation order. Kinds matching no rule qualify as ready.
_KIND_QUALIFICATION_RULES: tuple[tuple[tuple[str, ...], str], ...] = (
    (("missing",), "missing_evidence"),
    (("contradict",), "contradictory_evidence"),
    (
        ("infeasib", "structurally", "unsupported"),
        "structurally_infeasible",
    ),
    (("ready", "qualified", "generated", "projectable"), "ready"),
)

_EXCLUDED_SCOPES = ("capability_excluded", "governance_only")
_APPLICABLE_QUALIFICATIONS = (
    "ready",
    "missing_evidence",
    "contradictory_evidence",
    "structurally_infeasible",
)
_SETTLED_PROJECTIONS = ("not_attempted", "projection_infeasible")

# Candidate expansion sections in consumption order: (expansion key, default
# projection disposition, default reason, honor rejection_reason, accept bare
# string entries).
_CANDIDATE_SECTIONS: tuple[
    tuple[str, ObligationProjectionDisposition, str, bool, bool], ...
] = (
    ("candidates", "projectable", "", False, False),
    ("accepted_candidates", "projectable", "qualified combination", True, True),
    (
        "rejected_candidates",
        "projection_infeasible",
        "missing required resource",
        True,
        True,
    ),
)


def _collect_config_secrets(config: dict[str, Any]) -> set[str]:
    """Collect secret string tokens from configuration to sanitize traces."""
    secrets: set[str] = set()
    for _key, val in config.items():
        if isinstance(val, str) and val.strip():
            secrets.add(val.strip())
    return secrets


def _redact_text(text: str, secrets: set[str]) -> str:
    """Replace every known secret occurrence in a string."""
    for secret in secrets:
        if secret in text:
            text = text.replace(secret, _REDACTED)
    return text


def _sanitize_secrets(value: Any, secrets: set[str]) -> Any:
    """Remove known secrets from values."""
    if not secrets:
        return value
    if isinstance(value, str):
        return _redact_text(value, secrets)
    return _sanitize_container(value, secrets)


def _sanitize_container(value: Any, secrets: set[str]) -> Any:
    """Redact secrets inside mapping or sequence values."""
    if isinstance(value, dict):
        return {key: _sanitize_secrets(item, secrets) for key, item in value.items()}
    if isinstance(value, list):
        return [_sanitize_secrets(item, secrets) for item in value]
    return value


def _canonical_obligation_id(risk_id: str, pattern_id: str | None, pin_tag: str) -> str:
    """Construct deterministic canonical obligation identifier."""
    if pattern_id:
        return f"ob:{risk_id}:{pattern_id}:{pin_tag}"
    return f"ob:{risk_id}:{pin_tag}"


def _raw_dispositions(rel: dict[str, Any]) -> tuple[Any, Any, Any]:
    """Read explicit scope, qualification, and projection dispositions."""
    return (
        rel.get("scope_disposition") or rel.get("scope"),
        rel.get("qualification_disposition") or rel.get("qualification"),
        rel.get("projection_disposition") or rel.get("projection"),
    )


def _apply_legacy_disposition(
    rel: dict[str, Any],
    raw_scope: Any,
    raw_qualification: Any,
    raw_projection: Any,
) -> tuple[Any, Any, Any]:
    """Fill missing dispositions from a legacy single disposition string."""
    raw_disp = rel.get("disposition")
    if not raw_disp:
        return raw_scope, raw_qualification, raw_projection
    default_scope, default_qualification, default_projection = (
        _LEGACY_DISPOSITION_DEFAULTS.get(str(raw_disp), (None, None, None))
    )
    return (
        raw_scope or default_scope,
        raw_qualification or default_qualification,
        raw_projection or default_projection,
    )


def _matches_any(text: str, substrings: tuple[str, ...]) -> bool:
    """Report whether any substring occurs in the text."""
    return any(substring in text for substring in substrings)


def _explicit_scope(raw_scope: Any) -> str:
    """Normalize an explicitly provided scope disposition."""
    scope = str(raw_scope)
    if scope == "in-scope":
        return "applicable"
    if scope == "out-of-scope":
        return "capability_excluded"
    return scope


def _kind_scope(kind: str, pattern_id: str | None) -> str:
    """Derive the scope from the relationship kind when none is explicit."""
    if _matches_any(kind, _KIND_EXCLUSION_SUBSTRINGS):
        return "capability_excluded"
    if not pattern_id or _matches_any(kind, _KIND_GOVERNANCE_SUBSTRINGS):
        return "governance_only"
    return "applicable"


def _resolve_scope(raw_scope: Any, kind: str, pattern_id: str | None) -> str:
    """Resolve the scope disposition for one relationship."""
    if raw_scope:
        return _explicit_scope(raw_scope)
    return _kind_scope(kind, pattern_id)


def _kind_qualification(kind: str) -> str:
    """Derive the qualification disposition from the relationship kind."""
    for substrings, qualification in _KIND_QUALIFICATION_RULES:
        if _matches_any(kind, substrings):
            return qualification
    return "ready"


def _resolve_qualification(raw_qualification: Any, scope: str, kind: str) -> str:
    """Resolve the qualification disposition for one relationship."""
    if raw_qualification:
        return str(raw_qualification)
    if scope in _EXCLUDED_SCOPES:
        return "not_attempted"
    return _kind_qualification(kind)


def _resolve_projection(raw_projection: Any, qualification: str) -> str:
    """Resolve the projection disposition for one relationship."""
    if raw_projection:
        return str(raw_projection)
    if qualification == "ready":
        return "projectable"
    return "not_attempted"


def _reject_excluded_scope(scope: str, qualification: str, projection: str) -> None:
    """Reject non-terminal dispositions under an excluded scope."""
    if qualification != "not_attempted":
        raise ValueError(
            f"Invalid disposition combination: scope '{scope}' cannot be "
            f"combined with qualification '{qualification}'"
        )
    if projection != "not_attempted":
        raise ValueError(
            f"Invalid disposition combination: scope '{scope}' cannot be "
            f"combined with projection '{projection}'"
        )


def _reject_inapplicable(qualification: str, projection: str) -> None:
    """Reject qualification and projection values outside the applicable scope."""
    if qualification == "not_attempted":
        raise ValueError(
            "Invalid disposition combination: scope 'applicable' cannot be "
            f"combined with qualification '{qualification}'"
        )
    if qualification not in _APPLICABLE_QUALIFICATIONS:
        raise ValueError(
            f"Invalid qualification disposition '{qualification}' for scope 'applicable'"
        )
    if qualification != "ready" and projection not in _SETTLED_PROJECTIONS:
        raise ValueError(
            "Invalid disposition combination: qualification "
            f"'{qualification}' cannot be combined with projection '{projection}'"
        )


def _validate_dispositions(scope: str, qualification: str, projection: str) -> None:
    """Reject disposition combinations outside the closed Phase 1 contract."""
    if scope in _EXCLUDED_SCOPES:
        _reject_excluded_scope(scope, qualification, projection)
    elif scope == "applicable":
        _reject_inapplicable(qualification, projection)


def _resolve_dispositions(
    rel: dict[str, Any],
    pattern_id: str | None,
) -> tuple[str, str, str]:
    """Resolve scope, qualification, and projection dispositions for one relationship."""
    raw_scope, raw_qualification, raw_projection = _raw_dispositions(rel)
    (
        raw_scope,
        raw_qualification,
        raw_projection,
    ) = _apply_legacy_disposition(rel, raw_scope, raw_qualification, raw_projection)
    kind = rel.get("relationship_kind", "")
    scope = _resolve_scope(raw_scope, kind, pattern_id)
    qualification = _resolve_qualification(raw_qualification, scope, kind)
    projection = _resolve_projection(raw_projection, qualification)
    _validate_dispositions(scope, qualification, projection)
    return scope, qualification, projection


def _build_qualification_trace(
    evals: list[dict[str, Any]],
    risk_id: str,
    pattern_id: str | None,
    secrets: set[str],
) -> list[QualificationTraceItem]:
    """Extract and sanitize qualification traces matching this obligation."""
    trace_items: list[QualificationTraceItem] = []
    for ev in evals:
        if ev.get("risk_id") == risk_id and ev.get("pattern_id") == pattern_id:
            facts = _sanitize_secrets(ev.get("facts", ""), secrets)
            predicate = _sanitize_secrets(ev.get("predicate", ""), secrets)
            result = _sanitize_secrets(str(ev.get("result", "")), secrets)
            reason = _sanitize_secrets(ev.get("reason", ""), secrets)
            trace_items.append(
                QualificationTraceItem(
                    predicate=predicate,
                    facts=facts,
                    result=result,
                    reason=reason,
                )
            )
    return trace_items


def _candidate_reason(
    candidate: dict[str, Any], default: str, honor_rejection_reason: bool
) -> str:
    """Resolve a candidate entry's reason string."""
    if "reason" in candidate:
        return str(candidate["reason"])
    if honor_rejection_reason:
        return str(candidate.get("rejection_reason", default))
    return default


def _candidate_record(
    candidate: Any,
    default_disposition: ObligationProjectionDisposition,
    default_reason: str,
    honor_rejection_reason: bool,
) -> CandidateRecord | None:
    """Build one candidate record from a mapping or bare-string entry."""
    if isinstance(candidate, str):
        return CandidateRecord(
            candidate_id=candidate,
            projection_disposition=default_disposition,
            reason=default_reason,
        )
    candidate_id = str(candidate.get("candidate_id", ""))
    if not candidate_id:
        return None
    return CandidateRecord(
        candidate_id=candidate_id,
        projection_disposition=candidate.get(
            "projection_disposition", default_disposition
        ),
        reason=_candidate_reason(candidate, default_reason, honor_rejection_reason),
    )


def _append_unique_candidate(
    candidates: list[CandidateRecord],
    seen: set[str],
    record: CandidateRecord | None,
) -> None:
    """Append a record unless it is empty or duplicates a seen candidate id."""
    if record is not None and record.candidate_id not in seen:
        seen.add(record.candidate_id)
        candidates.append(record)


def _collect_candidate_section(
    candidates: list[CandidateRecord],
    seen: set[str],
    expansion: dict[str, Any],
    section: tuple[str, ObligationProjectionDisposition, str, bool, bool],
) -> None:
    """Collect one expansion section's records with per-section defaults."""
    (
        key,
        default_disposition,
        default_reason,
        honor_rejection_reason,
        accept_bare_strings,
    ) = section
    for entry in expansion.get(key, []):
        if isinstance(entry, str) and not accept_bare_strings:
            continue
        record = _candidate_record(
            entry, default_disposition, default_reason, honor_rejection_reason
        )
        _append_unique_candidate(candidates, seen, record)


def _expansion_matches(
    expansion: dict[str, Any], risk_id: str, pattern_id: str | None
) -> bool:
    """Report whether an expansion belongs to the given risk and pattern."""
    return (
        expansion.get("risk_id") == risk_id
        and expansion.get("pattern_id") == pattern_id
    )


def _build_candidate_records(
    expansions: list[dict[str, Any]],
    risk_id: str,
    pattern_id: str | None,
) -> list[CandidateRecord]:
    """Extract candidate expansion records matching this obligation."""
    candidates: list[CandidateRecord] = []
    seen: set[str] = set()
    for expansion in expansions:
        if not _expansion_matches(expansion, risk_id, pattern_id):
            continue
        for section in _CANDIDATE_SECTIONS:
            _collect_candidate_section(candidates, seen, expansion, section)
    return candidates


def _count_scope(obligations: list[TaxonomyObligation], disposition: str) -> int:
    """Count obligations carrying one scope disposition."""
    return sum(1 for o in obligations if o.scope_disposition == disposition)


def _count_qualification(
    obligations: list[TaxonomyObligation], *dispositions: str
) -> int:
    """Count obligations carrying any of the qualification dispositions."""
    return sum(1 for o in obligations if o.qualification_disposition in dispositions)


def _count_obligation_disposition(
    obligations: list[TaxonomyObligation], disposition: str
) -> int:
    """Count obligations carrying one terminal projection disposition."""
    return sum(1 for o in obligations if o.projection_disposition == disposition)


def _count_candidate_disposition(
    obligations: list[TaxonomyObligation], disposition: str
) -> int:
    """Count candidate records carrying one projection disposition."""
    return sum(
        1
        for o in obligations
        for c in o.candidate_records
        if c.projection_disposition == disposition
    )


def _count_projection(
    obligations: list[TaxonomyObligation],
    disposition: str,
    use_candidate_records: bool,
) -> int:
    """Count a projection disposition at the candidate level when records exist."""
    if use_candidate_records:
        return _count_candidate_disposition(obligations, disposition)
    return _count_obligation_disposition(obligations, disposition)


def _derive_summary(obligations: list[TaxonomyObligation]) -> ObligationPlanSummary:
    """Derive summary counts from obligation rows and candidate records."""
    use_candidate_records = any(o.candidate_records for o in obligations)
    return ObligationPlanSummary(
        total=len(obligations),
        applicable=_count_scope(obligations, "applicable"),
        governance_only=_count_scope(obligations, "governance_only"),
        capability_excluded=_count_scope(obligations, "capability_excluded"),
        ready=_count_qualification(obligations, "ready"),
        missing_or_contradictory=_count_qualification(
            obligations, "missing_evidence", "contradictory_evidence"
        ),
        structurally_infeasible=_count_qualification(
            obligations, "structurally_infeasible"
        ),
        projectable=_count_projection(
            obligations, "projectable", use_candidate_records
        ),
        projection_infeasible=_count_projection(
            obligations, "projection_infeasible", use_candidate_records
        ),
        budget_deferred=_count_projection(
            obligations, "budget_deferred", use_candidate_records
        ),
    )


def _canonicalize_relationship_for_digest(rel: dict[str, Any]) -> dict[str, Any]:
    """Strip non-structural generation prose (such as ICA prose) from relationship for digest stability."""
    return {
        "risk_id": str(rel.get("risk_id", "")),
        "pattern_id": str(rel.get("pattern_id", "")) if rel.get("pattern_id") else None,
        "relationship_kind": str(rel.get("relationship_kind", "")),
        "scope_disposition": str(rel.get("scope_disposition", rel.get("scope", ""))),
        "qualification_disposition": str(
            rel.get("qualification_disposition", rel.get("qualification", ""))
        ),
        "projection_disposition": str(
            rel.get("projection_disposition", rel.get("projection", ""))
        ),
    }


def _canonicalize_card_for_digest(card: dict[str, Any]) -> dict[str, Any]:
    """Strip non-structural prose from risk card for digest stability."""
    return {
        "risk_id": str(card.get("risk_id", "")),
        "pattern_id": str(card.get("pattern_id", ""))
        if card.get("pattern_id")
        else None,
    }


def _json_serializable(obj: Any) -> Any:
    """Ensure object is JSON serializable for sorting."""
    return json.dumps(obj, sort_keys=True, default=str)


def _planning_snapshot(
    snapshot: TaxonomyObligationSnapshot | dict[str, Any],
) -> TaxonomyObligationSnapshot:
    """Coerce a raw mapping into a snapshot model."""
    if isinstance(snapshot, dict):
        return TaxonomyObligationSnapshot.model_validate(snapshot)
    return snapshot


def _resolved_pin(pin: str | None, legacy_pin: str | None, default: str) -> str:
    """Prefer the explicit pin, then its legacy alias, then the default."""
    return pin or legacy_pin or default


def _generation_inputs_digest(
    snap: TaxonomyObligationSnapshot, catalog_pin: str, mapping_pin: str
) -> str:
    """Digest the canonical identity-bearing relationship and card content."""
    canonical_relationships = sorted(
        [_canonicalize_relationship_for_digest(rel) for rel in snap.relationships],
        key=_json_serializable,
    )
    canonical_cards = sorted(
        [_canonicalize_card_for_digest(card) for card in snap.risk_cards],
        key=_json_serializable,
    )
    return compute_sha256(
        {
            "catalog_pin": catalog_pin,
            "mapping_pin": mapping_pin,
            "relationships": canonical_relationships,
            "risk_cards": canonical_cards,
        }
    )


def _build_obligation(
    rel: dict[str, Any],
    snap: TaxonomyObligationSnapshot,
    pin_tag: str,
    secrets: set[str],
) -> TaxonomyObligation:
    """Build one ledger obligation from a snapshot relationship."""
    risk_id = str(rel.get("risk_id", ""))
    raw_pattern = rel.get("pattern_id")
    pattern_id = str(raw_pattern) if raw_pattern else None
    scope_disp, qual_disp, proj_disp = _resolve_dispositions(rel, pattern_id)
    evidence: dict[str, Any] = {}
    if rel.get("relationship_kind"):
        evidence["relationship_kind"] = rel["relationship_kind"]
    return TaxonomyObligation(
        obligation_id=_canonical_obligation_id(risk_id, pattern_id, pin_tag),
        risk_id=risk_id,
        pattern_id=pattern_id,
        scope_disposition=scope_disp,
        qualification_disposition=qual_disp,
        correspondence_disposition="not_assessed",
        projection_disposition=proj_disp,
        qualification_trace=_build_qualification_trace(
            snap.qualification_evaluations, risk_id, pattern_id, secrets
        ),
        candidate_records=_build_candidate_records(
            snap.candidate_expansions, risk_id, pattern_id
        ),
        evidence=evidence,
    )


def _build_obligations(
    snap: TaxonomyObligationSnapshot, pin_tag: str, secrets: set[str]
) -> list[TaxonomyObligation]:
    """Build the unsorted obligation ledger from snapshot relationships."""
    return [
        _build_obligation(rel, snap, pin_tag, secrets) for rel in snap.relationships
    ]


def plan_obligations(
    snapshot: TaxonomyObligationSnapshot | dict[str, Any],
) -> TaxonomyObligationPlan:
    """Produce a deterministic taxonomy obligation plan from a pinned snapshot.

    Makes zero network and model calls.
    """
    snap = _planning_snapshot(snapshot)
    catalog_pin = _resolved_pin(
        snap.catalog_pin, snap.taxonomy_version, _DEFAULT_CATALOG_PIN
    )
    mapping_pin = _resolved_pin(
        snap.mapping_pin, snap.mapping_version, _DEFAULT_MAPPING_PIN
    )
    capability_snapshot_digest = compute_sha256(snap.capability_content)
    qualification_facts_digest = compute_sha256(snap.qualification_facts)
    generation_inputs_digest = _generation_inputs_digest(snap, catalog_pin, mapping_pin)
    pin_tag = compute_sha256(
        f"{catalog_pin}|{mapping_pin}|{capability_snapshot_digest}"
    )[:8]

    obligations = _build_obligations(
        snap, pin_tag, _collect_config_secrets(snap.config)
    )
    obligations.sort(key=_canonical_sort_key)

    plan = TaxonomyObligationPlan(
        schema_version="taxonomy-obligation-plan-v1",
        catalog_pins={"catalog": catalog_pin, "atlas": catalog_pin},
        mapping_pins={"mapping": mapping_pin, "sssom": mapping_pin},
        capability_snapshot_digest=capability_snapshot_digest,
        qualification_facts_digest=qualification_facts_digest,
        generation_inputs_digest=generation_inputs_digest,
        semantic_digest="",
        obligations=obligations,
        summary=_derive_summary(obligations),
        network_calls=0,
        model_calls=0,
    )
    plan.semantic_digest = plan.compute_semantic_digest()
    return plan


def _canonical_sort_key(ob: TaxonomyObligation) -> tuple[str, str, str, str]:
    """Canonical sort key: semantic identity with content as the tiebreaker."""
    return (ob.risk_id, ob.pattern_id or "", ob.obligation_id, ob.model_dump_json())


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-27T17:13:03Z","module_hash":"58616a83f9300bff96aaa820d1c40e67156221b0c175f55f1b4418061cbde1a2","source_sha256":"8e1a0b3a373f01c3a4b775079aaa0391dea736ef756ef8493324312a4245257f","functions":[{"id":"func/_collect_config_secrets","name":"_collect_config_secrets","line":16,"end_line":22,"hash":"a8c4fc66772e128f9ecc4e577323d96df862eaef06a81b2333f16bbb4aed77a6"},{"id":"func/_sanitize_secrets","name":"_sanitize_secrets","line":25,"end_line":39,"hash":"e2bcd567c646a7ce6a8bfd95ce60bf375e4ab3d85272c2aa7ccbb7b7e4bba55a"},{"id":"func/_canonical_obligation_id","name":"_canonical_obligation_id","line":42,"end_line":46,"hash":"8cc67b81744a51271bf9d1c9eb2f3007fd6997402f470985e82a95190c67e9e3"},{"id":"func/_resolve_scope_and_disposition","name":"_resolve_scope_and_disposition","line":49,"end_line":79,"hash":"e58a3a687612a2f4728b0e700d0f8c4e847d143f95a37c0a55808037518aaf7d"},{"id":"func/_build_qualification_trace","name":"_build_qualification_trace","line":82,"end_line":104,"hash":"82820a3f4daebf0a03011f670adc0002de739cbb1a40b254336f3d0cfdd51029"},{"id":"func/_build_candidate_evidence","name":"_build_candidate_evidence","line":107,"end_line":128,"hash":"31e5c59a7c7ce296e656380d6be17bfe8303cc5dc74b050867dd50f4e4c94038"},{"id":"func/plan_obligations","name":"plan_obligations","line":131,"end_line":187,"hash":"12766197c7afefffaab85819d91944b00bcffb8eb2739774f83e5cb1a7cb713d"},{"id":"func/_canonical_sort_key","name":"_canonical_sort_key","line":190,"end_line":192,"hash":"ac77c500171be1c7761e31922c1dbdba71bdfce8287cb6f298fc1082c01cac43"}]}
# mutate4py-manifest-end
