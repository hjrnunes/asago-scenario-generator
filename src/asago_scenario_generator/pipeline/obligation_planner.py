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
# {"version":1,"tested_at":"2026-08-28T10:28:54Z","module_hash":"a99d4e5019bc6fb05da871eb76073223cd1791efb264805d932015da1845ae3f","source_sha256":"e739470e70ee0221e802410eb2a50a80d918e04e700b5df34b21100e1ae6c485","functions":[{"id":"func/_collect_config_secrets","name":"_collect_config_secrets","line":84,"end_line":90,"hash":"e81e1d78c3225399a6475f76a32a5e8a17b2d64b7e07b8ecfc708072de2ecac9"},{"id":"func/_redact_text","name":"_redact_text","line":93,"end_line":98,"hash":"2f1dfc73f75f23a3248af9b43a39cfb1be82b355fb145716ce5c9b395536122f"},{"id":"func/_sanitize_secrets","name":"_sanitize_secrets","line":101,"end_line":107,"hash":"52ebba85061c0261cde6e03c4a9ff85bc437da947a85c96840a51c41e787427d"},{"id":"func/_sanitize_container","name":"_sanitize_container","line":110,"end_line":116,"hash":"baeab770be10837607c1642a06900aff048e191eae71acd78b49b918e4485384"},{"id":"func/_canonical_obligation_id","name":"_canonical_obligation_id","line":119,"end_line":123,"hash":"1a71bb675d184f1afd5b3263af3626f7c414165b2d957b65a4fb1ffd82963820"},{"id":"func/_raw_dispositions","name":"_raw_dispositions","line":126,"end_line":132,"hash":"2a281b0f77acf2434ac5bc962ee65d77eae8eceed86631800f2c85f102b9f70c"},{"id":"func/_apply_legacy_disposition","name":"_apply_legacy_disposition","line":135,"end_line":152,"hash":"ae2a5b6942a394a851177bab4061ee98bcd45b1dd1deb7c6d101bea296b0259e"},{"id":"func/_matches_any","name":"_matches_any","line":155,"end_line":157,"hash":"4b08b6111399f202593fd75e93044b59a204cea6f14cf7ede1bd44483bf890cb"},{"id":"func/_explicit_scope","name":"_explicit_scope","line":160,"end_line":167,"hash":"acdfdb70e9d09c85436264f5b26c4857f36f4c95289e714f6aa3e582ec3d4ca3"},{"id":"func/_kind_scope","name":"_kind_scope","line":170,"end_line":176,"hash":"5a1eff6cec8bdb3d3800af331d84d4dba675cb3e16db8e84f934d1cd3b8fbffb"},{"id":"func/_resolve_scope","name":"_resolve_scope","line":179,"end_line":183,"hash":"786dc36153105519e07c0cdf941503ef106115d634364131977796d047d66994"},{"id":"func/_kind_qualification","name":"_kind_qualification","line":186,"end_line":191,"hash":"354104b97df1dd4a645603bcfce07c7ffc701c29c948606d33d45b4dc4741db4"},{"id":"func/_resolve_qualification","name":"_resolve_qualification","line":194,"end_line":200,"hash":"bfb11b4ff192259abe7f047b086c09e9feffce96463518ad1cfac6ea79e24675"},{"id":"func/_resolve_projection","name":"_resolve_projection","line":203,"end_line":209,"hash":"5df389d2e70c88de6a20b21bdd4d9b7e080cecafd1e686a29d16d6c67f47469f"},{"id":"func/_reject_excluded_scope","name":"_reject_excluded_scope","line":212,"end_line":223,"hash":"f2432199cd203f14120081153ce40af54c412e0fe9ac457ed3057fdeeb647c3e"},{"id":"func/_reject_inapplicable","name":"_reject_inapplicable","line":226,"end_line":241,"hash":"5d77624068a1771d015ef4d7b5691d8e710ae6adcdfe9a023539f612a7ab5a7a"},{"id":"func/_validate_dispositions","name":"_validate_dispositions","line":244,"end_line":249,"hash":"a2d2d99a67ab1b7d1d46253af95d21682e4c01ee8b304077b56b148668d7801a"},{"id":"func/_resolve_dispositions","name":"_resolve_dispositions","line":252,"end_line":268,"hash":"ef515639a805b44019b79551484d80fcd44ad498314ce31fdee3c23b88236564"},{"id":"func/_build_qualification_trace","name":"_build_qualification_trace","line":271,"end_line":293,"hash":"82820a3f4daebf0a03011f670adc0002de739cbb1a40b254336f3d0cfdd51029"},{"id":"func/_candidate_reason","name":"_candidate_reason","line":296,"end_line":304,"hash":"892ff8ce63b41e233c15760584c23d39a05641aeca1f153f47656ec3d2a469f5"},{"id":"func/_candidate_record","name":"_candidate_record","line":307,"end_line":329,"hash":"29b5a3cb4bf83788183619d419f64f5a1343210dbe18bdfe23027856823ce48c"},{"id":"func/_append_unique_candidate","name":"_append_unique_candidate","line":332,"end_line":340,"hash":"38edca1cbeaa72298e8ddf9f45cff906cb73e61d4429696462c4dc2f88d4a268"},{"id":"func/_collect_candidate_section","name":"_collect_candidate_section","line":343,"end_line":363,"hash":"25f3b2437092be19123b24d67cabff932ab2d71a09369f12dd2b5a23c98b08ae"},{"id":"func/_expansion_matches","name":"_expansion_matches","line":366,"end_line":373,"hash":"34e312194da0ed682fca29e23d42740fb214ad6f8e8c95368be28655f3666755"},{"id":"func/_build_candidate_records","name":"_build_candidate_records","line":376,"end_line":389,"hash":"15043673e615b32d9fd30acd8a280c4bc835a6c30588a1892193dd307794aa64"},{"id":"func/_count_scope","name":"_count_scope","line":392,"end_line":394,"hash":"f4853f9121383a0894a2692f388e081555711961cd121f37765e4e3f432158a3"},{"id":"func/_count_qualification","name":"_count_qualification","line":397,"end_line":401,"hash":"a6293b2490723109f7e395e1872da80b1ed358040000886fdb8f440e31a4270c"},{"id":"func/_count_obligation_disposition","name":"_count_obligation_disposition","line":404,"end_line":408,"hash":"38474515485edf7439832b402b377e161a69f026c3ea27089b8db4a7cc866fc4"},{"id":"func/_count_candidate_disposition","name":"_count_candidate_disposition","line":411,"end_line":420,"hash":"be16f15bafb8cc29fefe0901d78e1cb8d74ea5341065e413bfb196721004ea96"},{"id":"func/_count_projection","name":"_count_projection","line":423,"end_line":431,"hash":"b2c96d958a8a55a4e46459c0d33b567d245ba28bed2e583d54a5e7930ea8c182"},{"id":"func/_derive_summary","name":"_derive_summary","line":434,"end_line":458,"hash":"b833e95e2083520f97fceab272d979fb94a3dccceb2d3754b185c2035996dde0"},{"id":"func/_canonicalize_relationship_for_digest","name":"_canonicalize_relationship_for_digest","line":461,"end_line":474,"hash":"a1d4dd280fa5215e587056677c85a330dcf69be18098324c2143d72ae0cec560"},{"id":"func/_canonicalize_card_for_digest","name":"_canonicalize_card_for_digest","line":477,"end_line":484,"hash":"22c0e66fd91887117f4cea3da87fb172eb1b91cae31f5de17f4995c784ae6a96"},{"id":"func/_json_serializable","name":"_json_serializable","line":487,"end_line":489,"hash":"83919b4581fb61750efbe23eb197ebae0e58b4b76edf7a4cf21b427aa0b78795"},{"id":"func/_planning_snapshot","name":"_planning_snapshot","line":492,"end_line":498,"hash":"852b065369a3e4de7c56d40a191288a5b13edb4896224a069eb3adde35eec4d8"},{"id":"func/_resolved_pin","name":"_resolved_pin","line":501,"end_line":503,"hash":"e37dcf2d1b50ff1dd81fb5533c4a2f5c3b2d7fbd6a4736a59220103b5309b91c"},{"id":"func/_generation_inputs_digest","name":"_generation_inputs_digest","line":506,"end_line":525,"hash":"c023b9d4dd498189e0c6140651b6d42dd3bc85a47748a8fa15fa334fafd832e6"},{"id":"func/_build_obligation","name":"_build_obligation","line":528,"end_line":557,"hash":"e15349574686682b2499dca04f6ff91ec2244462ed2498eaf1ae6f1a57e504e1"},{"id":"func/_build_obligations","name":"_build_obligations","line":560,"end_line":566,"hash":"e7f4559898a99c35f1ab84ce14feaf88458f058d30092e4ff1c735f321b3a1e4"},{"id":"func/plan_obligations","name":"plan_obligations","line":569,"end_line":609,"hash":"5a4e4bb554e544cffcf3501facb9c61d2645f87cc3d79229a2e1849a82ec1213"},{"id":"func/_canonical_sort_key","name":"_canonical_sort_key","line":612,"end_line":614,"hash":"ac77c500171be1c7761e31922c1dbdba71bdfce8287cb6f298fc1082c01cac43"}]}
# mutate4py-manifest-end
