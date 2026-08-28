"""Deterministic offline taxonomy obligation planner."""

from __future__ import annotations

import json
from typing import Any

from asago_scenario_generator.models.obligation_plan import (
    CandidateRecord,
    ObligationPlanSummary,
    QualificationTraceItem,
    TaxonomyObligation,
    TaxonomyObligationPlan,
    TaxonomyObligationSnapshot,
    compute_sha256,
)


def _collect_config_secrets(config: dict[str, Any]) -> set[str]:
    """Collect secret string tokens from configuration to sanitize traces."""
    secrets: set[str] = set()
    for _key, val in config.items():
        if isinstance(val, str) and val.strip():
            secrets.add(val.strip())
    return secrets


def _sanitize_secrets(value: Any, secrets: set[str]) -> Any:
    """Remove known secrets from values."""
    if not secrets:
        return value
    if isinstance(value, str):
        sanitized = value
        for secret in secrets:
            if secret in sanitized:
                sanitized = sanitized.replace(secret, "[REDACTED]")
        return sanitized
    if isinstance(value, dict):
        return {k: _sanitize_secrets(v, secrets) for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitize_secrets(v, secrets) for v in value]
    return value


def _canonical_obligation_id(risk_id: str, pattern_id: str | None, pin_tag: str) -> str:
    """Construct deterministic canonical obligation identifier."""
    if pattern_id:
        return f"ob:{risk_id}:{pattern_id}:{pin_tag}"
    return f"ob:{risk_id}:{pin_tag}"


def _resolve_dispositions(
    rel: dict[str, Any],
    pattern_id: str | None,
) -> tuple[str, str, str]:
    """Resolve scope, qualification, and projection dispositions for one relationship."""
    raw_scope = rel.get("scope_disposition") or rel.get("scope")
    raw_qualification = rel.get("qualification_disposition") or rel.get("qualification")
    raw_projection = rel.get("projection_disposition") or rel.get("projection")
    raw_disp = rel.get("disposition")
    kind = rel.get("relationship_kind", "")

    # Normalize legacy disposition if present
    if raw_disp:
        disp_str = str(raw_disp)
        if disp_str in ("governance-only", "governance_only"):
            if not raw_scope:
                raw_scope = "governance_only"
            if not raw_qualification:
                raw_qualification = "not_attempted"
            if not raw_projection:
                raw_projection = "not_attempted"
        elif disp_str == "gated":
            if not raw_scope:
                raw_scope = "capability_excluded"
            if not raw_qualification:
                raw_qualification = "not_attempted"
            if not raw_projection:
                raw_projection = "not_attempted"
        elif disp_str in ("missing-template", "missing_evidence"):
            if not raw_qualification:
                raw_qualification = "missing_evidence"
        elif disp_str in ("infeasible", "unsupported", "structurally_infeasible"):
            if not raw_qualification:
                raw_qualification = "structurally_infeasible"
        elif disp_str == "contradictory_evidence":
            if not raw_qualification:
                raw_qualification = "contradictory_evidence"
        elif disp_str in ("generated", "ready"):
            if not raw_qualification:
                raw_qualification = "ready"
        elif disp_str in (
            "ready",
            "missing_evidence",
            "contradictory_evidence",
            "structurally_infeasible",
            "not_attempted",
        ):
            if not raw_qualification:
                raw_qualification = disp_str

    # 1. Scope
    if raw_scope:
        scope = str(raw_scope)
        if scope == "in-scope":
            scope = "applicable"
        elif scope == "out-of-scope":
            scope = "capability_excluded"
    elif "gated" in kind or "capability" in kind:
        scope = "capability_excluded"
    elif not pattern_id or "governance" in kind or "orphan" in kind:
        scope = "governance_only"
    else:
        scope = "applicable"

    # 2. Qualification
    if raw_qualification:
        qualification = str(raw_qualification)
    elif scope in ("capability_excluded", "governance_only"):
        qualification = "not_attempted"
    elif "missing" in kind:
        qualification = "missing_evidence"
    elif "contradict" in kind:
        qualification = "contradictory_evidence"
    elif "infeasib" in kind or "structurally" in kind or "unsupported" in kind:
        qualification = "structurally_infeasible"
    elif (
        "ready" in kind
        or "qualified" in kind
        or "generated" in kind
        or "projectable" in kind
    ):
        qualification = "ready"
    else:
        qualification = "ready"

    # 3. Projection
    if raw_projection:
        projection = str(raw_projection)
    elif qualification == "ready":
        projection = "projectable"
    else:
        projection = "not_attempted"

    # Validation of combinations
    if scope == "governance_only":
        if qualification != "not_attempted":
            raise ValueError(
                f"Invalid disposition combination: scope '{scope}' cannot be combined with qualification '{qualification}'"
            )
        if projection != "not_attempted":
            raise ValueError(
                f"Invalid disposition combination: scope '{scope}' cannot be combined with projection '{projection}'"
            )
    elif scope == "capability_excluded":
        if qualification != "not_attempted":
            raise ValueError(
                f"Invalid disposition combination: scope '{scope}' cannot be combined with qualification '{qualification}'"
            )
        if projection != "not_attempted":
            raise ValueError(
                f"Invalid disposition combination: scope '{scope}' cannot be combined with projection '{projection}'"
            )
    elif scope == "applicable":
        if qualification == "not_attempted":
            raise ValueError(
                f"Invalid disposition combination: scope '{scope}' cannot be combined with qualification '{qualification}'"
            )
        if qualification not in (
            "ready",
            "missing_evidence",
            "contradictory_evidence",
            "structurally_infeasible",
        ):
            raise ValueError(
                f"Invalid qualification disposition '{qualification}' for scope '{scope}'"
            )
        if qualification != "ready" and projection not in (
            "not_attempted",
            "projection_infeasible",
        ):
            raise ValueError(
                f"Invalid disposition combination: qualification '{qualification}' cannot be combined with projection '{projection}'"
            )

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


def _build_candidate_records(
    expansions: list[dict[str, Any]],
    risk_id: str,
    pattern_id: str | None,
) -> list[CandidateRecord]:
    """Extract candidate expansion records matching this obligation."""
    candidates: list[CandidateRecord] = []
    seen: set[str] = set()
    for exp in expansions:
        if exp.get("risk_id") == risk_id and exp.get("pattern_id") == pattern_id:
            for cand in exp.get("candidates", []):
                if isinstance(cand, dict):
                    cid = str(cand.get("candidate_id", ""))
                    if cid and cid not in seen:
                        seen.add(cid)
                        candidates.append(
                            CandidateRecord(
                                candidate_id=cid,
                                projection_disposition=cand.get(
                                    "projection_disposition", "projectable"
                                ),
                                reason=str(cand.get("reason", "")),
                            )
                        )
            for cand in exp.get("accepted_candidates", []):
                if isinstance(cand, dict):
                    cid = str(cand.get("candidate_id", ""))
                    if cid and cid not in seen:
                        seen.add(cid)
                        candidates.append(
                            CandidateRecord(
                                candidate_id=cid,
                                projection_disposition=cand.get(
                                    "projection_disposition", "projectable"
                                ),
                                reason=str(
                                    cand.get(
                                        "reason",
                                        cand.get(
                                            "rejection_reason", "qualified combination"
                                        ),
                                    )
                                ),
                            )
                        )
                elif isinstance(cand, str) and cand not in seen:
                    seen.add(cand)
                    candidates.append(
                        CandidateRecord(
                            candidate_id=cand,
                            projection_disposition="projectable",
                            reason="qualified combination",
                        )
                    )
            for rej in exp.get("rejected_candidates", []):
                if isinstance(rej, dict):
                    cid = str(rej.get("candidate_id", ""))
                    if cid and cid not in seen:
                        seen.add(cid)
                        candidates.append(
                            CandidateRecord(
                                candidate_id=cid,
                                projection_disposition=rej.get(
                                    "projection_disposition", "projection_infeasible"
                                ),
                                reason=str(
                                    rej.get(
                                        "reason",
                                        rej.get(
                                            "rejection_reason",
                                            "missing required resource",
                                        ),
                                    )
                                ),
                            )
                        )
                elif isinstance(rej, str) and rej not in seen:
                    seen.add(rej)
                    candidates.append(
                        CandidateRecord(
                            candidate_id=rej,
                            projection_disposition="projection_infeasible",
                            reason="missing required resource",
                        )
                    )
    return candidates


def _derive_summary(obligations: list[TaxonomyObligation]) -> ObligationPlanSummary:
    """Derive summary counts from obligation rows and candidate records."""
    total = len(obligations)
    applicable = sum(1 for o in obligations if o.scope_disposition == "applicable")
    governance_only = sum(
        1 for o in obligations if o.scope_disposition == "governance_only"
    )
    capability_excluded = sum(
        1 for o in obligations if o.scope_disposition == "capability_excluded"
    )
    ready = sum(1 for o in obligations if o.qualification_disposition == "ready")
    missing_or_contradictory = sum(
        1
        for o in obligations
        if o.qualification_disposition in ("missing_evidence", "contradictory_evidence")
    )
    structurally_infeasible = sum(
        1
        for o in obligations
        if o.qualification_disposition == "structurally_infeasible"
    )

    projectable = 0
    projection_infeasible = 0
    budget_deferred = 0

    has_candidate_records = any(o.candidate_records for o in obligations)
    if has_candidate_records:
        for o in obligations:
            for c in o.candidate_records:
                if c.projection_disposition == "projectable":
                    projectable += 1
                elif c.projection_disposition == "projection_infeasible":
                    projection_infeasible += 1
                elif c.projection_disposition == "budget_deferred":
                    budget_deferred += 1
    else:
        for o in obligations:
            if o.projection_disposition == "projectable":
                projectable += 1
            elif o.projection_disposition == "projection_infeasible":
                projection_infeasible += 1
            elif o.projection_disposition == "budget_deferred":
                budget_deferred += 1

    return ObligationPlanSummary(
        total=total,
        applicable=applicable,
        governance_only=governance_only,
        capability_excluded=capability_excluded,
        ready=ready,
        missing_or_contradictory=missing_or_contradictory,
        structurally_infeasible=structurally_infeasible,
        projectable=projectable,
        projection_infeasible=projection_infeasible,
        budget_deferred=budget_deferred,
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


def plan_obligations(
    snapshot: TaxonomyObligationSnapshot | dict[str, Any],
) -> TaxonomyObligationPlan:
    """Produce a deterministic taxonomy obligation plan from a pinned snapshot.

    Makes zero network and model calls.
    """
    if isinstance(snapshot, dict):
        snap = TaxonomyObligationSnapshot.model_validate(snapshot)
    else:
        snap = snapshot

    catalog_pin = snap.catalog_pin or snap.taxonomy_version or "atlas-2026.05"
    mapping_pin = snap.mapping_pin or snap.mapping_version or "sssom-v1"

    catalog_pins = {"catalog": catalog_pin, "atlas": catalog_pin}
    mapping_pins = {"mapping": mapping_pin, "sssom": mapping_pin}

    capability_snapshot_digest = compute_sha256(snap.capability_content)
    qualification_facts_digest = compute_sha256(snap.qualification_facts)

    canonical_rels = sorted(
        [_canonicalize_relationship_for_digest(r) for r in snap.relationships],
        key=_json_serializable,
    )
    canonical_cards = sorted(
        [_canonicalize_card_for_digest(c) for c in snap.risk_cards],
        key=_json_serializable,
    )

    generation_inputs_digest = compute_sha256(
        {
            "catalog_pin": catalog_pin,
            "mapping_pin": mapping_pin,
            "relationships": canonical_rels,
            "risk_cards": canonical_cards,
        }
    )

    pin_tag = compute_sha256(
        f"{catalog_pin}|{mapping_pin}|{capability_snapshot_digest}"
    )[:8]

    secrets = _collect_config_secrets(snap.config)
    obligations: list[TaxonomyObligation] = []

    for rel in snap.relationships:
        risk_id = str(rel.get("risk_id", ""))
        raw_pattern = rel.get("pattern_id")
        pattern_id = str(raw_pattern) if raw_pattern else None

        scope_disp, qual_disp, proj_disp = _resolve_dispositions(rel, pattern_id)
        obligation_id = _canonical_obligation_id(risk_id, pattern_id, pin_tag)

        trace = _build_qualification_trace(
            snap.qualification_evaluations, risk_id, pattern_id, secrets
        )
        candidates = _build_candidate_records(
            snap.candidate_expansions, risk_id, pattern_id
        )

        evidence: dict[str, Any] = {}
        if rel.get("relationship_kind"):
            evidence["relationship_kind"] = rel["relationship_kind"]

        obligations.append(
            TaxonomyObligation(
                obligation_id=obligation_id,
                risk_id=risk_id,
                pattern_id=pattern_id,
                scope_disposition=scope_disp,
                qualification_disposition=qual_disp,
                correspondence_disposition="not_assessed",
                projection_disposition=proj_disp,
                qualification_trace=trace,
                candidate_records=candidates,
                evidence=evidence,
            )
        )

    obligations.sort(key=_canonical_sort_key)
    summary = _derive_summary(obligations)

    plan = TaxonomyObligationPlan(
        schema_version="taxonomy-obligation-plan-v1",
        catalog_pins=catalog_pins,
        mapping_pins=mapping_pins,
        capability_snapshot_digest=capability_snapshot_digest,
        qualification_facts_digest=qualification_facts_digest,
        generation_inputs_digest=generation_inputs_digest,
        semantic_digest="",
        obligations=obligations,
        summary=summary,
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
