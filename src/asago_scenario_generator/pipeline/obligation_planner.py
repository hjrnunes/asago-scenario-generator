"""Deterministic offline taxonomy obligation planner."""

from __future__ import annotations

from typing import Any

from asago_scenario_generator.models.obligation_plan import (
    QualificationTraceItem,
    RejectedCandidateEvidence,
    TaxonomyObligation,
    TaxonomyObligationPlan,
    TaxonomyObligationSnapshot,
)


def _collect_config_secrets(config: dict[str, Any]) -> set[str]:
    """Collect secret string tokens from configuration to sanitize traces."""
    secrets: set[str] = set()
    for key, val in config.items():
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


def _canonical_obligation_id(risk_id: str, pattern_id: str | None) -> str:
    """Construct deterministic canonical obligation identifier."""
    if pattern_id:
        return f"ob:{risk_id}:{pattern_id}"
    return f"ob:{risk_id}"


def _resolve_scope_and_disposition(
    rel: dict[str, Any],
) -> tuple[str, str]:
    """Resolve scope and terminal disposition for one relationship."""
    raw_scope = rel.get("scope")
    raw_disposition = rel.get("disposition") or rel.get("terminal_disposition")
    kind = rel.get("relationship_kind", "")

    if raw_disposition:
        disposition = str(raw_disposition)
    elif "gated" in kind:
        disposition = "gated"
    elif "missing" in kind:
        disposition = "missing-template"
    elif "infeasib" in kind:
        disposition = "infeasible"
    elif "unsupported" in kind:
        disposition = "unsupported"
    elif "governance" in kind or not rel.get("pattern_id"):
        disposition = "governance-only"
    else:
        disposition = "generated"

    if raw_scope:
        scope = str(raw_scope)
    elif disposition == "gated":
        scope = "out-of-scope"
    else:
        scope = "in-scope"

    return scope, disposition


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


def _build_candidate_evidence(
    expansions: list[dict[str, Any]],
    risk_id: str,
    pattern_id: str | None,
) -> tuple[list[str], list[RejectedCandidateEvidence]]:
    """Extract candidate expansion evidence matching this obligation."""
    accepted: list[str] = []
    rejected: list[RejectedCandidateEvidence] = []
    for exp in expansions:
        if exp.get("risk_id") == risk_id and exp.get("pattern_id") == pattern_id:
            for cand in exp.get("accepted_candidates", []):
                if isinstance(cand, str) and cand not in accepted:
                    accepted.append(cand)
            for rej in exp.get("rejected_candidates", []):
                if isinstance(rej, dict):
                    rejected.append(
                        RejectedCandidateEvidence(
                            candidate_id=str(rej.get("candidate_id", "")),
                            reason=str(rej.get("reason", "")),
                        )
                    )
    return accepted, rejected


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

    secrets = _collect_config_secrets(snap.config)
    obligations: list[TaxonomyObligation] = []

    for rel in snap.relationships:
        risk_id = str(rel.get("risk_id", ""))
        raw_pattern = rel.get("pattern_id")
        pattern_id = str(raw_pattern) if raw_pattern else None

        obligation_id = _canonical_obligation_id(risk_id, pattern_id)
        scope, disposition = _resolve_scope_and_disposition(rel)

        trace = _build_qualification_trace(
            snap.qualification_evaluations, risk_id, pattern_id, secrets
        )
        accepted_cands, rejected_cands = _build_candidate_evidence(
            snap.candidate_expansions, risk_id, pattern_id
        )

        obligations.append(
            TaxonomyObligation(
                obligation_id=obligation_id,
                risk_id=risk_id,
                pattern_id=pattern_id,
                scope=scope,
                terminal_disposition=disposition,
                qualification_trace=trace,
                accepted_candidates=accepted_cands,
                rejected_candidates=rejected_cands,
            )
        )

    # Deterministic canonical sort by semantic identity (risk_id, pattern_id,
    # obligation_id).  Duplicate canonical ids can still carry distinct
    # evidence, so the full serialized obligation is the final tiebreaker and
    # ledger order never depends on snapshot presentation order.
    obligations.sort(key=_canonical_sort_key)

    return TaxonomyObligationPlan(
        taxonomy_version=snap.taxonomy_version,
        mapping_version=snap.mapping_version,
        qualification_ruleset_version=snap.qualification_ruleset_version,
        template_version=snap.template_version,
        digest=snap.digest,
        obligations=obligations,
    )


def _canonical_sort_key(ob: TaxonomyObligation) -> tuple[str, str, str, str]:
    """Canonical sort key: semantic identity with content as the tiebreaker."""
    return (ob.risk_id, ob.pattern_id or "", ob.obligation_id, ob.model_dump_json())


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-27T17:13:03Z","module_hash":"58616a83f9300bff96aaa820d1c40e67156221b0c175f55f1b4418061cbde1a2","source_sha256":"8e1a0b3a373f01c3a4b775079aaa0391dea736ef756ef8493324312a4245257f","functions":[{"id":"func/_collect_config_secrets","name":"_collect_config_secrets","line":16,"end_line":22,"hash":"a8c4fc66772e128f9ecc4e577323d96df862eaef06a81b2333f16bbb4aed77a6"},{"id":"func/_sanitize_secrets","name":"_sanitize_secrets","line":25,"end_line":39,"hash":"e2bcd567c646a7ce6a8bfd95ce60bf375e4ab3d85272c2aa7ccbb7b7e4bba55a"},{"id":"func/_canonical_obligation_id","name":"_canonical_obligation_id","line":42,"end_line":46,"hash":"8cc67b81744a51271bf9d1c9eb2f3007fd6997402f470985e82a95190c67e9e3"},{"id":"func/_resolve_scope_and_disposition","name":"_resolve_scope_and_disposition","line":49,"end_line":79,"hash":"e58a3a687612a2f4728b0e700d0f8c4e847d143f95a37c0a55808037518aaf7d"},{"id":"func/_build_qualification_trace","name":"_build_qualification_trace","line":82,"end_line":104,"hash":"82820a3f4daebf0a03011f670adc0002de739cbb1a40b254336f3d0cfdd51029"},{"id":"func/_build_candidate_evidence","name":"_build_candidate_evidence","line":107,"end_line":128,"hash":"31e5c59a7c7ce296e656380d6be17bfe8303cc5dc74b050867dd50f4e4c94038"},{"id":"func/plan_obligations","name":"plan_obligations","line":131,"end_line":187,"hash":"12766197c7afefffaab85819d91944b00bcffb8eb2739774f83e5cb1a7cb713d"},{"id":"func/_canonical_sort_key","name":"_canonical_sort_key","line":190,"end_line":192,"hash":"ac77c500171be1c7761e31922c1dbdba71bdfce8287cb6f298fc1082c01cac43"}]}
# mutate4py-manifest-end
