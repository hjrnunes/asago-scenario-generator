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
    obligations.sort(
        key=lambda ob: (
            ob.risk_id,
            ob.pattern_id or "",
            ob.obligation_id,
            ob.model_dump_json(),
        )
    )

    return TaxonomyObligationPlan(
        taxonomy_version=snap.taxonomy_version,
        mapping_version=snap.mapping_version,
        qualification_ruleset_version=snap.qualification_ruleset_version,
        template_version=snap.template_version,
        digest=snap.digest,
        obligations=obligations,
        network_calls=0,
        model_calls=0,
    )
