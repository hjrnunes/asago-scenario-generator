"""Focused unit tests for taxonomy obligation planner."""

from __future__ import annotations

from typing import Any

from asago_scenario_generator.models.obligation_plan import (
    TaxonomyObligationSnapshot,
)
from asago_scenario_generator.pipeline.obligation_planner import plan_obligations


def _rel(
    risk_id: str,
    pattern_id: str | None = None,
    *,
    scope: str = "in-scope",
    disposition: str = "generated",
) -> dict[str, Any]:
    return {
        "risk_id": risk_id,
        "pattern_id": pattern_id,
        "scope": scope,
        "disposition": disposition,
    }


def _make_snapshot(**overrides: Any) -> TaxonomyObligationSnapshot:
    defaults: dict[str, Any] = {
        "taxonomy_version": "atlas-2026.05",
        "mapping_version": "sssom-v1",
        "qualification_ruleset_version": "catalog-qualification-v1",
        "template_version": "scenario-envelope-v1",
        "digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "relationships": [],
    }
    defaults.update(overrides)
    return TaxonomyObligationSnapshot(**defaults)


def test_shared_pattern_distinct_risk_scoped_obligations() -> None:
    snapshot = _make_snapshot(
        relationships=[
            _rel("atlas-prompt-injection", "AP-T1-01"),
            _rel("atlas-memory-poisoning", "AP-T1-01", disposition="missing-template"),
        ],
    )

    plan = plan_obligations(snapshot)
    assert len(plan.obligations) == 2
    ob_prompt = next(
        o for o in plan.obligations if o.risk_id == "atlas-prompt-injection"
    )
    ob_memory = next(
        o for o in plan.obligations if o.risk_id == "atlas-memory-poisoning"
    )

    assert ob_prompt.pattern_id == "AP-T1-01"
    assert ob_memory.pattern_id == "AP-T1-01"
    assert ob_prompt.obligation_id != ob_memory.obligation_id
    assert ob_prompt.obligation_id == "ob:atlas-prompt-injection:AP-T1-01"
    assert ob_memory.obligation_id == "ob:atlas-memory-poisoning:AP-T1-01"
    assert plan.network_calls == 0
    assert plan.model_calls == 0


def test_order_independence() -> None:
    snapshot_a = _make_snapshot(
        relationships=[
            _rel("atlas-prompt-injection", "AP-T6-01"),
            _rel("atlas-memory-poisoning", "AP-T1-01", disposition="missing-template"),
        ],
    )
    snapshot_b = _make_snapshot(
        relationships=[
            _rel("atlas-memory-poisoning", "AP-T1-01", disposition="missing-template"),
            _rel("atlas-prompt-injection", "AP-T6-01"),
        ],
    )

    plan_a = plan_obligations(snapshot_a)
    plan_b = plan_obligations(snapshot_b)

    assert [o.obligation_id for o in plan_a.obligations] == [
        o.obligation_id for o in plan_b.obligations
    ]
    assert plan_a.to_json() == plan_b.to_json()
    assert plan_a.to_yaml() == plan_b.to_yaml()


def test_scope_and_terminal_dispositions() -> None:
    snapshot = _make_snapshot(
        relationships=[
            _rel(
                "atlas-prompt-injection",
                "AP-T11-01",
                scope="out-of-scope",
                disposition="gated",
            ),
            _rel("atlas-memory-poisoning", "AP-T1-01", disposition="missing-template"),
            _rel("atlas-memory-poisoning", "AP-T1-02", disposition="infeasible"),
            _rel("atlas-memory-poisoning", "AP-T1-03", disposition="unsupported"),
            _rel("atlas-prompt-injection", "AP-T6-01"),
            _rel("atlas-orphan-risk", disposition="governance-only"),
        ],
    )

    plan = plan_obligations(snapshot)
    assert len(plan.obligations) == 6
    dispositions = {
        o.obligation_id: (o.scope, o.terminal_disposition) for o in plan.obligations
    }

    assert dispositions["ob:atlas-prompt-injection:AP-T11-01"] == (
        "out-of-scope",
        "gated",
    )
    assert dispositions["ob:atlas-memory-poisoning:AP-T1-01"] == (
        "in-scope",
        "missing-template",
    )
    assert dispositions["ob:atlas-memory-poisoning:AP-T1-02"] == (
        "in-scope",
        "infeasible",
    )
    assert dispositions["ob:atlas-memory-poisoning:AP-T1-03"] == (
        "in-scope",
        "unsupported",
    )
    assert dispositions["ob:atlas-prompt-injection:AP-T6-01"] == (
        "in-scope",
        "generated",
    )
    assert dispositions["ob:atlas-orphan-risk"] == ("in-scope", "governance-only")


def test_governance_only_risk_without_pattern() -> None:
    snapshot = _make_snapshot(
        relationships=[_rel("atlas-orphan-risk", disposition="governance-only")],
    )

    plan = plan_obligations(snapshot)
    assert len(plan.obligations) == 1
    ob = plan.obligations[0]
    assert ob.risk_id == "atlas-orphan-risk"
    assert ob.pattern_id is None
    assert ob.terminal_disposition == "governance-only"
    assert ob.obligation_id == "ob:atlas-orphan-risk"


def test_qualification_trace_omits_secrets() -> None:
    secret_token = "**************************"
    snapshot = _make_snapshot(
        config={"api_key": secret_token, "custom_secret": secret_token},
        relationships=[_rel("atlas-prompt-injection", "AP-T6-01")],
        qualification_evaluations=[
            {
                "risk_id": "atlas-prompt-injection",
                "pattern_id": "AP-T6-01",
                "predicate": "deployment.attacker_code_execution_on_agent_host",
                "facts": "deployment.attacker_code_execution_on_agent_host=false",
                "result": "false",
                "reason": "fact present and unequal",
            }
        ],
    )

    plan = plan_obligations(snapshot)
    serialized_yaml = plan.to_yaml()
    serialized_json = plan.to_json()

    assert secret_token not in serialized_yaml
    assert secret_token not in serialized_json
    ob = plan.obligations[0]
    assert len(ob.qualification_trace) == 1
    assert (
        ob.qualification_trace[0].predicate
        == "deployment.attacker_code_execution_on_agent_host"
    )
    assert ob.qualification_trace[0].result == "false"
    assert ob.qualification_trace[0].reason == "fact present and unequal"


def test_candidate_expansion_evidence_retained() -> None:
    snapshot = _make_snapshot(
        relationships=[_rel("atlas-prompt-injection", "AP-T6-01")],
        candidate_expansions=[
            {
                "risk_id": "atlas-prompt-injection",
                "pattern_id": "AP-T6-01",
                "accepted_candidates": ["cand:v2:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
                "rejected_candidates": [
                    {
                        "candidate_id": "cand:v2:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                        "reason": "rule rejected combination",
                    }
                ],
            }
        ],
    )

    plan = plan_obligations(snapshot)
    ob = plan.obligations[0]
    assert ob.accepted_candidates == ["cand:v2:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
    assert len(ob.rejected_candidates) == 1
    assert (
        ob.rejected_candidates[0].candidate_id
        == "cand:v2:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    )
    assert ob.rejected_candidates[0].reason == "rule rejected combination"
