"""Focused unit tests for taxonomy obligation planner."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from typer.testing import CliRunner

from asago_scenario_generator.cli import app
from asago_scenario_generator.models.obligation_plan import (
    TaxonomyObligationPlan,
    TaxonomyObligationSnapshot,
)
from asago_scenario_generator.pipeline.obligation_planner import plan_obligations

runner = CliRunner()


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


def test_relationship_kind_derives_disposition() -> None:
    snapshot = _make_snapshot(
        relationships=[
            {
                "risk_id": "risk-gated",
                "pattern_id": "AP-T1-01",
                "relationship_kind": "gated threat",
            },
            {
                "risk_id": "risk-missing",
                "pattern_id": "AP-T1-02",
                "relationship_kind": "missing generation template",
            },
            {
                "risk_id": "risk-infeasible",
                "pattern_id": "AP-T1-03",
                "relationship_kind": "projection infeasibility",
            },
            {
                "risk_id": "risk-unsupported",
                "pattern_id": "AP-T1-04",
                "relationship_kind": "unsupported requirement",
            },
            {
                "risk_id": "risk-governance",
                "pattern_id": "AP-T1-05",
                "relationship_kind": "governance review",
            },
            {
                "risk_id": "risk-generated",
                "pattern_id": "AP-T1-06",
                "relationship_kind": "qualified generable pattern",
            },
            {"risk_id": "risk-orphan"},
        ],
    )

    plan = plan_obligations(snapshot)
    dispositions = {
        o.obligation_id: (o.scope, o.terminal_disposition) for o in plan.obligations
    }

    assert dispositions["ob:risk-gated:AP-T1-01"] == ("out-of-scope", "gated")
    assert dispositions["ob:risk-missing:AP-T1-02"] == ("in-scope", "missing-template")
    assert dispositions["ob:risk-infeasible:AP-T1-03"] == ("in-scope", "infeasible")
    assert dispositions["ob:risk-unsupported:AP-T1-04"] == (
        "in-scope",
        "unsupported",
    )
    assert dispositions["ob:risk-governance:AP-T1-05"] == (
        "in-scope",
        "governance-only",
    )
    assert dispositions["ob:risk-generated:AP-T1-06"] == ("in-scope", "generated")
    assert dispositions["ob:risk-orphan"] == ("in-scope", "governance-only")


def test_unknown_relationship_kind_defaults_to_generated() -> None:
    snapshot = _make_snapshot(
        relationships=[
            {
                "risk_id": "risk-x",
                "pattern_id": "AP-T1-01",
                "relationship_kind": "unclassified note",
            },
        ],
    )

    plan = plan_obligations(snapshot)
    assert plan.obligations[0].terminal_disposition == "generated"
    assert plan.obligations[0].scope == "in-scope"


def test_trace_matching_requires_risk_and_pattern() -> None:
    snapshot = _make_snapshot(
        relationships=[_rel("risk-a", "AP-T1-01")],
        qualification_evaluations=[
            {
                "risk_id": "risk-a",
                "pattern_id": "AP-T1-01",
                "predicate": "exact.match",
                "facts": "exact.match=true",
                "result": "true",
                "reason": "same risk and pattern",
            },
            {
                "risk_id": "risk-a",
                "pattern_id": "AP-T1-02",
                "predicate": "wrong.pattern",
                "facts": "wrong.pattern=true",
                "result": "true",
                "reason": "same risk other pattern",
            },
            {
                "risk_id": "risk-b",
                "pattern_id": "AP-T1-01",
                "predicate": "wrong.risk",
                "facts": "wrong.risk=true",
                "result": "true",
                "reason": "same pattern other risk",
            },
        ],
    )

    plan = plan_obligations(snapshot)
    predicates = [t.predicate for t in plan.obligations[0].qualification_trace]

    assert predicates == ["exact.match"]


def test_expansion_matching_requires_risk_and_pattern() -> None:
    snapshot = _make_snapshot(
        relationships=[_rel("risk-a", "AP-T1-01")],
        candidate_expansions=[
            {
                "risk_id": "risk-a",
                "pattern_id": "AP-T1-01",
                "accepted_candidates": ["cand:one", "cand:one", 7],
                "rejected_candidates": [
                    {"candidate_id": "cand:two", "reason": "duplicate rejected"},
                ],
            },
            {
                "risk_id": "risk-a",
                "pattern_id": "AP-T1-02",
                "accepted_candidates": ["cand:other-pattern"],
            },
            {
                "risk_id": "risk-b",
                "pattern_id": "AP-T1-01",
                "accepted_candidates": ["cand:other-risk"],
            },
        ],
    )

    plan = plan_obligations(snapshot)
    ob = plan.obligations[0]

    assert ob.accepted_candidates == ["cand:one"]
    assert [r.candidate_id for r in ob.rejected_candidates] == ["cand:two"]


def test_non_string_config_values_are_ignored_as_secrets() -> None:
    snapshot = _make_snapshot(
        config={"api_key": 12345, "blank": "   ", "real": "sekret-token"},
        relationships=[_rel("risk-a", "AP-T1-01")],
        qualification_evaluations=[
            {
                "risk_id": "risk-a",
                "pattern_id": "AP-T1-01",
                "predicate": "pred sekret-token tail",
                "facts": "f=1",
                "result": "true",
                "reason": "evaluated",
            },
        ],
    )

    plan = plan_obligations(snapshot)
    trace = plan.obligations[0].qualification_trace[0]

    assert trace.predicate == "pred [REDACTED] tail"
    assert "sekret-token" not in plan.to_json()


def test_yaml_artifact_is_block_style_with_sorted_keys() -> None:
    snapshot = _make_snapshot(relationships=[_rel("risk-a", "AP-T1-01")])
    text = plan_obligations(snapshot).to_yaml()

    assert text.startswith("digest: ")
    assert list(yaml.safe_load(text)) == sorted(yaml.safe_load(text))


def test_unicode_ids_survive_yaml_serialization() -> None:
    snapshot = _make_snapshot(
        relationships=[_rel("risco-falha-é", "AP-T1-01")],
    )

    plan = plan_obligations(snapshot)
    text = plan.to_yaml()

    assert "risco-falha-é" in text
    assert TaxonomyObligationPlan.from_yaml(text) == plan


def test_traces_pass_through_without_secrets() -> None:
    snapshot = _make_snapshot(
        relationships=[_rel("risk-a", "AP-T1-01")],
        qualification_evaluations=[
            {
                "risk_id": "risk-a",
                "pattern_id": "AP-T1-01",
                "predicate": "pred",
                "facts": "f=1",
                "result": "true",
                "reason": "evaluated",
            },
        ],
    )

    plan = plan_obligations(snapshot)
    trace = plan.obligations[0].qualification_trace[0]

    assert trace.predicate == "pred"
    assert trace.facts == "f=1"
    assert trace.reason == "evaluated"


def test_structured_fact_values_are_sanitized() -> None:
    snapshot = _make_snapshot(
        config={"real": "sekret-token"},
        relationships=[_rel("risk-a", "AP-T1-01")],
        qualification_evaluations=[
            {
                "risk_id": "risk-a",
                "pattern_id": "AP-T1-01",
                "predicate": "pred",
                "facts": {"env": "value sekret-token", "tags": ["a sekret-token"]},
                "result": "true",
                "reason": "evaluated",
            },
        ],
    )

    plan = plan_obligations(snapshot)
    trace = plan.obligations[0].qualification_trace[0]

    assert trace.facts == {"env": "value [REDACTED]", "tags": ["a [REDACTED]"]}
    assert "sekret-token" not in plan.to_yaml() + plan.to_json()


def test_plan_accepts_raw_dict_snapshot() -> None:
    snapshot = {
        "taxonomy_version": "atlas-2026.05",
        "mapping_version": "sssom-v1",
        "qualification_ruleset_version": "catalog-qualification-v1",
        "template_version": "scenario-envelope-v1",
        "digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "relationships": [_rel("risk-a", "AP-T1-01")],
    }

    plan = plan_obligations(snapshot)

    assert len(plan.obligations) == 1
    assert plan.obligations[0].risk_id == "risk-a"


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


def test_plan_obligations_cli_writes_yaml_and_json(tmp_path: Path) -> None:
    snapshot = _make_snapshot(
        relationships=[
            _rel("atlas-prompt-injection", "AP-T6-01"),
            _rel("atlas-orphan-risk", disposition="governance-only"),
        ],
    )
    snapshot_path = tmp_path / "snapshot.yaml"
    snapshot_path.write_text(
        yaml.safe_dump(snapshot.model_dump(mode="json")), encoding="utf-8"
    )
    output_dir = tmp_path / "plan"

    result = runner.invoke(
        app,
        [
            "plan-obligations",
            "--snapshot",
            str(snapshot_path),
            "--output-dir",
            str(output_dir),
        ],
    )

    assert result.exit_code == 0, result.stderr
    yaml_path = output_dir / "obligation-plan.yaml"
    json_path = output_dir / "obligation-plan.json"
    assert yaml_path.is_file()
    assert json_path.is_file()
    assert f"Obligation plan written to {yaml_path}" in result.stdout
    assert "Network calls: 0" in result.stdout
    assert "Model calls:   0" in result.stdout
    loaded = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    assert loaded["network_calls"] == 0
    assert loaded["model_calls"] == 0
    assert len(loaded["obligations"]) == 2


def test_plan_obligations_cli_rejects_missing_snapshot(tmp_path: Path) -> None:
    missing = tmp_path / "missing" / "snapshot.yaml"
    result = runner.invoke(
        app,
        [
            "plan-obligations",
            "--snapshot",
            str(missing),
            "--output-dir",
            str(tmp_path / "plan"),
        ],
    )

    assert result.exit_code == 1
    assert f"Error: obligation snapshot not found: {missing}" in result.stderr
