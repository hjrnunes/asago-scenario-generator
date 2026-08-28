"""Focused unit tests for taxonomy obligation planner."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import ValidationError
from typer.testing import CliRunner

from asago_scenario_generator.cli import app
from asago_scenario_generator.models.obligation_plan import (
    CandidateRecord,
    TaxonomyObligationPlan,
    TaxonomyObligationSnapshot,
)
from asago_scenario_generator.pipeline.obligation_planner import (
    _json_serializable,
    _sanitize_secrets,
    plan_obligations,
)

runner = CliRunner()


def _rel(
    risk_id: str,
    pattern_id: str | None = None,
    *,
    scope: str | None = None,
    disposition: str | None = "ready",
) -> dict[str, Any]:
    rel: dict[str, Any] = {
        "risk_id": risk_id,
        "pattern_id": pattern_id,
        "disposition": disposition,
    }
    if scope is not None:
        rel["scope"] = scope
    return rel


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
            _rel(
                "atlas-memory-poisoning",
                "AP-T1-01",
                disposition="missing_evidence",
            ),
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
    assert ob_prompt.obligation_id.startswith("ob:atlas-prompt-injection:AP-T1-01:")
    assert ob_memory.obligation_id.startswith("ob:atlas-memory-poisoning:AP-T1-01:")
    assert plan.network_calls == 0
    assert plan.model_calls == 0


def test_order_independence() -> None:
    snapshot_a = _make_snapshot(
        relationships=[
            _rel("atlas-prompt-injection", "AP-T6-01"),
            _rel(
                "atlas-memory-poisoning",
                "AP-T1-01",
                disposition="missing_evidence",
            ),
        ],
    )
    snapshot_b = _make_snapshot(
        relationships=[
            _rel(
                "atlas-memory-poisoning",
                "AP-T1-01",
                disposition="missing_evidence",
            ),
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
                scope="capability_excluded",
                disposition="not_attempted",
            ),
            _rel(
                "atlas-memory-poisoning",
                "AP-T1-01",
                disposition="missing_evidence",
            ),
            _rel(
                "atlas-memory-poisoning",
                "AP-T1-02",
                disposition="structurally_infeasible",
            ),
            _rel(
                "atlas-memory-poisoning",
                "AP-T1-03",
                disposition="contradictory_evidence",
            ),
            _rel("atlas-prompt-injection", "AP-T6-01"),
            _rel("atlas-orphan-risk", disposition="governance_only"),
        ],
    )

    plan = plan_obligations(snapshot)
    assert len(plan.obligations) == 6
    dispositions = {
        (o.risk_id, o.pattern_id): (
            o.scope_disposition,
            o.qualification_disposition,
            o.projection_disposition,
        )
        for o in plan.obligations
    }

    assert dispositions[("atlas-prompt-injection", "AP-T11-01")] == (
        "capability_excluded",
        "not_attempted",
        "not_attempted",
    )
    assert dispositions[("atlas-memory-poisoning", "AP-T1-01")] == (
        "applicable",
        "missing_evidence",
        "not_attempted",
    )
    assert dispositions[("atlas-memory-poisoning", "AP-T1-02")] == (
        "applicable",
        "structurally_infeasible",
        "not_attempted",
    )
    assert dispositions[("atlas-memory-poisoning", "AP-T1-03")] == (
        "applicable",
        "contradictory_evidence",
        "not_attempted",
    )
    assert dispositions[("atlas-prompt-injection", "AP-T6-01")] == (
        "applicable",
        "ready",
        "projectable",
    )
    assert dispositions[("atlas-orphan-risk", None)] == (
        "governance_only",
        "not_attempted",
        "not_attempted",
    )


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
        (o.risk_id, o.pattern_id): (
            o.scope_disposition,
            o.qualification_disposition,
            o.projection_disposition,
        )
        for o in plan.obligations
    }

    assert dispositions[("risk-gated", "AP-T1-01")] == (
        "capability_excluded",
        "not_attempted",
        "not_attempted",
    )
    assert dispositions[("risk-missing", "AP-T1-02")] == (
        "applicable",
        "missing_evidence",
        "not_attempted",
    )
    assert dispositions[("risk-infeasible", "AP-T1-03")] == (
        "applicable",
        "structurally_infeasible",
        "not_attempted",
    )
    assert dispositions[("risk-unsupported", "AP-T1-04")] == (
        "applicable",
        "structurally_infeasible",
        "not_attempted",
    )
    assert dispositions[("risk-governance", "AP-T1-05")] == (
        "governance_only",
        "not_attempted",
        "not_attempted",
    )
    assert dispositions[("risk-generated", "AP-T1-06")] == (
        "applicable",
        "ready",
        "projectable",
    )
    assert dispositions[("risk-orphan", None)] == (
        "governance_only",
        "not_attempted",
        "not_attempted",
    )


def test_unknown_relationship_kind_defaults_to_ready() -> None:
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
    assert plan.obligations[0].scope_disposition == "applicable"
    assert plan.obligations[0].qualification_disposition == "ready"
    assert plan.obligations[0].projection_disposition == "projectable"


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
                "accepted_candidates": [
                    {
                        "candidate_id": "cand:one",
                        "projection_disposition": "projectable",
                    },
                    {
                        "candidate_id": "cand:one",
                        "projection_disposition": "projectable",
                    },
                ],
                "rejected_candidates": [
                    {
                        "candidate_id": "cand:two",
                        "projection_disposition": "projection_infeasible",
                        "reason": "duplicate rejected",
                    },
                ],
            },
            {
                "risk_id": "risk-a",
                "pattern_id": "AP-T1-02",
                "accepted_candidates": [
                    {
                        "candidate_id": "cand:other-pattern",
                        "projection_disposition": "projectable",
                    }
                ],
            },
            {
                "risk_id": "risk-b",
                "pattern_id": "AP-T1-01",
                "accepted_candidates": [
                    {
                        "candidate_id": "cand:other-risk",
                        "projection_disposition": "projectable",
                    }
                ],
            },
        ],
    )

    plan = plan_obligations(snapshot)
    ob = plan.obligations[0]

    assert len(ob.candidate_records) == 2
    assert ob.candidate_records[0].candidate_id == "cand:one"
    assert ob.candidate_records[1].candidate_id == "cand:two"


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

    assert "semantic_digest: " in text
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
        relationships=[
            {
                "risk_id": "atlas-orphan-risk",
                "scope_disposition": "governance_only",
                "qualification_disposition": "not_attempted",
                "projection_disposition": "not_attempted",
            }
        ],
    )

    plan = plan_obligations(snapshot)
    assert len(plan.obligations) == 1
    ob = plan.obligations[0]
    assert ob.risk_id == "atlas-orphan-risk"
    assert ob.pattern_id is None
    assert ob.scope_disposition == "governance_only"
    assert ob.qualification_disposition == "not_attempted"
    assert ob.projection_disposition == "not_attempted"
    assert ob.obligation_id.startswith("ob:atlas-orphan-risk:")


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
                "accepted_candidates": [
                    {
                        "candidate_id": "cand:v2:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        "projection_disposition": "projectable",
                    }
                ],
                "rejected_candidates": [
                    {
                        "candidate_id": "cand:v2:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                        "projection_disposition": "projection_infeasible",
                        "reason": "rule rejected combination",
                    }
                ],
            }
        ],
    )

    plan = plan_obligations(snapshot)
    ob = plan.obligations[0]
    assert len(ob.candidate_records) == 2
    assert (
        ob.candidate_records[0].candidate_id
        == "cand:v2:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    )
    assert (
        ob.candidate_records[1].candidate_id
        == "cand:v2:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    )
    assert ob.candidate_records[1].reason == "rule rejected combination"


def test_plan_obligations_cli_writes_yaml_and_json(tmp_path: Path) -> None:
    snapshot = _make_snapshot(
        relationships=[
            _rel("atlas-prompt-injection", "AP-T6-01"),
            _rel("atlas-orphan-risk", disposition="governance_only"),
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
    yaml_path = output_dir / "taxonomy-obligation-plan.yaml"
    json_path = output_dir / "taxonomy-obligation-plan.json"
    assert yaml_path.is_file()
    assert json_path.is_file()
    assert f"Obligation plan written to {yaml_path}" in result.stdout
    assert "Network calls: 0" in result.stdout
    assert "Model calls:   0" in result.stdout
    loaded = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    assert loaded["network_calls"] == 0
    assert loaded["model_calls"] == 0
    assert len(loaded["obligations"]) == 2


@pytest.mark.parametrize("format_name", ["yaml", "json"])
def test_plan_obligations_cli_writes_only_requested_format(
    tmp_path: Path, format_name: str
) -> None:
    snapshot = _make_snapshot(relationships=[_rel("risk-a", "AP-T1-01")])
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
            "--format",
            format_name,
        ],
    )

    assert result.exit_code == 0, result.stderr
    yaml_path = output_dir / "taxonomy-obligation-plan.yaml"
    json_path = output_dir / "taxonomy-obligation-plan.json"
    assert yaml_path.is_file() == (format_name == "yaml")
    assert json_path.is_file() == (format_name == "json")


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


@pytest.mark.parametrize(
    ("disposition", "expected"),
    [
        ("gated", ("capability_excluded", "not_attempted", "not_attempted")),
        ("governance-only", ("governance_only", "not_attempted", "not_attempted")),
        ("missing-template", ("applicable", "missing_evidence", "not_attempted")),
        ("infeasible", ("applicable", "structurally_infeasible", "not_attempted")),
        ("unsupported", ("applicable", "structurally_infeasible", "not_attempted")),
        ("generated", ("applicable", "ready", "projectable")),
    ],
)
def test_legacy_dispositions_map_to_contract_dispositions(
    disposition: str, expected: tuple[str, str, str]
) -> None:
    snapshot = _make_snapshot(
        relationships=[_rel("risk-a", "AP-T1-01", disposition=disposition)],
    )

    plan = plan_obligations(snapshot)
    ob = plan.obligations[0]

    assert (
        ob.scope_disposition,
        ob.qualification_disposition,
        ob.projection_disposition,
    ) == expected


def test_legacy_not_attempted_without_pattern_is_governance_only() -> None:
    snapshot = _make_snapshot(
        relationships=[_rel("risk-orphan", None, disposition="not_attempted")],
    )

    plan = plan_obligations(snapshot)
    ob = plan.obligations[0]

    assert (
        ob.scope_disposition,
        ob.qualification_disposition,
        ob.projection_disposition,
    ) == (
        "governance_only",
        "not_attempted",
        "not_attempted",
    )


def test_unknown_legacy_disposition_falls_back_to_kind_derivation() -> None:
    snapshot = _make_snapshot(
        relationships=[_rel("risk-a", "AP-T1-01", disposition="mystery")],
    )

    plan = plan_obligations(snapshot)
    ob = plan.obligations[0]

    assert ob.scope_disposition == "applicable"
    assert ob.qualification_disposition == "ready"
    assert ob.projection_disposition == "projectable"


def test_legacy_excluded_scope_with_conflicting_projection_is_rejected() -> None:
    snapshot = _make_snapshot(
        relationships=[
            {
                "risk_id": "risk-a",
                "pattern_id": "AP-T1-01",
                "disposition": "governance-only",
                "projection_disposition": "projectable",
            }
        ],
    )

    with pytest.raises(ValueError, match="Invalid disposition combination"):
        plan_obligations(snapshot)


def test_explicit_pins_take_precedence_over_legacy_aliases() -> None:
    snapshot = _make_snapshot(
        catalog_pin="atlas-modern",
        taxonomy_version="atlas-legacy",
        mapping_pin="sssom-modern",
        mapping_version="sssom-legacy",
    )

    plan = plan_obligations(snapshot)

    assert plan.catalog_pins["catalog"] == "atlas-modern"
    assert plan.mapping_pins["mapping"] == "sssom-modern"


def test_canonical_json_serialization_is_key_order_independent() -> None:
    assert _json_serializable({"a": 1, "b": 2}) == _json_serializable({"b": 2, "a": 1})


@pytest.mark.parametrize(
    ("scope", "expected"),
    [
        ("in-scope", ("applicable", "ready", "projectable")),
        ("out-of-scope", ("capability_excluded", "not_attempted", "not_attempted")),
    ],
)
def test_explicit_scope_aliases_are_normalized(
    scope: str, expected: tuple[str, str, str]
) -> None:
    snapshot = _make_snapshot(
        relationships=[_rel("risk-a", "AP-T1-01", scope=scope, disposition=None)],
    )

    plan = plan_obligations(snapshot)
    ob = plan.obligations[0]

    assert (
        ob.scope_disposition,
        ob.qualification_disposition,
        ob.projection_disposition,
    ) == expected


@pytest.mark.parametrize(
    ("scope", "qualification", "projection", "message"),
    [
        (
            "governance_only",
            "ready",
            "not_attempted",
            "scope 'governance_only' cannot be combined with qualification 'ready'",
        ),
        (
            "capability_excluded",
            "ready",
            "not_attempted",
            "scope 'capability_excluded' cannot be combined with qualification 'ready'",
        ),
        (
            "applicable",
            "not_attempted",
            "not_attempted",
            "scope 'applicable' cannot be combined with qualification 'not_attempted'",
        ),
        (
            "applicable",
            "missing_evidence",
            "projectable",
            "qualification 'missing_evidence' cannot be combined with projection 'projectable'",
        ),
        (
            "applicable",
            "bogus_qualification",
            "not_attempted",
            "Invalid qualification disposition 'bogus_qualification' for scope 'applicable'",
        ),
    ],
)
def test_invalid_disposition_combinations_are_rejected(
    scope: str,
    qualification: str,
    projection: str,
    message: str,
) -> None:
    snapshot = _make_snapshot(
        relationships=[
            {
                "risk_id": "risk-a",
                "pattern_id": "AP-T1-01",
                "scope_disposition": scope,
                "qualification_disposition": qualification,
                "projection_disposition": projection,
            }
        ],
    )

    with pytest.raises(ValueError, match=message):
        plan_obligations(snapshot)


def test_summary_counts_follow_candidate_records_when_present() -> None:
    snapshot = _make_snapshot(
        relationships=[
            _rel("risk-a", "AP-T1-01"),
            _rel("risk-b", "AP-T1-02", disposition="missing_evidence"),
        ],
        candidate_expansions=[
            {
                "risk_id": "risk-a",
                "pattern_id": "AP-T1-01",
                "candidates": [
                    {
                        "candidate_id": "cand:one",
                        "projection_disposition": "projectable",
                        "reason": "ready",
                    },
                    {
                        "candidate_id": "cand:two",
                        "projection_disposition": "projection_infeasible",
                        "reason": "infeasible",
                    },
                    {
                        "candidate_id": "cand:three",
                        "projection_disposition": "budget_deferred",
                        "reason": "deferred",
                    },
                ],
            }
        ],
    )

    plan = plan_obligations(snapshot)
    summary = plan.summary

    assert summary.total == 2
    assert summary.applicable == 2
    assert summary.ready == 1
    assert summary.missing_or_contradictory == 1
    assert summary.projectable == 1
    assert summary.projection_infeasible == 1
    assert summary.budget_deferred == 1


def test_summary_counts_follow_obligation_rows_without_candidate_records() -> None:
    snapshot = _make_snapshot(
        relationships=[
            _rel("risk-a", "AP-T1-01"),
            _rel(
                "risk-gated",
                "AP-T1-02",
                scope="capability_excluded",
                disposition="not_attempted",
            ),
            _rel("risk-orphan", disposition="governance_only"),
            _rel("risk-missing", "AP-T1-03", disposition="missing_evidence"),
            _rel(
                "risk-contradictory", "AP-T1-04", disposition="contradictory_evidence"
            ),
            _rel("risk-struct", "AP-T1-05", disposition="structurally_infeasible"),
        ],
    )

    plan = plan_obligations(snapshot)
    summary = plan.summary

    assert summary.total == 6
    assert summary.applicable == 4
    assert summary.governance_only == 1
    assert summary.capability_excluded == 1
    assert summary.ready == 1
    assert summary.missing_or_contradictory == 2
    assert summary.structurally_infeasible == 1
    assert summary.projectable == 1
    assert summary.projection_infeasible == 0
    assert summary.budget_deferred == 0


def test_sanitize_secrets_passes_through_other_scalars() -> None:
    secrets = {"sekret-token"}

    assert _sanitize_secrets(4104, secrets) == 4104
    assert _sanitize_secrets(None, secrets) is None
    assert _sanitize_secrets({"facts": 4104}, secrets) == {"facts": 4104}
    assert _sanitize_secrets("no secret here", set()) == "no secret here"


def test_excluded_scope_with_unsettled_projection_is_rejected() -> None:
    snapshot = _make_snapshot(
        relationships=[
            {
                "risk_id": "risk-a",
                "pattern_id": "AP-T1-01",
                "scope_disposition": "capability_excluded",
                "qualification_disposition": "not_attempted",
                "projection_disposition": "projectable",
            }
        ],
    )

    with pytest.raises(
        ValueError,
        match="scope 'capability_excluded' cannot be combined with projection 'projectable'",
    ):
        plan_obligations(snapshot)


def test_unknown_scope_disposition_is_rejected_by_closed_model() -> None:
    snapshot = _make_snapshot(
        relationships=[
            {
                "risk_id": "risk-a",
                "pattern_id": "AP-T1-01",
                "scope_disposition": "unclassified_scope",
                "qualification_disposition": "ready",
                "projection_disposition": "projectable",
            }
        ],
    )

    with pytest.raises(ValidationError):
        plan_obligations(snapshot)


def test_bare_string_entries_in_candidates_section_are_ignored() -> None:
    snapshot = _make_snapshot(
        relationships=[_rel("risk-a", "AP-T1-01")],
        candidate_expansions=[
            {
                "risk_id": "risk-a",
                "pattern_id": "AP-T1-01",
                "candidates": ["cand:bare-string"],
            }
        ],
    )

    plan = plan_obligations(snapshot)

    assert plan.obligations[0].candidate_records == []


def test_candidates_without_identifier_are_skipped() -> None:
    snapshot = _make_snapshot(
        relationships=[_rel("risk-a", "AP-T1-01")],
        candidate_expansions=[
            {
                "risk_id": "risk-a",
                "pattern_id": "AP-T1-01",
                "accepted_candidates": [
                    {"projection_disposition": "projectable"},
                    "cand:bare-accepted",
                ],
            }
        ],
    )

    plan = plan_obligations(snapshot)

    records = plan.obligations[0].candidate_records
    assert [c.candidate_id for c in records] == ["cand:bare-accepted"]
    assert records[0].projection_disposition == "projectable"
    assert records[0].reason == "qualified combination"


@pytest.mark.parametrize(
    ("section_key", "expected_reason"),
    [
        ("accepted_candidates", "qualified combination"),
        ("rejected_candidates", "missing required resource"),
    ],
)
def test_section_entries_without_reason_use_section_default(
    section_key: str, expected_reason: str
) -> None:
    snapshot = _make_snapshot(
        relationships=[_rel("risk-a", "AP-T1-01")],
        candidate_expansions=[
            {
                "risk_id": "risk-a",
                "pattern_id": "AP-T1-01",
                section_key: [{"candidate_id": "cand:no-reason"}],
            }
        ],
    )

    plan = plan_obligations(snapshot)

    records = plan.obligations[0].candidate_records
    assert len(records) == 1
    assert records[0].reason == expected_reason


def test_plan_pins_fall_back_to_defaults_when_blank() -> None:
    snapshot = _make_snapshot(
        catalog_pin="",
        taxonomy_version=None,
        mapping_pin="",
        mapping_version=None,
        relationships=[_rel("risk-a", "AP-T1-01")],
    )

    plan = plan_obligations(snapshot)

    assert plan.catalog_pins == {"catalog": "atlas-2026.05", "atlas": "atlas-2026.05"}
    assert plan.mapping_pins == {"mapping": "sssom-v1", "sssom": "sssom-v1"}


def test_plan_pins_backfill_from_legacy_alias_when_modern_pin_blank() -> None:
    snapshot = _make_snapshot(
        catalog_pin="",
        taxonomy_version="atlas-legacy",
        mapping_pin="",
        mapping_version="sssom-legacy",
        relationships=[_rel("risk-a", "AP-T1-01")],
    )

    plan = plan_obligations(snapshot)

    assert plan.catalog_pins == {"catalog": "atlas-legacy", "atlas": "atlas-legacy"}
    assert plan.mapping_pins == {"mapping": "sssom-legacy", "sssom": "sssom-legacy"}
