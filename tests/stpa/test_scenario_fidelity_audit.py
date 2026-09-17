"""Deterministic offline qualification audit regressions."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from scripts.qualification.audit_scenario_fidelity_evidence import (
    AUDIT_ARTIFACTS,
    build_completion_status,
    build_reachability,
    build_run_recount,
    build_secret_scan,
    build_usage_ledger,
    write_audit_artifacts,
)


def test_audit_writes_the_complete_deterministic_artifact_set(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "calls.jsonl").write_text(
        '{"stage":"stage_5","prompt_tokens":3,"completion_tokens":2}\n',
        encoding="utf-8",
    )
    first = write_audit_artifacts(tmp_path / "first", source_roots=(source,))
    second = write_audit_artifacts(tmp_path / "second", source_roots=(source,))

    assert [path.name for path in first] == list(AUDIT_ARTIFACTS)
    assert [path.name for path in second] == list(AUDIT_ARTIFACTS)
    for left, right in zip(first, second):
        assert json.loads(left.read_text()) == json.loads(right.read_text())


def test_usage_ledger_keeps_provider_category_and_unavailable_denominators(
    tmp_path: Path,
) -> None:
    (tmp_path / "calls.jsonl").write_text(
        '{"stage":"stage_5","prompt_tokens":3,"completion_tokens":2}\n',
        encoding="utf-8",
    )

    ledger = build_usage_ledger((tmp_path,))

    assert ledger["category_totals"]["producer_provider"] == {
        "call_count": 1,
        "total_tokens": 5,
    }
    assert (
        ledger["denominators"]["consumer_authoring_attempts"]
        == "unavailable_without_consumer_records"
    )
    assert ledger["spending"] == {
        "raw_provider_records": 1,
        "available_provider_tokens": 5,
        "raw_primary_records": 1,
        "available_token_records": 1,
        "unavailable_usage_records": 0,
        "provider_available_token_records": 1,
        "provider_unavailable_usage_records": 0,
    }


def test_usage_ledger_reports_duplicate_primary_attempts_before_aggregation(
    tmp_path: Path,
) -> None:
    (tmp_path / "calls.jsonl").write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "attempt_id": "producer:one",
                        "call_category": "producer_provider",
                        "provider_request": True,
                        "prompt_tokens": 3,
                        "completion_tokens": 2,
                    }
                ),
                json.dumps(
                    {
                        "attempt_id": "producer:one",
                        "call_category": "producer_provider",
                        "provider_request": True,
                        "prompt_tokens": 7,
                        "completion_tokens": 4,
                    }
                ),
                json.dumps(
                    {
                        "attempt_id": "producer:two",
                        "call_category": "producer_provider",
                        "provider_request": True,
                        "prompt_tokens": 11,
                        "completion_tokens": 13,
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    (tmp_path / "design-record.json").write_text(
        json.dumps(
            {
                "authoring": {
                    "attempts": [
                        {
                            "attempt_id": "consumer:one",
                            "call_category": "consumer_authoring",
                            "provider_request": False,
                            "usage": {
                                "status": "unavailable",
                                "prompt_tokens": None,
                                "completion_tokens": None,
                            },
                        }
                    ]
                }
            }
        ),
        encoding="utf-8",
    )

    ledger = build_usage_ledger((tmp_path,))

    assert ledger["duplicate_attempt_ids"] == ["producer:one"]
    assert ledger["reuse_check"] == {
        "status": "invalid",
        "duplicate_ids": ["producer:one"],
    }
    assert ledger["valid"] is False
    assert ledger["category_totals"]["producer_provider"] == {
        "call_count": 3,
        "total_tokens": 40,
    }
    assert ledger["category_totals"]["consumer_authoring"] == {
        "call_count": 1,
        "total_tokens": 0,
    }
    assert ledger["denominators"]["provider_requests"] == 3
    assert ledger["denominators"]["consumer_authoring_attempts"] == 1


def test_usage_ledger_counts_superseded_raw_records_and_locates_collisions(
    tmp_path: Path,
) -> None:
    """Historical collisions remain spend while identity remains auditable."""
    run = tmp_path / "fresh-miniklarna-qualification-20260917"
    run.mkdir()
    (run / "run-status.json").write_text(
        json.dumps(
            {
                "run_id": "superseded-run",
                "stages": {"generation": {"run_id": "superseded-run"}},
            }
        ),
        encoding="utf-8",
    )
    calls = run / "calls.jsonl"
    calls.write_text(
        "\n".join(
            json.dumps(
                {
                    "attempt_id": "historical:reused",
                    "call_category": "producer_provider",
                    "provider_request": True,
                    "usage": {
                        "status": "reported",
                        "prompt_tokens": 3,
                        "completion_tokens": 2,
                    },
                }
            )
            for _ in range(2)
        )
        + "\n"
        + json.dumps(
            {
                "attempt_id": "historical:unique",
                "call_category": "producer_provider",
                "provider_request": True,
                "usage": {
                    "status": "unavailable",
                    "prompt_tokens": None,
                    "completion_tokens": None,
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )

    ledger = build_usage_ledger((tmp_path,))

    assert ledger["category_totals"]["producer_provider"] == {
        "call_count": 3,
        "total_tokens": 10,
    }
    assert ledger["denominators"]["provider_requests"] == 3
    assert ledger["denominators"]["available_token_records"] == 2
    assert ledger["denominators"]["unavailable_usage_records"] == 1
    assert ledger["spending"]["provider_available_token_records"] == 2
    assert ledger["spending"]["provider_unavailable_usage_records"] == 1
    assert ledger["reuse_check"]["status"] == "historical_only"
    assert ledger["valid"] is True
    collision = ledger["historical_collisions"][0]
    assert collision["attempt_id"] == "historical:reused"
    assert (
        collision["source_file_sha256"]
        == hashlib.sha256(calls.read_bytes()).hexdigest()
    )
    assert collision["line_positions"] == [1, 2]


def test_usage_ledger_rejects_duplicate_identity_in_force_or_unregistered_runs(
    tmp_path: Path,
) -> None:
    for root_name, expected_bucket in (
        ("fresh-miniairbnb-qualification-20260917", "in_force"),
        ("unregistered-run", "unregistered"),
    ):
        run = tmp_path / root_name
        run.mkdir()
        (run / "run-status.json").write_text(
            json.dumps(
                {
                    "run_id": root_name,
                    "stages": {"generation": {"run_id": root_name}},
                }
            ),
            encoding="utf-8",
        )
        (run / "calls.jsonl").write_text(
            "\n".join(
                json.dumps(
                    {
                        "attempt_id": "reused",
                        "call_category": "producer_provider",
                        "provider_request": True,
                    }
                )
                for _ in range(2)
            )
            + "\n",
            encoding="utf-8",
        )

        ledger = build_usage_ledger((tmp_path,))

        assert ledger["valid"] is False
        assert ledger["reuse_check"]["status"] == "invalid"
        assert ledger[f"{expected_bucket}_duplicate_attempt_ids"] == ["reused"]


def test_reachability_marks_unselected_published_scenarios_not_attempted(
    tmp_path: Path,
) -> None:
    """A bounded selection does not shrink the published denominator."""
    generation = tmp_path / "fresh-miniairbnb-qualification-20260917"
    scenarios = generation / "generation" / "scenarios"
    scenarios.mkdir(parents=True)
    for scenario_id in ("SCN-001", "SCN-002"):
        (scenarios / f"{scenario_id}.yaml").write_text(
            "schema_version: scenario-handoff-v1\n",
            encoding="utf-8",
        )
    generation_status = {
        "target_domain": "airbnb",
        "stages": {
            "generation": {
                "run_id": "in-force-run",
                "scenarios_published": 2,
                "scenarios_dir": str(scenarios),
            },
            "artifact": {"status": "not_run", "attempts": []},
        },
    }
    (generation / "run-status.json").write_text(
        json.dumps(generation_status),
        encoding="utf-8",
    )
    authoring = tmp_path / "fresh-miniairbnb-qualification-20260917-authoring"
    authoring.mkdir()
    (authoring / "run-status.json").write_text(
        json.dumps(
            {
                "target_domain": "airbnb",
                "stages": {
                    "generation": {
                        "run_id": "in-force-run",
                        "scenarios_published": 2,
                        "scenarios_dir": str(scenarios),
                    },
                    "artifact": {
                        "status": "failed",
                        "attempts": [
                            {
                                "scenario_id": "SCN-001",
                                "design_id": "SCN-001:design-1",
                                "compiled": False,
                                "exclusion_code": "unsupported",
                            }
                        ],
                    },
                },
            }
        ),
        encoding="utf-8",
    )

    report = build_reachability((generation, authoring))

    assert report["counts"] == {
        "published": 2,
        "consumer_evaluated": 1,
        "compiled": 0,
        "excluded": 1,
        "functional_specification": 0,
        "not_attempted": 1,
        "unresolved": 0,
    }
    assert report["per_run"]["in-force-run"]["reconciled"] is True
    not_attempted = next(
        row for row in report["scenarios"] if row["scenario_id"] == "SCN-002"
    )
    assert not_attempted["terminal_status"] == "not_attempted"
    assert not_attempted["consumer_validity_credit"] == 0
    assert not_attempted["compilation_credit"] == 0
    assert not_attempted["recovery_credit"] == 0


def test_usage_ledger_marks_unique_attempts_valid_and_keeps_prebound_zero_calls(
    tmp_path: Path,
) -> None:
    (tmp_path / "calls.jsonl").write_text(
        json.dumps(
            {
                "attempt_id": "producer:one",
                "call_category": "producer_provider",
                "provider_request": True,
                "prompt_tokens": 3,
                "completion_tokens": 2,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (tmp_path / "design-record.json").write_text(
        json.dumps(
            {
                "authoring": {
                    "attempts": [
                        {
                            "attempt_id": "consumer:prebound",
                            "call_category": "consumer_authoring",
                            "provider_request": False,
                            "usage": {
                                "status": "unavailable",
                                "prompt_tokens": None,
                                "completion_tokens": None,
                            },
                        }
                    ]
                }
            }
        ),
        encoding="utf-8",
    )

    ledger = build_usage_ledger((tmp_path,))

    assert ledger["duplicate_attempt_ids"] == []
    assert ledger["reuse_check"] == {"status": "valid", "duplicate_ids": []}
    assert ledger["valid"] is True
    assert ledger["denominators"]["provider_requests"] == 1
    assert ledger["denominators"]["consumer_authoring_attempts"] == 1
    assert ledger["category_totals"]["consumer_authoring"]["call_count"] == 1


def test_completion_status_blocks_duplicate_attempt_identity(
    tmp_path: Path,
) -> None:
    (tmp_path / "calls.jsonl").write_text(
        "\n".join(
            json.dumps(
                {
                    "attempt_id": "producer:reused",
                    "call_category": "producer_provider",
                    "provider_request": True,
                }
            )
            for _ in range(2)
        )
        + "\n",
        encoding="utf-8",
    )
    (tmp_path / "design-record.json").write_text(
        json.dumps(
            {
                "authoring": {
                    "attempts": [
                        {
                            "attempt_id": "consumer:one",
                            "call_category": "consumer_authoring",
                            "provider_request": False,
                        }
                    ]
                }
            }
        ),
        encoding="utf-8",
    )

    status = build_completion_status((tmp_path,))

    assert status["status"] == "blocked"
    assert any(
        item["code"] == "usage_ledger_duplicate_attempt_id"
        for item in status["blockers"]
    )


def test_completion_status_does_not_claim_complete_without_consumer_accounting(
    tmp_path: Path,
) -> None:
    status = build_completion_status((tmp_path,))

    assert status["status"] == "blocked"
    assert any(
        item["code"] == "consumer_call_accounting_unavailable"
        for item in status["blockers"]
    )


def test_secret_scan_reports_locations_without_secret_values(tmp_path: Path) -> None:
    path = tmp_path / "evidence.json"
    path.write_text(
        '{"token": "sk-secret-value-that-is-not-persisted"}\n', encoding="utf-8"
    )

    report = build_secret_scan((tmp_path,))

    assert report["clean"] is False
    assert report["matches"][0]["path"].endswith("evidence.json")
    assert "secret-value" not in json.dumps(report)


def test_secret_scan_labels_preserved_historical_matches(tmp_path: Path) -> None:
    """Historical leaks stay visible and are not relabeled as clean."""
    historical = tmp_path / "adaptive-runs" / "old-run"
    historical.mkdir(parents=True)
    (historical / "run-manifest.yaml").write_text(
        "base_url: https://private.apps.example/v1\n",
        encoding="utf-8",
    )

    report = build_secret_scan((tmp_path,))

    assert report["clean"] is False
    assert report["historical_only"] is True
    assert report["historical_matches"] == 1
    assert report["current_matches"] == 0
    assert report["matches"][0]["scope"] == "historical"


def test_run_recount_records_freshness_hashes_selection_and_predispatch(
    tmp_path: Path,
) -> None:
    """The qualification audit exposes every gate from a saved run."""
    run = tmp_path / "fresh-target"
    generation = run / "generation"
    scenarios = generation / "scenarios"
    execution = run / "execution"
    scenarios.mkdir(parents=True)
    execution.mkdir()
    (scenarios / "SCN-001.yaml").write_text(
        "schema_version: scenario-handoff-v1\n", encoding="utf-8"
    )
    (generation / "run-manifest.yaml").write_text(
        "\n".join(
            [
                "run_id: synthesis-1",
                "input_hashes:",
                "  target_observations: " + "a" * 64,
                "  loss_analysis: " + "b" * 64,
                "stage_summary:",
                "  stage_1a:",
                "    call_count: 0",
                "    source: pinned",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    (run / "run-status.json").write_text(
        json.dumps(
            {
                "schema_version": "orchestration-status-v1",
                "target_domain": "target",
                "stages": {
                    "generation": {
                        "status": "success",
                        "run_id": "synthesis-1",
                        "producer_run_status": "completed",
                        "scenarios_published": 1,
                        "scenarios_dir": str(scenarios),
                    },
                    "artifact": {
                        "status": "success",
                        "selected_scenario": "SCN-001",
                        "selected_design_id": "SCN-001:design-1",
                        "attempts": [
                            {
                                "scenario_id": "SCN-001",
                                "design_id": "SCN-001:design-1",
                                "compiled": True,
                            }
                        ],
                    },
                    "execution": {"status": "not_run"},
                },
            }
        ),
        encoding="utf-8",
    )
    (execution / "pre-dispatch-checks.yaml").write_text(
        "\n".join(
            [
                "scenario_meaning: {semantic_failure_criterion: command is issued}",
                "stimulus_exercise_rationale: {rationale: names the supported operation}",
                "verified_permissions_prerequisites: {holds: true}",
                "safe_alternatives_availability: {available: true}",
                "detector_discrimination: {observation_level: command}",
                "target_tools_and_instructions: {tools: [target_tool]}",
                "observation_limitations: [backend effect is separate]",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    recount = build_run_recount((tmp_path,))
    record = recount["runs"][0]

    assert record["freshness"] == "fresh"
    assert record["input_hashes"]["run_manifest"]["target_observations"] == "a" * 64
    assert record["predispatch"]["complete"] is True
    assert record["selection"]["selected_scenario"] == "SCN-001"
    assert record["selection"]["reason_validation"]["cites_gold_id"] is False
    assert (
        record["selection"]["reason_validation"]["cites_expected_unsafe_verdict"]
        is False
    )
    assert record["stage_1a"] == {
        "call_count": 0,
        "source": "pinned",
        "status": "valid",
    }


def test_reachability_prefers_authoring_chain_for_shared_generation_id(
    tmp_path: Path,
) -> None:
    """A producer manifest and its authoring child yield one terminal row."""
    generation = tmp_path / "producer" / "scenarios"
    generation.mkdir(parents=True)
    (generation / "SCN-001.yaml").write_text(
        "schema_version: scenario-handoff-v1\n", encoding="utf-8"
    )
    producer = tmp_path / "producer"
    producer_status = {
        "target_domain": "target",
        "stages": {
            "generation": {
                "run_id": "synthesis-shared",
                "scenarios_published": 1,
                "scenarios_dir": str(generation),
            },
            "artifact": {"status": "not_run", "attempts": []},
        },
    }
    (producer / "run-status.json").write_text(
        json.dumps(producer_status), encoding="utf-8"
    )
    authoring = tmp_path / "authoring"
    authoring.mkdir()
    (authoring / "run-status.json").write_text(
        json.dumps(
            {
                "target_domain": "target",
                "stages": {
                    "generation": {
                        "run_id": "synthesis-shared",
                        "scenarios_published": 1,
                        "scenarios_dir": str(generation),
                    },
                    "artifact": {
                        "status": "failed",
                        "attempts": [
                            {
                                "scenario_id": "SCN-001",
                                "design_id": "SCN-001:design-1",
                                "compiled": False,
                                "exclusion_code": "unsupported",
                            }
                        ],
                    },
                },
            }
        ),
        encoding="utf-8",
    )

    report = build_reachability((tmp_path,))

    assert len(report["scenarios"]) == 1
    assert report["scenarios"][0]["terminal_status"] == "excluded"
    assert report["scenarios"][0]["source_run_path"].endswith("authoring")
    assert report["reconciled"] is True
