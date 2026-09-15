"""Offline tests for the orchestration entry point's pure seams."""

import json

import yaml

import run_end_to_end
from run_end_to_end import build_report, reuse_generation, select_handoffs


def write_handoff(
    directory,
    scenario_id,
    *,
    kind="adversarial",
    operations=("process_refund",),
):
    envelope = {
        "schema_version": "scenario-handoff-v1",
        "scenario_id": scenario_id,
        "kind": kind,
        "documented_operations": [
            {"name": name, "relevance": "test"} for name in operations
        ],
    }
    (directory / f"{scenario_id}.yaml").write_text(
        yaml.safe_dump(envelope), encoding="utf-8"
    )


def test_select_handoffs_prefers_operation_match_then_id_order(tmp_path):
    write_handoff(tmp_path, "SCN-002")
    write_handoff(tmp_path, "SCN-003", operations=("other_tool",))
    write_handoff(tmp_path, "SCN-001", kind="functional")

    selected = select_handoffs(
        tmp_path, documented_operation="process_refund", max_attempts=3
    )

    assert [c["scenario_id"] for c in selected] == ["SCN-002", "SCN-003"]
    assert selected[0]["operation_match"] is True
    assert selected[1]["operation_match"] is False


def test_select_handoffs_respects_max_attempts(tmp_path):
    for index in range(1, 5):
        write_handoff(tmp_path, f"SCN-{index:03d}")

    selected = select_handoffs(
        tmp_path, documented_operation="process_refund", max_attempts=2
    )

    assert [c["scenario_id"] for c in selected] == ["SCN-001", "SCN-002"]


def test_select_handoffs_skips_functional_scenarios(tmp_path):
    write_handoff(tmp_path, "SCN-001", kind="functional")
    write_handoff(tmp_path, "SCN-002", kind="functional")

    selected = select_handoffs(
        tmp_path, documented_operation="process_refund", max_attempts=3
    )

    assert selected == []


def test_reuse_generation_reports_success_only_with_published_handoffs(tmp_path):
    import yaml

    # No manifest: failed.
    assert reuse_generation(tmp_path)["status"] == "failed"

    # Manifest plus published handoffs: success with the run id verified.
    (tmp_path / "run-manifest.yaml").write_text(
        yaml.safe_dump({"run_id": "synthesis-x", "run_status": "degraded"}),
        encoding="utf-8",
    )
    scenarios = tmp_path / "scenarios"
    scenarios.mkdir()
    write_handoff(scenarios, "SCN-001")
    record = reuse_generation(tmp_path)
    assert record["status"] == "success"
    assert record["source"] == "reused"
    assert record["run_id"] == "synthesis-x"
    assert record["scenarios_published"] == 1


def test_reuse_generation_reports_run_status_from_synthesis_manifest(tmp_path):
    # The producer run_status/run_status_reason live in synthesis-manifest.yaml;
    # run-manifest.yaml does not carry the producer classification, so the
    # synthesis manifest must win even when both exist.
    (tmp_path / "run-manifest.yaml").write_text(
        yaml.safe_dump({"run_id": "run-legacy", "run_status": "completed"}),
        encoding="utf-8",
    )
    (tmp_path / "synthesis-manifest.yaml").write_text(
        yaml.safe_dump(
            {
                "run_id": "synthesis-x",
                "run_status": "degraded",
                "run_status_reason": "partial_candidate_yield",
            }
        ),
        encoding="utf-8",
    )
    scenarios = tmp_path / "scenarios"
    scenarios.mkdir()
    write_handoff(scenarios, "SCN-001")

    record = reuse_generation(tmp_path)

    assert record["status"] == "success"
    assert record["producer_run_status"] == "degraded"
    assert record["producer_run_status_reason"] == "partial_candidate_yield"


def test_reuse_generation_falls_back_to_run_manifest_run_status(tmp_path):
    # Older generation directories without a synthesis manifest still report
    # a run-manifest.yaml run_status when present (legacy fallback).
    (tmp_path / "run-manifest.yaml").write_text(
        yaml.safe_dump({"run_id": "run-legacy", "run_status": "completed"}),
        encoding="utf-8",
    )
    scenarios = tmp_path / "scenarios"
    scenarios.mkdir()
    write_handoff(scenarios, "SCN-001")

    record = reuse_generation(tmp_path)

    assert record["status"] == "success"
    assert record["producer_run_status"] == "completed"
    assert record["producer_run_status_reason"] is None


def test_build_report_keeps_stage_statuses_independent():
    report = build_report(
        domain_name="klarna",
        started_at="2026-09-15T00:00:00Z",
        finished_at="2026-09-15T00:10:00Z",
        preflight={"stack_listening": {"safe_mcp": False, "ogx": False}},
        generation={"status": "success", "run_id": "r1", "scenarios_published": 2},
        artifact={"status": "success", "selected_design_id": "SCN-026:design-1"},
        execution={"status": "failed", "exit_code": 1, "error": "transport"},
    )

    stages = report["stages"]
    assert stages["generation"]["status"] == "success"
    assert stages["artifact"]["status"] == "success"
    assert stages["execution"]["status"] == "failed"
    # A failed execution stage must not erase the successful upstream stages.
    assert stages["generation"]["run_id"] == "r1"
    assert stages["artifact"]["selected_design_id"] == "SCN-026:design-1"
    assert report["schema_version"] == "orchestration-status-v1"


def test_corrupted_generation_output_persists_terminal_report(tmp_path, monkeypatch):
    """A parse escape in the generation stage must still persist run-status.json.

    Failure injection: the reused generation directory holds a corrupted
    run-manifest.yaml. The orchestration must catch the escape, report the
    failed stage with the upstream/downstream statuses independent, persist
    the terminal report, and return non-zero — never crash unwritten.
    """
    profiles = tmp_path / "profiles.yaml"
    profiles.write_text(
        yaml.safe_dump(
            {
                "test-profile": {
                    "base_url": "http://127.0.0.1:9/v1",
                    "model": "test-model",
                }
            }
        ),
        encoding="utf-8",
    )
    domain: dict[str, object] = {
        "mcp_url": "http://127.0.0.1:8888/sse",
        "state_tool": "get_klarna_state_summary",
        "documented_operation": "process_refund",
        "model": "test-model",
    }
    for key in (
        "use_case",
        "risk_extraction",
        "qualification_facts",
        "sssom",
        "loss_analysis",
        "capability_profile",
        "target_profile",
        "target_observations",
    ):
        path = tmp_path / f"input-{key}"
        path.write_text("placeholder\n", encoding="utf-8")
        domain[key] = str(path)
    monkeypatch.setitem(run_end_to_end.DOMAINS, "klarna", domain)

    generation_dir = tmp_path / "generation"
    generation_dir.mkdir()
    (generation_dir / "scenarios").mkdir()
    (generation_dir / "run-manifest.yaml").write_text(
        "{ not: [valid yaml\n", encoding="utf-8"
    )

    output_dir = tmp_path / "orchestration"
    exit_code = run_end_to_end.main(
        [
            "--domain",
            "klarna",
            "--output-dir",
            str(output_dir),
            "--profiles-file",
            str(profiles),
            "--profile",
            "test-profile",
            "--generation-dir",
            str(generation_dir),
        ]
    )

    assert exit_code == 1
    report = json.loads((output_dir / "run-status.json").read_text(encoding="utf-8"))
    assert report["schema_version"] == "orchestration-status-v1"
    assert report["started_at"] and report["finished_at"]
    stages = report["stages"]
    assert stages["generation"]["status"] == "failed"
    assert stages["generation"]["error"]
    assert stages["artifact"]["status"] == "not_run"
    assert stages["execution"]["status"] == "not_run"
