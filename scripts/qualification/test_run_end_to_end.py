"""Offline tests for the orchestration entry point's pure seams."""

import yaml

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
