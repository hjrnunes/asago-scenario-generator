"""Offline tests for the orchestration entry point's pure seams."""

import json
from pathlib import Path

import pytest
import yaml

import run_end_to_end
from run_end_to_end import (
    DOMAIN_INPUT_KEYS,
    DOMAINS,
    PRODUCER_ROOT,
    build_generation_command,
    build_report,
    domain_port,
    reuse_generation,
    select_handoffs,
)


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


EXPECTED_TARGETS = {
    "klarna": {
        "port": 8888,
        "state_tool": "get_klarna_state_summary",
        "documented_operation": "process_refund",
    },
    "occiai": {
        "port": 8892,
        "state_tool": "get_occiai_state_summary",
        "documented_operation": "commit_to_ehr",
    },
    "airbnb": {
        "port": 8890,
        "state_tool": "get_airbnb_state_summary",
        "documented_operation": "modify_booking",
    },
}


def test_domains_register_all_three_targets():
    """Every target is registered before any live confirmation (VAL-O-001)."""
    assert set(DOMAINS) == {"klarna", "occiai", "airbnb"}
    for domain_name, expected in EXPECTED_TARGETS.items():
        domain = DOMAINS[domain_name]
        assert domain["mcp_url"] == f"http://127.0.0.1:{expected['port']}/sse"
        assert domain["state_tool"] == expected["state_tool"]
        assert domain["documented_operation"] == expected["documented_operation"]
        assert domain["model"] == "gemma-4-26b-a4b-it"
        assert domain_port(domain_name) == expected["port"]


def test_domains_registered_inputs_are_staged_files():
    """Every registered input path exists under the producer worktree root."""
    for domain_name, domain in DOMAINS.items():
        for key in DOMAIN_INPUT_KEYS:
            if not domain.get(key):
                continue
            path = PRODUCER_ROOT / domain[key]
            assert path.is_file(), f"{domain_name}.{key} is not a staged file: {path}"


def test_only_klarna_pins_a_loss_analysis_or_capability_profile():
    """Klarna pins the historical reviewed analysis and capability profile.

    occiai and airbnb register neither: no staged pinned loss analysis exists
    for them, so their Stage 1a runs derived (proposed authority), and no
    review-gate or escalation evidence is claimed from the earlier occiai
    identity-error run.
    """
    assert DOMAINS["klarna"]["loss_analysis"]
    assert DOMAINS["klarna"]["capability_profile"]
    for domain_name in ("occiai", "airbnb"):
        assert "loss_analysis" not in DOMAINS[domain_name]
        assert "capability_profile" not in DOMAINS[domain_name]


def _load_registered_runtime_context(domain_name):
    return json.loads(
        (PRODUCER_ROOT / DOMAINS[domain_name]["target_observations"]).read_text(
            encoding="utf-8"
        )
    )


def _registered_profile_digest_pairing_holds(domain_name):
    """The registered runtime context pairs with the registered profile.

    This is the exact pairing check the producer ``run`` performs: the
    normalized context's ``target_profile_digest`` must equal the
    execution-target profile's semantic digest.
    """
    from asago_scenario_generator.stpa.models.execution_classification import (
        ExecutionTargetProfile,
    )
    from asago_scenario_generator.stpa.scenario_prod.target_observations import (
        TargetObservationSnapshot,
    )

    profile = ExecutionTargetProfile.model_validate(
        json.loads(
            (PRODUCER_ROOT / DOMAINS[domain_name]["target_profile"]).read_text(
                encoding="utf-8"
            )
        )
    )
    snapshot = TargetObservationSnapshot.from_runtime_context(
        _load_registered_runtime_context(domain_name)
    )
    return snapshot.target_profile_digest == profile.semantic_digest


@pytest.mark.parametrize("domain_name", ["klarna", "occiai", "airbnb"])
def test_registered_runtime_context_pairs_with_registered_profile(domain_name):
    assert _registered_profile_digest_pairing_holds(domain_name) is True


def test_occiai_registration_stages_supported_patient_draft_relationship():
    """The occiai registration stages the seeded authenticated patient.

    The mini-agents OcciAI seed authenticates PAT-104, and its executor only
    ever creates a draft for the authenticated patient
    (``summarize_for_ehr`` stores an ``EhrDraft`` whose ``patient_id`` is the
    authenticated patient; ``commit_to_ehr`` requires
    ``draft.patient_id == patient_id``). The registered runtime context must
    therefore name that seeded patient, never an ``unknown`` patient id, and
    must not fabricate a draft the seeded state does not hold (the seeded
    ``ehr_drafts`` ledger is empty; the session's own ``summarize_for_ehr``
    call creates the draft the scenario commits).
    """
    context = _load_registered_runtime_context("occiai")
    state = context["state"]
    assert state["authenticated_patient_id"] == "PAT-104"
    assert state["ehr_drafts"] == []
    assert "unknown" not in json.dumps(context)
    # The dangerous operation the occiai scenarios stage (commit_to_ehr) is
    # exactly the operation gated by the patient/draft relationship above.
    assert DOMAINS["occiai"]["documented_operation"] == "commit_to_ehr"


@pytest.mark.parametrize("domain_name", ["klarna", "occiai", "airbnb"])
def test_select_handoffs_prefers_each_domain_dangerous_operation(tmp_path, domain_name):
    """Per-target deterministic selection: operation match first, then id order.

    For every registered domain, a handoff naming that domain's dangerous
    operation precedes an earlier-numbered handoff that names a different
    operation; functional scenarios are never selected.
    """
    documented_operation = DOMAINS[domain_name]["documented_operation"]
    write_handoff(tmp_path, "SCN-001", operations=("other_operation",))
    write_handoff(tmp_path, "SCN-002", operations=(documented_operation,))
    write_handoff(tmp_path, "SCN-003", kind="functional")

    selected = select_handoffs(
        tmp_path, documented_operation=documented_operation, max_attempts=3
    )

    assert [c["scenario_id"] for c in selected] == ["SCN-002", "SCN-001"]
    assert selected[0]["operation_match"] is True
    assert selected[1]["operation_match"] is False


def test_build_generation_command_passes_only_registered_optional_inputs():
    """Optional producer inputs are passed only when registered."""
    klarna_command = build_generation_command(
        DOMAINS["klarna"], "gemma4-oc", Path("build/out")
    )
    for flag in (
        "--loss-analysis",
        "--capability-profile",
        "--target-profile",
        "--target-observations",
    ):
        assert flag in klarna_command
    for domain_name in ("occiai", "airbnb"):
        command = build_generation_command(
            DOMAINS[domain_name], "gemma4-oc", Path("build/out")
        )
        assert "--loss-analysis" not in command
        assert "--capability-profile" not in command
        assert "--target-profile" in command
        assert "--target-observations" in command
        assert command[command.index("--profile") + 1] == "gemma4-oc"


def _registered_domain_with_placeholder_inputs(tmp_path):
    """A klarna registration whose inputs are placeholder files in tmp_path."""
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
    return domain


def _reused_generation_dir(tmp_path):
    generation_dir = tmp_path / "generation"
    generation_dir.mkdir()
    (generation_dir / "scenarios").mkdir()
    (generation_dir / "run-manifest.yaml").write_text(
        yaml.safe_dump({"run_id": "synthesis-x"}), encoding="utf-8"
    )
    write_handoff(generation_dir / "scenarios", "SCN-001")
    return generation_dir


def _test_profiles_file(tmp_path):
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
    return profiles


COMPILED_ARTIFACT = {
    "status": "success",
    "output_dir": "artifact",
    "selected_scenario": "SCN-001",
    "selected_design_id": "SCN-001:design-1",
    "attempts": [
        {
            "scenario_id": "SCN-001",
            "compiled": True,
            "design_id": "SCN-001:design-1",
            "artifact": "artifact/SCN-001/SCN-001:design-1/executable-conversation.json",
            "execution_plan": "artifact/SCN-001/SCN-001:design-1/execution-plan.json",
        }
    ],
}


def test_pause_before_dispatch_persists_status_without_execution(
    tmp_path, monkeypatch
):
    """--pause-before-dispatch stops after the artifact stage, pre-dispatch.

    The live pre-dispatch record must be written AFTER the frozen plan exists
    and BEFORE the Garak dispatch, so the entry point pauses between the two
    with an honest not_run execution status.
    """
    monkeypatch.setitem(
        run_end_to_end.DOMAINS, "klarna", _registered_domain_with_placeholder_inputs(tmp_path)
    )
    monkeypatch.setattr(
        run_end_to_end, "stage_artifact", lambda *args, **kwargs: dict(COMPILED_ARTIFACT)
    )
    output_dir = tmp_path / "orchestration"
    exit_code = run_end_to_end.main(
        [
            "--domain",
            "klarna",
            "--output-dir",
            str(output_dir),
            "--profiles-file",
            str(_test_profiles_file(tmp_path)),
            "--profile",
            "test-profile",
            "--generation-dir",
            str(_reused_generation_dir(tmp_path)),
            "--pause-before-dispatch",
        ]
    )

    assert exit_code == 0
    report = json.loads((output_dir / "run-status.json").read_text(encoding="utf-8"))
    assert report["paused_before_dispatch"] is True
    stages = report["stages"]
    assert stages["generation"]["status"] == "success"
    assert stages["artifact"]["status"] == "success"
    assert stages["execution"]["status"] == "not_run"
    assert "pre-dispatch-checks.yaml" in stages["execution"]["reason"]
    assert not list(output_dir.glob("execution/qualification.json"))


def _paused_run_status():
    return {
        "schema_version": "orchestration-status-v1",
        "target_domain": "klarna",
        "started_at": "2026-09-15T00:00:00Z",
        "finished_at": "2026-09-15T00:01:00Z",
        "preflight": {"inputs_present": True},
        "paused_before_dispatch": True,
        "stages": {
            "generation": {"status": "success", "run_id": "r1"},
            "artifact": dict(COMPILED_ARTIFACT),
            "execution": {"status": "not_run"},
        },
    }


def test_resume_dispatch_requires_complete_pre_dispatch_record(tmp_path, monkeypatch):
    """--resume-dispatch refuses to dispatch without the seven record keys."""
    output_dir = tmp_path / "orchestration"
    output_dir.mkdir()
    (output_dir / "run-status.json").write_text(
        json.dumps(_paused_run_status()), encoding="utf-8"
    )

    with pytest.raises(SystemExit):
        run_end_to_end.main(
            [
                "--domain",
                "klarna",
                "--output-dir",
                str(output_dir),
                "--profiles-file",
                str(_test_profiles_file(tmp_path)),
                "--profile",
                "test-profile",
                "--resume-dispatch",
            ]
        )


def test_resume_dispatch_writes_record_into_execution_stage(tmp_path, monkeypatch):
    """A complete pre-dispatch record unblocks exactly the execution stage."""
    output_dir = tmp_path / "orchestration"
    output_dir.mkdir()
    (output_dir / "run-status.json").write_text(
        json.dumps(_paused_run_status()), encoding="utf-8"
    )
    execution_dir = output_dir / "execution"
    execution_dir.mkdir()
    record = {key: "recorded" for key in run_end_to_end.REQUIRED_PRE_DISPATCH_RECORDS}
    (execution_dir / "pre-dispatch-checks.yaml").write_text(
        yaml.safe_dump(record), encoding="utf-8"
    )
    observed: dict[str, object] = {}

    def fake_stage_execution(domain, artifact, model_settings, exec_dir, log_path):
        observed["execution_dir"] = str(exec_dir)
        observed["artifact"] = artifact
        return {"status": "success", "exit_code": 0}

    monkeypatch.setattr(run_end_to_end, "stage_execution", fake_stage_execution)
    exit_code = run_end_to_end.main(
        [
            "--domain",
            "klarna",
            "--output-dir",
            str(output_dir),
            "--profiles-file",
            str(_test_profiles_file(tmp_path)),
            "--profile",
            "test-profile",
            "--resume-dispatch",
        ]
    )

    assert exit_code == 0
    assert observed["execution_dir"] == str(execution_dir)
    report = json.loads((output_dir / "run-status.json").read_text(encoding="utf-8"))
    stages = report["stages"]
    assert stages["generation"]["status"] == "success"
    assert stages["artifact"]["status"] == "success"
    assert stages["execution"]["status"] == "success"
    assert stages["execution"]["pre_dispatch_record"].endswith("pre-dispatch-checks.yaml")
    assert "paused_before_dispatch" not in report


def test_resume_dispatch_refuses_a_run_that_is_not_paused(tmp_path):
    """A finished or non-paused run is never partially re-executed."""
    output_dir = tmp_path / "orchestration"
    output_dir.mkdir()
    status = _paused_run_status()
    status["paused_before_dispatch"] = False
    status["stages"]["execution"] = {"status": "success"}
    (output_dir / "run-status.json").write_text(
        json.dumps(status), encoding="utf-8"
    )

    with pytest.raises(SystemExit):
        run_end_to_end.main(
            [
                "--domain",
                "klarna",
                "--output-dir",
                str(output_dir),
                "--profiles-file",
                str(_test_profiles_file(tmp_path)),
                "--profile",
                "test-profile",
                "--resume-dispatch",
            ]
        )


def test_resume_dispatch_retries_execution_failed_before_dispatch(
    tmp_path, monkeypatch
):
    """A prior execution stage that failed BEFORE any dispatch (no execution
    evidence written) leaves the run resumable: the upstream stages and the
    pre-dispatch record are intact and the retry overwrites no evidence. The
    retried execution record carries the prior pre-dispatch failure."""
    output_dir = tmp_path / "orchestration"
    output_dir.mkdir()
    status = _paused_run_status()
    status.pop("paused_before_dispatch")
    status["stages"]["execution"] = {
        "status": "failed",
        "exit_code": 1,
        "error": "garak runner failed; see the log",
    }
    (output_dir / "run-status.json").write_text(
        json.dumps(status), encoding="utf-8"
    )
    execution_dir = output_dir / "execution"
    execution_dir.mkdir()
    record = {key: "recorded" for key in run_end_to_end.REQUIRED_PRE_DISPATCH_RECORDS}
    (execution_dir / "pre-dispatch-checks.yaml").write_text(
        yaml.safe_dump(record), encoding="utf-8"
    )

    def fake_stage_execution(domain, artifact, model_settings, exec_dir, log_path):
        return {"status": "success", "exit_code": 0}

    monkeypatch.setattr(run_end_to_end, "stage_execution", fake_stage_execution)
    exit_code = run_end_to_end.main(
        [
            "--domain",
            "klarna",
            "--output-dir",
            str(output_dir),
            "--profiles-file",
            str(_test_profiles_file(tmp_path)),
            "--profile",
            "test-profile",
            "--resume-dispatch",
        ]
    )

    assert exit_code == 0
    report = json.loads((output_dir / "run-status.json").read_text(encoding="utf-8"))
    execution = report["stages"]["execution"]
    assert execution["status"] == "success"
    assert execution["prior_predispatch_failure"]["status"] == "failed"
    assert "paused_before_dispatch" not in report


def test_resume_dispatch_refuses_execution_failed_with_evidence(
    tmp_path, monkeypatch
):
    """A prior execution stage that dispatched and failed (evidence written)
    is never retried in place: the attempt is preserved and the resume
    refuses."""
    output_dir = tmp_path / "orchestration"
    output_dir.mkdir()
    status = _paused_run_status()
    status.pop("paused_before_dispatch")
    status["stages"]["execution"] = {
        "status": "failed",
        "exit_code": 1,
        "error": "garak runner failed; see the log",
    }
    (output_dir / "run-status.json").write_text(
        json.dumps(status), encoding="utf-8"
    )
    execution_dir = output_dir / "execution"
    execution_dir.mkdir()
    record = {key: "recorded" for key in run_end_to_end.REQUIRED_PRE_DISPATCH_RECORDS}
    (execution_dir / "pre-dispatch-checks.yaml").write_text(
        yaml.safe_dump(record), encoding="utf-8"
    )
    (execution_dir / "qualification.json").write_text("{}", encoding="utf-8")

    with pytest.raises(SystemExit):
        run_end_to_end.main(
            [
                "--domain",
                "klarna",
                "--output-dir",
                str(output_dir),
                "--profiles-file",
                str(_test_profiles_file(tmp_path)),
                "--profile",
                "test-profile",
                "--resume-dispatch",
            ]
        )


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
