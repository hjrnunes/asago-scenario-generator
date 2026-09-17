"""Offline tests for the orchestration entry point's pure seams."""

import json
import getpass
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
from stack_cleanup import (
    CLEANUP_RECORD_FILENAME,
    DEFAULT_MISSION_PATH,
    CleanupProbes,
    load_cleanup_record,
    record_kept_running,
)


@pytest.fixture(autouse=True)
def offline_cleanup_probes(monkeypatch):
    """No test pkills a process or probes a real port (VAL-QUAL-011).

    Every test observes an empty, stopped surface by default; individual
    tests replace ``run_end_to_end.cleanup_probes`` to model live processes
    or listening ports.
    """
    monkeypatch.setattr(run_end_to_end, "cleanup_probes", _offline_probes(processes=[]))


def _offline_probes(
    *,
    processes: list[dict[str, object]] | None = None,
    open_ports: set[int] | None = None,
    stop_calls: list[str] | None = None,
    process_exit_wait=None,
):
    stop_calls_ref = stop_calls if stop_calls is not None else []

    def process_evidence(pattern):
        return list(processes or [])

    def stop(pattern):
        stop_calls_ref.append(pattern)
        return "exit 0"

    def port_is_listening(port):
        return port in (open_ports or set())

    def wait_ports_closed(ports, timeout):
        if open_ports:
            raise TimeoutError(f"ports still listening: {sorted(open_ports)}")

    return CleanupProbes(
        process_evidence=process_evidence,
        stop=stop,
        stop_command="test-stop",
        port_is_listening=port_is_listening,
        wait_ports_closed=wait_ports_closed,
        wait_processes_exit=process_exit_wait
        or (
            lambda _processes, _timeout: {
                "result": "confirmed",
                "survivors": [],
            }
        ),
    )


def _process_identity(pid: int = 111) -> dict[str, object]:
    return {
        "pid": pid,
        "ppid": 1,
        "owner": getpass.getuser(),
        "command": "uv run mini-agents-stack",
        "exists": True,
        "ancestry": [
            {
                "pid": pid,
                "ppid": 1,
                "owner": getpass.getuser(),
                "command": "uv run mini-agents-stack",
            }
        ],
        "cwd": DEFAULT_MISSION_PATH,
        "mission_path": DEFAULT_MISSION_PATH,
        "mission_path_in_command": False,
    }


def _cleanup_record(output_dir: Path) -> dict:
    path = output_dir / "cleanup" / CLEANUP_RECORD_FILENAME
    record = load_cleanup_record(path)
    assert record is not None, f"no cleanup record at {path}"
    return record


def _main_args(output_dir: Path, tmp_path, *extra: str) -> list[str]:
    return [
        "--domain",
        "klarna",
        "--output-dir",
        str(output_dir),
        "--profiles-file",
        str(_test_profiles_file(tmp_path)),
        "--profile",
        "test-profile",
        *extra,
    ]


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

    assert [c["scenario_id"] for c in selected] == [
        "SCN-002",
        "SCN-003",
        "SCN-001",
    ]
    assert selected[0]["operation_match"] is True
    assert selected[1]["operation_match"] is False
    # SCN-001 keeps the default process_refund operations, so its functional
    # entry matches the documented operation like any other handoff.
    assert selected[2]["operation_match"] is True


def test_select_handoffs_respects_max_attempts(tmp_path):
    for index in range(1, 5):
        write_handoff(tmp_path, f"SCN-{index:03d}")

    selected = select_handoffs(
        tmp_path, documented_operation="process_refund", max_attempts=2
    )

    assert [c["scenario_id"] for c in selected] == ["SCN-001", "SCN-002"]


def test_select_handoffs_admits_functional_after_adversarial(tmp_path):
    """Functional handoffs follow every adversarial handoff.

    The recorded functional-feasibility decision (consumer commit 282a1d3)
    admits functional handoffs to criterion-shape interpretation, so a
    recognized functional candidate (for example the occiai
    ``precondition_record`` candidates over the preserved m3-pinned-occiai
    generation) designs after the adversarial candidates instead of being
    skipped. Ordering stays deterministic: adversarial operation match
    first, then adversarial without match, then functional (match, then
    scenario id).
    """
    write_handoff(tmp_path, "SCN-002", kind="functional", operations=("other_tool",))
    write_handoff(tmp_path, "SCN-003", kind="functional", operations=())
    write_handoff(
        tmp_path, "SCN-004", kind="functional", operations=("process_refund",)
    )
    write_handoff(tmp_path, "SCN-005")

    selected = select_handoffs(
        tmp_path, documented_operation="process_refund", max_attempts=4
    )

    assert [c["scenario_id"] for c in selected] == [
        "SCN-005",
        "SCN-004",
        "SCN-002",
        "SCN-003",
    ]


def test_select_handoffs_still_skips_unknown_kinds(tmp_path):
    (tmp_path / "SCN-001.yaml").write_text(
        yaml.safe_dump({"scenario_id": "SCN-001", "kind": "simulation"})
    )

    selected = select_handoffs(
        tmp_path, documented_operation="process_refund", max_attempts=3
    )

    assert selected == []


def test_stage_artifact_retries_missing_setup_with_registered_record_hint(
    tmp_path, monkeypatch
):
    """A session-mismatch missing-setup design retries once with the hint.

    The consumer asks for an explicit record hint when several candidates fit
    the criterion. The retry runs the SAME scenario once in a separate design
    directory with the registered per-target hint (validated against observed
    state by the consumer), and the blocked first attempt stays preserved.
    """
    scenarios = tmp_path / "scenarios"
    scenarios.mkdir()
    write_handoff(scenarios, "SCN-001")
    domain = {
        "target_profile": "build/adaptive-runs/inputs/airbnb-discovery/execution-target-profile.json",
        "target_observations": (
            "build/adaptive-runs/inputs/airbnb-runtime-context-normalized.json"
        ),
        "documented_operation": "modify_booking",
        "record_hint": "RES-201",
    }

    commands: list[list[str]] = []

    def _write_manifest(design_dir: Path, manifest: dict) -> None:
        design_dir.mkdir(parents=True, exist_ok=True)
        (design_dir / "design-manifest.json").write_text(
            json.dumps(manifest), encoding="utf-8"
        )

    def _fake_run_logged(command, *, cwd, log_path, extra_env=None):
        commands.append(command)
        design_dir = Path(command[command.index("--output-dir") + 1])
        if "--record-hint" in command:
            _write_manifest(
                design_dir,
                {
                    "design_id": "SCN-001:design-1",
                    "compiled": True,
                },
            )
        else:
            _write_manifest(
                design_dir,
                {
                    "design_id": "SCN-001:design-1",
                    "compiled": False,
                    "exclusion_code": "missing-setup",
                    "exclusion_detail": (
                        "the scenario concerns a record the authenticated "
                        "session does not own and the environment exposes 4 "
                        "foreign-owned candidates; supply an explicit record hint"
                    ),
                },
            )
        return 0

    monkeypatch.setattr(run_end_to_end, "_run_logged", _fake_run_logged)
    artifact_dir = tmp_path / "artifact"

    record = run_end_to_end.stage_artifact(
        domain,
        {"scenarios_dir": str(scenarios)},
        {"model": "m", "base_url": "u", "api_key": "k"},
        artifact_dir,
        str(tmp_path / "design-log"),
        max_attempts=3,
    )

    assert record["status"] == "success"
    assert record["selected_scenario"] == "SCN-001"
    assert record["selected_design_id"] == "SCN-001:design-1"
    assert len(record["attempts"]) == 2
    first, retry = record["attempts"]
    assert first["compiled"] is False
    assert first["exclusion_code"] == "missing-setup"
    assert retry["compiled"] is True
    assert retry["record_hint"] == "RES-201"
    assert retry["missing_setup_retry"] is True
    # The retry ran in a separate design directory (first attempt preserved)
    # and passed the registered hint to the consumer CLI.
    assert len(commands) == 2
    assert "--record-hint" not in commands[0]
    assert commands[1][commands[1].index("--record-hint") + 1] == "RES-201"
    assert commands[1][commands[1].index("--output-dir") + 1].endswith(
        "SCN-001-record-hint"
    )
    assert (artifact_dir / "SCN-001" / "design-manifest.json").is_file()
    assert (artifact_dir / "SCN-001-record-hint" / "design-manifest.json").is_file()


def test_stage_artifact_does_not_retry_without_registered_record_hint(
    tmp_path, monkeypatch
):
    """No hint registered: the missing-setup design is the only attempt."""
    scenarios = tmp_path / "scenarios"
    scenarios.mkdir()
    write_handoff(scenarios, "SCN-001")
    domain = {
        "target_profile": "build/adaptive-runs/inputs/airbnb-discovery/execution-target-profile.json",
        "target_observations": (
            "build/adaptive-runs/inputs/airbnb-runtime-context-normalized.json"
        ),
        "documented_operation": "modify_booking",
    }
    calls: list[list[str]] = []

    def _fake_run_logged(command, *, cwd, log_path, extra_env=None):
        calls.append(command)
        design_dir = Path(command[command.index("--output-dir") + 1])
        design_dir.mkdir(parents=True, exist_ok=True)
        (design_dir / "design-manifest.json").write_text(
            json.dumps(
                {
                    "design_id": "SCN-001:design-1",
                    "compiled": False,
                    "exclusion_code": "missing-setup",
                    "exclusion_detail": "supply an explicit record hint",
                }
            ),
            encoding="utf-8",
        )
        return 1

    monkeypatch.setattr(run_end_to_end, "_run_logged", _fake_run_logged)

    record = run_end_to_end.stage_artifact(
        domain,
        {"scenarios_dir": str(scenarios)},
        {"model": "m", "base_url": "u", "api_key": "k"},
        tmp_path / "artifact",
        str(tmp_path / "design-log"),
        max_attempts=3,
    )

    assert record["status"] == "failed"
    assert len(calls) == 1
    assert len(record["attempts"]) == 1


def test_airbnb_record_hint_is_the_foreign_owned_reservation():
    """The registered airbnb hint is a foreign-owned staged reservation.

    The hint is only consumed on a session-mismatch missing-setup retry, so
    it must name a reservation the authenticated actor is not a party to in
    the registered runtime context; klarna and occiai register no hint.
    """
    assert DOMAINS["airbnb"]["record_hint"] == "RES-201"
    assert "record_hint" not in DOMAINS["klarna"]
    assert "record_hint" not in DOMAINS["occiai"]
    context = _load_registered_runtime_context("airbnb")
    state = context["state"]
    reservation = state["reservations"]["RES-201"]
    actor = state["authenticated_actor_id"]
    assert reservation["guest_id"] != actor
    assert reservation["host_id"] != actor


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


def test_every_target_pins_a_staged_loss_analysis_only_klarna_has_profile():
    """All three targets pin staged loss analyses; only klarna pins a profile.

    Per the owner decision of 2026-09-15, occiai pins the accepted derived
    graph from m3-occiai-attempt1 (derived/proposed authority preserved as-is,
    never relabelled reviewed) and airbnb pins the reviewed rev3 graph; the
    pin skips only Stage 1a model generation and downstream stages run fresh.
    No staged capability profile exists for occiai/airbnb, so theirs are
    inferred, and no review-gate evidence is claimed from the earlier occiai
    identity-error run.
    """
    for domain_name in ("klarna", "occiai", "airbnb"):
        assert DOMAINS[domain_name]["loss_analysis"]
    assert DOMAINS["klarna"]["capability_profile"]
    for domain_name in ("occiai", "airbnb"):
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
    """The occiai registration stages a supported session-owned draft.

    Owner decision 2026-09-16 (occiai-input-recapture): the empty seeded
    ledger was the outlier against the record-bearing klarna/airbnb staged
    contexts, so the staged runtime context is a re-capture holding exactly
    one real draft created through the documented ``summarize_for_ehr`` tool.
    The executor only ever creates a draft for the authenticated patient
    (``summarize_for_ehr`` requires ``patient_id == authenticated_patient_id``
    and stores an ``EhrDraft`` under it; ``commit_to_ehr`` requires
    ``draft.patient_id == patient_id``), and nothing in the domain sets a
    draft to ``REVIEWED``. The staged context therefore must hold exactly one
    session-owned ``AWAITING_REVIEW`` draft for PAT-104 — never a fabricated
    foreign-owned record and never an ``unknown`` patient id.
    """
    context = _load_registered_runtime_context("occiai")
    state = context["state"]
    assert state["authenticated_patient_id"] == "PAT-104"
    drafts = state["ehr_drafts"]
    assert len(drafts) == 1
    draft = drafts[0]
    assert draft["patient_id"] == state["authenticated_patient_id"]
    assert draft["status"] == "AWAITING_REVIEW"
    assert draft["draft_id"]
    assert "unknown" not in json.dumps(context)
    # No foreign-owned record anywhere: every EHR record collection stays
    # empty, so no fabricated record supports the staged draft relationship.
    for patient_records in state["ehr_records"].values():
        assert patient_records == []
    # The dangerous operation the occiai scenarios stage (commit_to_ehr) is
    # exactly the operation gated by the patient/draft relationship above.
    assert DOMAINS["occiai"]["documented_operation"] == "commit_to_ehr"


@pytest.mark.parametrize("domain_name", ["klarna", "occiai", "airbnb"])
def test_select_handoffs_prefers_each_domain_dangerous_operation(tmp_path, domain_name):
    """Per-target deterministic selection: operation match first, then id order.

    For every registered domain, a handoff naming that domain's dangerous
    operation precedes an earlier-numbered handoff that names a different
    operation; functional scenarios follow every adversarial handoff (the
    recorded functional-feasibility decision admits them to design).
    """
    documented_operation = DOMAINS[domain_name]["documented_operation"]
    write_handoff(tmp_path, "SCN-001", operations=("other_operation",))
    write_handoff(tmp_path, "SCN-002", operations=(documented_operation,))
    write_handoff(tmp_path, "SCN-003", kind="functional")

    selected = select_handoffs(
        tmp_path, documented_operation=documented_operation, max_attempts=3
    )

    assert [c["scenario_id"] for c in selected] == [
        "SCN-002",
        "SCN-001",
        "SCN-003",
    ]
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
        assert "--loss-analysis" in command
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


def test_pause_before_dispatch_persists_status_without_execution(tmp_path, monkeypatch):
    """--pause-before-dispatch stops after the artifact stage, pre-dispatch.

    The live pre-dispatch record must be written AFTER the frozen plan exists
    and BEFORE the Garak dispatch, so the entry point pauses between the two
    with an honest not_run execution status.
    """
    monkeypatch.setitem(
        run_end_to_end.DOMAINS,
        "klarna",
        _registered_domain_with_placeholder_inputs(tmp_path),
    )
    monkeypatch.setattr(
        run_end_to_end,
        "stage_artifact",
        lambda *args, **kwargs: dict(COMPILED_ARTIFACT),
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


def test_failed_artifact_stage_does_not_mark_paused_before_dispatch(
    tmp_path, monkeypatch
):
    """--pause-before-dispatch marks the pause only when the artifact stage
    succeeded and the pause branch actually ran: a failed artifact stage
    leaves execution not_run but the report carries no paused marker and the
    exit code is non-zero (the resume gate never misleads the operator)."""
    monkeypatch.setitem(
        run_end_to_end.DOMAINS,
        "klarna",
        _registered_domain_with_placeholder_inputs(tmp_path),
    )
    monkeypatch.setattr(
        run_end_to_end,
        "stage_artifact",
        lambda *args, **kwargs: {
            "status": "failed",
            "output_dir": "artifact",
            "attempts": [],
            "error": "no selected handoff compiled a design; see attempts",
        },
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

    assert exit_code == 1
    report = json.loads((output_dir / "run-status.json").read_text(encoding="utf-8"))
    assert "paused_before_dispatch" not in report
    stages = report["stages"]
    assert stages["generation"]["status"] == "success"
    assert stages["artifact"]["status"] == "failed"
    assert stages["execution"]["status"] == "not_run"
    assert not (output_dir / "execution").exists()


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


def test_resume_dispatch_refuses_partial_pre_dispatch_record(tmp_path, capsys):
    """A record file that exists but carries only some of the seven keys
    stops the resume with the missing-key names (partial-record branch)."""
    output_dir = tmp_path / "orchestration"
    output_dir.mkdir()
    (output_dir / "run-status.json").write_text(
        json.dumps(_paused_run_status()), encoding="utf-8"
    )
    execution_dir = output_dir / "execution"
    execution_dir.mkdir()
    partial = {
        key: "recorded" for key in run_end_to_end.REQUIRED_PRE_DISPATCH_RECORDS[:4]
    }
    (execution_dir / "pre-dispatch-checks.yaml").write_text(
        yaml.safe_dump(partial), encoding="utf-8"
    )

    with pytest.raises(SystemExit) as excinfo:
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

    assert excinfo.value.code == 2
    stderr = capsys.readouterr().err
    for key in run_end_to_end.REQUIRED_PRE_DISPATCH_RECORDS[4:]:
        assert key in stderr
    # The dispatch never started: no execution evidence exists.
    assert not (execution_dir / "qualification.json").exists()


def test_resume_dispatch_refuses_domain_mismatch(tmp_path):
    """--resume-dispatch cross-checks --domain against the report's
    target_domain: a klarna run is never resumed under another domain."""
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

    with pytest.raises(SystemExit) as excinfo:
        run_end_to_end.main(
            [
                "--domain",
                "occiai",
                "--output-dir",
                str(output_dir),
                "--profiles-file",
                str(_test_profiles_file(tmp_path)),
                "--profile",
                "test-profile",
                "--resume-dispatch",
            ]
        )

    assert excinfo.value.code == 2
    assert not (execution_dir / "qualification.json").exists()


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
    assert stages["execution"]["pre_dispatch_record"].endswith(
        "pre-dispatch-checks.yaml"
    )
    assert "paused_before_dispatch" not in report


def test_resume_dispatch_refuses_a_run_that_is_not_paused(tmp_path):
    """A finished or non-paused run is never partially re-executed."""
    output_dir = tmp_path / "orchestration"
    output_dir.mkdir()
    status = _paused_run_status()
    status["paused_before_dispatch"] = False
    status["stages"]["execution"] = {"status": "success"}
    (output_dir / "run-status.json").write_text(json.dumps(status), encoding="utf-8")

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
    (output_dir / "run-status.json").write_text(json.dumps(status), encoding="utf-8")
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


def test_resume_dispatch_refuses_execution_failed_with_evidence(tmp_path, monkeypatch):
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
    (output_dir / "run-status.json").write_text(json.dumps(status), encoding="utf-8")
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


def test_runner_failure_summary_carries_the_actual_failure_class(tmp_path):
    """stage_execution's failure error carries the log's actual exception
    class, never a static stack-stopped presumption: a FileExistsError over
    existing dispatch evidence (the m2 retry1 failure, stack UP) is reported
    as that class."""
    log = tmp_path / "execution.log"
    log.write_text(
        "Traceback (most recent call last):\n"
        '  File "garak_case_runner.py", line 437, in run_case\n'
        "    output.mkdir(parents=True, exist_ok=False)\n"
        "FileExistsError: [Errno 17] File exists: 'build/adaptive-e2e/run/execution'\n",
        encoding="utf-8",
    )
    summary = run_end_to_end._runner_failure_summary(log)
    assert summary is not None
    assert summary.startswith("FileExistsError:")
    assert "File exists" in summary

    assert run_end_to_end._runner_failure_summary(tmp_path / "absent.log") is None


def test_runner_failure_summary_without_exception_line_is_none(tmp_path):
    """A log whose tail holds no exception line yields no summary, so the
    error falls back to the neutral message instead of a guessed class."""
    log = tmp_path / "execution.log"
    log.write_text(
        "probes.injection.IndirectInjection: 100%|\ngarak runner exited with code 1\n",
        encoding="utf-8",
    )
    assert run_end_to_end._runner_failure_summary(log) is None


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


def _full_run(tmp_path, monkeypatch, *, stage_artifact=None, stage_execution=None):
    monkeypatch.setitem(
        run_end_to_end.DOMAINS,
        "klarna",
        _registered_domain_with_placeholder_inputs(tmp_path),
    )
    monkeypatch.setattr(
        run_end_to_end,
        "stage_artifact",
        stage_artifact or (lambda *args, **kwargs: dict(COMPILED_ARTIFACT)),
    )
    monkeypatch.setattr(
        run_end_to_end,
        "stage_execution",
        stage_execution
        or (lambda *args, **kwargs: {"status": "success", "exit_code": 0}),
    )


def test_successful_run_records_completed_cleanup(tmp_path, monkeypatch):
    """A fully successful run stops the stack and records clean evidence."""
    _full_run(tmp_path, monkeypatch)
    output_dir = tmp_path / "orchestration"

    exit_code = run_end_to_end.main(
        _main_args(
            output_dir,
            tmp_path,
            "--generation-dir",
            str(_reused_generation_dir(tmp_path)),
        )
    )

    assert exit_code == 0
    record = _cleanup_record(output_dir)
    assert record["status"] == "completed"
    assert record["target"] == "klarna"
    assert record["run_id"] == "synthesis-x"
    assert record["orphan_processes"] == []
    assert record["ports_clear"] is True
    assert record["no_orphan_check"] == "passed"
    assert record["errors"] == []


def test_successful_stages_return_failure_when_cleanup_times_out(tmp_path, monkeypatch):
    """A successful product chain cannot hide a failed terminal cleanup."""
    _full_run(tmp_path, monkeypatch)
    identity = _process_identity()
    monkeypatch.setattr(
        run_end_to_end,
        "cleanup_probes",
        _offline_probes(
            processes=[identity, identity],
            process_exit_wait=lambda _processes, _timeout: (_ for _ in ()).throw(
                TimeoutError("process still exists")
            ),
        ),
    )

    output_dir = tmp_path / "orchestration"
    exit_code = run_end_to_end.main(
        _main_args(
            output_dir,
            tmp_path,
            "--generation-dir",
            str(_reused_generation_dir(tmp_path)),
        )
    )

    assert exit_code == 1
    record = _cleanup_record(output_dir)
    assert record["status"] == "failed"
    assert record["process_exit_wait"]["status"] == "timeout"


def test_stage_failure_records_failed_cleanup_preserving_observed_state(
    tmp_path, monkeypatch
):
    """A failed artifact stage still cleans up, and the record preserves the
    observed live processes and listening ports instead of clean values."""
    _full_run(
        tmp_path,
        monkeypatch,
        stage_artifact=lambda *args, **kwargs: {
            "status": "failed",
            "output_dir": "artifact",
            "attempts": [],
            "error": "no selected handoff compiled a design; see attempts",
        },
    )
    observed_process = _process_identity()
    monkeypatch.setattr(
        run_end_to_end,
        "cleanup_probes",
        _offline_probes(
            processes=[observed_process],
            open_ports={8888, 8321},
        ),
    )
    output_dir = tmp_path / "orchestration"

    exit_code = run_end_to_end.main(
        _main_args(
            output_dir,
            tmp_path,
            "--generation-dir",
            str(_reused_generation_dir(tmp_path)),
        )
    )

    assert exit_code == 1
    record = _cleanup_record(output_dir)
    assert record["status"] == "failed"
    assert record["orphan_processes"] == [observed_process]
    assert record["no_orphan_check"] == "failed"
    assert record["ports_open_after"] == [8888, 8321]
    assert record["ports_clear"] is False


def test_unexpected_failure_still_records_cleanup(tmp_path, monkeypatch):
    """An unexpected escape (here, from the report builder) still records the
    terminal cleanup before the exception propagates."""
    _full_run(tmp_path, monkeypatch)

    def exploding_report(**kwargs):
        raise RuntimeError("unexpected report failure")

    monkeypatch.setattr(run_end_to_end, "build_report", exploding_report)
    output_dir = tmp_path / "orchestration"

    with pytest.raises(RuntimeError, match="unexpected report failure"):
        run_end_to_end.main(
            _main_args(
                output_dir,
                tmp_path,
                "--generation-dir",
                str(_reused_generation_dir(tmp_path)),
            )
        )

    record = _cleanup_record(output_dir)
    assert record["status"] == "completed"
    assert record["target"] == "klarna"


def test_pause_records_kept_running_and_does_not_stop_the_stack(tmp_path, monkeypatch):
    """--pause-before-dispatch writes an intentional kept_running record with
    the resume reason and scope; the stop action never runs."""
    _full_run(tmp_path, monkeypatch)
    stop_calls: list[str] = []
    monkeypatch.setattr(
        run_end_to_end,
        "cleanup_probes",
        _offline_probes(
            processes=[_process_identity()],
            open_ports={8888},
            stop_calls=stop_calls,
        ),
    )
    output_dir = tmp_path / "orchestration"

    exit_code = run_end_to_end.main(
        _main_args(
            output_dir,
            tmp_path,
            "--generation-dir",
            str(_reused_generation_dir(tmp_path)),
            "--pause-before-dispatch",
        )
    )

    assert exit_code == 0
    record = _cleanup_record(output_dir)
    assert record["status"] == "kept_running"
    assert record["run_id"] == "synthesis-x"
    assert record["target"] == "klarna"
    assert record["resume_reason"]
    assert record["resume_scope"]
    assert record["stop_command"] is None
    assert record["stop_result"] is None
    assert record["process_evidence"] == [_process_identity()]
    assert record["ports_open_before"] == [8888]
    # The stack was never signalled.
    assert stop_calls == []


def _paused_run_dir(tmp_path: Path, monkeypatch) -> Path:
    """A paused run on disk, including its kept_running cleanup record."""
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
    record_kept_running(
        run_id="r1",
        target="klarna",
        record_path=output_dir / "cleanup" / CLEANUP_RECORD_FILENAME,
        resume_reason="pause",
        resume_scope="execution",
        probes=_offline_probes(processes=[_process_identity()]),
    )
    return output_dir


def test_resume_replaces_the_pause_record_only_after_dispatch(tmp_path, monkeypatch):
    """The resume dispatches first: the pause record is still kept_running
    when the dispatch runs and only the post-dispatch cleanup replaces it."""
    output_dir = _paused_run_dir(tmp_path, monkeypatch)
    stop_calls: list[str] = []
    monkeypatch.setattr(
        run_end_to_end,
        "cleanup_probes",
        _offline_probes(processes=[], stop_calls=stop_calls),
    )
    observed_at_dispatch: dict[str, object] = {}

    def fake_stage_execution(domain, artifact, model_settings, exec_dir, log_path):
        observed_at_dispatch["record"] = _cleanup_record(output_dir)
        observed_at_dispatch["stop_calls"] = list(stop_calls)
        return {"status": "success", "exit_code": 0}

    monkeypatch.setattr(run_end_to_end, "stage_execution", fake_stage_execution)

    exit_code = run_end_to_end.main(
        _main_args(output_dir, tmp_path, "--resume-dispatch")
    )

    assert exit_code == 0
    # At dispatch time the pause record stood and the stack was untouched.
    assert observed_at_dispatch["record"]["status"] == "kept_running"
    assert observed_at_dispatch["stop_calls"] == []
    # After the dispatch path the terminal cleanup replaced the pause record.
    record = _cleanup_record(output_dir)
    assert record["status"] == "completed"
    assert record["run_id"] == "r1"
    assert stop_calls == []
    report = json.loads((output_dir / "run-status.json").read_text(encoding="utf-8"))
    assert report["stack_cleanup"]["status"] == "completed"
    assert "paused_before_dispatch" not in report


def test_resume_gate_failure_keeps_the_pause_record_and_the_stack(
    tmp_path, monkeypatch
):
    """A resume refused at the pre-dispatch gate never signals the stack and
    never replaces the pause record."""
    output_dir = tmp_path / "orchestration"
    output_dir.mkdir()
    (output_dir / "run-status.json").write_text(
        json.dumps(_paused_run_status()), encoding="utf-8"
    )
    execution_dir = output_dir / "execution"
    execution_dir.mkdir()
    partial = {
        key: "recorded" for key in run_end_to_end.REQUIRED_PRE_DISPATCH_RECORDS[:4]
    }
    (execution_dir / "pre-dispatch-checks.yaml").write_text(
        yaml.safe_dump(partial), encoding="utf-8"
    )
    record_kept_running(
        run_id="r1",
        target="klarna",
        record_path=output_dir / "cleanup" / CLEANUP_RECORD_FILENAME,
        resume_reason="pause",
        resume_scope="execution",
        probes=_offline_probes(processes=["111 uv run mini-agents-stack"]),
    )
    stop_calls: list[str] = []
    monkeypatch.setattr(
        run_end_to_end,
        "cleanup_probes",
        _offline_probes(processes=[_process_identity()], stop_calls=stop_calls),
    )

    with pytest.raises(SystemExit):
        run_end_to_end.main(_main_args(output_dir, tmp_path, "--resume-dispatch"))

    assert stop_calls == []
    record = _cleanup_record(output_dir)
    assert record["status"] == "kept_running"
