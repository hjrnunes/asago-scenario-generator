#!/usr/bin/env python
"""One reusable orchestration entry point for the complete end-to-end path (M4).

Runs, for one target, the three product stages through their documented CLIs
with no manual file operations between stages:

1. generation   producer ``asago-scenario-generator run`` over the registered
                staged inputs, publishing the scenario handoff artifacts.
2. artifact     consumer ``asago-artifact-generator design`` on the selected
                adversarial handoff, producing the executable artifact,
                detector and fidelity record.
3. execution    ``garak_case_runner.py`` against the local mini-agent,
                producing ``qualification.json`` and ``garak-attempts.jsonl``.

The three stages are reported as INDEPENDENT statuses in ``run-status.json``
and on stdout. A failure in one stage never erases or conflates another
stage's outcome: a failed execution stage leaves the generation and artifact
statuses, and their published artifacts, intact and marked successful.

Every terminal outcome ends with a recorded stack cleanup (VAL-QUAL-011): the
maintained seam in ``stack_cleanup.py`` stops the documented supervisor
pattern and atomically writes ``cleanup/stack-cleanup.json`` beside the run
status, preserving the observed process/port state before and after the stop,
the stop command and result, the final no-orphan check, the status, a
timestamp, and errors. Success, stage failure, and unexpected failure all
record cleanup. A ``--pause-before-dispatch`` run instead records an
intentional ``kept_running`` record with the resume reason and scope and does
not stop the stack; ``--resume-dispatch`` replaces that record only after the
dispatch path runs.

The script never prints or logs the model endpoint or key. Environment
bridging (consumer/runner model settings) happens in the child-process
environment only.

Run CWD-anchored to the producer worktree root::

    uv run python scripts/qualification/run_end_to_end.py \\
        --output-dir build/adaptive-e2e/<fresh-run-name>

The mini-agents stack is an execution-stage prerequisite, not a stage: start
or reset it with the documented ``run_recipe.py reset`` before invoking this
script when the execution stage should run. With the stack stopped the
generation and artifact stages still complete (their inputs are staged
files), and only the execution status reports failed.

For live confirmations the pre-dispatch record
(``library/live-run-playbook.md``) must be written AFTER the frozen plan
exists and BEFORE the Garak dispatch. Run with
``--pause-before-dispatch`` to stop after the artifact stage, write
``execution/pre-dispatch-checks.yaml`` from the frozen plan and the live
runtime, then resume the dispatch with ``--resume-dispatch``. The resume
refuses to dispatch unless the record carries all seven required playbook
sections and never reruns the successful upstream stages.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from stack_cleanup import (
    CLEANUP_RECORD_FILENAME,
    CleanupProbes,
    record_kept_running,
    run_stack_cleanup,
)

SCRIPT_PATH = Path(__file__).resolve()
PRODUCER_ROOT = SCRIPT_PATH.parents[2]
WORKTREE_ROOT = PRODUCER_ROOT.parent
CONSUMER_ROOT = WORKTREE_ROOT / "asago-artifact-generator"
GARAK_PYTHON = WORKTREE_ROOT / ".mission-runtime" / "garak-venv" / "bin" / "python"
GARAK_RUNNER = PRODUCER_ROOT / "scripts" / "qualification" / "garak_case_runner.py"
DEFAULT_PROFILES_FILE = PRODUCER_ROOT / "config" / "model-profiles.yaml"
DEFAULT_PROFILE = "gemma4-oc"
OGX_PORT = 8321
KLARNA_SAFE_PORT = 8888
AIRBNB_SAFE_PORT = 8890
OCCIAI_SAFE_PORT = 8892
STATUS_SCHEMA = "orchestration-status-v1"

# Registration input keys. The first four are required producer ``run``
# inputs; the last four are optional (``loss_analysis`` pins Stage 1a,
# ``capability_profile`` skips profile inference, and the paired
# discovery profile + normalized runtime context drive target realization
# and the consumer design). Optional keys participate only when registered.
DOMAIN_INPUT_KEYS = (
    "use_case",
    "risk_extraction",
    "qualification_facts",
    "sssom",
    "loss_analysis",
    "capability_profile",
    "target_profile",
    "target_observations",
)

# Registered targets with their staged inputs (established in M2/M3 and
# staged under build/adaptive-runs/inputs/). Paths are relative to the
# producer worktree root. Each target's environment inputs are its pinned
# discovery execution-target profile and its paired normalized runtime
# context (the pair's digests must match, which the producer validates);
# the consumer design consumes both as staged files, so the artifact stage
# never needs the live target.
#
# Every target pins a staged loss analysis (Stage 1a validated offline, zero
# Stage 1a model calls). Klarna pins the historical reviewed analysis plus its
# capability profile; occiai pins the accepted derived graph from
# build/adaptive-runs/m3-occiai-attempt1 (owner decision 2026-09-15: the
# derived/proposed authority is preserved as-is, never relabelled reviewed);
# airbnb pins the reviewed rev3 graph from build/adaptive-runs/airbnb-followup
# (acceptance record acceptance-rev3-20260915.json in the same directory).
# Both pinned graphs validated against the exact staged fs-isac risk cards
# still registered here. None of the three registers a staged capability
# profile except klarna; occiai/airbnb infer theirs.
#
# ``record_hint`` (airbnb only) names the one foreign-owned reservation in
# the staged runtime context (RES-201, guest GST002; the authenticated actor
# is GST001). The design stage uses it only when the consumer reports a
# session-mismatch ``missing-setup`` that asks for an explicit record hint
# (several candidates fit the criterion); the consumer validates the hint
# against the observed state and discloses it as an explicit choice.
DOMAINS: dict[str, dict[str, Any]] = {
    "klarna": {
        "use_case": "build/adaptive-runs/inputs/use-case-klarna-fs-isac-v36.txt",
        "risk_extraction": "build/adaptive-runs/inputs/risk-extraction-fs-isac.json",
        "qualification_facts": "build/adaptive-runs/inputs/klarna-qualification-facts.yaml",
        "sssom": "build/adaptive-runs/inputs/risk-to-llm.sssom.tsv",
        "loss_analysis": "build/adaptive-redesign-inputs/historical/loss-analysis.yaml",
        "capability_profile": "build/adaptive-redesign-inputs/historical/capability-profile.yaml",
        "target_profile": "build/adaptive-redesign-inputs/historical/execution-target-profile.json",
        "target_observations": (
            "build/adaptive-runs/inputs/klarna-runtime-context-20260906-normalized.json"
        ),
        "mcp_url": f"http://127.0.0.1:{KLARNA_SAFE_PORT}/sse",
        "state_tool": "get_klarna_state_summary",
        "documented_operation": "process_refund",
        "model": "gemma-4-26b-a4b-it",
    },
    "occiai": {
        "use_case": (
            "build/adaptive-runs/inputs/use-case-occiai-clinical-escalation.txt"
        ),
        "risk_extraction": "build/adaptive-runs/inputs/risk-extraction-fs-isac.json",
        "qualification_facts": "build/adaptive-runs/inputs/occiai-qualification-facts.yaml",
        "sssom": "build/adaptive-runs/inputs/risk-to-llm.sssom.tsv",
        "loss_analysis": ("build/adaptive-runs/m3-occiai-attempt1/loss-analysis.yaml"),
        "target_profile": (
            "build/adaptive-runs/inputs/occiai-discovery-r2/execution-target-profile.json"
        ),
        # Re-captured runtime context (owner decision 2026-09-16): one real
        # AWAITING_REVIEW draft for the session patient PAT-104, created via
        # the documented summarize_for_ehr tool. The original empty staged
        # context (occiai-runtime-context-normalized.json) stays byte-untouched.
        # Draft ids are uuid4-generated and die with a stack reset, so each
        # attempt whose dispatch gate needs the live draft re-captures the
        # context against the CURRENT live stack (keep-stack-up procedure:
        # reset once, create the draft via the dirty seam, capture, keep the
        # stack UP through design and dispatch). Third capture (2026-09-16):
        # taken after the consumer dispatch-gate correction (95908b6) landed
        # and passed its independent review; draft DFT72D242 stays live
        # through dispatch — see the CAPTURE-RECORD.yaml beside it.
        "target_observations": (
            "build/adaptive-runs/inputs/"
            "occiai-runtime-context-recapture3-20260916-normalized.json"
        ),
        "mcp_url": f"http://127.0.0.1:{OCCIAI_SAFE_PORT}/sse",
        "state_tool": "get_occiai_state_summary",
        "documented_operation": "commit_to_ehr",
        "model": "gemma-4-26b-a4b-it",
    },
    "airbnb": {
        "use_case": (
            "build/adaptive-runs/inputs/use-case-airbnb-booking-modification.txt"
        ),
        "risk_extraction": "build/adaptive-runs/inputs/risk-extraction-fs-isac.json",
        "qualification_facts": "build/adaptive-runs/inputs/airbnb-qualification-facts.yaml",
        "sssom": "build/adaptive-runs/inputs/risk-to-llm.sssom.tsv",
        "loss_analysis": (
            "build/adaptive-runs/airbnb-followup/loss-analysis-reviewed-rev3.yaml"
        ),
        "target_profile": (
            "build/adaptive-runs/inputs/airbnb-discovery/execution-target-profile.json"
        ),
        "target_observations": (
            "build/adaptive-runs/inputs/airbnb-runtime-context-normalized.json"
        ),
        "mcp_url": f"http://127.0.0.1:{AIRBNB_SAFE_PORT}/sse",
        "state_tool": "get_airbnb_state_summary",
        "documented_operation": "modify_booking",
        "record_hint": "RES-201",
        "model": "gemma-4-26b-a4b-it",
    },
}

MAX_WORKERS = "4"
RUNNER_TIMEOUT = "240"

# The live pre-dispatch record (library/live-run-playbook.md) is written into
# the execution directory AFTER the frozen plan exists and BEFORE the Garak
# dispatch. ``--pause-before-dispatch`` stops between the artifact and
# execution stages; ``--resume-dispatch`` verifies the record and dispatches.
PRE_DISPATCH_RECORD = "pre-dispatch-checks.yaml"
REQUIRED_PRE_DISPATCH_RECORDS = (
    "scenario_meaning",
    "stimulus_exercise_rationale",
    "verified_permissions_prerequisites",
    "safe_alternatives_availability",
    "detector_discrimination",
    "target_tools_and_instructions",
    "observation_limitations",
)


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# Injectable cleanup probes (VAL-QUAL-011): ``None`` uses the documented
# production probes; tests inject offline fakes so no test pkills a process
# or probes a real port.
cleanup_probes: CleanupProbes | None = None

PAUSE_RESUME_REASON = (
    "paused before dispatch; the stack stays up for the operator's "
    "pre-dispatch record and the resumed execution stage"
)
PAUSE_RESUME_SCOPE = (
    "execution stage dispatch after execution/pre-dispatch-checks.yaml is "
    "complete; resume with --resume-dispatch"
)


def cleanup_record_path(output_dir: Path) -> Path:
    """The per-run cleanup record path inside one orchestration output root."""
    return output_dir / "cleanup" / CLEANUP_RECORD_FILENAME


def record_orchestration_cleanup(
    *,
    output_dir: Path,
    run_id: str | None,
    target: str,
    paused: bool,
) -> dict[str, Any] | None:
    """Record terminal stack cleanup for one orchestration run.

    Success, stage failure, and unexpected failure all stop the stack and
    write the atomic per-run cleanup record. A paused run keeps the stack up
    for the documented resume path: the kept_running record written at pause
    time stands.
    """
    record_path = cleanup_record_path(output_dir)
    if paused:
        if not record_path.exists():
            try:
                record_kept_running(
                    run_id=run_id,
                    target=target,
                    record_path=record_path,
                    resume_reason=PAUSE_RESUME_REASON,
                    resume_scope=PAUSE_RESUME_SCOPE,
                    probes=cleanup_probes,
                )
            except Exception as error:  # noqa: BLE001 - never masks the outcome
                print(
                    f"kept-running record could not be written: {error}",
                    file=sys.stderr,
                )
        return None
    try:
        return run_stack_cleanup(
            run_id=run_id,
            target=target,
            record_path=record_path,
            probes=cleanup_probes,
        )
    except Exception as error:  # noqa: BLE001 - cleanup never masks the outcome
        print(f"stack cleanup could not be recorded: {error}", file=sys.stderr)
        return None


def read_profile_settings(profiles_file: Path, profile: str) -> dict[str, str]:
    """Return the profile's model settings without ever printing them."""
    import yaml

    document = yaml.safe_load(profiles_file.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError(f"{profiles_file} is not a profile mapping")
    nested = document.get("profiles")
    lookup = nested if isinstance(nested, dict) else document
    entry = lookup.get(profile)
    if not isinstance(entry, dict):
        raise ValueError(f"profile {profile!r} not found in {profiles_file}")
    base_url = entry.get("base_url")
    if not isinstance(base_url, str) or not base_url.strip():
        raise ValueError(f"profile {profile!r} has no base_url")
    return {
        "base_url": base_url,
        "model": str(entry.get("model") or ""),
        "api_key": str(entry.get("api_key") or "unused"),
    }


def _port_is_listening(port: int) -> bool:
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.25)
        return sock.connect_ex(("127.0.0.1", port)) == 0


def _run_logged(
    command: list[str],
    *,
    cwd: Path,
    log_path: Path,
    extra_env: dict[str, str] | None = None,
) -> int:
    """Run one stage command with its output captured to a log file."""
    environment = {**os.environ, **(extra_env or {})}
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("wb") as log:
        completed = subprocess.run(
            command,
            cwd=str(cwd),
            env=environment,
            stdout=log,
            stderr=subprocess.STDOUT,
            check=False,
        )
    return completed.returncode


def select_handoffs(
    scenarios_dir: Path,
    *,
    documented_operation: str,
    max_attempts: int,
) -> list[dict[str, Any]]:
    """Select candidate handoffs for artifact design, deterministically.

    Adversarial handoffs come first, ordered so handoffs whose
    ``documented_operations`` name the domain's dangerous operation precede
    the rest, then by scenario id. Functional handoffs follow every
    adversarial handoff, with the same match-then-id ordering: the recorded
    functional-feasibility decision (consumer commit 282a1d3) admits
    functional handoffs to criterion-shape interpretation, and the recognized
    functional candidates (for example the occiai ``precondition_record``
    wordings) are exactly where the occiai resumed chain compiles. Any other
    kind is never selected.
    """
    import yaml

    candidates: list[dict[str, Any]] = []
    for path in sorted(scenarios_dir.glob("*.yaml")):
        envelope = yaml.safe_load(path.read_text(encoding="utf-8"))
        kind = envelope.get("kind") if isinstance(envelope, dict) else None
        if kind not in ("adversarial", "functional"):
            continue
        operations = [
            str(entry.get("name"))
            for entry in (envelope.get("documented_operations") or [])
            if isinstance(entry, dict)
        ]
        candidates.append(
            {
                "scenario_id": str(envelope.get("scenario_id") or path.stem),
                "path": path,
                "operation_match": documented_operation in operations,
                "adversarial": kind == "adversarial",
            }
        )
    candidates.sort(
        key=lambda c: (
            0 if c["adversarial"] else 1,
            0 if c["operation_match"] else 1,
            c["scenario_id"],
        )
    )
    return candidates[:max_attempts]


def read_producer_run_status(generation_dir: Path) -> dict[str, Any]:
    """Read the producer run classification from the synthesis manifest.

    ``run_status``/``run_status_reason`` are published by
    ``synthesis-manifest.yaml``; ``run-manifest.yaml`` does not carry the
    producer classification. Older generation directories that predate the
    synthesis manifest fall back to a ``run-manifest.yaml`` ``run_status`` key
    when present.
    """
    import yaml

    def _read(path: Path) -> dict[str, Any]:
        if not path.is_file():
            return {}
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        return document if isinstance(document, dict) else {}

    synthesis = _read(generation_dir / "synthesis-manifest.yaml")
    legacy = _read(generation_dir / "run-manifest.yaml")
    values: dict[str, Any] = {}
    for key, record_key in (
        ("run_status", "producer_run_status"),
        ("run_status_reason", "producer_run_status_reason"),
    ):
        value = synthesis.get(key)
        if value is None:
            value = legacy.get(key)
        values[record_key] = value
    return values


def build_generation_command(
    domain: dict[str, Any],
    profile: str,
    generation_dir: Path,
) -> list[str]:
    """Build the producer ``run`` command over the registered staged inputs.

    Required inputs are always passed; optional registration keys
    (``loss_analysis``, ``capability_profile``, ``target_profile``,
    ``target_observations``) are passed only when registered.
    """
    command = [
        "uv",
        "run",
        "asago-scenario-generator",
        "run",
        "--use-case",
        f"@{PRODUCER_ROOT / domain['use_case']}",
        "--risk-extraction",
        str(PRODUCER_ROOT / domain["risk_extraction"]),
        "--qualification-facts",
        str(PRODUCER_ROOT / domain["qualification_facts"]),
        "--sssom",
        str(PRODUCER_ROOT / domain["sssom"]),
    ]
    for key, flag in (
        ("loss_analysis", "--loss-analysis"),
        ("capability_profile", "--capability-profile"),
        ("target_profile", "--target-profile"),
        ("target_observations", "--target-observations"),
    ):
        if domain.get(key):
            command += [flag, str(PRODUCER_ROOT / domain[key])]
    return [
        *command,
        "--profile",
        profile,
        "--max-workers",
        MAX_WORKERS,
        "--output-dir",
        str(generation_dir),
    ]


def stage_generation(
    domain: dict[str, Any],
    profile: str,
    generation_dir: Path,
    log_path: Path,
) -> dict[str, Any]:
    """Run the producer ``run`` over the registered staged inputs."""
    command = build_generation_command(domain, profile, generation_dir)
    exit_code = _run_logged(command, cwd=PRODUCER_ROOT, log_path=log_path)
    record: dict[str, Any] = {
        "status": "success" if exit_code == 0 else "failed",
        "exit_code": exit_code,
        "output_dir": str(generation_dir),
        "log": str(log_path),
    }
    if generation_dir.exists():
        run_manifest = generation_dir / "run-manifest.yaml"
        if run_manifest.exists():
            import yaml

            manifest = yaml.safe_load(run_manifest.read_text(encoding="utf-8"))
            record["run_id"] = manifest.get("run_id")
        record.update(read_producer_run_status(generation_dir))
        scenarios_dir = generation_dir / "scenarios"
        if scenarios_dir.is_dir():
            published = sorted(scenarios_dir.glob("*.yaml"))
            record["scenarios_published"] = len(published)
            record["scenarios_dir"] = str(scenarios_dir)
    return record


def reuse_generation(generation_dir: Path) -> dict[str, Any]:
    """Verify an existing generation output and report it as reused.

    Used by failure-injection demonstrations that must vary only one variable
    (the stack), reusing the exact generation artifacts of the normal run.
    """
    record: dict[str, Any] = {
        "status": "failed",
        "source": "reused",
        "output_dir": str(generation_dir),
    }
    run_manifest = generation_dir.absolute() / "run-manifest.yaml"
    scenarios_dir = run_manifest.parent / "scenarios"
    if not run_manifest.exists() or not scenarios_dir.is_dir():
        record["error"] = (
            f"reused generation dir has no {run_manifest.name} or scenarios/"
        )
        return record
    import yaml

    manifest = yaml.safe_load(run_manifest.read_text(encoding="utf-8"))
    record["run_id"] = manifest.get("run_id")
    record.update(read_producer_run_status(generation_dir.absolute()))
    published = sorted(scenarios_dir.glob("*.yaml"))
    record["scenarios_published"] = len(published)
    record["scenarios_dir"] = str(scenarios_dir)
    record["status"] = "success" if published else "failed"
    if not published:
        record["error"] = "reused generation dir publishes no scenario handoffs"
    return record


def stage_artifact(
    domain: dict[str, Any],
    generation: dict[str, Any],
    model_settings: dict[str, str],
    artifact_dir: Path,
    log_prefix: str,
    max_attempts: int,
) -> dict[str, Any]:
    """Design the artifact for the selected handoff through the consumer CLI."""
    record: dict[str, Any] = {
        "status": "failed",
        "output_dir": str(artifact_dir),
        "attempts": [],
    }
    scenarios_dir = Path(generation.get("scenarios_dir", ""))
    if not scenarios_dir.is_dir():
        record["error"] = "generation published no scenarios directory"
        return record
    candidates = select_handoffs(
        scenarios_dir,
        documented_operation=domain["documented_operation"],
        max_attempts=max_attempts,
    )
    if not candidates:
        record["error"] = "generation published no selectable scenario handoffs"
        return record
    bridge = {
        "REDTEAM_PROVIDER": "openai",
        "REDTEAM_MODEL": model_settings["model"],
        "OPENAI_BASE_URL": model_settings["base_url"],
        "OPENAI_API_KEY": model_settings["api_key"],
    }
    record_hint = domain.get("record_hint")

    def _run_design(
        design_dir: Path, log_path: Path, extra_args: list[str]
    ) -> dict[str, Any]:
        command = [
            "uv",
            "run",
            "asago-artifact-generator",
            "design",
            "--handoff",
            str(candidate["path"]),
            "--target-profile",
            str(PRODUCER_ROOT / domain["target_profile"]),
            "--runtime-context",
            str(PRODUCER_ROOT / domain["target_observations"]),
            "--platform",
            "garak",
            "--output-dir",
            str(design_dir),
            *extra_args,
        ]
        exit_code = _run_logged(
            command, cwd=CONSUMER_ROOT, log_path=log_path, extra_env=bridge
        )
        attempt: dict[str, Any] = {
            "scenario_id": candidate["scenario_id"],
            "handoff": str(candidate["path"]),
            "exit_code": exit_code,
            "log": str(log_path),
        }
        manifest_path = design_dir / "design-manifest.json"
        if manifest_path.exists():
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            attempt["design_id"] = manifest.get("design_id")
            attempt["compiled"] = manifest.get("compiled") is True
            attempt["exclusion_code"] = manifest.get("exclusion_code")
            attempt["exclusion_detail"] = manifest.get("exclusion_detail")
            if manifest.get("compiled") is True:
                attempt["artifact"] = str(
                    design_dir
                    / f"{manifest.get('design_id')}"
                    / "executable-conversation.json"
                )
                attempt["execution_plan"] = str(
                    design_dir / f"{manifest.get('design_id')}" / "execution-plan.json"
                )
        else:
            attempt["compiled"] = False
            attempt["error"] = "consumer produced no design manifest"
        return attempt

    for candidate in candidates:
        scenario_id = candidate["scenario_id"]
        design_dir = artifact_dir / scenario_id
        log_path = Path(f"{log_prefix}-{scenario_id}.log")
        attempt = _run_design(design_dir, log_path, [])
        record["attempts"].append(attempt)
        if attempt.get("compiled") is True:
            record["status"] = "success"
            record["selected_scenario"] = scenario_id
            record["selected_design_id"] = attempt.get("design_id")
            return record
        if (
            attempt.get("exclusion_code") == "missing-setup"
            and "record hint" in str(attempt.get("exclusion_detail") or "")
            and record_hint
        ):
            # The consumer asked for an explicit record hint (several
            # candidates fit the criterion). Retry the same scenario once in
            # a separate design directory with the registered per-target
            # hint; the consumer validates it against the observed state and
            # discloses it as an explicit choice, so a wrong hint fails
            # closed. The first attempt stays preserved beside the retry.
            hint_dir = artifact_dir / f"{scenario_id}-record-hint"
            hint_log = Path(f"{log_prefix}-{scenario_id}-record-hint.log")
            retry = _run_design(hint_dir, hint_log, ["--record-hint", record_hint])
            retry["record_hint"] = record_hint
            retry["missing_setup_retry"] = True
            record["attempts"].append(retry)
            if retry.get("compiled") is True:
                record["status"] = "success"
                record["selected_scenario"] = scenario_id
                record["selected_design_id"] = retry.get("design_id")
                return record
    record["error"] = "no selected handoff compiled a design; see attempts"
    return record


def _runner_failure_summary(log_path: Path) -> str | None:
    """Extract the actual failure class from a runner log's tail.

    The runner log ends with the runner's traceback when it crashes, so the
    last exception line names the real failure (for example a
    FileExistsError over existing dispatch evidence, or a transport error
    with the stack stopped). Returns the bounded exception line, or None
    when no exception line is present.
    """
    try:
        tail = log_path.read_text(encoding="utf-8", errors="replace")[-8192:]
    except OSError:
        return None
    for line in reversed(tail.splitlines()):
        stripped = line.strip()
        if not stripped:
            continue
        head = stripped.split(":", 1)[0].strip()
        head_class = head.rsplit(".", 1)[-1]
        if head_class.endswith(("Error", "Exception", "Exit", "Interrupt")):
            return f"{head_class}: {stripped.split(':', 1)[1].strip()}"[:300]
    return None


def stage_execution(
    domain: dict[str, Any],
    artifact: dict[str, Any],
    model_settings: dict[str, str],
    execution_dir: Path,
    log_path: Path,
) -> dict[str, Any]:
    """Execute the compiled artifact through the pinned Garak runner."""
    selected = next(
        (a for a in artifact.get("attempts", []) if a.get("compiled") is True), None
    )
    if selected is None:
        return {"status": "not_run", "reason": "no compiled artifact to execute"}
    command = [
        str(GARAK_PYTHON),
        str(GARAK_RUNNER),
        "--case",
        selected["artifact"],
        "--plan",
        selected["execution_plan"],
        "--mcp-url",
        domain["mcp_url"],
        "--model-url",
        f"http://127.0.0.1:{OGX_PORT}/v1/",
        "--model",
        domain["model"],
        "--state-tool",
        domain["state_tool"],
        "--timeout",
        RUNNER_TIMEOUT,
        "--output",
        str(execution_dir),
    ]
    extra_env = {
        "OPENAI_API_KEY": model_settings["api_key"],
        "PYTHONPATH": f"{PRODUCER_ROOT / 'src'}:{CONSUMER_ROOT / 'src'}",
    }
    exit_code = _run_logged(
        command, cwd=PRODUCER_ROOT, log_path=log_path, extra_env=extra_env
    )
    record: dict[str, Any] = {
        "status": "success" if exit_code == 0 else "failed",
        "exit_code": exit_code,
        "evidence_dir": str(execution_dir),
        "log": str(log_path),
    }
    qualification = execution_dir / "qualification.json"
    record["qualification_report"] = str(qualification)
    record["qualification_present"] = qualification.exists()
    if exit_code != 0:
        failure_class = _runner_failure_summary(log_path)
        record["error"] = (
            f"garak runner failed with {failure_class}; see the log and "
            "evidence directory"
            if failure_class
            else "garak runner failed; see the log and evidence directory"
        )
    return record


def build_report(
    *,
    domain_name: str,
    started_at: str,
    finished_at: str,
    preflight: dict[str, Any],
    generation: dict[str, Any],
    artifact: dict[str, Any],
    execution: dict[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": STATUS_SCHEMA,
        "target_domain": domain_name,
        "started_at": started_at,
        "finished_at": finished_at,
        "preflight": preflight,
        "stages": {
            "generation": generation,
            "artifact": artifact,
            "execution": execution,
        },
    }


def print_summary(report: dict[str, Any]) -> None:
    stages = report["stages"]
    print("\n=== orchestration status ===")
    for name in ("generation", "artifact", "execution"):
        stage = stages[name]
        line = f"{name:>10}: {stage['status']}"
        if name == "generation" and "run_id" in stage:
            line += f" (run_id {stage['run_id']}, {stage.get('scenarios_published', 0)} scenarios)"
        if name == "artifact" and stage.get("selected_design_id"):
            line += f" ({stage['selected_design_id']})"
        if name == "execution" and stage["status"] == "failed":
            line += f" ({stage.get('error', 'see log')})"
        print(line)
    print("full report: run-status.json in the output directory")


def load_pre_dispatch_record(execution_dir: Path) -> dict[str, Any]:
    """Load and structurally check the operator-written pre-dispatch record.

    The record's seven playbook sections must all be present and non-empty;
    the content quality (verification methods, live values, scoping) is
    judged from the file itself by validators, while this gate guarantees the
    dispatch never starts without the record's skeleton in place.
    """
    import yaml

    record_path = execution_dir / PRE_DISPATCH_RECORD
    if not record_path.is_file():
        raise ValueError(
            f"no pre-dispatch record at {record_path}; write it from the "
            "frozen plan and the live runtime before resuming the dispatch"
        )
    record = yaml.safe_load(record_path.read_text(encoding="utf-8"))
    if not isinstance(record, dict):
        raise ValueError(f"{record_path} is not a YAML mapping")
    missing = [key for key in REQUIRED_PRE_DISPATCH_RECORDS if not record.get(key)]
    if missing:
        raise ValueError(
            f"{record_path} is missing required pre-dispatch records: "
            f"{', '.join(missing)}"
        )
    return record


def _execution_evidence_present(execution_dir: Path) -> bool:
    """True when the execution directory already holds dispatch evidence.

    Evidence means the dispatch happened: a qualification report or Garak
    attempt records exist. Only the pre-dispatch record (written before the
    dispatch by design) does not count as evidence.
    """
    return any(
        (execution_dir / name).exists()
        for name in ("qualification.json", "garak-attempts.jsonl")
    )


def _resume_dispatch(
    parser: argparse.ArgumentParser,
    args: argparse.Namespace,
    output_dir: Path,
) -> int:
    """Resume a paused run: verify the pre-dispatch record, then dispatch."""
    status_path = output_dir / "run-status.json"
    if not output_dir.is_dir() or not status_path.is_file():
        parser.error(f"no paused run to resume under: {output_dir}")
    report = json.loads(status_path.read_text(encoding="utf-8"))
    if report.get("target_domain") != args.domain:
        parser.error(
            f"paused run targets domain {report.get('target_domain')!r}, "
            f"not {args.domain!r}: {status_path}"
        )
    stages = report.get("stages", {})
    execution_stage = stages.get("execution", {})
    execution_status = execution_stage.get("status")
    # A prior execution stage that failed BEFORE any dispatch (no execution
    # evidence written) leaves the run resumable: the upstream stages and the
    # pre-dispatch record are intact and the retry overwrites no evidence. A
    # dispatch that produced evidence is never retried in place.
    prior_predispatch_failure = (
        execution_status == "failed"
        and not _execution_evidence_present(output_dir / "execution")
    )
    execution_pending = execution_status == "not_run" or prior_predispatch_failure
    upstream_success = (
        stages.get("generation", {}).get("status") == "success"
        and stages.get("artifact", {}).get("status") == "success"
    )
    if not (upstream_success and execution_pending):
        parser.error(
            f"run is not paused before dispatch (or resumable after a "
            f"pre-dispatch execution failure) with successful upstream "
            f"stages: {status_path}"
        )
    try:
        model_settings = read_profile_settings(args.profiles_file, args.profile)
        # The dispatch gate: the record must already be complete; a missing
        # or partial record stops the resume before the execution stage.
        load_pre_dispatch_record(output_dir / "execution")
    except (OSError, ValueError) as error:
        parser.error(str(error))
    cleanup: dict[str, Any] | None = None
    try:
        execution = stage_execution(
            DOMAINS[args.domain],
            stages["artifact"],
            model_settings,
            output_dir / "execution",
            output_dir / "execution.log",
        )
    finally:
        # The dispatch path has run (completed or raised unexpectedly): the
        # pause record is now replaced by terminal cleanup evidence. A
        # pre-dispatch gate failure never reaches this point, so the stack is
        # never stopped before the dispatch it serves.
        cleanup = record_orchestration_cleanup(
            output_dir=output_dir,
            run_id=stages.get("generation", {}).get("run_id"),
            target=args.domain,
            paused=False,
        )
    execution["pre_dispatch_record"] = str(
        output_dir / "execution" / PRE_DISPATCH_RECORD
    )
    if prior_predispatch_failure:
        execution["prior_predispatch_failure"] = {
            "status": "failed",
            "record": execution_stage,
            "reason": (
                "prior execution stage failed before any dispatch (no "
                "execution evidence written); the retry followed a fix to "
                "the blocking seam and re-dispatched with the same record"
            ),
        }
    stages["execution"] = execution
    if cleanup is not None:
        report["stack_cleanup"] = {
            "status": cleanup.get("status"),
            "record": cleanup.get("record_path"),
            "orphan_processes": cleanup.get("orphan_processes"),
            "ports_clear": cleanup.get("ports_clear"),
        }
    report.pop("paused_before_dispatch", None)
    report["finished_at"] = utc_now()
    status_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print_summary(report)
    statuses = [
        stages[name]["status"] for name in ("generation", "artifact", "execution")
    ]
    cleanup_ok = cleanup is not None and cleanup.get("status") == "completed"
    return 0 if statuses == ["success", "success", "success"] and cleanup_ok else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--domain",
        choices=sorted(DOMAINS),
        default="klarna",
        help="Registered target configuration to run (default: klarna).",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="Fresh output root for this run; must not already exist.",
    )
    parser.add_argument(
        "--pause-before-dispatch",
        action="store_true",
        help=(
            "Run the generation and artifact stages, then stop with execution "
            f"not_run so the operator can write {PRE_DISPATCH_RECORD} into the "
            "execution directory from the frozen plan and live runtime; "
            "resume with --resume-dispatch."
        ),
    )
    parser.add_argument(
        "--resume-dispatch",
        action="store_true",
        help=(
            "Resume a run paused with --pause-before-dispatch: verify the "
            f"complete {PRE_DISPATCH_RECORD} in the output directory's "
            "execution dir, then run only the execution stage. Never reruns "
            "the generation or artifact stages."
        ),
    )
    parser.add_argument(
        "--profiles-file",
        type=Path,
        default=DEFAULT_PROFILES_FILE,
        help="Producer model-profile file (default: worktree config).",
    )
    parser.add_argument("--profile", default=DEFAULT_PROFILE)
    parser.add_argument(
        "--max-design-attempts",
        type=int,
        default=3,
        help="How many selected handoffs artifact design may try (default: 3).",
    )
    parser.add_argument(
        "--generation-dir",
        type=Path,
        default=None,
        help="Reuse an existing generation output directory (published "
        "scenarios and run manifest) instead of running the producer. The "
        "generation status then reports source: reused after verifying the "
        "artifacts exist; use this for failure-injection demonstrations that "
        "must vary only one variable.",
    )
    args = parser.parse_args(argv)

    # Downstream CLIs run with their own working directories, so every path
    # handed to a stage subprocess must be absolute.
    output_dir = args.output_dir.absolute()
    if args.resume_dispatch:
        return _resume_dispatch(parser, args, output_dir)
    if output_dir.exists():
        parser.error(f"output directory already exists: {output_dir} (never overwrite)")
    output_dir.mkdir(parents=True, exist_ok=False)

    # VAL-QUAL-011: cleanup runs automatically on success, stage failure, and
    # unexpected failure. A paused run keeps the stack up; the kept_running
    # record written at pause time stands.
    exit_code = 1
    paused = False
    run_id: str | None = None
    try:
        exit_code, paused, run_id = _run_stages_and_report(args, output_dir)
    finally:
        cleanup = record_orchestration_cleanup(
            output_dir=output_dir,
            run_id=run_id,
            target=args.domain,
            paused=paused,
        )
        if cleanup is not None:
            print(
                f"stack cleanup: {cleanup.get('status')} "
                f"(record: {cleanup.get('record_path')})"
            )
            if cleanup.get("status") != "completed" and not paused:
                exit_code = 1
    return exit_code


def _run_stages_and_report(
    args: argparse.Namespace, output_dir: Path
) -> tuple[int, bool, str | None]:
    """Run the staged pipeline, persist run-status.json, and report its outcome.

    Returns ``(exit_code, paused_before_dispatch, run_id)``. The pause
    branch writes the kept_running cleanup record itself; the terminal
    cleanup for every other outcome is the caller's ``finally`` duty.
    """
    domain = DOMAINS[args.domain]
    started_at = utc_now()
    preflight: dict[str, Any] = {}
    generation: dict[str, Any] = {"status": "not_run"}
    artifact: dict[str, Any] = {"status": "not_run"}
    execution: dict[str, Any] = {"status": "not_run"}
    paused_before_dispatch = False

    try:
        model_settings = read_profile_settings(args.profiles_file, args.profile)
        preflight = {
            "inputs_present": all(
                (PRODUCER_ROOT / domain[key]).exists()
                for key in DOMAIN_INPUT_KEYS
                if domain.get(key)
            ),
            "stack_listening": {
                "safe_mcp": _port_is_listening(domain_port(args.domain)),
                "ogx": _port_is_listening(OGX_PORT),
            },
            "note": (
                "stack availability is an execution-stage prerequisite; the "
                "generation and artifact stages run from staged files"
            ),
        }
    except (OSError, ValueError) as error:
        preflight = {"error": str(error)}
        model_settings = {}

    if model_settings and preflight.get("inputs_present"):
        # The generation and artifact stages parse and validate generation
        # and artifact outputs; an unexpected parse/validation escape here
        # must still persist the terminal run-status.json below (failed
        # stage failed, downstream not_run, upstream artifacts intact)
        # instead of escaping unwritten.
        if args.generation_dir is not None:
            try:
                generation = reuse_generation(args.generation_dir)
            except Exception as error:  # noqa: BLE001 - terminal report below
                generation = {
                    "status": "failed",
                    "source": "reused",
                    "output_dir": str(args.generation_dir.absolute()),
                    "error": f"generation output could not be read: {error}",
                }
            print(f"generation: {generation['status']} (reused)")
        else:
            try:
                generation = stage_generation(
                    domain,
                    args.profile,
                    output_dir / "generation",
                    output_dir / "generation.log",
                )
            except Exception as error:  # noqa: BLE001 - terminal report below
                generation = {
                    "status": "failed",
                    "output_dir": str(output_dir / "generation"),
                    "error": f"generation stage failed unexpectedly: {error}",
                }
            print(f"generation: {generation['status']}")
        if generation["status"] == "success":
            try:
                artifact = stage_artifact(
                    domain,
                    generation,
                    model_settings,
                    output_dir / "artifact",
                    str(output_dir / "artifact-design"),
                    args.max_design_attempts,
                )
            except Exception as error:  # noqa: BLE001 - terminal report below
                artifact = {
                    "status": "failed",
                    "output_dir": str(output_dir / "artifact"),
                    "error": f"artifact stage failed unexpectedly: {error}",
                }
            print(f"artifact:   {artifact['status']}")
            if artifact["status"] == "success":
                if args.pause_before_dispatch:
                    execution = {
                        "status": "not_run",
                        "reason": (
                            f"paused before dispatch; write {PRE_DISPATCH_RECORD} "
                            "into the execution directory from the frozen plan "
                            "and the live runtime, then resume with --resume-dispatch"
                        ),
                    }
                    (output_dir / "execution").mkdir(exist_ok=True)
                    paused_before_dispatch = True
                    record_kept_running(
                        run_id=generation.get("run_id"),
                        target=args.domain,
                        record_path=cleanup_record_path(output_dir),
                        resume_reason=PAUSE_RESUME_REASON,
                        resume_scope=PAUSE_RESUME_SCOPE,
                        probes=cleanup_probes,
                    )
                    print("execution:  paused before dispatch")
                else:
                    execution = stage_execution(
                        domain,
                        artifact,
                        model_settings,
                        output_dir / "execution",
                        output_dir / "execution.log",
                    )
                    print(f"execution:  {execution['status']}")
    else:
        if not model_settings:
            generation = {"status": "failed", "error": "profile settings unavailable"}

    finished_at = utc_now()
    report = build_report(
        domain_name=args.domain,
        started_at=started_at,
        finished_at=finished_at,
        preflight=preflight,
        generation=generation,
        artifact=artifact,
        execution=execution,
    )
    if paused_before_dispatch and execution["status"] == "not_run":
        report["paused_before_dispatch"] = True
    report_path = output_dir / "run-status.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print_summary(report)
    statuses = [
        report["stages"][name]["status"]
        for name in ("generation", "artifact", "execution")
    ]
    if report.get("paused_before_dispatch") is True:
        return 0, True, generation.get("run_id")
    exit_code = 0 if statuses == ["success", "success", "success"] else 1
    return exit_code, False, generation.get("run_id")


def domain_port(domain_name: str) -> int:
    return {
        "klarna": KLARNA_SAFE_PORT,
        "occiai": OCCIAI_SAFE_PORT,
        "airbnb": AIRBNB_SAFE_PORT,
    }.get(domain_name, 0)


if __name__ == "__main__":
    sys.exit(main())
