"""External QA helpers for the typed correspondence CLI.

This module intentionally imports only standard-library and YAML readers. It
constructs the wire payloads independently of the application models and
checks the published artifacts through the public command surface.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import threading
import importlib.util
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]
FIXTURE_ROOT = REPO_ROOT / "src/asago_scenario_generator/stpa/fixtures"
MAP = FIXTURE_ROOT / "system_resource_map_klarna.yaml"
SNAPSHOT = FIXTURE_ROOT / "capability_fact_snapshot_klarna.yaml"
CONTROL = FIXTURE_ROOT / "control_structure_klarna.yaml"
QA_ENV = "ASAGO_SCENARIO_GENERATOR_QA_PIPELINE"
OBLIGATION_ID = "ob:v1:" + "1" * 64
RISK_ID = "risk-1"
ATTACK_PATTERN_ID = "AML.T0001"
TAXONOMY_CANDIDATE_ID = "cand:v2:" + "a" * 32
ICA_SLOT_ID = "RESP-1:CA-1-1:WRONG_TIMING"
ICA_ID = ICA_SLOT_ID + ":1"
EXEC_ID = "EXEC:RESP-1:CA-1-1:WRONG_TIMING"


def _compatibility_fixture_module() -> Any:
    """Load the existing deterministic workflow fixture without project imports."""
    path = Path(__file__).with_name("obligation_planner_compatibility.py")
    spec = importlib.util.spec_from_file_location(
        "asago_external_obligation_planner_compatibility", path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load compatibility fixture: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def command() -> list[str]:
    """Locate the project CLI without importing project modules."""
    search_path = f"/opt/homebrew/bin:/usr/local/bin:{os.environ.get('PATH', '')}"
    uv = shutil.which("uv", path=search_path)
    if uv:
        return [uv, "run", "asago-scenario-generator"]
    executable = REPO_ROOT / ".venv/bin/asago-scenario-generator"
    if executable.is_file():
        return [str(executable)]
    raise RuntimeError("neither uv nor .venv/bin/asago-scenario-generator is available")


def source_payload() -> dict[str, Any]:
    """Return an independently authored typed source-artifact payload."""
    map_payload = yaml.safe_load(MAP.read_text(encoding="utf-8"))
    pins = {
        "resource_map_semantic_digest": map_payload["semantic_digest"],
        "capability_snapshot_digest": map_payload["capability_snapshot_digest"],
        "obligation_plan_semantic_digest": "2" * 64,
        "control_structure_digest": map_payload["control_structure_digest"],
        "ica_enumeration_digest": "3" * 64,
        "loss_analysis_digest": "4" * 64,
        "taxonomy_version": "atlas-v1",
        "stpa_version": "stpa-v1",
    }
    resource_ref = map_payload["links"][0]["capability_resource_ref"]
    return {
        "authority": {
            "source_pins": pins,
            "obligations": [
                {
                    "obligation_id": OBLIGATION_ID,
                    "risk_id": RISK_ID,
                    "attack_pattern_id": ATTACK_PATTERN_ID,
                    "taxonomy_candidate_ids": [TAXONOMY_CANDIDATE_ID],
                    "candidate_resource_refs": [resource_ref],
                }
            ],
            "structural_findings": [
                {
                    "ica_slot_id": ICA_SLOT_ID,
                    "ica_id": ICA_ID,
                    "exec_candidate_id": EXEC_ID,
                    "hazard_ids": ["H-1"],
                    "constraint_ids": ["SC-1"],
                    "resource_link_ids": ["srm:v1:klarna-payment-action"],
                }
            ],
            "hazard_ids": ["H-1"],
            "constraint_ids": ["SC-1"],
            "inventory_complete": True,
        },
        "evidence": [
            {
                "obligation_id": OBLIGATION_ID,
                "risk_id": RISK_ID,
                "attack_pattern_id": ATTACK_PATTERN_ID,
                "taxonomy_candidate_ids": [TAXONOMY_CANDIDATE_ID],
                "ica_slot_id": ICA_SLOT_ID,
                "ica_id": ICA_ID,
                "exec_candidate_id": EXEC_ID,
                "relation_kind": "same_mechanism",
                "resource_link_ids": ["srm:v1:klarna-payment-action"],
                "hazard_ids": ["H-1"],
                "constraint_ids": ["SC-1"],
                "evidence_source": "exact_id",
                "evidence_refs": ["id:obligation", "id:ica"],
                "confidence": 1.0,
                "evidence_strength": "high",
                "proposer_id": "exact-id-v1",
                "proposer_version": "1",
                "source_pins": pins,
                "rationale": "exact reviewed identities",
            }
        ],
    }


def run_cli(
    args: list[str], *, cwd: Path = REPO_ROOT
) -> subprocess.CompletedProcess[str]:
    """Run one CLI command with model QA explicitly disabled."""
    env = os.environ.copy()
    env.pop(QA_ENV, None)
    env.pop("ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL", None)
    return subprocess.run(
        [*command(), *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


def produce_proposals(workspace: Path) -> tuple[Path, dict[str, Any]]:
    """Publish one proposal artifact and return its parsed payload."""
    workspace.mkdir(parents=True, exist_ok=True)
    map_path = workspace / "system-resource-map.yaml"
    source_path = workspace / "source-artifacts.yaml"
    snapshot_path = workspace / "capability-fact-snapshot.yaml"
    control_path = workspace / "control-structure.yaml"
    map_path.write_text(MAP.read_text(encoding="utf-8"), encoding="utf-8")
    snapshot_path.write_text(SNAPSHOT.read_text(encoding="utf-8"), encoding="utf-8")
    control_path.write_text(CONTROL.read_text(encoding="utf-8"), encoding="utf-8")
    source_path.write_text(
        yaml.safe_dump(source_payload(), sort_keys=False), encoding="utf-8"
    )
    output = workspace / "proposals"
    result = run_cli(
        [
            "propose-correspondence",
            "--map",
            str(map_path),
            "--artifacts",
            str(source_path),
            "--capability-snapshot",
            str(snapshot_path),
            "--control-structure",
            str(control_path),
            "--output-dir",
            str(output),
            "--format",
            "yaml",
        ]
    )
    if result.returncode != 0:
        raise AssertionError(result.stderr or result.stdout)
    artifact = output / "correspondence-proposals.yaml"
    if not artifact.is_file():
        raise AssertionError("correspondence proposal artifact was not published")
    payload = yaml.safe_load(artifact.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise AssertionError("proposal artifact is not a mapping")
    return artifact, payload


def publish_reconciliation(
    workspace: Path, proposal_payload: dict[str, Any], *, adjudicate: bool
) -> tuple[Path, dict[str, Any]]:
    """Publish and parse one reconciliation artifact."""
    map_path = workspace / "system-resource-map.yaml"
    proposals_path = workspace / "input-proposals.yaml"
    snapshot_path = workspace / "capability-fact-snapshot.yaml"
    control_path = workspace / "control-structure.yaml"
    if not snapshot_path.is_file():
        snapshot_path.write_text(SNAPSHOT.read_text(encoding="utf-8"), encoding="utf-8")
    if not control_path.is_file():
        control_path.write_text(CONTROL.read_text(encoding="utf-8"), encoding="utf-8")
    proposals_path.write_text(
        yaml.safe_dump(proposal_payload, sort_keys=False), encoding="utf-8"
    )
    output = workspace / ("reconciled-confirmed" if adjudicate else "reconciled-open")
    args = [
        "reconcile-correspondence",
        "--map",
        str(map_path),
        "--proposals",
        str(proposals_path),
        "--capability-snapshot",
        str(snapshot_path),
        "--control-structure",
        str(control_path),
        "--output-dir",
        str(output),
        "--format",
        "yaml",
    ]
    if adjudicate:
        proposal_id = proposal_payload["proposals"][0]["proposal_id"]
        adjudications = workspace / "adjudications.yaml"
        adjudications.write_text(
            yaml.safe_dump(
                {
                    "decisions": [
                        {
                            "proposal_id": proposal_id,
                            "status": "confirmed",
                            "reason": "reviewed exact evidence",
                            "adjudicated_by": "operator-1",
                        }
                    ]
                },
                sort_keys=False,
            ),
            encoding="utf-8",
        )
        args.extend(["--adjudications", str(adjudications)])
    result = run_cli(args)
    if adjudicate and result.returncode != 0:
        raise AssertionError(result.stderr or result.stdout)
    if not adjudicate and result.returncode != 0:
        raise AssertionError(result.stderr or result.stdout)
    artifact = output / "correspondence-reconciliation.yaml"
    if not artifact.is_file():
        raise AssertionError("correspondence reconciliation artifact was not published")
    payload = yaml.safe_load(artifact.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise AssertionError("reconciliation artifact is not a mapping")
    return artifact, payload


def _publish_phase2_sidecars(workspace: Path) -> Path:
    """Place valid Phase 2 sidecars beside, but not inside, workflow output."""
    phase2 = workspace / "phase2-inputs"
    phase2.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(MAP, phase2 / "system-resource-map.yaml")
    proposal_artifact, proposal_payload = produce_proposals(phase2 / "correspondence")
    reconciliation_artifact, _ = publish_reconciliation(
        phase2 / "correspondence", proposal_payload, adjudicate=True
    )
    shutil.copyfile(proposal_artifact, phase2 / proposal_artifact.name)
    shutil.copyfile(reconciliation_artifact, phase2 / reconciliation_artifact.name)
    assessment = REPO_ROOT / "tests/fixtures/hybrid-coverage-assessment.yaml"
    if assessment.is_file():
        shutil.copyfile(assessment, phase2 / assessment.name)
    return phase2


def _normalized_files(root: Path) -> dict[str, bytes]:
    """Capture output bytes while normalizing only documented run-local fields."""
    result: dict[str, bytes] = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        # Run-local IDs also occur in artifact directory and file names. Keep
        # those names comparable while preserving every stable path segment.
        relative = re.sub(
            r"\b\d{8}T\d{6}_[0-9a-f]{32}\b",
            "<volatile-run-directory>",
            relative,
        )
        relative = re.sub(
            r"\bscenario:v[0-9]+:[0-9a-f]{64}\b",
            "scenario:v<volatile-scenario-id>",
            relative,
        )
        relative = re.sub(
            r"\bcandidate:v[0-9]+:[0-9a-f]{64}\b",
            "candidate:v<volatile-candidate-id>",
            relative,
        )
        if path.suffix not in {".yaml", ".yml", ".json", ".feature"}:
            result[relative] = path.read_bytes()
            continue
        text = path.read_text(encoding="utf-8")
        for pattern, replacement in (
            (r"(?m)^(run_id:\s*).*$", r"\1<volatile-run-id>"),
            (r"(?m)^(scenario_id:\s*).*$", r"\1<volatile-scenario-id>"),
            (r"(?m)^(candidate_id:\s*).*$", r"\1<volatile-candidate-id>"),
            (r"(?m)^(generated_at:\s*).*$", r"\1<volatile-timestamp>"),
            (r"(?m)^(started_at:\s*).*$", r"\1<volatile-timestamp>"),
            (r"(?m)^(completed_at:\s*).*$", r"\1<volatile-timestamp>"),
            (r"(?m)^(\s*duration_ms:\s*).*$", r"\1<volatile-duration>"),
            (r"(?m)^(\s*elapsed_ms:\s*).*$", r"\1<volatile-duration>"),
        ):
            text = re.sub(pattern, replacement, text)
        result[relative] = text.encode("utf-8")
    return result


def _scenario_artifacts(root: Path) -> dict[str, bytes]:
    """Capture published scenario files with only run-local IDs normalized."""
    scenarios = root / "scenarios"
    if not scenarios.is_dir():
        return {}
    return _normalized_files(scenarios)


def _artifact_roles(root: Path) -> tuple[str, ...]:
    """Return the stable non-scenario artifact-role inventory."""
    return tuple(
        sorted(
            path.name
            for path in root.iterdir()
            if path.is_file() and not path.name.startswith("scenario:")
        )
    )


def _summary(stdout: str, labels: tuple[str, ...]) -> dict[str, str | None]:
    """Extract stable public summary values from a CLI invocation."""
    return {
        label: (
            match.group(1)
            if (match := re.search(rf"^\s*{re.escape(label)}:\s+(\S+)", stdout, re.M))
            else None
        )
        for label in labels
    }


def _run_child(
    fixtures: Any,
    argv: list[str],
    *,
    case: str,
    timeout: int,
) -> subprocess.CompletedProcess[str]:
    """Run a public CLI child with live-model configuration removed."""
    environment = os.environ.copy()
    environment.pop(QA_ENV, None)
    environment.pop("ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL", None)
    environment.pop("OPENAI_BASE_URL", None)
    environment.pop("OPENAI_API_KEY", None)
    environment.pop("ASAGO_SCENARIO_GENERATOR_API_KEY", None)
    environment["PYTHONHASHSEED"] = "0"
    return fixtures._run_cli(case, argv, env=environment, timeout=timeout)


def _taxonomy_with_sidecars(fixtures: Any, root: Path, server: Any) -> dict[str, Any]:
    """Compare two real ``generate`` subprocesses with identical sidecars."""
    labels = (
        "Candidates admitted",
        "Candidates quarantined",
        "Candidates failed",
        "Scenarios generated",
        "Governance-only",
    )
    captures: list[dict[str, Any]] = []
    for label, with_sidecars in (("before", False), ("after", True)):
        workspace = root / label
        workspace.mkdir(parents=True)
        fixtures._write_generate_inputs(workspace)
        if with_sidecars:
            _publish_phase2_sidecars(workspace)
        fixtures.FixtureHandler.reset()
        command = fixtures._generate_argv(workspace, server)
        completed = _run_child(
            fixtures, command, case=f"phase2-compat-generate-{label}", timeout=600
        )
        run_dir = fixtures._run_dir(workspace)
        requests = list(fixtures.FixtureHandler.requests)
        captures.append(
            {
                "completed": completed,
                "command": command,
                "run_dir": run_dir,
                "files": _scenario_artifacts(run_dir) if run_dir else {},
                "artifact_roles": _artifact_roles(run_dir) if run_dir else (),
                "output_files": _normalized_files(run_dir) if run_dir else {},
                "summary": _summary(completed.stdout, labels),
                "prompts": fixtures._prompt_evidence(requests),
                "requests": requests,
                "sidecar_files": sorted(
                    path.name for path in (workspace / "phase2-inputs").glob("*")
                )
                if with_sidecars
                else [],
            }
        )
    before, after = captures
    phase2_output = any(
        any(
            marker in name.lower()
            for marker in ("system-resource-map", "correspondence", "hybrid-coverage")
        )
        for name in after["output_files"]
    )
    return {
        "workflow": "taxonomy/risk",
        "command": "generate",
        "exit_match": before["completed"].returncode
        == after["completed"].returncode
        == 0,
        "artifacts_match": (
            bool(before["files"])
            and before["files"] == after["files"]
            and before["artifact_roles"] == after["artifact_roles"]
        ),
        "counts_match": before["summary"] == after["summary"]
        and all(value is not None for value in after["summary"].values()),
        "prompts_match": bool(before["requests"])
        and before["prompts"] == after["prompts"],
        "sidecars_present": bool(after["sidecar_files"]),
        "no_phase2_output": not phase2_output,
        "detail": (
            f"before_exit={before['completed'].returncode}, "
            f"after_exit={after['completed'].returncode}, "
            f"scenario_files={len(after['files'])}, "
            f"prompt_requests={len(after['requests'])}"
        ),
    }


def _stpa_with_sidecars(fixtures: Any, root: Path) -> dict[str, Any]:
    """Compare two real resume-mode ``stpa-run`` subprocesses with sidecars."""
    labels = (
        "Losses",
        "Hazards",
        "Constraints",
        "Responsibilities",
        "Control Actions",
        "Total slots",
        "N/A slots",
        "Structural threats",
        "Mapped",
        "Unmapped",
    )
    captures: list[dict[str, Any]] = []
    for label, with_sidecars in (("before", False), ("after", True)):
        workspace = root / label
        workspace.mkdir(parents=True)
        fixtures._write_stpa_fixture(workspace)
        if with_sidecars:
            _publish_phase2_sidecars(workspace)
        output_dir = workspace / "output"
        before_files = _normalized_files(output_dir)
        command = [
            *fixtures._command(),
            "stpa-run",
            "--use-case",
            str(workspace / "use-case.txt"),
            "--risk-extraction",
            str(workspace / "risk-extraction.json"),
            "--output-dir",
            str(output_dir),
            "--resume",
        ]
        completed = _run_child(
            fixtures, command, case=f"phase2-compat-stpa-{label}", timeout=180
        )
        captures.append(
            {
                "completed": completed,
                "command": command,
                "before": before_files,
                "after": _normalized_files(output_dir),
                "summary": _summary(completed.stdout, labels),
                "has_prompt_log": (output_dir / "calls.jsonl").is_file(),
                "sidecar_files": sorted(
                    path.name for path in (workspace / "phase2-inputs").glob("*")
                )
                if with_sidecars
                else [],
            }
        )
    before, after = captures
    phase2_output = any(
        any(
            marker in name.lower()
            for marker in ("system-resource-map", "correspondence", "hybrid-coverage")
        )
        for name in after["after"]
    )
    return {
        "workflow": "STPA",
        "command": "stpa-run",
        "exit_match": before["completed"].returncode
        == after["completed"].returncode
        == 0,
        "artifacts_match": before["after"] == after["after"],
        "counts_match": before["summary"] == after["summary"]
        and all(value is not None for value in after["summary"].values()),
        "prompts_match": not before["has_prompt_log"] and not after["has_prompt_log"],
        "sidecars_present": bool(after["sidecar_files"]),
        "no_phase2_output": not phase2_output,
        "detail": (
            f"before_exit={before['completed'].returncode}, "
            f"after_exit={after['completed'].returncode}, "
            f"output_files={len(after['after'])}"
        ),
    }


def run_workflow_compatibility(workflow: str) -> dict[str, Any]:
    """Run a full before/after Phase 2 compatibility comparison."""
    if workflow not in {"taxonomy/risk", "STPA"}:
        raise ValueError(f"unknown compatibility workflow: {workflow}")
    fixtures = _compatibility_fixture_module()
    root = Path(tempfile.mkdtemp(prefix="asago-phase2-compat-"))
    if workflow == "taxonomy/risk":
        server = fixtures.ThreadingHTTPServer(("127.0.0.1", 0), fixtures.FixtureHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        previous = os.environ.get("ACCEPT_PATTERN")
        os.environ["ACCEPT_PATTERN"] = fixtures.ACCEPT_AP_T6_04
        try:
            return _taxonomy_with_sidecars(fixtures, root, server)
        finally:
            if previous is None:
                os.environ.pop("ACCEPT_PATTERN", None)
            else:
                os.environ["ACCEPT_PATTERN"] = previous
            server.shutdown()
            server.server_close()
    return _stpa_with_sidecars(fixtures, root)
