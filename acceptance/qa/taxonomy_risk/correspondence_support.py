"""External QA helpers for the typed correspondence CLI.

This module intentionally imports only standard-library and YAML readers. It
constructs the wire payloads independently of the application models and
checks the published artifacts through the public command surface.
"""

from __future__ import annotations

import os
import shutil
import subprocess
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
