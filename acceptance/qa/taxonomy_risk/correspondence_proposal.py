#!/usr/bin/env python3
"""Executable end-to-end QA suite for correspondence proposal.

Mirrors ``correspondence_proposal.md`` (QA-CP-01..05).  Drives the public
``asago-scenario-generator propose-correspondence`` file-to-file command: a
resource map and source-artifact fixtures in, a published YAML or JSON
proposal-set artifact out.  Inspects the artifact with standard JSON/YAML
readers, the console, and the filesystem.  Never imports project modules,
never calls ``propose_correspondence``, and never sets
``ASAGO_SCENARIO_GENERATOR_QA_PIPELINE``.

Run with::

    uv run python acceptance/qa/taxonomy_risk/correspondence_proposal.py

Exit status is 0 only when every pinned assertion passes.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]
QA_PIPELINE_ENV = "ASAGO_SCENARIO_GENERATOR_QA_PIPELINE"
failures: list[str] = []
notes: list[str] = []

_SEARCH_PATH = f"/opt/homebrew/bin:/usr/local/bin:{os.environ.get('PATH', '')}"
_UV = shutil.which("uv", path=_SEARCH_PATH) or "uv"

EP = "ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
TB = "tb:v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
AP = "AP-T6-01"


def _command() -> list[str]:
    if shutil.which("uv", path=_SEARCH_PATH):
        return [_UV, "run", "asago-scenario-generator"]
    executable = REPO_ROOT / ".venv" / "bin" / "asago-scenario-generator"
    if executable.is_file():
        return [str(executable)]
    raise RuntimeError("neither uv nor .venv/bin/asago-scenario-generator is available")


def _resource_map(**overrides: object) -> dict:
    payload: dict[str, object] = {
        "schema_version": "1",
        "stpa_version": "stpa-v1",
        "taxonomy_version": "atlas-2026.05",
        "system_resources": [
            {"element_id": "SR-1", "name": "Primary Database", "taxonomy_ref": EP},
            {
                "element_id": "SR-2",
                "name": "Attack Pattern Reference",
                "taxonomy_ref": AP,
            },
        ],
        "controlled_processes": [
            {"element_id": "CP-2", "name": "Payment Pipeline"},
        ],
        "control_actions": [
            {
                "element_id": "CA-1-1",
                "controller_id": "RESP-1",
                "process_id": "CP-2",
                "action_name": "Issue Payment",
            }
        ],
        "loss_links": [{"element_id": "LL-1", "loss_id": "L-1", "hazard_id": "H-1"}],
        "trust_boundaries": [
            {
                "element_id": "TB-1",
                "name": "DMZ Boundary",
                "resource_ids": ["SR-1"],
                "taxonomy_ref": TB,
            },
        ],
    }
    payload.update(overrides)
    return payload


def _item(
    proposal_id: str,
    evidence_source: str,
    left_ref: str,
    right_ref: str,
    **extra: object,
) -> dict:
    payload: dict[str, object] = {
        "proposal_id": proposal_id,
        "evidence_source": evidence_source,
        "left_ref": left_ref,
        "right_ref": right_ref,
    }
    payload.update(extra)
    return payload


def _new_workspace(case: str) -> Path:
    ws = RUN_ROOT / "workspaces" / case
    if ws.exists():
        shutil.rmtree(ws)
    ws.mkdir(parents=True)
    return ws


def _run_cli(case: str, argv: list[str]) -> subprocess.CompletedProcess[str]:
    capture_dir = RUN_ROOT / "captures" / case
    capture_dir.mkdir(parents=True, exist_ok=True)
    child = os.environ.copy()
    child.pop(QA_PIPELINE_ENV, None)
    child.pop("ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL", None)
    completed = subprocess.run(
        argv,
        cwd=REPO_ROOT,
        env=child,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    (capture_dir / "command.txt").write_text(" ".join(argv) + "\n", encoding="utf-8")
    (capture_dir / "stdout.txt").write_text(completed.stdout, encoding="utf-8")
    (capture_dir / "stderr.txt").write_text(completed.stderr, encoding="utf-8")
    (capture_dir / "exit.txt").write_text(f"{completed.returncode}\n", encoding="utf-8")
    (capture_dir / "env-qa-pipeline.txt").write_text(
        f"{QA_PIPELINE_ENV}={'set' if QA_PIPELINE_ENV in child else 'unset'}\n",
        encoding="utf-8",
    )
    return completed


def _check(case: str, condition: bool, message: str) -> None:
    if not condition:
        failures.append(f"{case}: {message}")


def _proposal(payload: dict, proposal_id: str) -> dict | None:
    for row in payload.get("proposals") or []:
        if isinstance(row, dict) and row.get("proposal_id") == proposal_id:
            return row
    return None


def _produce(
    case: str, evidence: list[dict], *, fmt: str = "yaml"
) -> tuple[Path, dict, subprocess.CompletedProcess[str]]:
    ws = _new_workspace(case)
    map_path = ws / "resource-map.yaml"
    artifacts_path = ws / "artifacts.yaml"
    map_path.write_text(
        yaml.safe_dump(_resource_map(), sort_keys=False), encoding="utf-8"
    )
    artifacts_path.write_text(
        yaml.safe_dump({"evidence": evidence}, sort_keys=False), encoding="utf-8"
    )
    output_dir = ws / "out"
    argv = [
        *_command(),
        "propose-correspondence",
        "--map",
        str(map_path),
        "--artifacts",
        str(artifacts_path),
        "--output-dir",
        str(output_dir),
        "--format",
        fmt,
    ]
    completed = _run_cli(case, argv)
    _check(
        case,
        completed.returncode == 0,
        f"exit {completed.returncode}: {completed.stderr[-300:]!r}",
    )
    artifact = output_dir / (
        "proposal-set.json" if fmt == "json" else "proposal-set.yaml"
    )
    _check(case, artifact.is_file(), f"missing published artifact {artifact.name}")
    parsed = (
        yaml.safe_load(artifact.read_text(encoding="utf-8"))
        if artifact.is_file()
        else {}
    )
    if not isinstance(parsed, dict):
        parsed = {}
        _check(case, False, f"{artifact.name} is not a mapping")
    return artifact, parsed, completed


def _not_confirmed(case: str, row: dict | None, proposal_id: str) -> None:
    _check(case, row is not None, f"missing proposal {proposal_id}")
    if row is None:
        return
    _check(
        case,
        row.get("is_confirmed") is False,
        f"{proposal_id} is_confirmed={row.get('is_confirmed')!r}",
    )


def qa_cp_01() -> None:
    """QA-CP-01: exact-id and curated-map evidence stay unconfirmed."""
    case = "CP-01"
    artifact, payload, completed = _produce(
        case,
        [
            _item("P-1", "exact-id", "CA-1-1", EP),
            _item("P-2", "curated-map", "L-1", AP),
        ],
    )
    p1 = _proposal(payload, "P-1")
    p2 = _proposal(payload, "P-2")
    _not_confirmed(case, p1, "P-1")
    _not_confirmed(case, p2, "P-2")
    if p1 is not None:
        _check(
            case,
            p1.get("evidence_source") == "exact-id",
            f"P-1 source {p1.get('evidence_source')!r}",
        )
        _check(
            case, p1.get("strength") == "high", f"P-1 strength {p1.get('strength')!r}"
        )
        _check(
            case,
            p1.get("relation_type") == "supports",
            f"P-1 type {p1.get('relation_type')!r}",
        )
        _check(case, p1.get("left_ref") == "CA-1-1", f"P-1 left {p1.get('left_ref')!r}")
        _check(case, p1.get("right_ref") == EP, f"P-1 right {p1.get('right_ref')!r}")
    if p2 is not None:
        _check(
            case,
            p2.get("evidence_source") == "curated-map",
            f"P-2 source {p2.get('evidence_source')!r}",
        )
        _check(
            case, p2.get("strength") == "high", f"P-2 strength {p2.get('strength')!r}"
        )
        _check(
            case,
            p2.get("relation_type") == "addresses",
            f"P-2 type {p2.get('relation_type')!r}",
        )
        _check(case, p2.get("left_ref") == "L-1", f"P-2 left {p2.get('left_ref')!r}")
        _check(case, p2.get("right_ref") == AP, f"P-2 right {p2.get('right_ref')!r}")
    combined = completed.stdout + completed.stderr
    _check(case, "http://" not in combined, "network endpoint mentioned")
    _check(
        case,
        "Network calls: 0" in completed.stdout,
        "console omitted network-call count",
    )
    notes.append(f"01: published {artifact.name}")


def qa_cp_02() -> None:
    """QA-CP-02: weak resource overlap is distinct from high-strength evidence."""
    case = "CP-02"
    _artifact, payload, _completed = _produce(
        case, [_item("P-3", "resource-overlap", "CP-2", TB)]
    )
    p3 = _proposal(payload, "P-3")
    _not_confirmed(case, p3, "P-3")
    if p3 is not None:
        _check(
            case,
            p3.get("evidence_source") == "resource-overlap",
            f"P-3 source {p3.get('evidence_source')!r}",
        )
        _check(
            case, p3.get("strength") == "weak", f"P-3 strength {p3.get('strength')!r}"
        )
        _check(
            case, p3.get("evidence_source") != "exact-id", "P-3 classified as exact-id"
        )
        _check(
            case,
            p3.get("evidence_source") != "curated-map",
            "P-3 classified as curated-map",
        )


def qa_cp_03() -> None:
    """QA-CP-03: typed proposal provenance is retained."""
    case = "CP-03"
    _artifact, payload, _completed = _produce(
        case,
        [
            _item(
                "P-1",
                "exact-id",
                "CA-1-1",
                EP,
                proposer_id="exact-id-adapter",
                proposer_version="1",
                evidence_refs=["CA-1-1", EP],
                stpa_version="stpa-v1",
                taxonomy_version="atlas-2026.05",
                rationale="exact identifier match",
            )
        ],
    )
    p1 = _proposal(payload, "P-1")
    _check(case, p1 is not None, "missing proposal P-1")
    if p1 is not None:
        _check(case, p1.get("left_ref") == "CA-1-1", f"left {p1.get('left_ref')!r}")
        _check(case, p1.get("right_ref") == EP, f"right {p1.get('right_ref')!r}")
        _check(
            case,
            p1.get("proposer_id") == "exact-id-adapter",
            f"proposer {p1.get('proposer_id')!r}",
        )
        _check(
            case,
            str(p1.get("proposer_version")) == "1",
            f"version {p1.get('proposer_version')!r}",
        )
        _check(
            case,
            p1.get("evidence_refs") == ["CA-1-1", EP],
            f"refs {p1.get('evidence_refs')!r}",
        )
        _check(
            case,
            p1.get("stpa_version") == "stpa-v1",
            f"stpa {p1.get('stpa_version')!r}",
        )
        _check(
            case,
            p1.get("taxonomy_version") == "atlas-2026.05",
            f"taxonomy {p1.get('taxonomy_version')!r}",
        )
        _check(
            case,
            p1.get("rationale") == "exact identifier match",
            f"rationale {p1.get('rationale')!r}",
        )


def qa_cp_04() -> None:
    """QA-CP-04: heuristic and model-assisted adapters cannot confirm."""
    for proposer_id, kind in (
        ("heuristic-adapter", "heuristic"),
        ("model-assisted-adapter", "model-assisted"),
    ):
        case = f"CP-04-{kind}"
        _artifact, payload, _completed = _produce(
            case,
            [
                _item(
                    f"P-{proposer_id}",
                    kind,
                    "CA-1-1",
                    EP,
                    proposer_id=proposer_id,
                    adapter_kind=kind,
                    strength="weak",
                    relation_type="supports",
                )
            ],
        )
        rows = [
            row
            for row in payload.get("proposals") or []
            if isinstance(row, dict) and row.get("proposer_id") == proposer_id
        ]
        _check(case, rows, f"no proposals from {proposer_id}")
        for row in rows:
            _check(
                case,
                row.get("evidence_source") == kind,
                f"{row.get('proposal_id')} source {row.get('evidence_source')!r}",
            )
            _check(
                case,
                row.get("is_confirmed") is False,
                f"{row.get('proposal_id')} confirmed by {proposer_id}",
            )


def qa_cp_05() -> None:
    """QA-CP-05: proposal records zero network and model calls."""
    case = "CP-05"
    _check(
        case,
        QA_PIPELINE_ENV not in os.environ,
        f"{QA_PIPELINE_ENV} is set in the parent environment",
    )
    artifact, payload, completed = _produce(
        case,
        [
            _item("P-1", "exact-id", "CA-1-1", EP),
            _item("P-3", "resource-overlap", "CP-2", TB),
        ],
    )
    _check(
        case,
        "Network calls: 0" in completed.stdout,
        "console omitted network-call count",
    )
    _check(
        case, "Model calls:   0" in completed.stdout, "console omitted model-call count"
    )
    combined = completed.stdout + completed.stderr
    _check(case, "openai" not in combined.lower(), "LLM client mentioned")
    raw = artifact.read_bytes() if artifact.is_file() else b""
    _check(case, b"sk-" not in raw, "artifact contains a secret-shaped token")
    p1 = _proposal(payload, "P-1")
    p3 = _proposal(payload, "P-3")
    _not_confirmed(case, p1, "P-1")
    _not_confirmed(case, p3, "P-3")


def main() -> int:
    if os.environ.get(QA_PIPELINE_ENV):
        print(f"Refusing to run: {QA_PIPELINE_ENV} must not be set.", file=sys.stderr)
        return 2
    print(f"QA evidence: {RUN_ROOT.relative_to(REPO_ROOT)}", flush=True)
    for procedure in (qa_cp_01, qa_cp_02, qa_cp_03, qa_cp_04, qa_cp_05):
        procedure()
        print(f"  [done] {procedure.__name__}", flush=True)
    print("\n=== SUMMARY ===", flush=True)
    print(f"  Failures: {len(failures)}", flush=True)
    for failure in failures:
        print(f"    - {failure}", flush=True)
    for note in notes:
        print(f"  note: {note}", flush=True)
    print("  Result: FAIL" if failures else "  Result: PASS", flush=True)
    return 1 if failures else 0


RUN_ROOT = (
    REPO_ROOT
    / "tmp"
    / "qa-taxonomy-correspondence-proposal"
    / datetime.now(UTC).strftime("%Y%m%dT%H%M%S.%fZ")
)


if __name__ == "__main__":
    sys.exit(main())
