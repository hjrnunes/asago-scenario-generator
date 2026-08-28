#!/usr/bin/env python3
"""Executable end-to-end QA suite for correspondence artifacts.

Mirrors ``correspondence_artifact.md`` (QA-CA-01..06).  Drives the public
``propose-correspondence`` and ``reconcile-correspondence`` file-to-file
commands and inspects published YAML and JSON with standard readers and
byte comparison.  Never imports project modules, never calls
``propose_correspondence`` or ``reconcile_correspondence``, and never
sets ``ASAGO_SCENARIO_GENERATOR_QA_PIPELINE``.

Run with::

    uv run python acceptance/qa/taxonomy_risk/correspondence_artifact.py

Exit status is 0 only when every pinned assertion passes.
"""

from __future__ import annotations

import json
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

_SEARCH_PATH = f"/opt/homebrew/bin:/usr/local/bin:{os.environ.get('PATH', '')}"
_UV = shutil.which("uv", path=_SEARCH_PATH) or "uv"

EP = "ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
TB = "tb:v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
AP = "AP-T6-01"
PINNED = {"stpa_version": "stpa-v1", "taxonomy_version": "atlas-2026.05"}


def _command() -> list[str]:
    if shutil.which("uv", path=_SEARCH_PATH):
        return [_UV, "run", "asago-scenario-generator"]
    executable = REPO_ROOT / ".venv" / "bin" / "asago-scenario-generator"
    if executable.is_file():
        return [str(executable)]
    raise RuntimeError("neither uv nor .venv/bin/asago-scenario-generator is available")


def _resource_map() -> dict:
    return {
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
        "controlled_processes": [{"element_id": "CP-2", "name": "Payment Pipeline"}],
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
            }
        ],
    }


def _proposal(
    proposal_id: str,
    *,
    left_ref: str = "CA-1-1",
    right_ref: str = EP,
    relation_type: str = "supports",
    evidence_source: str = "exact-id",
    strength: str = "high",
    evidence_refs: list[str] | None = None,
    proposer_id: str = "",
    adjudication: str | None = None,
    **extra: object,
) -> dict:
    payload: dict[str, object] = {
        "proposal_id": proposal_id,
        "left_ref": left_ref,
        "right_ref": right_ref,
        "relation_type": relation_type,
        "evidence_source": evidence_source,
        "strength": strength,
        "evidence_refs": evidence_refs if evidence_refs is not None else [left_ref],
        "proposer_id": proposer_id,
        "stpa_version": "stpa-v1",
        "taxonomy_version": "atlas-2026.05",
    }
    if adjudication is not None:
        payload["adjudication"] = adjudication
        payload["adjudication_history"] = [{"adjudication": adjudication}]
    payload.update(extra)
    return payload


def _varied_proposals() -> list[dict]:
    return [
        _proposal("P-1", relation_type="supports", proposer_id="exact-id-adapter"),
        _proposal(
            "P-2",
            left_ref="L-1",
            right_ref=AP,
            relation_type="addresses",
            evidence_source="curated-map",
            evidence_refs=["L-1"],
            proposer_id="curated-map-adapter",
        ),
        _proposal(
            "P-3",
            right_ref=TB,
            relation_type="overlaps",
            evidence_source="resource-overlap",
            strength="weak",
            proposer_id="overlap-adapter",
        ),
    ]


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
    return completed


def _check(case: str, condition: bool, message: str) -> None:
    if not condition:
        failures.append(f"{case}: {message}")


def _load(raw: bytes, fmt: str) -> dict:
    parsed = json.loads(raw) if fmt == "json" else yaml.safe_load(raw)
    return parsed if isinstance(parsed, dict) else {}


def _propose(case: str, evidence: list[dict], *, fmt: str) -> tuple[Path, bytes, dict]:
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
    completed = _run_cli(
        case,
        [
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
        ],
    )
    if completed.returncode != 0:
        failures.append(
            f"{case}: propose exit {completed.returncode}: {completed.stderr[-300:]!r}"
        )
    name = "proposal-set.json" if fmt == "json" else "proposal-set.yaml"
    artifact = output_dir / name
    if not artifact.is_file():
        failures.append(f"{case}: missing {name}")
        return artifact, b"", {}
    raw = artifact.read_bytes()
    return artifact, raw, _load(raw, fmt)


def _reconcile(
    case: str,
    proposals: list[dict],
    adjudications: dict[str, str] | None = None,
    *,
    fmt: str,
) -> tuple[Path, bytes, dict]:
    ws = _new_workspace(case)
    map_path = ws / "resource-map.yaml"
    proposals_path = ws / "proposals.yaml"
    map_path.write_text(
        yaml.safe_dump(_resource_map(), sort_keys=False), encoding="utf-8"
    )
    proposals_path.write_text(
        yaml.safe_dump(
            {
                "schema_version": "1",
                "stpa_version": "stpa-v1",
                "taxonomy_version": "atlas-2026.05",
                "proposals": proposals,
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    output_dir = ws / "out"
    argv = [
        *_command(),
        "reconcile-correspondence",
        "--map",
        str(map_path),
        "--proposals",
        str(proposals_path),
        "--output-dir",
        str(output_dir),
        "--format",
        fmt,
    ]
    if adjudications is not None:
        adj_path = ws / "adjudications.yaml"
        adj_path.write_text(
            yaml.safe_dump(adjudications, sort_keys=False), encoding="utf-8"
        )
        argv.extend(["--adjudications", str(adj_path)])
    completed = _run_cli(case, argv)
    if completed.returncode != 0:
        failures.append(
            f"{case}: reconcile exit {completed.returncode}: {completed.stderr[-300:]!r}"
        )
    name = (
        "reconciliation-result.json" if fmt == "json" else "reconciliation-result.yaml"
    )
    artifact = output_dir / name
    if not artifact.is_file():
        failures.append(f"{case}: missing {name}")
        return artifact, b"", {}
    raw = artifact.read_bytes()
    return artifact, raw, _load(raw, fmt)


def _ids(payload: dict) -> list[str]:
    return [
        str(row.get("proposal_id"))
        for row in payload.get("proposals") or []
        if isinstance(row, dict)
    ]


def _by_id(payload: dict, proposal_id: str) -> dict | None:
    for row in payload.get("proposals") or []:
        if isinstance(row, dict) and row.get("proposal_id") == proposal_id:
            return row
    return None


def qa_ca_01() -> None:
    """QA-CA-01: pinned source versions are copied into proposals."""
    case = "CA-01"
    _artifact, _raw, payload = _propose(
        case,
        [
            {
                "proposal_id": "P-1",
                "evidence_source": "exact-id",
                "left_ref": "CA-1-1",
                "right_ref": EP,
            }
        ],
        fmt="yaml",
    )
    rows = payload.get("proposals") or []
    _check(
        case,
        any(row.get("proposal_id") == "P-1" for row in rows if isinstance(row, dict)),
        "P-1 missing",
    )
    for row in rows:
        if not isinstance(row, dict):
            continue
        _check(
            case,
            row.get("stpa_version") == PINNED["stpa_version"],
            f"{row.get('proposal_id')} stpa {row.get('stpa_version')!r}",
        )
        _check(
            case,
            row.get("taxonomy_version") == PINNED["taxonomy_version"],
            f"{row.get('proposal_id')} taxonomy {row.get('taxonomy_version')!r}",
        )


def qa_ca_02() -> None:
    """QA-CA-02: YAML and JSON round-trip without semantic loss."""
    proposals = _varied_proposals()
    adjudications = {"P-1": "confirmed", "P-2": "rejected", "P-3": "unresolved"}
    for fmt in ("yaml", "json"):
        case = f"CA-02-{fmt}"
        _path, raw, original = _reconcile(case, proposals, adjudications, fmt=fmt)
        round_tripped = _load(raw, fmt)
        _check(
            case,
            _ids(original) == _ids(round_tripped),
            f"identities lost: {_ids(original)}",
        )
        for proposal_id in ("P-1", "P-2", "P-3"):
            orig = _by_id(original, proposal_id)
            rt = _by_id(round_tripped, proposal_id)
            _check(
                case,
                orig is not None and rt is not None,
                f"{proposal_id} missing after round-trip",
            )
            if orig is None or rt is None:
                continue
            _check(
                case,
                orig.get("relation_type") == rt.get("relation_type"),
                f"{proposal_id} relation type lost",
            )
            _check(
                case,
                orig.get("evidence_source") == rt.get("evidence_source"),
                f"{proposal_id} evidence provenance lost",
            )
            _check(
                case,
                orig.get("adjudication_history") == rt.get("adjudication_history"),
                f"{proposal_id} adjudication history lost",
            )
            _check(
                case,
                orig.get("proposer_id") == rt.get("proposer_id"),
                f"{proposal_id} proposer lost",
            )


def qa_ca_03() -> None:
    """QA-CA-03: identical inputs are byte-stable."""
    proposals = _varied_proposals()
    adjudications = {"P-1": "confirmed", "P-2": "rejected", "P-3": "unresolved"}
    for fmt in ("yaml", "json"):
        _p1, raw1, _plan1 = _reconcile(
            f"CA-03-{fmt}-1", proposals, adjudications, fmt=fmt
        )
        _p2, raw2, _plan2 = _reconcile(
            f"CA-03-{fmt}-2", proposals, adjudications, fmt=fmt
        )
        _check(f"CA-03-{fmt}", raw1 == raw2, f"{fmt} artifacts are not byte-identical")


def qa_ca_04() -> None:
    """QA-CA-04: identifiers and order ignore presentation order."""
    by_id = {row["proposal_id"]: row for row in _varied_proposals()}
    order_a = ["P-1", "P-2", "P-3"]
    order_b = ["P-3", "P-2", "P-1"]
    adjudications = {"P-1": "confirmed", "P-2": "rejected", "P-3": "unresolved"}
    _a_path, a_raw, plan_a = _reconcile(
        "CA-04-a", [by_id[pid] for pid in order_a], adjudications, fmt="yaml"
    )
    _b_path, b_raw, plan_b = _reconcile(
        "CA-04-b", [by_id[pid] for pid in order_b], adjudications, fmt="yaml"
    )
    ids_a = _ids(plan_a)
    ids_b = _ids(plan_b)
    _check("CA-04", ids_a == ids_b, f"identities differ: {ids_a} vs {ids_b}")
    _check(
        "CA-04",
        ids_a == sorted(ids_a),
        f"canonical order is not identity order: {ids_a}",
    )
    _check(
        "CA-04",
        a_raw == b_raw,
        "serialized YAML artifacts are not canonically equivalent",
    )


def qa_ca_05() -> None:
    """QA-CA-05: a new proposer can be added without changing reconciliation rules."""
    case = "CA-05"
    proposals = [
        _proposal(
            "P-1",
            relation_type="supports",
            proposer_id="exact-id-adapter",
            adjudication="confirmed",
        ),
        _proposal(
            "P-2",
            left_ref="L-1",
            right_ref=AP,
            relation_type="addresses",
            evidence_source="curated-map",
            evidence_refs=["L-1"],
            proposer_id="curated-map-adapter",
            adjudication="rejected",
        ),
        _proposal(
            "P-3",
            right_ref=TB,
            relation_type="overlaps",
            evidence_source="resource-overlap",
            strength="weak",
            proposer_id="overlap-adapter",
        ),
    ]
    _artifact, _raw, payload = _reconcile(
        case, proposals, {"P-1": "confirmed", "P-2": "rejected"}, fmt="yaml"
    )
    p1 = _by_id(payload, "P-1")
    p2 = _by_id(payload, "P-2")
    p3 = _by_id(payload, "P-3")
    _check(case, p3 is not None, "P-3 missing")
    if p3 is not None:
        _check(
            case,
            p3.get("adjudication") == "unresolved",
            f"P-3 adj {p3.get('adjudication')!r}",
        )
        _check(
            case,
            p3.get("proposer_id") == "overlap-adapter",
            f"P-3 proposer {p3.get('proposer_id')!r}",
        )
        _check(
            case,
            p3.get("adjudication") != "confirmed",
            "new proposer wrote a confirmed relation",
        )
    if p1 is not None:
        _check(
            case,
            p1.get("adjudication") == "confirmed",
            f"P-1 adj changed to {p1.get('adjudication')!r}",
        )
    if p2 is not None:
        _check(
            case,
            p2.get("adjudication") == "rejected",
            f"P-2 adj changed to {p2.get('adjudication')!r}",
        )


def qa_ca_06() -> None:
    """QA-CA-06: coverage scores and blended method metrics are omitted."""
    proposals = _varied_proposals()
    adjudications = {"P-1": "confirmed", "P-2": "rejected", "P-3": "unresolved"}
    for fmt in ("yaml", "json"):
        case = f"CA-06-{fmt}"
        _path, raw, _payload = _reconcile(case, proposals, adjudications, fmt=fmt)
        text = raw.decode("utf-8").lower()
        _check(case, "coverage" not in text, "artifact contains a coverage score")
        _check(case, "blended" not in text, "artifact contains a blended method metric")


def main() -> int:
    if os.environ.get(QA_PIPELINE_ENV):
        print(f"Refusing to run: {QA_PIPELINE_ENV} must not be set.", file=sys.stderr)
        return 2
    print(f"QA evidence: {RUN_ROOT.relative_to(REPO_ROOT)}", flush=True)
    for procedure in (qa_ca_01, qa_ca_02, qa_ca_03, qa_ca_04, qa_ca_05, qa_ca_06):
        procedure()
        print(f"  [done] {procedure.__name__}", flush=True)
    print("\n=== SUMMARY ===", flush=True)
    print(f"  Failures: {len(failures)}", flush=True)
    for failure in failures:
        print(f"    - {failure}", flush=True)
    print("  Result: FAIL" if failures else "  Result: PASS", flush=True)
    return 1 if failures else 0


RUN_ROOT = (
    REPO_ROOT
    / "tmp"
    / "qa-taxonomy-correspondence-artifact"
    / datetime.now(UTC).strftime("%Y%m%dT%H%M%S.%fZ")
)


if __name__ == "__main__":
    sys.exit(main())
