#!/usr/bin/env python3
"""Executable end-to-end QA suite for correspondence reconciliation.

Mirrors ``correspondence_reconciliation.md`` (QA-CR-01..08).  Drives the
public ``asago-scenario-generator reconcile-correspondence`` file-to-file
command: a resource map and a ProposalSet in, a published YAML or JSON
ReconciliationResult out.  Inspects artifacts with standard JSON/YAML
readers, the console, and the filesystem.  Never imports project modules,
never calls ``reconcile_correspondence``, and never sets
``ASAGO_SCENARIO_GENERATOR_QA_PIPELINE``.

Run with::

    uv run python acceptance/qa/taxonomy_risk/correspondence_reconciliation.py

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
    payload.update(overrides)
    return payload


def _proposal(
    proposal_id: str,
    *,
    left_ref: str = "CA-1-1",
    right_ref: str = EP,
    relation_type: str = "supports",
    evidence_source: str = "exact-id",
    strength: str = "high",
    evidence_refs: list[str] | None = None,
    stpa_version: str = "stpa-v1",
    taxonomy_version: str = "atlas-2026.05",
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
        "stpa_version": stpa_version,
        "taxonomy_version": taxonomy_version,
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


def _row(payload: dict, proposal_id: str) -> dict | None:
    for item in payload.get("proposals") or []:
        if isinstance(item, dict) and item.get("proposal_id") == proposal_id:
            return item
    return None


def _reconcile(
    case: str,
    proposals: list[dict],
    adjudications: dict[str, str] | None = None,
    *,
    resource_map: dict | None = None,
    fmt: str = "yaml",
    expect_ok: bool = True,
) -> tuple[Path, dict, subprocess.CompletedProcess[str]]:
    ws = _new_workspace(case)
    map_path = ws / "resource-map.yaml"
    proposals_path = ws / "proposals.yaml"
    map_path.write_text(
        yaml.safe_dump(resource_map or _resource_map(), sort_keys=False),
        encoding="utf-8",
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
    if expect_ok:
        _check(
            case,
            completed.returncode == 0,
            f"exit {completed.returncode}: {completed.stderr[-300:]!r}",
        )
    artifact = output_dir / (
        "reconciliation-result.json" if fmt == "json" else "reconciliation-result.yaml"
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


def qa_cr_01() -> None:
    """QA-CR-01: confirmed, rejected, and unresolved outcomes are retained."""
    case = "CR-01"
    _artifact, payload, _completed = _reconcile(
        case,
        [
            _proposal("P-1", relation_type="supports"),
            _proposal(
                "P-2",
                left_ref="L-1",
                right_ref=AP,
                relation_type="addresses",
                evidence_source="curated-map",
                evidence_refs=["L-1"],
            ),
            _proposal(
                "P-3",
                right_ref=TB,
                relation_type="overlaps",
                evidence_source="resource-overlap",
                strength="weak",
            ),
        ],
        {"P-1": "confirmed", "P-2": "rejected", "P-3": "unresolved"},
    )
    p1 = _row(payload, "P-1")
    p2 = _row(payload, "P-2")
    p3 = _row(payload, "P-3")
    _check(case, p1 is not None, "P-1 missing")
    _check(case, p2 is not None, "P-2 missing")
    _check(case, p3 is not None, "P-3 missing")
    if p1 is not None:
        _check(
            case,
            p1.get("adjudication") == "confirmed",
            f"P-1 adj {p1.get('adjudication')!r}",
        )
        _check(
            case,
            p1.get("relation_type") == "supports",
            f"P-1 type {p1.get('relation_type')!r}",
        )
    if p2 is not None:
        _check(
            case,
            p2.get("adjudication") == "rejected",
            f"P-2 adj {p2.get('adjudication')!r}",
        )
        _check(
            case,
            p2.get("relation_type") == "addresses",
            f"P-2 type {p2.get('relation_type')!r}",
        )
    if p3 is not None:
        _check(
            case,
            p3.get("adjudication") == "unresolved",
            f"P-3 adj {p3.get('adjudication')!r}",
        )
        _check(
            case,
            p3.get("relation_type") == "overlaps",
            f"P-3 type {p3.get('relation_type')!r}",
        )
    ids = [row.get("proposal_id") for row in payload.get("proposals") or []]
    _check(case, "P-2" in ids and "P-3" in ids, f"rejected/unresolved dropped: {ids}")


def qa_cr_02() -> None:
    """QA-CR-02: relation type stays separate from strength and adjudication."""
    cases = (
        (
            "CR-02-supports",
            _proposal("P-1", relation_type="supports", strength="high"),
            "confirmed",
            "supports",
            "high",
            "confirmed",
        ),
        (
            "CR-02-contradicts",
            _proposal("P-4", relation_type="contradicts", strength="high"),
            "rejected",
            "contradicts",
            "high",
            "rejected",
        ),
        (
            "CR-02-overlaps",
            _proposal(
                "P-3",
                right_ref=TB,
                relation_type="overlaps",
                evidence_source="resource-overlap",
                strength="weak",
            ),
            "unresolved",
            "overlaps",
            "weak",
            "unresolved",
        ),
    )
    for case, proposal, adjudication, rel, strength, adj in cases:
        _artifact, payload, _completed = _reconcile(
            case, [proposal], {proposal["proposal_id"]: adjudication}
        )
        row = _row(payload, proposal["proposal_id"])
        _check(case, row is not None, f"missing {proposal['proposal_id']}")
        if row is None:
            continue
        _check(
            case, row.get("relation_type") == rel, f"type {row.get('relation_type')!r}"
        )
        _check(
            case, row.get("strength") == strength, f"strength {row.get('strength')!r}"
        )
        _check(case, row.get("adjudication") == adj, f"adj {row.get('adjudication')!r}")
        _check(
            case,
            row.get("relation_type") != row.get("adjudication"),
            "type equals adjudication",
        )
        _check(
            case,
            row.get("relation_type") != row.get("strength"),
            "type equals strength",
        )


def qa_cr_03() -> None:
    """QA-CR-03: conflicting proposals stay unresolved regardless of order."""
    p1 = _proposal("P-1", relation_type="supports")
    p4 = _proposal("P-4", relation_type="contradicts")
    for order in (("P-1", "P-4"), ("P-4", "P-1")):
        case = f"CR-03-{'-'.join(order)}"
        by_id = {"P-1": p1, "P-4": p4}
        _artifact, payload, _completed = _reconcile(
            case,
            [by_id[pid] for pid in order],
            {"P-1": "confirmed", "P-4": "confirmed"},
        )
        rows = [_row(payload, pid) for pid in ("P-1", "P-4")]
        _check(case, all(row is not None for row in rows), "conflict pair not retained")
        for row in rows:
            if row is None:
                continue
            _check(
                case,
                row.get("adjudication") == "unresolved",
                f"{row.get('proposal_id')} adj {row.get('adjudication')!r}",
            )
            _check(
                case,
                row.get("conflict_reason") == "conflict",
                f"{row.get('proposal_id')} reason {row.get('conflict_reason')!r}",
            )
            _check(
                case,
                row.get("adjudication") != "confirmed",
                "confirmed by iteration order",
            )


def qa_cr_04() -> None:
    """QA-CR-04: dangling, stale, and evidence-free confirmation fail closed."""
    defects = (
        (
            "dangling-left",
            _proposal("P-9", left_ref="MISSING-LEFT", evidence_refs=["MISSING-LEFT"]),
            "dangling_reference",
        ),
        (
            "dangling-right",
            _proposal("P-9", right_ref="missing-right", evidence_refs=["CA-1-1"]),
            "dangling_reference",
        ),
        (
            "stale-version",
            _proposal("P-9", stpa_version="stpa-v0"),
            "source_version_mismatch",
        ),
        (
            "evidence-free",
            _proposal("P-9", evidence_source="none", evidence_refs=[]),
            "evidence_required",
        ),
    )
    for label, proposal, error_code in defects:
        case = f"CR-04-{label}"
        _artifact, payload, completed = _reconcile(
            case, [proposal], {"P-9": "confirmed"}, expect_ok=False
        )
        _check(case, completed.returncode != 0, f"{label} succeeded")
        errors = payload.get("errors") or []
        codes = [err.get("error_code") for err in errors if isinstance(err, dict)]
        ids = [err.get("proposal_id") for err in errors if isinstance(err, dict)]
        _check(case, error_code in codes, f"{label} codes {codes}")
        _check(case, "P-9" in ids, f"{label} did not identify P-9: {ids}")
        row = _row(payload, "P-9")
        _check(
            case,
            row is None or row.get("adjudication") != "confirmed",
            f"{label} wrote a confirmed relation",
        )
        _check(
            case,
            payload.get("is_valid") is False,
            f"{label} is_valid={payload.get('is_valid')!r}",
        )


def qa_cr_05() -> None:
    """QA-CR-05: reconciliation is deterministic and idempotent."""
    proposals = [
        _proposal("P-1", relation_type="supports"),
        _proposal(
            "P-2",
            left_ref="L-1",
            right_ref=AP,
            relation_type="addresses",
            evidence_source="curated-map",
            evidence_refs=["L-1"],
        ),
        _proposal(
            "P-3",
            right_ref=TB,
            relation_type="overlaps",
            evidence_source="resource-overlap",
            strength="weak",
        ),
    ]
    adjudications = {"P-1": "confirmed", "P-2": "rejected", "P-3": "unresolved"}
    _a_path, result_a, _ = _reconcile("CR-05-a", proposals, adjudications)
    _b_path, result_b, _ = _reconcile(
        "CR-05-b", [proposals[2], proposals[0], proposals[1]], adjudications
    )
    ids_a = [row.get("proposal_id") for row in result_a.get("proposals") or []]
    ids_b = [row.get("proposal_id") for row in result_b.get("proposals") or []]
    adj_a = [row.get("adjudication") for row in result_a.get("proposals") or []]
    adj_b = [row.get("adjudication") for row in result_b.get("proposals") or []]
    _check("CR-05", ids_a == ids_b, f"identities differ: {ids_a} vs {ids_b}")
    _check("CR-05", adj_a == adj_b, f"adjudications differ: {adj_a} vs {adj_b}")
    _c_path, result_c, _ = _reconcile(
        "CR-05-repeat",
        list(result_a.get("proposals") or []),
        adjudications,
    )
    ids_c = [row.get("proposal_id") for row in result_c.get("proposals") or []]
    adj_c = [row.get("adjudication") for row in result_c.get("proposals") or []]
    _check("CR-05", ids_c == ids_a, f"repeat identities changed: {ids_c}")
    _check("CR-05", adj_c == adj_a, f"repeat adjudications changed: {adj_c}")


def qa_cr_06() -> None:
    """QA-CR-06: scenario wording infers no relation."""
    case = "CR-06"
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
                "proposals": [],
                "scenario_prose": "the assistant supports prompt injection",
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    output_dir = ws / "out"
    completed = _run_cli(
        case,
        [
            *_command(),
            "reconcile-correspondence",
            "--map",
            str(map_path),
            "--proposals",
            str(proposals_path),
            "--output-dir",
            str(output_dir),
            "--format",
            "yaml",
        ],
    )
    _check(
        case,
        completed.returncode == 0,
        f"exit {completed.returncode}: {completed.stderr[-300:]!r}",
    )
    artifact = output_dir / "reconciliation-result.yaml"
    payload = (
        yaml.safe_load(artifact.read_text(encoding="utf-8"))
        if artifact.is_file()
        else {}
    )
    rows = payload.get("proposals") if isinstance(payload, dict) else None
    _check(
        case, isinstance(rows, list) and len(rows) == 0, f"inferred proposals: {rows!r}"
    )
    raw = artifact.read_bytes() if artifact.is_file() else b""
    _check(
        case,
        b"the assistant supports prompt injection" not in raw,
        "prose-only relation stored",
    )


def qa_cr_07() -> None:
    """QA-CR-07: source STPA and taxonomy artifacts are unchanged."""
    case = "CR-07"
    ws = _new_workspace(case)
    stpa = ws / "control-structure.yaml"
    taxonomy = ws / "attack-patterns.sssom.tsv"
    stpa_text = "responsibilities:\n- resp_id: RESP-1\n"
    taxonomy_text = "subject_id\tobject_id\nCA-1-1\tAP-T6-01\n"
    stpa.write_text(stpa_text, encoding="utf-8")
    taxonomy.write_text(taxonomy_text, encoding="utf-8")
    before_stpa = stpa.read_bytes()
    before_tax = taxonomy.read_bytes()
    map_path = ws / "resource-map.yaml"
    artifacts_path = ws / "artifacts.yaml"
    map_path.write_text(
        yaml.safe_dump(_resource_map(), sort_keys=False), encoding="utf-8"
    )
    artifacts_path.write_text(
        yaml.safe_dump(
            {
                "evidence": [
                    {
                        "proposal_id": "P-1",
                        "evidence_source": "exact-id",
                        "left_ref": "CA-1-1",
                        "right_ref": EP,
                    }
                ]
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    propose_dir = ws / "propose"
    propose = _run_cli(
        f"{case}-propose",
        [
            *_command(),
            "propose-correspondence",
            "--map",
            str(map_path),
            "--artifacts",
            str(artifacts_path),
            "--output-dir",
            str(propose_dir),
            "--format",
            "yaml",
        ],
    )
    _check(
        case,
        propose.returncode == 0,
        f"propose exit {propose.returncode}: {propose.stderr[-300:]!r}",
    )
    adj_path = ws / "adjudications.yaml"
    adj_path.write_text(
        yaml.safe_dump({"P-1": "confirmed"}, sort_keys=False), encoding="utf-8"
    )
    reconcile = _run_cli(
        f"{case}-reconcile",
        [
            *_command(),
            "reconcile-correspondence",
            "--map",
            str(map_path),
            "--proposals",
            str(propose_dir / "proposal-set.yaml"),
            "--adjudications",
            str(adj_path),
            "--output-dir",
            str(ws / "out"),
            "--format",
            "yaml",
        ],
    )
    _check(
        case,
        reconcile.returncode == 0,
        f"reconcile exit {reconcile.returncode}: {reconcile.stderr[-300:]!r}",
    )
    _check(case, stpa.read_bytes() == before_stpa, "control-structure.yaml changed")
    _check(
        case, taxonomy.read_bytes() == before_tax, "attack-patterns.sssom.tsv changed"
    )


def qa_cr_08() -> None:
    """QA-CR-08: reconciliation records zero network and model calls."""
    case = "CR-08"
    _check(
        case,
        QA_PIPELINE_ENV not in os.environ,
        f"{QA_PIPELINE_ENV} is set in the parent environment",
    )
    artifact, payload, completed = _reconcile(
        case,
        [
            _proposal("P-1", relation_type="supports"),
            _proposal(
                "P-2",
                left_ref="L-1",
                right_ref=AP,
                relation_type="addresses",
                evidence_source="curated-map",
                evidence_refs=["L-1"],
            ),
            _proposal(
                "P-3",
                right_ref=TB,
                relation_type="overlaps",
                evidence_source="resource-overlap",
                strength="weak",
            ),
        ],
        {"P-1": "confirmed", "P-2": "rejected", "P-3": "unresolved"},
    )
    _check(
        case,
        payload.get("network_calls") == 0,
        f"network_calls={payload.get('network_calls')!r}",
    )
    _check(
        case,
        payload.get("model_calls") == 0,
        f"model_calls={payload.get('model_calls')!r}",
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
    notes.append(f"08: published {artifact.name}")


def main() -> int:
    if os.environ.get(QA_PIPELINE_ENV):
        print(f"Refusing to run: {QA_PIPELINE_ENV} must not be set.", file=sys.stderr)
        return 2
    print(f"QA evidence: {RUN_ROOT.relative_to(REPO_ROOT)}", flush=True)
    for procedure in (
        qa_cr_01,
        qa_cr_02,
        qa_cr_03,
        qa_cr_04,
        qa_cr_05,
        qa_cr_06,
        qa_cr_07,
        qa_cr_08,
    ):
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
    / "qa-taxonomy-correspondence-reconciliation"
    / datetime.now(UTC).strftime("%Y%m%dT%H%M%S.%fZ")
)


if __name__ == "__main__":
    sys.exit(main())
