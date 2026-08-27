#!/usr/bin/env python3
"""Executable end-to-end QA suite for the system resource map artifact.

Mirrors ``system_resource_map_artifact.md`` (QA-SRMA-01..05).  Drives the
public ``asago-scenario-generator validate-resource-map`` file-to-file
command and inspects published YAML and JSON with standard readers and
byte comparison.  Never imports project modules, never calls
``validate_resource_map``, and never sets
``ASAGO_SCENARIO_GENERATOR_QA_PIPELINE``.

Run with::

    uv run python acceptance/qa/taxonomy_risk/system_resource_map_artifact.py

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
PINNED = {
    "schema_version": "1",
    "stpa_version": "stpa-v1",
    "taxonomy_version": "atlas-2026.05",
}


def _command() -> list[str]:
    if shutil.which("uv", path=_SEARCH_PATH):
        return [_UV, "run", "asago-scenario-generator"]
    executable = REPO_ROOT / ".venv" / "bin" / "asago-scenario-generator"
    if executable.is_file():
        return [str(executable)]
    raise RuntimeError("neither uv nor .venv/bin/asago-scenario-generator is available")


def _snapshot() -> dict:
    return {
        "schema_version": "1",
        "stpa_version": "stpa-v1",
        "taxonomy_version": "atlas-2026.05",
        "stpa_identifiers": ["RESP-1", "CP-2", "CA-1-1", "FB-1-1", "L-1", "H-1"],
        "taxonomy_identifiers": [EP, TB],
        "facts": {},
    }


def _representative_map() -> dict:
    return {
        "schema_version": "1",
        "stpa_version": "stpa-v1",
        "taxonomy_version": "atlas-2026.05",
        "system_resources": [
            {
                "element_id": "SR-1",
                "name": "Primary Database",
                "description": "Database hosting user records",
                "taxonomy_ref": EP,
                "entity_family": "system-resource",
            }
        ],
        "actor_controllers": [
            {
                "element_id": "RESP-1",
                "name": "Agent Controller",
                "description": "Controller handling agent decisions",
                "entity_family": "actor-controller",
            }
        ],
        "controlled_processes": [
            {
                "element_id": "CP-2",
                "name": "Payment Pipeline",
                "description": "Process executing transactions",
                "entity_family": "controlled-process",
            }
        ],
        "control_actions": [
            {
                "element_id": "CA-1-1",
                "controller_id": "RESP-1",
                "process_id": "CP-2",
                "action_name": "Issue Payment",
                "entity_family": "control-action",
            }
        ],
        "feedback_paths": [
            {
                "element_id": "FB-1-1",
                "controller_id": "RESP-1",
                "process_id": "CP-2",
                "feedback_name": "Payment Confirmation",
                "entity_family": "feedback-path",
            }
        ],
        "trust_boundaries": [
            {
                "element_id": "TB-1",
                "name": "DMZ Boundary",
                "resource_ids": ["SR-1"],
                "taxonomy_ref": TB,
                "entity_family": "trust-boundary",
            }
        ],
        "data_flows": [
            {
                "element_id": "DF-1",
                "name": "User Record Sync",
                "source_resource_id": "SR-1",
                "target_resource_id": "SR-1",
                "entity_family": "data-flow",
            }
        ],
        "loss_links": [
            {
                "element_id": "LL-1",
                "loss_id": "L-1",
                "hazard_id": "H-1",
                "entity_family": "loss-link",
            }
        ],
        "use_case_facts": [
            {
                "element_id": "UF-1",
                "fact_key": "auth.token_validation",
                "resolution_status": "unknown",
                "provenance_kind": "analyst",
                "entity_family": "use-case-fact",
            },
            {
                "element_id": "UF-2",
                "fact_key": "storage.encryption_at_rest",
                "resolution_status": "absent",
                "provenance_kind": "imported-source",
                "entity_family": "use-case-fact",
            },
        ],
        "assertions": [
            {
                "element_id": "A-1",
                "description": "Analyst assertion 1",
                "provenance_kind": "analyst",
                "entity_family": "assertion",
            },
            {
                "element_id": "A-2",
                "description": "Imported source assertion 2",
                "provenance_kind": "imported-source",
                "entity_family": "assertion",
            },
        ],
        "aliases": {},
    }


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


def _publish(case: str, resource_map: dict, *, fmt: str) -> tuple[Path, bytes, dict]:
    ws = _new_workspace(case)
    snapshot = ws / "snapshot.yaml"
    map_path = ws / "resource-map.yaml"
    snapshot.write_text(yaml.safe_dump(_snapshot(), sort_keys=False), encoding="utf-8")
    map_path.write_text(yaml.safe_dump(resource_map, sort_keys=False), encoding="utf-8")
    output_dir = ws / "out"
    argv = [
        *_command(),
        "validate-resource-map",
        "--snapshot",
        str(snapshot),
        "--map",
        str(map_path),
        "--output-dir",
        str(output_dir),
        "--format",
        fmt,
    ]
    completed = _run_cli(case, argv)
    if completed.returncode != 0:
        failures.append(
            f"{case}: exit {completed.returncode}: {completed.stderr[-300:]!r}"
        )
    name = "resource-map.json" if fmt == "json" else "resource-map.yaml"
    artifact = output_dir / name
    if not artifact.is_file():
        failures.append(f"{case}: missing {name}")
        return artifact, b"", {}
    raw = artifact.read_bytes()
    parsed = json.loads(raw) if fmt == "json" else yaml.safe_load(raw)
    if not isinstance(parsed, dict):
        failures.append(f"{case}: {name} is not a mapping")
        return artifact, raw, {}
    return artifact, raw, parsed


def _ids(payload: dict) -> list[str]:
    ids: list[str] = []
    for key in (
        "system_resources",
        "actor_controllers",
        "controlled_processes",
        "control_actions",
        "feedback_paths",
        "trust_boundaries",
        "data_flows",
        "loss_links",
        "use_case_facts",
        "assertions",
    ):
        for row in payload.get(key) or []:
            if isinstance(row, dict) and row.get("element_id"):
                ids.append(str(row["element_id"]))
    return ids


def _family(payload: dict, family: str) -> list[dict]:
    key = {
        "system-resource": "system_resources",
        "actor-controller": "actor_controllers",
        "controlled-process": "controlled_processes",
        "control-action": "control_actions",
        "feedback-path": "feedback_paths",
        "trust-boundary": "trust_boundaries",
        "data-flow": "data_flows",
        "loss-link": "loss_links",
        "use-case-fact": "use_case_facts",
        "assertion": "assertions",
    }[family]
    rows = payload.get(key) or []
    return [row for row in rows if isinstance(row, dict)]


def qa_srma_01() -> None:
    """QA-SRMA-01: pinned snapshot versions are copied into the map."""
    case = "SRMA-01"
    _artifact, _raw, payload = _publish(case, _representative_map(), fmt="yaml")
    for key, expected in PINNED.items():
        _check(
            case,
            payload.get(key) == expected,
            f"{key} {payload.get(key)!r} != {expected!r}",
        )


def qa_srma_02() -> None:
    """QA-SRMA-02: identifiers and order ignore presentation order."""
    authored_a = _representative_map()
    authored_b = _representative_map()
    authored_b["assertions"] = list(reversed(authored_b["assertions"]))
    _a_path, a_raw, plan_a = _publish("SRMA-02-a", authored_a, fmt="yaml")
    _b_path, b_raw, plan_b = _publish("SRMA-02-b", authored_b, fmt="yaml")
    ids_a = _ids(plan_a)
    ids_b = _ids(plan_b)
    _check("SRMA-02", ids_a == ids_b, f"identifiers differ: {ids_a} vs {ids_b}")
    assertion_ids_a = [row.get("element_id") for row in plan_a.get("assertions") or []]
    assertion_ids_b = [row.get("element_id") for row in plan_b.get("assertions") or []]
    _check(
        "SRMA-02",
        assertion_ids_a == assertion_ids_b,
        f"canonical assertion order differs: {assertion_ids_a} vs {assertion_ids_b}",
    )
    _check(
        "SRMA-02",
        a_raw == b_raw,
        "serialized YAML artifacts are not canonically equivalent",
    )


def qa_srma_03() -> None:
    """QA-SRMA-03: YAML and JSON round-trip without semantic loss."""
    resource_map = _representative_map()
    _yaml_path, yaml_raw, yaml_plan = _publish("SRMA-03-yaml", resource_map, fmt="yaml")
    _json_path, json_raw, json_plan = _publish("SRMA-03-json", resource_map, fmt="json")
    yaml_again = yaml.safe_load(yaml_raw)
    json_again = json.loads(json_raw)
    for label, original, round_tripped in (
        ("YAML", yaml_plan, yaml_again),
        ("JSON", json_plan, json_again),
    ):
        case = f"SRMA-03-{label.lower()}"
        _check(case, _ids(original) == _ids(round_tripped), "identities lost")
        orig_ca = _family(original, "control-action")
        rt_ca = _family(round_tripped, "control-action")
        _check(
            case,
            orig_ca == rt_ca,
            f"control-action cross-references lost: {orig_ca} vs {rt_ca}",
        )
        orig_tb = _family(original, "trust-boundary")
        rt_tb = _family(round_tripped, "trust-boundary")
        _check(
            case,
            orig_tb == rt_tb,
            f"trust-boundary cross-references lost: {orig_tb} vs {rt_tb}",
        )
        orig_facts = {
            row.get("element_id"): (
                row.get("resolution_status"),
                row.get("provenance_kind"),
            )
            for row in original.get("use_case_facts") or []
        }
        rt_facts = {
            row.get("element_id"): (
                row.get("resolution_status"),
                row.get("provenance_kind"),
            )
            for row in round_tripped.get("use_case_facts") or []
        }
        _check(case, orig_facts == rt_facts, "status or provenance lost")
        _check(
            case,
            orig_facts.get("UF-1", (None, None))[0] == "unknown",
            "unknown status lost",
        )
        _check(
            case,
            orig_facts.get("UF-2", (None, None))[0] == "absent",
            "absent status lost",
        )


def qa_srma_04() -> None:
    """QA-SRMA-04: identical inputs are byte-stable."""
    resource_map = _representative_map()
    for fmt in ("yaml", "json"):
        _p1, raw1, _plan1 = _publish(f"SRMA-04-{fmt}-1", resource_map, fmt=fmt)
        _p2, raw2, _plan2 = _publish(f"SRMA-04-{fmt}-2", resource_map, fmt=fmt)
        _check(
            f"SRMA-04-{fmt}", raw1 == raw2, f"{fmt} artifacts are not byte-identical"
        )


def qa_srma_05() -> None:
    """QA-SRMA-05: consumers read the domain contract without persistence details."""
    resource_map = _representative_map()
    _yaml_path, yaml_raw, yaml_plan = _publish("SRMA-05-yaml", resource_map, fmt="yaml")
    _json_path, json_raw, json_plan = _publish("SRMA-05-json", resource_map, fmt="json")
    yaml_family = _family(yaml_plan, "control-action")
    json_family = _family(json_plan, "trust-boundary")
    _check("SRMA-05-yaml", bool(yaml_family), "YAML consumer missed control-action")
    _check("SRMA-05-json", bool(json_family), "JSON consumer missed trust-boundary")
    yaml_text = yaml_raw.decode("utf-8")
    json_text = json_raw.decode("utf-8")
    for case, text in (("SRMA-05-yaml", yaml_text), ("SRMA-05-json", json_text)):
        lowered = text.lower()
        _check(
            case,
            "persistence" not in lowered,
            "artifact exposes persistence adapter details",
        )
        _check(
            case,
            "adapter" not in lowered,
            "artifact exposes adapter details",
        )


def main() -> int:
    if os.environ.get(QA_PIPELINE_ENV):
        print(f"Refusing to run: {QA_PIPELINE_ENV} must not be set.", file=sys.stderr)
        return 2
    print(f"QA evidence: {RUN_ROOT.relative_to(REPO_ROOT)}", flush=True)
    for procedure in (
        qa_srma_01,
        qa_srma_02,
        qa_srma_03,
        qa_srma_04,
        qa_srma_05,
    ):
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
    / "qa-taxonomy-system-resource-map-artifact"
    / datetime.now(UTC).strftime("%Y%m%dT%H%M%S.%fZ")
)


if __name__ == "__main__":
    sys.exit(main())
