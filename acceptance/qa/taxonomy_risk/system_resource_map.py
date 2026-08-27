#!/usr/bin/env python3
"""Executable end-to-end QA suite for system resource map validation.

Mirrors ``system_resource_map.md`` (QA-SRM-01..13).  Drives the public
``asago-scenario-generator validate-resource-map`` file-to-file command:
a snapshot fixture and a ``SystemResourceMap`` YAML or JSON file in, a
published validation result and canonical map artifact out.  Inspects
artifacts with standard JSON/YAML readers, the console, and the
filesystem.  Never imports project modules, never calls
``validate_resource_map``, and never sets
``ASAGO_SCENARIO_GENERATOR_QA_PIPELINE``.

Run with::

    uv run python acceptance/qa/taxonomy_risk/system_resource_map.py

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


def _command() -> list[str]:
    if shutil.which("uv", path=_SEARCH_PATH):
        return [_UV, "run", "asago-scenario-generator"]
    executable = REPO_ROOT / ".venv" / "bin" / "asago-scenario-generator"
    if executable.is_file():
        return [str(executable)]
    raise RuntimeError("neither uv nor .venv/bin/asago-scenario-generator is available")


def _snapshot(**overrides: object) -> dict:
    payload: dict[str, object] = {
        "schema_version": "1",
        "stpa_version": "stpa-v1",
        "taxonomy_version": "atlas-2026.05",
        "stpa_identifiers": ["RESP-1", "CP-2", "CA-1-1", "FB-1-1", "L-1", "H-1"],
        "taxonomy_identifiers": [EP, TB],
        "facts": {},
    }
    payload.update(overrides)
    return payload


def _representative_map(**overrides: object) -> dict:
    payload: dict[str, object] = {
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
    payload.update(overrides)
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


def _load_yaml(path: Path) -> dict:
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path} is not a YAML mapping")
    return payload


def _validate(
    case: str,
    snapshot: dict,
    resource_map: dict,
    *,
    fmt: str = "yaml",
    context_hint: str | None = None,
    expect_ok: bool = True,
) -> tuple[dict, dict | None, subprocess.CompletedProcess[str]]:
    ws = _new_workspace(case)
    snap_path = ws / "snapshot.yaml"
    map_path = ws / "resource-map.yaml"
    snap_path.write_text(yaml.safe_dump(snapshot, sort_keys=False), encoding="utf-8")
    map_path.write_text(yaml.safe_dump(resource_map, sort_keys=False), encoding="utf-8")
    output_dir = ws / "out"
    argv = [
        *_command(),
        "validate-resource-map",
        "--snapshot",
        str(snap_path),
        "--map",
        str(map_path),
        "--output-dir",
        str(output_dir),
        "--format",
        fmt,
    ]
    if context_hint:
        argv.extend(["--context-hint", context_hint])
    completed = _run_cli(case, argv)
    expected_exit = 0 if expect_ok else 1
    _check(
        case,
        completed.returncode == expected_exit,
        f"exit {completed.returncode} (expected {expected_exit}): "
        f"{completed.stderr[-300:]!r}",
    )
    validation_path = output_dir / (
        "resource-map-validation.json"
        if fmt == "json"
        else "resource-map-validation.yaml"
    )
    _check(
        case,
        validation_path.is_file(),
        f"missing published validation {validation_path.name}",
    )
    result = _load_yaml(validation_path) if validation_path.is_file() else {}
    canonical_path = output_dir / (
        "resource-map.json" if fmt == "json" else "resource-map.yaml"
    )
    canonical = _load_yaml(canonical_path) if canonical_path.is_file() else None
    return result, canonical, completed


def _error_codes(result: dict) -> list[str]:
    return [str(item.get("code")) for item in result.get("errors") or []]


def _warning_codes(result: dict) -> list[str]:
    return [str(item.get("code")) for item in result.get("warnings") or []]


def _error_ids(result: dict, code: str) -> set[str]:
    return {
        str(item.get("element_id"))
        for item in result.get("errors") or []
        if item.get("code") == code
    }


def _error_fields(result: dict, code: str) -> set[str]:
    return {
        str(item.get("field"))
        for item in result.get("errors") or []
        if item.get("code") == code
    }


def qa_srm_01() -> None:
    """QA-SRM-01: a representative valid map covers the v1 families."""
    case = "SRM-01"
    result, canonical, completed = _validate(
        case, _snapshot(), _representative_map(), expect_ok=True
    )
    _check(case, result.get("is_valid") is True, f"is_valid={result.get('is_valid')!r}")
    _check(case, len(result.get("errors") or []) == 0, "expected 0 errors")
    _check(
        case,
        result.get("correspondence_relations") == [],
        f"correspondence={result.get('correspondence_relations')!r}",
    )
    _check(
        case,
        result.get("network_calls") == 0,
        f"network_calls={result.get('network_calls')!r}",
    )
    _check(
        case,
        result.get("model_calls") == 0,
        f"model_calls={result.get('model_calls')!r}",
    )
    _check(case, canonical is not None, "canonical map missing")
    _check(
        case,
        "http://" not in completed.stdout + completed.stderr,
        "network endpoint mentioned",
    )
    notes.append("01: representative map published with 0 errors")


def qa_srm_02() -> None:
    """QA-SRM-02: duplicate and unstable identifiers fail closed."""
    duplicate = _representative_map()
    duplicate["system_resources"] = list(duplicate["system_resources"]) + [
        {
            "element_id": "SR-1",
            "name": "Duplicate Resource",
            "entity_family": "system-resource",
        }
    ]
    result, canonical, _completed = _validate(
        "SRM-02-duplicate", _snapshot(), duplicate, expect_ok=False
    )
    _check(
        "SRM-02-duplicate",
        "duplicate_identifier" in _error_codes(result),
        f"codes={_error_codes(result)}",
    )
    _check(
        "SRM-02-duplicate",
        "SR-1" in _error_ids(result, "duplicate_identifier"),
        f"ids={_error_ids(result, 'duplicate_identifier')}",
    )
    _check("SRM-02-duplicate", canonical is None, "canonical map published on error")

    unstable = _representative_map()
    unstable["system_resources"] = list(unstable["system_resources"]) + [
        {
            "element_id": "idx-0",
            "name": "Positional Resource",
            "entity_family": "system-resource",
        }
    ]
    result, canonical, _completed = _validate(
        "SRM-02-unstable", _snapshot(), unstable, expect_ok=False
    )
    _check(
        "SRM-02-unstable",
        "unstable_identifier" in _error_codes(result),
        f"codes={_error_codes(result)}",
    )
    _check(
        "SRM-02-unstable",
        "idx-0" in _error_ids(result, "unstable_identifier"),
        f"ids={_error_ids(result, 'unstable_identifier')}",
    )
    _check("SRM-02-unstable", canonical is None, "canonical map published on error")


def qa_srm_03() -> None:
    """QA-SRM-03: dangling STPA and taxonomy references fail closed."""
    cases = (
        ("responsibility", "RESP-99", "controller"),
        ("process", "CP-99", "process"),
        ("control-action", "CA-99-1", "control-action"),
        ("feedback", "FB-99-1", "feedback"),
        ("loss", "L-99", "loss"),
        ("hazard", "H-99", "hazard"),
        ("entry-point", "ep:v1:ffffffffffffffffffffffffffffffff", "taxonomy"),
        ("boundary", "tb:v1:ffffffffffffffffffffffffffffffff", "taxonomy"),
    )
    for label, element_id, kind in cases:
        case = f"SRM-03-{label}"
        resource_map = _representative_map()
        if kind == "controller":
            resource_map["control_actions"][0]["controller_id"] = element_id
        elif kind == "process":
            resource_map["control_actions"][0]["process_id"] = element_id
        elif kind == "control-action":
            resource_map["control_actions"] = list(resource_map["control_actions"]) + [
                {
                    "element_id": "CA-extra",
                    "controller_id": element_id,
                    "process_id": "CP-2",
                    "action_name": "Extra",
                    "entity_family": "control-action",
                }
            ]
        elif kind == "feedback":
            resource_map["feedback_paths"][0]["controller_id"] = element_id
        elif kind == "loss":
            resource_map["loss_links"][0]["loss_id"] = element_id
        elif kind == "hazard":
            resource_map["loss_links"][0]["hazard_id"] = element_id
        else:
            resource_map["system_resources"][0]["taxonomy_ref"] = element_id
        result, _canonical, _completed = _validate(
            case,
            _snapshot(),
            resource_map,
            context_hint="dangling_reference",
            expect_ok=False,
        )
        _check(
            case,
            "dangling_reference" in _error_codes(result),
            f"codes={_error_codes(result)}",
        )
        _check(
            case,
            element_id in _error_ids(result, "dangling_reference"),
            f"ids={_error_ids(result, 'dangling_reference')}",
        )


def qa_srm_04() -> None:
    """QA-SRM-04: invalid enum and status values fail closed."""
    family = _representative_map()
    family["system_resources"][0]["entity_family"] = "correspondence"
    result, _canonical, _completed = _validate(
        "SRM-04-entity_family", _snapshot(), family, expect_ok=False
    )
    _check(
        "SRM-04-entity_family",
        "invalid_enum" in _error_codes(result),
        f"codes={_error_codes(result)}",
    )
    _check(
        "SRM-04-entity_family",
        "entity_family" in _error_fields(result, "invalid_enum"),
        f"fields={_error_fields(result, 'invalid_enum')}",
    )

    status = _representative_map()
    status["use_case_facts"][0]["resolution_status"] = "confirmed-absent-as-unknown"
    result, _canonical, _completed = _validate(
        "SRM-04-resolution_status", _snapshot(), status, expect_ok=False
    )
    _check(
        "SRM-04-resolution_status",
        "invalid_enum" in _error_codes(result),
        f"codes={_error_codes(result)}",
    )
    _check(
        "SRM-04-resolution_status",
        "resolution_status" in _error_fields(result, "invalid_enum"),
        f"fields={_error_fields(result, 'invalid_enum')}",
    )

    provenance = _representative_map()
    provenance["use_case_facts"][0]["provenance_kind"] = "inferred-match"
    result, _canonical, _completed = _validate(
        "SRM-04-provenance_kind", _snapshot(), provenance, expect_ok=False
    )
    _check(
        "SRM-04-provenance_kind",
        "invalid_enum" in _error_codes(result),
        f"codes={_error_codes(result)}",
    )
    _check(
        "SRM-04-provenance_kind",
        "provenance_kind" in _error_fields(result, "invalid_enum"),
        f"fields={_error_fields(result, 'invalid_enum')}",
    )


def qa_srm_05() -> None:
    """QA-SRM-05: source-version pins must match the snapshot."""
    snapshot = _snapshot(stpa_version="stpa-v1", taxonomy_version="atlas-2026.05")
    stpa = _representative_map(stpa_version="stpa-v9", taxonomy_version="atlas-2026.05")
    result, _canonical, _completed = _validate(
        "SRM-05-stpa", snapshot, stpa, expect_ok=False
    )
    _check(
        "SRM-05-stpa",
        "source_version_mismatch" in _error_codes(result),
        f"codes={_error_codes(result)}",
    )
    taxonomy = _representative_map(
        stpa_version="stpa-v1", taxonomy_version="atlas-1999.01"
    )
    result, _canonical, _completed = _validate(
        "SRM-05-taxonomy", snapshot, taxonomy, expect_ok=False
    )
    _check(
        "SRM-05-taxonomy",
        "source_version_mismatch" in _error_codes(result),
        f"codes={_error_codes(result)}",
    )


def qa_srm_06() -> None:
    """QA-SRM-06: control actions require valid controller and process references."""
    missing_controller = _representative_map()
    missing_controller["control_actions"][0]["controller_id"] = ""
    result, _canonical, _completed = _validate(
        "SRM-06-controller", _snapshot(), missing_controller, expect_ok=False
    )
    _check(
        "SRM-06-controller",
        "invalid_control_action_link" in _error_codes(result),
        f"codes={_error_codes(result)}",
    )
    _check(
        "SRM-06-controller",
        "CA-1-1" in _error_ids(result, "invalid_control_action_link"),
        f"ids={_error_ids(result, 'invalid_control_action_link')}",
    )

    missing_process = _representative_map()
    missing_process["control_actions"][0]["process_id"] = ""
    result, _canonical, _completed = _validate(
        "SRM-06-process", _snapshot(), missing_process, expect_ok=False
    )
    _check(
        "SRM-06-process",
        "invalid_control_action_link" in _error_codes(result),
        f"codes={_error_codes(result)}",
    )
    _check(
        "SRM-06-process",
        "CA-1-1" in _error_ids(result, "invalid_control_action_link"),
        f"ids={_error_ids(result, 'invalid_control_action_link')}",
    )


def qa_srm_07() -> None:
    """QA-SRM-07: data flows and trust boundaries cannot name unknown resources."""
    data_flow = _representative_map()
    data_flow["data_flows"] = [
        {
            "element_id": "DF-1",
            "name": "Bad Flow",
            "source_resource_id": "SR-99",
            "target_resource_id": "SR-1",
            "entity_family": "data-flow",
        }
    ]
    result, _canonical, _completed = _validate(
        "SRM-07-data-flow", _snapshot(), data_flow, expect_ok=False
    )
    _check(
        "SRM-07-data-flow",
        "unknown_resource_link" in _error_codes(result),
        f"codes={_error_codes(result)}",
    )
    _check(
        "SRM-07-data-flow",
        "DF-1" in _error_ids(result, "unknown_resource_link"),
        f"ids={_error_ids(result, 'unknown_resource_link')}",
    )

    boundary = _representative_map()
    boundary["trust_boundaries"] = [
        {
            "element_id": "TB-1",
            "name": "Bad Boundary",
            "resource_ids": ["SR-99"],
            "taxonomy_ref": TB,
            "entity_family": "trust-boundary",
        }
    ]
    result, _canonical, _completed = _validate(
        "SRM-07-trust-boundary", _snapshot(), boundary, expect_ok=False
    )
    _check(
        "SRM-07-trust-boundary",
        "unknown_resource_link" in _error_codes(result),
        f"codes={_error_codes(result)}",
    )
    _check(
        "SRM-07-trust-boundary",
        "TB-1" in _error_ids(result, "unknown_resource_link"),
        f"ids={_error_ids(result, 'unknown_resource_link')}",
    )


def qa_srm_08() -> None:
    """QA-SRM-08: loss links cannot name unknown STPA losses or hazards."""
    loss = _representative_map()
    loss["loss_links"] = [
        {
            "element_id": "LL-1",
            "loss_id": "L-99",
            "hazard_id": "H-1",
            "entity_family": "loss-link",
        }
    ]
    result, _canonical, _completed = _validate(
        "SRM-08-loss", _snapshot(), loss, expect_ok=False
    )
    _check(
        "SRM-08-loss",
        "unknown_loss_link" in _error_codes(result),
        f"codes={_error_codes(result)}",
    )
    _check(
        "SRM-08-loss",
        "L-99" in _error_ids(result, "unknown_loss_link"),
        f"ids={_error_ids(result, 'unknown_loss_link')}",
    )

    hazard = _representative_map()
    hazard["loss_links"] = [
        {
            "element_id": "LL-1",
            "loss_id": "L-1",
            "hazard_id": "H-99",
            "entity_family": "loss-link",
        }
    ]
    result, _canonical, _completed = _validate(
        "SRM-08-hazard", _snapshot(), hazard, expect_ok=False
    )
    _check(
        "SRM-08-hazard",
        "unknown_loss_link" in _error_codes(result),
        f"codes={_error_codes(result)}",
    )
    _check(
        "SRM-08-hazard",
        "H-99" in _error_ids(result, "unknown_loss_link"),
        f"ids={_error_ids(result, 'unknown_loss_link')}",
    )


def qa_srm_09() -> None:
    """QA-SRM-09: ambiguous aliases fail closed."""
    resource_map = _representative_map(aliases={"payment-backend": ["CP-2", "CP-4"]})
    result, _canonical, _completed = _validate(
        "SRM-09", _snapshot(), resource_map, expect_ok=False
    )
    _check(
        "SRM-09",
        "ambiguous_alias" in _error_codes(result),
        f"codes={_error_codes(result)}",
    )
    _check(
        "SRM-09",
        "payment-backend" in _error_ids(result, "ambiguous_alias"),
        f"ids={_error_ids(result, 'ambiguous_alias')}",
    )


def qa_srm_10() -> None:
    """QA-SRM-10: unknown is not confirmed absence."""
    unknown = _representative_map()
    unknown["use_case_facts"] = [
        {
            "element_id": "UF-1",
            "fact_key": "auth.token_validation",
            "resolution_status": "unknown",
            "provenance_kind": "analyst",
            "entity_family": "use-case-fact",
        }
    ]
    result, canonical, _completed = _validate(
        "SRM-10-unknown", _snapshot(), unknown, expect_ok=True
    )
    _check("SRM-10-unknown", result.get("is_valid") is True, "expected valid map")
    facts = (canonical or {}).get("use_case_facts") or []
    uf1 = next((row for row in facts if row.get("element_id") == "UF-1"), None)
    _check("SRM-10-unknown", uf1 is not None, "UF-1 missing from canonical map")
    _check(
        "SRM-10-unknown",
        (uf1 or {}).get("resolution_status") == "unknown",
        f"UF-1 status={(uf1 or {}).get('resolution_status')!r}",
    )
    _check(
        "SRM-10-unknown",
        (uf1 or {}).get("resolution_status") != "absent",
        "UF-1 treated as absent",
    )

    absent = _representative_map()
    absent["use_case_facts"] = [
        {
            "element_id": "UF-2",
            "fact_key": "storage.encryption_at_rest",
            "resolution_status": "absent",
            "provenance_kind": "imported-source",
            "entity_family": "use-case-fact",
        }
    ]
    result, canonical, _completed = _validate(
        "SRM-10-absent", _snapshot(), absent, expect_ok=True
    )
    _check("SRM-10-absent", result.get("is_valid") is True, "expected valid map")
    facts = (canonical or {}).get("use_case_facts") or []
    uf2 = next((row for row in facts if row.get("element_id") == "UF-2"), None)
    _check("SRM-10-absent", uf2 is not None, "UF-2 missing from canonical map")
    _check(
        "SRM-10-absent",
        (uf2 or {}).get("resolution_status") == "absent",
        f"UF-2 status={(uf2 or {}).get('resolution_status')!r}",
    )
    _check(
        "SRM-10-absent",
        (uf2 or {}).get("resolution_status") != "unknown",
        "UF-2 treated as unknown",
    )


def qa_srm_11() -> None:
    """QA-SRM-11: provenance distinguishes analyst from imported source facts."""
    analyst = _representative_map()
    analyst["assertions"] = [
        {
            "element_id": "A-1",
            "description": "Analyst assertion 1",
            "provenance_kind": "analyst",
            "entity_family": "assertion",
        }
    ]
    result, canonical, _completed = _validate(
        "SRM-11-analyst", _snapshot(), analyst, expect_ok=True
    )
    _check("SRM-11-analyst", result.get("is_valid") is True, "expected valid map")
    rows = (canonical or {}).get("assertions") or []
    a1 = next((row for row in rows if row.get("element_id") == "A-1"), None)
    _check("SRM-11-analyst", a1 is not None, "A-1 missing")
    _check(
        "SRM-11-analyst",
        (a1 or {}).get("provenance_kind") == "analyst",
        f"A-1 provenance={(a1 or {}).get('provenance_kind')!r}",
    )
    _check(
        "SRM-11-analyst",
        (a1 or {}).get("provenance_kind") != "imported-source",
        "A-1 recorded as imported-source",
    )

    imported = _representative_map()
    imported["assertions"] = [
        {
            "element_id": "A-2",
            "description": "Imported source assertion 2",
            "provenance_kind": "imported-source",
            "entity_family": "assertion",
        }
    ]
    result, canonical, _completed = _validate(
        "SRM-11-imported", _snapshot(), imported, expect_ok=True
    )
    _check("SRM-11-imported", result.get("is_valid") is True, "expected valid map")
    rows = (canonical or {}).get("assertions") or []
    a2 = next((row for row in rows if row.get("element_id") == "A-2"), None)
    _check("SRM-11-imported", a2 is not None, "A-2 missing")
    _check(
        "SRM-11-imported",
        (a2 or {}).get("provenance_kind") == "imported-source",
        f"A-2 provenance={(a2 or {}).get('provenance_kind')!r}",
    )
    _check(
        "SRM-11-imported",
        (a2 or {}).get("provenance_kind") != "analyst",
        "A-2 recorded as analyst",
    )


def qa_srm_12() -> None:
    """QA-SRM-12: missing optional provenance is a warning."""
    resource_map = _representative_map()
    resource_map["assertions"] = list(resource_map["assertions"]) + [
        {
            "element_id": "A-3",
            "description": "Assertion missing provenance",
            "provenance_kind": None,
            "entity_family": "assertion",
        }
    ]
    result, _canonical, _completed = _validate(
        "SRM-12", _snapshot(), resource_map, expect_ok=True
    )
    _check("SRM-12", result.get("is_valid") is True, "expected valid map")
    _check(
        "SRM-12", len(result.get("errors") or []) == 0, f"errors={result.get('errors')}"
    )
    _check(
        "SRM-12",
        "missing_optional_provenance" in _warning_codes(result),
        f"warnings={result.get('warnings')}",
    )
    warning_ids = {
        str(item.get("element_id"))
        for item in result.get("warnings") or []
        if item.get("code") == "missing_optional_provenance"
    }
    _check("SRM-12", "A-3" in warning_ids, f"warning ids={warning_ids}")


def qa_srm_13() -> None:
    """QA-SRM-13: validation infers no correspondence."""
    result, _canonical, _completed = _validate(
        "SRM-13", _snapshot(), _representative_map(), expect_ok=True
    )
    _check("SRM-13", result.get("is_valid") is True, "expected valid map")
    _check(
        "SRM-13",
        result.get("correspondence_relations") == [],
        f"correspondence={result.get('correspondence_relations')!r}",
    )
    serialized = yaml.safe_dump(result)
    _check(
        "SRM-13",
        "lexical" not in serialized.lower(),
        "lexical match recorded",
    )
    _check(
        "SRM-13",
        EP not in str(result.get("correspondence_relations")),
        "taxonomy identifier recorded as a match",
    )


def main() -> int:
    if os.environ.get(QA_PIPELINE_ENV):
        print(f"Refusing to run: {QA_PIPELINE_ENV} must not be set.", file=sys.stderr)
        return 2
    print(f"QA evidence: {RUN_ROOT.relative_to(REPO_ROOT)}", flush=True)
    for procedure in (
        qa_srm_01,
        qa_srm_02,
        qa_srm_03,
        qa_srm_04,
        qa_srm_05,
        qa_srm_06,
        qa_srm_07,
        qa_srm_08,
        qa_srm_09,
        qa_srm_10,
        qa_srm_11,
        qa_srm_12,
        qa_srm_13,
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
    / "qa-taxonomy-system-resource-map"
    / datetime.now(UTC).strftime("%Y%m%dT%H%M%S.%fZ")
)


if __name__ == "__main__":
    sys.exit(main())
