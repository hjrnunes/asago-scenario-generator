#!/usr/bin/env python3
"""External QA for the canonical hybrid coverage assessment artifact."""

from __future__ import annotations

import hashlib
import json
import sys
import unicodedata
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[3]
ARTIFACT = ROOT / "tests/fixtures/hybrid-coverage-assessment.yaml"
DOMAIN = "asago-scenario-generator:hybrid-coverage-assessment:v1"
COVERAGE_KINDS = {
    "same_mechanism",
    "mechanism_enables_ica",
    "ica_specializes_mechanism",
    "mechanism_specializes_ica",
}


def _normalize(value: Any) -> Any:
    """Apply the public NFC canonicalization rule independently."""
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, list):
        return [_normalize(item) for item in value]
    if isinstance(value, dict):
        return {
            unicodedata.normalize("NFC", str(key)): _normalize(item)
            for key, item in value.items()
        }
    return value


def _digest(payload: dict[str, Any]) -> str:
    """Compute the version-framed artifact digest without project imports."""
    canonical = json.dumps(
        _normalize(payload),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(DOMAIN.encode("utf-8") + b"\0" + canonical).hexdigest()


def _semantic_payload(data: dict[str, Any]) -> dict[str, Any]:
    """Select exactly the fields bound by the assessment digest."""
    return {
        "schema_version": data["schema_version"],
        "capability_snapshot_digest": data["capability_snapshot_digest"],
        "source_pins": data["source_pins"],
        "structural_inventory_status": data["structural_inventory_status"],
        "structural_consideration": data["structural_consideration"],
        "taxonomy_correspondence": data["taxonomy_correspondence"],
        "scenario_realization": data["scenario_realization"],
        "proposal_outcomes": data["proposal_outcomes"],
        "findings": data["findings"],
        "diagnostics": data["diagnostics"],
        "network_calls": data["network_calls"],
        "model_calls": data["model_calls"],
    }


def _check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def _expected_diagnostics(data: dict[str, Any]) -> dict[str, int]:
    """Independently reconcile the artifact's separate count diagnostics."""
    structural = data["structural_consideration"]
    taxonomy = data["taxonomy_correspondence"]
    realization = data["scenario_realization"]
    outcomes = data["proposal_outcomes"]
    findings = data["findings"]
    unresolved = {
        "unresolved_missing_resource_map",
        "unresolved_no_proposal",
        "unresolved_ambiguous",
        "unresolved_rejected_proposals",
    }
    return {
        "structural_ica": sum(row["disposition"] == "ica" for row in structural),
        "structural_justified_na": sum(
            row["disposition"] == "justified_na" for row in structural
        ),
        "structural_unresolved": sum(
            row["disposition"] == "unresolved" for row in structural
        ),
        "taxonomy_satisfied": sum(
            row["correspondence_disposition"] == "satisfied" for row in taxonomy
        ),
        "taxonomy_structurally_inapplicable": sum(
            row["correspondence_disposition"] == "structurally_inapplicable"
            for row in taxonomy
        ),
        "taxonomy_unresolved": sum(
            row["correspondence_disposition"] in unresolved for row in taxonomy
        ),
        "taxonomy_not_applicable": sum(
            row["correspondence_disposition"]
            in {"governance_only", "capability_excluded"}
            for row in taxonomy
        ),
        "unmatched_obligations": sum(
            row["correspondence_disposition"] == "unresolved_no_proposal"
            for row in taxonomy
        ),
        "accepted_relations": len(realization),
        "coverage_bearing_relations": sum(
            row["coverage_bearing"] for row in realization
        ),
        "rejected_proposals": sum(row["status"] == "rejected" for row in outcomes),
        "unresolved_proposals": sum(row["status"] == "unresolved" for row in outcomes),
        "contradictory_findings": sum(
            row["kind"] == "contradictory_proposals" for row in findings
        ),
    }


def main() -> int:
    """Verify the representative output from outside the application package."""
    data = yaml.safe_load(ARTIFACT.read_text(encoding="utf-8"))
    _check(isinstance(data, dict), "artifact is not a mapping")
    _check(
        data["schema_version"] == "hybrid-coverage-assessment-v1",
        "schema version mismatch",
    )
    _check(
        data["semantic_digest"] == _digest(_semantic_payload(data)), "digest mismatch"
    )
    snapshot_digest = data["capability_snapshot_digest"]
    _check(
        isinstance(snapshot_digest, str)
        and len(snapshot_digest) == 64
        and set(snapshot_digest) <= set("0123456789abcdef"),
        "invalid capability snapshot digest",
    )
    _check(
        any(
            pin
            == {
                "artifact_id": "capability-fact-snapshot",
                "schema_version": "capability-fact-snapshot-v1",
                "semantic_digest": snapshot_digest,
            }
            for pin in data["source_pins"]
        ),
        "capability snapshot source pin is missing or substituted",
    )
    matrices = (
        "structural_consideration",
        "taxonomy_correspondence",
        "scenario_realization",
    )
    _check(all(data[name] for name in matrices), "empty normative matrix")
    _check(data["network_calls"] == data["model_calls"] == 0, "nonzero call counter")

    structural = data["structural_consideration"]
    taxonomy = data["taxonomy_correspondence"]
    realization = data["scenario_realization"]
    rows = (*structural, *taxonomy, *realization)
    _check(
        all(row["source_pins"] and row["trace_refs"] for row in rows),
        "untraceable matrix row",
    )
    _check(
        len({row["slot_id"] for row in structural}) == len(structural),
        "duplicate structural slot row",
    )
    _check(
        all(
            (row["disposition"] == "ica") == bool(row["ica_ids"]) and row["evidence"]
            for row in structural
        ),
        "structural disposition/evidence mismatch",
    )
    _check(
        len({row["obligation_id"] for row in taxonomy}) == len(taxonomy),
        "duplicate taxonomy obligation row",
    )
    _check(
        all(
            row["risk_id"]
            and row["attack_pattern_id"]
            and row["taxonomy_candidate_ids"]
            for row in taxonomy
        ),
        "taxonomy authority identity is incomplete",
    )
    _check(
        len({row["relation_id"] for row in realization}) == len(realization),
        "duplicate accepted relation row",
    )
    _check(
        len({row["proposal_id"] for row in realization}) == len(realization),
        "accepted relation does not retain exact proposal support",
    )
    taxonomy_by_obligation = {row["obligation_id"]: row for row in taxonomy}
    _check(
        all(
            row["obligation_id"] in taxonomy_by_obligation
            and row["risk_id"]
            == taxonomy_by_obligation[row["obligation_id"]]["risk_id"]
            and row["attack_pattern_id"]
            == taxonomy_by_obligation[row["obligation_id"]]["attack_pattern_id"]
            and row["taxonomy_candidate_ids"]
            == taxonomy_by_obligation[row["obligation_id"]]["taxonomy_candidate_ids"]
            for row in realization
        ),
        "scenario realization substituted taxonomy authority identity",
    )
    cells = (*data["proposal_outcomes"], *data["findings"])
    _check(
        all(cell["source_pins"] and cell["trace_refs"] for cell in cells),
        "untraceable diagnostic cell",
    )
    _check(
        all(
            cell.get("kind")
            or (
                cell["risk_id"]
                and cell["attack_pattern_id"]
                and cell["taxonomy_candidate_ids"]
            )
            for cell in cells
        ),
        "proposal diagnostic lost taxonomy authority identity",
    )
    _check(
        all(
            row["coverage_bearing"]
            == (row["correspondence_relation_kind"] in COVERAGE_KINDS)
            for row in realization
        ),
        "noncoverage realization misclassified",
    )
    _check(
        all(
            row["hybrid_generation_status"] == "not_attempted"
            and row["hybrid_admission_status"] == "not_assessed"
            for row in realization
        ),
        "legacy scenario observation promoted to hybrid admission",
    )
    taxonomy_relation_ids = {
        relation_id for row in taxonomy for relation_id in row["accepted_relation_ids"]
    }
    realization_relation_ids = {
        row["relation_id"] for row in realization if row["coverage_bearing"]
    }
    _check(
        taxonomy_relation_ids == realization_relation_ids,
        "coverage-bearing relation IDs do not reconcile",
    )
    _check(
        data["diagnostics"] == _expected_diagnostics(data),
        "diagnostics do not reconcile",
    )
    _check(
        not ({"matrix_a", "matrix_b", "matrix_c"} & set(data)),
        "obsolete task-shorthand matrix found",
    )
    _check(
        "score" not in json.dumps(data).lower()
        and "coverage_rate" not in json.dumps(data).lower(),
        "blended score/rate found",
    )
    print("hybrid coverage assessment external QA: 21/21 passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # noqa: BLE001 - external QA diagnostic boundary
        print(f"hybrid coverage assessment external QA: FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
