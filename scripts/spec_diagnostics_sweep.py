#!/usr/bin/env python3
"""Compute the report-only specification diagnostics of saved runs.

    uv run --frozen python scripts/spec_diagnostics_sweep.py --out-dir DIR \\
        RUN_DIR [RUN_DIR ...]

Offline: the script reads saved files, writes only to ``--out-dir``, and calls
no model.  Each ``RUN_DIR`` is a producer output directory, or a directory
holding exactly one (found by its ``loss-analysis.yaml``); its name labels the
run, and labels must be unique.  Every path the script writes must lie
outside every run; otherwise it writes nothing.

A run is diagnosed on its final artifacts, each checked against the identity
``synthesis-manifest.yaml`` pins for it:

- the final loss analysis is ``loss-analysis.yaml``;
- the final control structure is ``control-structure-final.yaml`` when a
  structural revision applied, otherwise ``control-structure.yaml`` with the
  descriptions ``control-action-enrichment.yaml`` records;
- the retained ICAs are the baseline slots of the effective view in
  ``target-realization.yaml``, loaded with its integrity check
  (``TargetRealizationResult.from_yaml``) and matched to the manifest's
  ``target_realization`` identity.  The snapshot omits each ICA's
  ``process_model_context``, which no check reads.  Without the file the ICA
  checks are recorded as not run.

A run that lacks a final artifact, whose artifact cannot be read or parsed,
fails its check, or does not load under the current schema, is skipped with
the reason, and the sweep goes on to the next run.

Outputs in ``--out-dir``:

- ``<label>/spec-diagnostics.yaml``: the artifact a run would write;
- ``spec-diagnostics-runs.jsonl``: one row per run, diagnosed or skipped;
- ``spec-diagnostics-findings.jsonl``: one row per (run, finding);
- ``spec-diagnostics-counts.json``: per check, the runs it ran on, the runs
  with a finding, and the findings.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from asago_scenario_generator.models.target_realization import (
    TargetRealizationResult,
)
from asago_scenario_generator.pipeline.synthesis_manifest import (
    _manifest_artifact_identity,
)
from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.models.ica_enumeration import ICAEnumeration
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.stpa.spec_diagnostics import (
    SPEC_DIAGNOSTICS_FILENAME,
    SpecCheck,
    SpecDiagnostics,
    diagnose_final_artifacts,
    write_spec_diagnostics,
)

MANIFEST = "synthesis-manifest.yaml"
LOSS = "loss-analysis.yaml"
STRUCTURE = "control-structure.yaml"
FINAL_STRUCTURE = "control-structure-final.yaml"
ENRICHMENT = "control-action-enrichment.yaml"
TARGET_REALIZATION = "target-realization.yaml"
RUN_MANIFEST = "run-manifest.yaml"


class Skip(Exception):
    """A run that cannot be diagnosed, with the reason."""


@dataclass(frozen=True)
class FinalArtifacts:
    loss_analysis: LossAnalysis
    control_structure: ControlStructure
    ica_enumeration: ICAEnumeration | None
    ica_unavailable_reason: str


def find_output_dir(run_dir: Path) -> Path:
    """Return the producer output directory of *run_dir*."""
    if (run_dir / LOSS).is_file() or (run_dir / MANIFEST).is_file():
        return run_dir
    found = sorted({path.parent for path in run_dir.rglob(LOSS)})
    if not found:
        raise Skip("no producer output: no loss analysis was published")
    if len(found) > 1:
        raise Skip(f"{len(found)} producer output directories; expected one")
    return found[0]


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise Skip(f"{path.name} cannot be read: {exc.strerror or exc}") from exc


def _read(path: Path) -> Any:
    try:
        return yaml.safe_load(_read_text(path))
    except yaml.YAMLError as exc:
        first = str(exc).splitlines()[0]
        raise Skip(f"{path.name} is not valid YAML: {first}") from exc


def _read_mapping(path: Path) -> dict[str, Any]:
    data = _read(path)
    if not isinstance(data, dict):
        raise Skip(f"{path.name} is not a mapping")
    return data


def _load(model: type, data: Any, name: str) -> Any:
    try:
        return model.model_validate(data)
    except ValidationError as exc:
        first = str(exc).splitlines()[0]
        raise Skip(f"{name} does not load under the current schema: {first}") from exc


def _check_identity(value: Any, artifact_id: str, pinned: Any, name: str) -> None:
    digest = _manifest_artifact_identity(artifact_id, "", value)["semantic_digest"]
    expected = pinned.get("semantic_digest") if isinstance(pinned, dict) else None
    if digest != expected:
        raise Skip(f"{name} does not match the manifest's {artifact_id} identity")


def _final_structure(output: Path) -> tuple[Any, str]:
    if (output / FINAL_STRUCTURE).is_file():
        return _read_mapping(output / FINAL_STRUCTURE), FINAL_STRUCTURE
    raw = _read_mapping(output / STRUCTURE)
    if not (output / ENRICHMENT).is_file():
        return raw, STRUCTURE
    try:
        enriched = {
            row["control_action_id"]: row["enriched_description"]
            for row in _read_mapping(output / ENRICHMENT).get("rows") or []
            if row.get("enriched") is True
        }
        for responsibility in raw.get("responsibilities") or []:
            for action in responsibility.get("control_actions") or []:
                if action.get("ca_id") in enriched:
                    action["description"] = enriched[action["ca_id"]]
    except (AttributeError, KeyError, TypeError) as exc:
        raise Skip(f"{ENRICHMENT} or {STRUCTURE} is malformed: {exc!r}") from exc
    return raw, f"{STRUCTURE} + {ENRICHMENT}"


def _retained_icas(output: Path, pinned: dict[str, Any]) -> ICAEnumeration | None:
    if not (output / TARGET_REALIZATION).is_file():
        return None
    try:
        realization = TargetRealizationResult.from_yaml(
            _read_text(output / TARGET_REALIZATION)
        )
    except (ValueError, TypeError) as exc:
        first = str(exc).splitlines()[0]
        raise Skip(f"{TARGET_REALIZATION} fails its integrity check: {first}") from exc
    _check_identity(
        realization,
        "target-realization",
        pinned.get("target_realization"),
        TARGET_REALIZATION,
    )
    view = realization.effective_view
    if view is None:
        raise Skip(f"{TARGET_REALIZATION} has no effective view")
    baseline_slots = set(view.baseline_ica_slot_ids)
    slots = [
        slot.model_dump(mode="json")
        for slot in view.effective_ica_enumeration.slots
        if slot.slot_id in baseline_slots
    ]
    icas = _load(ICAEnumeration, {"slots": slots}, TARGET_REALIZATION)
    ids = {ica.ica_id for slot in icas.slots for ica in slot.icas}
    if ids != set(view.baseline_ica_ids):
        raise Skip(f"{TARGET_REALIZATION} baseline ICAs do not match its ICA IDs")
    return icas


def _first_stage_error(output: Path) -> str:
    """Name the step and error type of the run's first recorded stage error."""
    path = output / RUN_MANIFEST
    try:
        errors = _read_mapping(path).get("stage_errors") if path.is_file() else None
    except Skip:
        return ""
    if not isinstance(errors, list) or not errors:
        return ""
    step, _, rest = str(errors[0]).partition(": ")
    kind = rest.partition(":")[0].strip()
    return f" (first stage error: {step}: {kind})" if kind else f" ({step})"


def load_final_artifacts(output: Path) -> FinalArtifacts:
    """Load and check a saved run's final artifacts, or raise :class:`Skip`."""
    if not (output / MANIFEST).is_file():
        if not (output / STRUCTURE).is_file():
            reason = (
                "no control structure: the run stopped before Stage 2 published one"
            )
        else:
            reason = "no synthesis manifest: the run stopped before its final artifacts"
        raise Skip(reason + _first_stage_error(output))
    if not (output / LOSS).is_file():
        raise Skip(f"the synthesis manifest has no {LOSS} beside it")
    pinned = _read_mapping(output / MANIFEST).get("source_artifacts") or {}
    if not isinstance(pinned, dict):
        raise Skip(f"{MANIFEST} has no source_artifacts mapping")
    loss = _load(LossAnalysis, _read(output / LOSS), LOSS)
    _check_identity(
        loss, "stpa-loss-analysis-final", pinned.get("final_loss_analysis"), LOSS
    )
    raw, name = _final_structure(output)
    structure = _load(ControlStructure, raw, name)
    _check_identity(
        structure,
        "stpa-control-structure-final",
        pinned.get("final_control_structure"),
        name,
    )
    icas = _retained_icas(output, pinned)
    return FinalArtifacts(
        loss_analysis=loss,
        control_structure=structure,
        ica_enumeration=icas,
        ica_unavailable_reason=f"the run persisted no {TARGET_REALIZATION}",
    )


def diagnose_run(run_dir: Path) -> SpecDiagnostics:
    """Diagnose one saved run, or raise :class:`Skip` with the reason."""
    final = load_final_artifacts(find_output_dir(run_dir))
    return diagnose_final_artifacts(
        loss_analysis=final.loss_analysis,
        control_structure=final.control_structure,
        ica_enumeration=final.ica_enumeration,
        ica_unavailable_reason=final.ica_unavailable_reason,
    )


def _counts(results: dict[str, SpecDiagnostics]) -> dict[str, Any]:
    counts: dict[str, Any] = {}
    for check in SpecCheck:
        ran = [
            label
            for label, result in results.items()
            if any(s.check is check and s.status == "run" for s in result.checks)
        ]
        per_run = {
            label: sum(f.check is check for f in results[label].findings)
            for label in ran
        }
        counts[check.value] = {
            "runs_checked": len(ran),
            "runs_with_findings": sum(1 for n in per_run.values() if n),
            "findings": sum(per_run.values()),
        }
    return counts


def sweep(run_dirs: list[Path], out_dir: Path) -> dict[str, Any]:
    """Diagnose every run into *out_dir* and return the counts."""
    labels = [run_dir.name for run_dir in run_dirs]
    if len(set(labels)) != len(labels):
        raise ValueError("run directory names must be unique")
    _refuse_writes_inside_runs(_destinations(out_dir, labels), run_dirs)
    out_dir.mkdir(parents=True, exist_ok=True)
    results: dict[str, SpecDiagnostics] = {}
    run_rows: list[dict[str, Any]] = []
    finding_rows: list[dict[str, Any]] = []
    for label, run_dir in zip(labels, run_dirs, strict=True):
        try:
            result = diagnose_run(run_dir)
        except Skip as skip:
            run_rows.append({"run": label, "status": "skipped", "reason": str(skip)})
            continue
        results[label] = result
        write_spec_diagnostics(out_dir / label, result)
        run_rows.append(
            {
                "run": label,
                "status": "diagnosed",
                "checks": {
                    s.check.value: s.findings if s.status == "run" else None
                    for s in result.checks
                },
            }
        )
        finding_rows.extend(
            {"run": label, **finding.model_dump(mode="json")}
            for finding in result.findings
        )
    counts = {
        "runs": len(run_rows),
        "diagnosed": len(results),
        "skipped": len(run_rows) - len(results),
        "checks": _counts(results),
    }
    _write_jsonl(out_dir / RUNS_FILE, run_rows)
    _write_jsonl(out_dir / FINDINGS_FILE, finding_rows)
    (out_dir / COUNTS_FILE).write_text(
        json.dumps(counts, indent=2) + "\n", encoding="utf-8"
    )
    return counts


RUNS_FILE = "spec-diagnostics-runs.jsonl"
FINDINGS_FILE = "spec-diagnostics-findings.jsonl"
COUNTS_FILE = "spec-diagnostics-counts.json"


def _destinations(out_dir: Path, labels: list[str]) -> list[Path]:
    """Every directory and file the sweep may create, before it writes."""
    paths = [
        out_dir,
        *(out_dir / name for name in (RUNS_FILE, FINDINGS_FILE, COUNTS_FILE)),
    ]
    for label in labels:
        paths += [out_dir / label, out_dir / label / SPEC_DIAGNOSTICS_FILENAME]
    return paths


def _refuse_writes_inside_runs(destinations: list[Path], run_dirs: list[Path]) -> None:
    runs = [(run_dir.name, run_dir.resolve()) for run_dir in run_dirs]
    for destination in destinations:
        resolved = destination.resolve()
        for name, run in runs:
            if resolved.is_relative_to(run):
                raise ValueError(f"{destination} lies inside run {name}")


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compute the specification diagnostics of saved runs."
    )
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("run_dirs", type=Path, nargs="+")
    args = parser.parse_args(argv)
    counts = sweep(args.run_dirs, args.out_dir)
    json.dump(counts, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
