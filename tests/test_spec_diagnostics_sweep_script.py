"""The offline specification diagnostics of saved runs."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml

from asago_scenario_generator.pipeline.synthesis_manifest import (
    _manifest_artifact_identity,
)
from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.stpa.spec_diagnostics import (
    ICA_CHECKS,
    SPEC_DIAGNOSTICS_FILENAME,
    SpecCheck,
    read_spec_diagnostics,
)

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "spec_diagnostics_sweep.py"


def _script() -> ModuleType:
    name = "spec_diagnostics_sweep_script"
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, _SCRIPT)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name]


_LOSS = {
    "risk_card_losses": [],
    "use_case_losses": [
        {"loss_id": "L-1", "description": "Loss", "provenance": "use_case"}
    ],
    "hazards": [
        {"hazard_id": "H-1", "description": "One", "related_losses": ["L-1"]},
        {"hazard_id": "H-2", "description": "Two", "related_losses": ["L-1"]},
    ],
    "security_constraints": [
        {"constraint_id": "SC-1", "rule": "Rule", "related_hazards": ["H-1"]}
    ],
}


def _structure() -> dict[str, Any]:
    """CA-1-2 acts on CP-2, which no channel observes."""
    cp = {"type": "controlled_process", "id": "CP-1"}
    return {
        "responsibilities": [
            {
                "resp_id": "RESP-1",
                "description": "Controller",
                "process_model_parts": [
                    {"pm_id": "PM-1-1", "description": "State", "values": ["a"]}
                ],
                "control_actions": [
                    {
                        "ca_id": "CA-1-1",
                        "description": "Act",
                        "target": cp,
                        "effect_kind": "tool_call",
                        "temporality": "discrete",
                        "process_model_refs": ["PM-1-1"],
                    },
                    {
                        "ca_id": "CA-1-2",
                        "description": "Act again",
                        "target": {"type": "controlled_process", "id": "CP-2"},
                        "effect_kind": "tool_call",
                        "temporality": "discrete",
                        "process_model_refs": ["PM-1-1"],
                    },
                ],
                "feedback_channels": [
                    {
                        "fb_id": "FB-1-1",
                        "description": "Observe",
                        "updates": "PM-1-1",
                        "source": cp,
                    }
                ],
            }
        ],
        "controlled_processes": [
            {"cp_id": "CP-1", "description": "One"},
            {"cp_id": "CP-2", "description": "Two"},
        ],
    }


def _slot(slot_id: str, ica_ids: list[str], hazards: list[str]) -> dict[str, Any]:
    return {
        "slot_id": slot_id,
        "responsibility": "RESP-1",
        "coordination_link": None,
        "control_action": "CA-1-1",
        "action_temporality": "discrete",
        "uca_type": "INCORRECT",
        "is_na": False,
        "na_justification": None,
        "unresolved_reason": None,
        "icas": [
            {
                "ica_id": ica_id,
                "ica_text": "Unsafe",
                "deviation": None,
                "hazardous_context": "Context",
                "loss_scenario": "Scenario",
                "related_hazards": hazards,
                "related_constraints": ["SC-1"],
                "quality_warnings": [],
            }
            for ica_id in ica_ids
        ],
    }


def _write(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def _pin(artifact_id: str, value: Any) -> dict[str, str]:
    return _manifest_artifact_identity(artifact_id, "", value)


def _run(root: Path, *, target_realization: bool = True) -> Path:
    """A saved run whose final structure carries one enriched description."""
    output = root / "stages" / "generate" / "output"
    structure = _structure()
    _write(output / "loss-analysis.yaml", _LOSS)
    _write(output / "control-structure.yaml", structure)
    _write(
        output / "control-action-enrichment.yaml",
        {
            "rows": [
                {
                    "control_action_id": "CA-1-1",
                    "enriched": True,
                    "enriched_description": "Act (documented operation: op)",
                },
                {"control_action_id": "CA-1-2", "enriched": False},
            ]
        },
    )
    final = _structure()
    final["responsibilities"][0]["control_actions"][0]["description"] = (
        "Act (documented operation: op)"
    )
    _write(
        output / "synthesis-manifest.yaml",
        {
            "source_artifacts": {
                "final_loss_analysis": _pin(
                    "stpa-loss-analysis-final", LossAnalysis.model_validate(_LOSS)
                ),
                "final_control_structure": _pin(
                    "stpa-control-structure-final",
                    ControlStructure.model_validate(final),
                ),
            }
        },
    )
    if target_realization:
        _write(
            output / "target-realization.yaml",
            {
                "effective_view": {
                    "baseline_ica_slot_ids": ["RESP-1:CA-1-1:INCORRECT"],
                    "baseline_ica_ids": ["RESP-1:CA-1-1:INCORRECT:1"],
                    "effective_ica_enumeration": {
                        "slots": [
                            _slot(
                                "RESP-1:CA-1-1:INCORRECT",
                                ["RESP-1:CA-1-1:INCORRECT:1"],
                                ["H-1"],
                            ),
                            # Target-derived: outside the retained ICAs.
                            _slot("RESP-1:CA-9-1:INCORRECT", ["X:1"], ["H-2"]),
                        ]
                    },
                }
            },
        )
    return output


def _counts(result: Any) -> dict[SpecCheck, int]:
    return {s.check: s.findings for s in result.checks if s.status == "run"}


def test_a_saved_run_is_diagnosed_on_its_verified_final_artifacts(tmp_path: Path):
    _run(tmp_path / "run-a")

    result = _script().diagnose_run(tmp_path / "run-a")

    assert _counts(result) == {
        SpecCheck.controlled_process_without_feedback: 1,
        SpecCheck.controlled_process_unobserved: 1,
        SpecCheck.hazard_without_ica: 1,
        SpecCheck.action_without_process_model_refs: 0,
        SpecCheck.process_model_variable_without_values: 0,
        SpecCheck.ica_without_related_constraints: 0,
        SpecCheck.hazard_without_constraint: 1,
    }
    [hazard] = [f for f in result.findings if f.check is SpecCheck.hazard_without_ica]
    assert hazard.subject_ids == ("H-2",)


def test_without_a_target_realization_the_ica_checks_do_not_run(tmp_path: Path):
    _run(tmp_path / "run-a", target_realization=False)

    result = _script().diagnose_run(tmp_path / "run-a")

    assert {s.check for s in result.checks if s.status == "not_run"} == set(ICA_CHECKS)


def _skip_reason(run_dir: Path) -> str:
    script = _script()
    with pytest.raises(script.Skip) as caught:
        script.diagnose_run(run_dir)
    return str(caught.value)


def test_a_run_without_producer_output_is_skipped(tmp_path: Path):
    (tmp_path / "empty").mkdir()

    assert "no producer output" in _skip_reason(tmp_path / "empty")


def test_a_run_stopped_before_stage_2_is_skipped_with_its_first_error(
    tmp_path: Path,
):
    output = tmp_path / "run-a"
    _write(output / "loss-analysis.yaml", _LOSS)
    _write(
        output / "run-manifest.yaml",
        {"stage_errors": ["stage_2/call_1: LiveRequestBudgetError: spent"]},
    )

    reason = _skip_reason(output)

    assert reason.startswith("no control structure")
    assert "stage_2/call_1: LiveRequestBudgetError" in reason


def test_a_run_without_a_synthesis_manifest_is_skipped(tmp_path: Path):
    output = _run(tmp_path / "run-a")
    (output / "synthesis-manifest.yaml").unlink()

    assert _skip_reason(tmp_path / "run-a").startswith("no synthesis manifest")


def test_a_structure_that_is_not_the_pinned_final_one_is_skipped(tmp_path: Path):
    output = _run(tmp_path / "run-a")
    (output / "control-action-enrichment.yaml").unlink()

    assert "does not match the manifest" in _skip_reason(tmp_path / "run-a")


def test_an_artifact_of_an_older_schema_is_skipped_not_adapted(tmp_path: Path):
    output = _run(tmp_path / "run-a")
    structure = _structure()
    structure["responsibilities"][0]["control_actions"][0]["action_id"] = "CA-1-1"
    del structure["responsibilities"][0]["control_actions"][0]["ca_id"]
    _write(output / "control-structure.yaml", structure)

    assert "does not load under the current schema" in _skip_reason(tmp_path / "run-a")


def test_baseline_icas_that_disagree_with_the_view_are_skipped(tmp_path: Path):
    output = _run(tmp_path / "run-a")
    document = yaml.safe_load((output / "target-realization.yaml").read_text())
    document["effective_view"]["baseline_ica_ids"].append("RESP-1:CA-1-1:INCORRECT:2")
    _write(output / "target-realization.yaml", document)

    assert "baseline ICAs do not match" in _skip_reason(tmp_path / "run-a")


def test_the_sweep_writes_only_to_the_out_dir(tmp_path: Path):
    _run(tmp_path / "runs" / "run-a")
    (tmp_path / "runs" / "run-b").mkdir()
    before = sorted(p for p in (tmp_path / "runs").rglob("*"))
    out = tmp_path / "out"

    counts = _script().sweep(
        [tmp_path / "runs" / "run-a", tmp_path / "runs" / "run-b"], out
    )

    assert sorted(p for p in (tmp_path / "runs").rglob("*")) == before
    assert counts["diagnosed"] == 1 and counts["skipped"] == 1
    assert counts["checks"]["hazard_without_ica"] == {
        "runs_checked": 1,
        "runs_with_findings": 1,
        "findings": 1,
    }
    assert read_spec_diagnostics(out / "run-a" / SPEC_DIAGNOSTICS_FILENAME)
    rows = [
        json.loads(line)
        for line in (out / "spec-diagnostics-runs.jsonl").read_text().splitlines()
    ]
    assert [(row["run"], row["status"]) for row in rows] == [
        ("run-a", "diagnosed"),
        ("run-b", "skipped"),
    ]
    findings = (out / "spec-diagnostics-findings.jsonl").read_text().splitlines()
    assert len(findings) == 4
    assert json.loads((out / "spec-diagnostics-counts.json").read_text()) == counts


def test_the_sweep_refuses_an_out_dir_inside_a_run(tmp_path: Path):
    _run(tmp_path / "run-a")

    with pytest.raises(ValueError, match="inside run run-a"):
        _script().sweep([tmp_path / "run-a"], tmp_path / "run-a" / "out")


def test_the_sweep_requires_unique_run_names(tmp_path: Path):
    with pytest.raises(ValueError, match="unique"):
        _script().sweep([tmp_path / "a" / "run", tmp_path / "b" / "run"], tmp_path)
