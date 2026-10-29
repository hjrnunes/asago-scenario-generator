"""The offline specification diagnostics of saved runs."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml

from asago_scenario_generator.models.target_realization import (
    SystemicStpaBaseline,
    TargetRealizationDisposition,
    TargetRealizationResult,
    TargetRealizationRow,
    TargetRealizationSummary,
    canonical_target_realization,
)
from asago_scenario_generator.pipeline.synthesis_manifest import (
    _manifest_artifact_identity,
)
from asago_scenario_generator.pipeline.target_realization import (
    realize_target_derived_icas,
)
from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.models.ica_enumeration import ICAEnumeration
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.stpa.spec_diagnostics import (
    ICA_CHECKS,
    SPEC_DIAGNOSTICS_FILENAME,
    SpecCheck,
    read_spec_diagnostics,
)

from tests.helpers.target_realization import (
    _ExtensionInterpreter,
    _profile,
    _realize,
    _UnmappedInterpreter,
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
        "control_action": "CA-1-1",
        "action_temporality": "discrete",
        "uca_type": "INCORRECT",
        "is_na": False,
        "icas": [
            {
                "ica_id": ica_id,
                "ica_text": "Unsafe",
                "hazardous_context": "Context",
                "loss_scenario": "Scenario",
                "related_hazards": hazards,
                "related_constraints": ["SC-1"],
            }
            for ica_id in ica_ids
        ],
    }


def _realization(hazards: list[str]) -> TargetRealizationResult:
    """A target realization built the way the pipeline builds one."""
    baseline = SystemicStpaBaseline.from_stpa(
        loss_analysis=LossAnalysis.model_validate(_LOSS),
        control_structure=ControlStructure.model_validate(_structure()),
        ica_enumeration=ICAEnumeration.model_validate(
            {"slots": [_slot(_SLOT, [_ICA], hazards)]}
        ),
    )
    rows = tuple(
        TargetRealizationRow(
            control_action_id=action_id,
            controller_id="RESP-1",
            disposition=TargetRealizationDisposition.unmapped,
        )
        for action_id in ("CA-1-1", "CA-1-2")
    )
    realization = canonical_target_realization(
        TargetRealizationResult(
            baseline_id=baseline.baseline_id,
            baseline_digest=baseline.baseline_digest,
            profile_id="profile-fixture",
            profile_digest="d" * 64,
            rows=rows,
            operation_records=(),
            summary=TargetRealizationSummary(
                baseline_control_actions=2,
                observed_operations=0,
                supported=0,
                ambiguous=0,
                unmapped=0,
                contradictory=0,
            ),
        )
    )
    return realize_target_derived_icas(baseline, realization, finder=None)


_SLOT = "RESP-1:CA-1-1:INCORRECT"
_ICA = "RESP-1:CA-1-1:INCORRECT:1"


def _write(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def _pin(artifact_id: str, value: Any) -> dict[str, str]:
    return _manifest_artifact_identity(artifact_id, "", value)


def _run(
    root: Path,
    *,
    target_realization: bool = True,
    loss: dict[str, Any] | None = None,
    structure: dict[str, Any] | None = None,
    realization: TargetRealizationResult | None = None,
) -> Path:
    """A saved run whose final structure carries one enriched description."""
    output = root / "stages" / "generate" / "output"
    loss = loss or _LOSS
    structure = structure or _structure()
    _write(output / "loss-analysis.yaml", loss)
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
    final = copy.deepcopy(structure)
    final["responsibilities"][0]["control_actions"][0]["description"] = (
        "Act (documented operation: op)"
    )
    pins = {
        "final_loss_analysis": _pin(
            "stpa-loss-analysis-final", LossAnalysis.model_validate(loss)
        ),
        "final_control_structure": _pin(
            "stpa-control-structure-final", ControlStructure.model_validate(final)
        ),
    }
    if target_realization:
        realization = realization or _realization(["H-1"])
        (output / "target-realization.yaml").write_text(
            realization.to_yaml(), encoding="utf-8"
        )
        pins["target_realization"] = _pin("target-realization", realization)
    _write(output / "synthesis-manifest.yaml", {"source_artifacts": pins})
    return output


def _target_only_finder(request: Any) -> dict[str, Any]:
    """A deterministic target-derived ICA finder: one verified H-2 finding."""
    slot = next(
        item
        for item in request.target_derived_ica_slots
        if item.uca_type == "INCORRECT"
    )
    return {
        "findings": (
            {
                "slot_id": slot.slot_id,
                "ica_id": f"{slot.slot_id}:1",
                "ica_text": "The target operation is issued unchecked.",
                "deviation": "The operation is issued unchecked.",
                "hazardous_context": "The observed operation is available.",
                "loss_scenario": "An unauthorized payment is scheduled.",
                "related_hazards": ("H-2",),
                "related_constraints": ("SC-2",),
                "verification": {
                    "status": "verified",
                    "detail": "stub target-derived finding verification",
                    "evidence_refs": ("verification:stub",),
                },
            },
        )
    }


def _target_extended_inputs() -> tuple[dict, dict, TargetRealizationResult]:
    """Loss, structure and a realization whose only H-2 ICA is target-derived.

    The target lens adds an action for an uncovered observed operation, and
    the stub finder gives its slot one verified ICA citing H-2, which no
    baseline ICA cites.  SC-2 governs H-2 and RESP-1 cites it, as the
    target-derived compiler requires.
    """
    loss = copy.deepcopy(_LOSS)
    loss["security_constraints"].append(
        {"constraint_id": "SC-2", "rule": "Rule two", "related_hazards": ["H-2"]}
    )
    structure = _structure()
    structure["responsibilities"][0]["security_constraint_refs"] = ["SC-1", "SC-2"]
    baseline = SystemicStpaBaseline.from_stpa(
        loss_analysis=LossAnalysis.model_validate(loss),
        control_structure=ControlStructure.model_validate(structure),
        ica_enumeration=ICAEnumeration.model_validate(
            {"slots": [_slot(_SLOT, [_ICA], ["H-1"])]}
        ),
    )
    extended = _realize(
        baseline,
        _profile(),
        lambda: _UnmappedInterpreter(),
        extension=_ExtensionInterpreter(),
    )
    realization = realize_target_derived_icas(baseline, extended, _target_only_finder)
    return loss, structure, realization


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


def test_a_target_derived_ica_does_not_cover_a_hazard(tmp_path: Path):
    loss, structure, realization = _target_extended_inputs()
    view = realization.effective_view
    assert view is not None
    target_only = [
        ica
        for slot in view.effective_ica_enumeration.slots
        if slot.slot_id not in view.baseline_ica_slot_ids
        for ica in slot.icas
    ]
    assert [ica.related_hazards for ica in target_only] == [("H-2",)]
    _run(tmp_path / "run-a", loss=loss, structure=structure, realization=realization)

    result = _script().diagnose_run(tmp_path / "run-a")

    hazards = [
        f.subject_ids
        for f in result.findings
        if f.check is SpecCheck.hazard_without_ica
    ]
    assert hazards == [("H-2",)]


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


def test_changed_ica_citations_fail_the_integrity_check(tmp_path: Path):
    """Citations edited in place, IDs untouched: the digest no longer holds."""
    output = _run(tmp_path / "run-a")
    path = output / "target-realization.yaml"
    text = path.read_text(encoding="utf-8")
    assert text.count("- H-1") == 1
    path.write_text(text.replace("- H-1", "- H-2"), encoding="utf-8")

    assert "fails its integrity check" in _skip_reason(tmp_path / "run-a")


def test_a_valid_realization_the_manifest_does_not_pin_is_skipped(tmp_path: Path):
    """Same ICA IDs, other citations, a self-consistent digest: not the run's."""
    output = _run(tmp_path / "run-a")
    other = _realization(["H-2"])
    (output / "target-realization.yaml").write_text(other.to_yaml(), encoding="utf-8")

    assert "does not match the manifest's target-realization identity" in (
        _skip_reason(tmp_path / "run-a")
    )


def test_a_manifest_without_its_control_structure_is_skipped(tmp_path: Path):
    output = _run(tmp_path / "run-a")
    (output / "control-structure.yaml").unlink()

    assert "control-structure.yaml cannot be read" in _skip_reason(tmp_path / "run-a")


def test_malformed_yaml_is_skipped(tmp_path: Path):
    output = _run(tmp_path / "run-a")
    (output / "loss-analysis.yaml").write_text("hazards: [unclosed\n", encoding="utf-8")

    assert "loss-analysis.yaml is not valid YAML" in _skip_reason(tmp_path / "run-a")


def test_the_sweep_goes_on_after_unreadable_runs(tmp_path: Path):
    broken = _run(tmp_path / "runs" / "run-a")
    (broken / "control-structure.yaml").unlink()
    bad_yaml = _run(tmp_path / "runs" / "run-b")
    (bad_yaml / "synthesis-manifest.yaml").write_text(": : :\n", encoding="utf-8")
    _run(tmp_path / "runs" / "run-c")

    counts = _script().sweep(
        [tmp_path / "runs" / name for name in ("run-a", "run-b", "run-c")],
        tmp_path / "out",
    )

    assert (counts["diagnosed"], counts["skipped"]) == (1, 2)
    rows = (tmp_path / "out" / "spec-diagnostics-runs.jsonl").read_text()
    assert [json.loads(line)["status"] for line in rows.splitlines()] == [
        "skipped",
        "skipped",
        "diagnosed",
    ]


def _sweep_statuses(tmp_path: Path) -> list[str]:
    _run(tmp_path / "runs" / "run-b")
    counts = _script().sweep(
        [tmp_path / "runs" / "run-a", tmp_path / "runs" / "run-b"], tmp_path / "out"
    )
    assert (counts["diagnosed"], counts["skipped"]) == (1, 1)
    rows = (tmp_path / "out" / "spec-diagnostics-runs.jsonl").read_text()
    return [json.loads(line)["status"] for line in rows.splitlines()]


def test_the_sweep_goes_on_after_a_malformed_target_realization(tmp_path: Path):
    output = _run(tmp_path / "runs" / "run-a")
    (output / "target-realization.yaml").write_text("a: [unclosed\n", encoding="utf-8")

    assert "target-realization.yaml is not valid YAML" in _skip_reason(
        tmp_path / "runs" / "run-a"
    )
    assert _sweep_statuses(tmp_path) == ["skipped", "diagnosed"]


def test_the_sweep_goes_on_after_invalid_utf8(tmp_path: Path):
    output = _run(tmp_path / "runs" / "run-a")
    (output / "control-structure.yaml").write_bytes(b"responsibilities: \xff\n")

    assert "control-structure.yaml is not valid UTF-8" in _skip_reason(
        tmp_path / "runs" / "run-a"
    )
    assert _sweep_statuses(tmp_path) == ["skipped", "diagnosed"]


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


def test_the_sweep_refuses_an_out_dir_that_holds_a_run(tmp_path: Path):
    """The run's own artifact would land at <out-dir>/<label>, inside the run."""
    runs = tmp_path / "runs"
    _run(runs / "run-a")
    before = sorted(runs.rglob("*"))

    with pytest.raises(ValueError, match="inside run run-a"):
        _script().sweep([runs / "run-a"], runs)

    assert sorted(runs.rglob("*")) == before


def test_the_sweep_refuses_colliding_run_names_before_writing(tmp_path: Path):
    _run(tmp_path / "a" / "run")
    _run(tmp_path / "b" / "run")
    out = tmp_path / "out"

    with pytest.raises(ValueError, match="unique"):
        _script().sweep([tmp_path / "a" / "run", tmp_path / "b" / "run"], out)

    assert not out.exists()


def test_feedback_findings_are_split_by_the_actions_they_name(tmp_path: Path):
    """A finding naming a tool call bound to an operation is counted apart."""
    structure = _structure()
    resp = structure["responsibilities"][0]
    resp["control_actions"][1]["operation"] = "op_two"
    resp["control_actions"].append(
        {
            "ca_id": "CA-1-3",
            "description": "Reply",
            "target": {"type": "controlled_process", "id": "CP-3"},
            "effect_kind": "model_output",
            "temporality": "discrete",
            "process_model_refs": ["PM-1-1"],
        }
    )
    structure["controlled_processes"].append({"cp_id": "CP-3", "description": "Three"})
    _run(tmp_path / "runs" / "run-a", structure=structure)
    out = tmp_path / "out"

    counts = _script().sweep([tmp_path / "runs" / "run-a"], out)

    split = {"runs_with_findings": 1, "findings": 1}
    assert counts["feedback_by_action"] == {
        check: {"bound_tool_call": split, "other": split}
        for check in (
            "controlled_process_without_feedback",
            "controlled_process_unobserved",
        )
    }
    rows = [
        json.loads(line)
        for line in (out / "spec-diagnostics-findings.jsonl").read_text().splitlines()
    ]
    actions = {
        tuple(row["subject_ids"]): row["actions"]
        for row in rows
        if row["check"] == "controlled_process_without_feedback"
    }
    assert actions == {
        ("CP-2", "RESP-1", "CA-1-2"): [
            {"ca_id": "CA-1-2", "effect_kind": "tool_call", "operation": "op_two"}
        ],
        ("CP-3", "RESP-1", "CA-1-3"): [
            {"ca_id": "CA-1-3", "effect_kind": "model_output", "operation": None}
        ],
    }
    assert all(
        ("actions" in row) == (row["check"] in counts["feedback_by_action"])
        for row in rows
    )


def test_stage2_only_diagnoses_the_published_stage2_structure(tmp_path: Path):
    """A run stopped after Stage 2 is diagnosed on its Stage 2 artifacts."""
    output = _run(tmp_path / "runs" / "run-a")
    (output / "synthesis-manifest.yaml").unlink()
    (output / "target-realization.yaml").unlink()
    out = tmp_path / "out"

    counts = _script().main(
        ["--stage2-only", "--out-dir", str(out), str(tmp_path / "runs" / "run-a")]
    )

    assert counts == 0
    written = json.loads((out / "spec-diagnostics-counts.json").read_text())
    assert written["diagnosed"] == 1
    assert written["checks"]["controlled_process_unobserved"] == {
        "runs_checked": 1,
        "runs_with_findings": 1,
        "findings": 1,
    }
    assert written["checks"]["hazard_without_ica"]["runs_checked"] == 0
    diagnostics = read_spec_diagnostics(out / "run-a" / SPEC_DIAGNOSTICS_FILENAME)
    reasons = {s.check: s.reason for s in diagnostics.checks}
    assert "Stage 2" in reasons[SpecCheck.hazard_without_ica]
    # Without the flag the same run has no final artifacts to diagnose.
    assert _skip_reason(tmp_path / "runs" / "run-a").startswith("no synthesis manifest")
