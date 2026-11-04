"""The gate's revision requests and evidence have one runner and one writer.

The density round, the stated-rule round and the graph-revision call send
every Stage 1a revision request from ``loss_analysis_gate_runner``; the
artifact, the round records and the ``rule_span`` repair records are written
by ``loss_analysis_gate_publication``.  The gate keeps the orchestration and
the failure policy, and the old import path keeps working for one cycle.
These cases pin that seam; the per-round behaviour stays covered by
``test_loss_analysis_gates.py``, ``test_loss_analysis_gate_decisions.py`` and
the two graph-revision reply cases.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from asago_scenario_generator.stpa.system_model import (
    loss_analysis_gate_publication,
    loss_analysis_gate_runner,
    loss_analysis_gates,
)
from asago_scenario_generator.stpa.system_model.loss_analysis import (
    RevisionConstraintEdit,
    Stage1aRevisionPatch,
)
from asago_scenario_generator.stpa.system_model.loss_analysis_gate_checks import (
    HazardGraphDensityReport,
    RiskAccountingReport,
)
from asago_scenario_generator.stpa.system_model.loss_analysis_repair import (
    RepairRecord,
)
from asago_scenario_generator.stpa.system_model.rule_span_repair import (
    RuleSpanRepair,
    RuleSpanRepairRecord,
)

# The contract's check: a runner may not borrow a private name from
# ``loss_analysis``, because those names change with the provider models.
PRIVATE_LOSS_ANALYSIS_IMPORT = re.compile(r"from [^\n]*loss_analysis import [^\n]*\b_")


def _density_report(**overrides: object) -> HazardGraphDensityReport:
    fields: dict[str, object] = {
        "losses_without_hazard": ("L-2",),
        "constraints_without_hazard": (),
        "hazards_without_constraint": (),
        "subject_checks": (),
        "class_own_hazard_checks": (),
        "constraint_classes": (("SC-1", "disclosure"),),
        "unclassified_constraints": (),
    }
    fields.update(overrides)
    return HazardGraphDensityReport(**fields)  # type: ignore[arg-type]


def _accounting_report() -> RiskAccountingReport:
    return RiskAccountingReport(
        missing_dispositions=(),
        unaccounted_risk_refs=(),
        not_applicable_refs=(),
        cited_refs=("atlas-001",),
    )


def test_the_gate_delegates_each_revision_call_to_the_runner() -> None:
    for name in (
        "_run_density_revision",
        "_run_stated_rule_revision",
        "_run_graph_revision_call",
    ):
        assert getattr(loss_analysis_gate_runner, name) is getattr(
            loss_analysis_gates, name
        ), name


def test_the_gate_keeps_the_old_import_path_for_the_round_machinery() -> None:
    for name in (
        "GRAPH_REVISION_ROUNDS",
        "REVISION_CORRECTION_FEEDBACK",
        "REVISION_CORRECTION_SCOPE",
        "StatedRuleCheck",
        "_RevisionAttempt",
        "_addition_only_constraint_edit",
        "_draft_from_analysis",
        "_revised_analysis",
        "_revision_patch_to_draft",
        "_revision_policy",
        "_run_graph_revision_call",
        "_run_stated_rule_revision",
        "_unknown_edit_targets",
        "_validate_revision",
    ):
        assert getattr(loss_analysis_gate_runner, name) is getattr(
            loss_analysis_gates, name
        ), name
    assert loss_analysis_gates._RevisionConstraintEdit is RevisionConstraintEdit
    assert loss_analysis_gates._Stage1aRevisionPatch is Stage1aRevisionPatch


def test_the_runner_imports_no_private_loss_analysis_name() -> None:
    source = Path(loss_analysis_gate_runner.__file__).read_text()

    assert PRIVATE_LOSS_ANALYSIS_IMPORT.findall(source) == []


def test_the_publication_module_imports_no_private_loss_analysis_name() -> None:
    source = Path(loss_analysis_gate_publication.__file__).read_text()

    assert PRIVATE_LOSS_ANALYSIS_IMPORT.findall(source) == []


def test_the_publication_writes_the_gates_artifact(tmp_path: Path) -> None:
    loss_analysis_gate_publication.write_gates_artifact(
        tmp_path,
        accounting=_accounting_report(),
        density=_density_report(),
        failing_checks=["loss L-2 has no hazard"],
        revision_attempted=True,
        revision_applied=False,
        normalization_warnings=["normalized atlas-001"],
        revision_call_count=2,
        revision_rounds=[{"round": 1, "revision_valid": False}],
    )

    artifact = yaml.safe_load(
        (tmp_path / "loss-analysis-gates.yaml").read_text(encoding="utf-8")
    )
    assert artifact["revision_attempted"] is True
    assert artifact["revision_applied"] is False
    assert artifact["revision_call_count"] == 2
    assert artifact["failing_checks"] == ["loss L-2 has no hazard"]
    assert artifact["hazard_graph_density"]["losses_without_hazard"] == ["L-2"]
    assert artifact["normalization_warnings"] == ["normalized atlas-001"]
    assert artifact["revision_rounds"] == [{"round": 1, "revision_valid": False}]
    assert artifact["passed"] is False


def test_the_publication_records_a_failed_round_as_invalid() -> None:
    record = loss_analysis_gate_publication.revision_round_record(
        2,
        before=_density_report(),
        after=None,
        original=_density_report(losses_without_hazard=()),
    )

    assert record == {
        "round": 2,
        "failing_checks_before": ["loss L-2 has no hazard"],
        "failing_checks_after": [],
        "introduced_checks": [],
        "revision_valid": False,
    }


def test_the_publication_marks_only_the_final_attempts_repairs_applied(
    tmp_path: Path,
) -> None:
    repair_record = RepairRecord()
    repair = RuleSpanRepairRecord(
        constraint="SC-1",
        obligation_id="O-1",
        repair=RuleSpanRepair(
            kind="whitespace", original="do not disclose", repaired="Do not disclose"
        ),
    )

    loss_analysis_gate_publication.write_revision_span_repairs(
        repair_record,
        tmp_path,
        [[], [repair]],
        accepted=True,
    )

    artifact = yaml.safe_load(
        (tmp_path / "loss-analysis-repair.yaml").read_text(encoding="utf-8")
    )
    assert [(row["attempt"], row["outcome"]) for row in artifact["records"]] == [
        ("correction", "applied")
    ]
