"""The slot/hazard check and the coverage diagnostic are counted and shown apart.

The verification batch records both kinds of finding as diagnostics. The
manifest counts each code beside the batch, and the report gives each its own
section and metric.
"""

from __future__ import annotations

import re
from pathlib import Path
from types import SimpleNamespace

from asago_scenario_generator.pipeline.synthesis_manifest import (
    _manifest_provider_evidence,
)
from asago_scenario_generator.report.generate_report import build_report
from asago_scenario_generator.report.run_data import load_run
from asago_scenario_generator.report_kit import read_metrics
from asago_scenario_generator.stpa.models.ica_enumeration import ICAEnumeration
from asago_scenario_generator.stpa.obligation_aware.ica_verification import (
    verify_final_ica_batch,
)
from asago_scenario_generator.stpa.obligation_aware.slot_hazard_ownership import (
    SLOT_HAZARD_MISMATCH_CODE,
    UNINVOKED_HAZARD_OPERATION_CODE,
)
from tests.helpers.generate_report_fixture import copy_run, edit_yaml
from tests.test_ica_slot_hazard_ownership import (
    _Supporting,
    _hazard_text,
    _slot,
    _structure,
)


def _batch():
    """One slot/hazard flag and one coverage finding, on two slots."""
    losses = _hazard_text(
        "A concern reaches neither `escalate_trust_safety` nor `notify_staff`."
    )
    _, batch = verify_final_ica_batch(
        _Supporting(),
        ICAEnumeration(
            slots=[
                _slot("RESP-8", "CA-8-1", "H-3", "SC-1"),
                _slot("RESP-7", "CA-7-2", "H-1", "SC-2"),
            ]
        ),
        loss_analysis=losses,
        control_structure=_structure(),
        operation_inventory=("escalate_trust_safety", "notify_staff"),
    )
    return batch


def _evidence(batch) -> dict:
    stage = SimpleNamespace(call_evidence=(), ica_hazard_verification=batch)
    evidence = _manifest_provider_evidence(
        {"ica": stage}, SimpleNamespace(profile="synthesis")
    )
    return evidence["ica"]


def test_the_manifest_counts_each_check_under_its_own_code() -> None:
    assert _evidence(_batch())["ica_hazard_check_counts"] == {
        SLOT_HAZARD_MISMATCH_CODE: 1,
        UNINVOKED_HAZARD_OPERATION_CODE: 1,
    }


def test_the_manifest_leaves_out_a_zero_count() -> None:
    _, batch = verify_final_ica_batch(
        _Supporting(),
        ICAEnumeration(slots=[_slot("RESP-8", "CA-8-1", "H-3", "SC-1")]),
        loss_analysis=_hazard_text("A concern never reaches `escalate_trust_safety`."),
        control_structure=_structure(),
    )

    assert _evidence(batch)["ica_hazard_check_counts"] == {SLOT_HAZARD_MISMATCH_CODE: 1}


def test_a_batch_with_no_finding_has_no_counts() -> None:
    _, batch = verify_final_ica_batch(
        _Supporting(),
        ICAEnumeration(slots=[_slot("RESP-7", "CA-7-2", "H-3", "SC-1")]),
        loss_analysis=_hazard_text("A concern never reaches `escalate_trust_safety`."),
        control_structure=_structure(),
    )

    assert "ica_hazard_check_counts" not in _evidence(batch)


def test_a_stage_without_verification_has_no_counts() -> None:
    assert "ica_hazard_check_counts" not in _evidence(None)


SLOT_DETAIL = (
    "hazard H-3 depends on `escalate_trust_safety`, but control action CA-8-1 "
    "of slot RESP-8:CA-8-1:NOT_PROVIDED invokes no operation; the owning slot "
    "is RESP-7:CA-7-2:NOT_PROVIDED"
)
COVERAGE_DETAIL = (
    "hazard H-4 names `notify_staff`, but no control action invokes it, so no "
    "slot owns it; ICA RESP-8:CA-8-1:INCORRECT:2 of slot "
    "RESP-8:CA-8-1:INCORRECT cites the hazard"
)


def _report(tmp_path: Path, diagnostics: list[dict]) -> str:
    output = copy_run(tmp_path)

    def add(manifest: dict) -> None:
        verification = manifest["provider_evidence"]["ica"]["ica_hazard_verification"]
        verification["diagnostics"] = diagnostics

    edit_yaml(output / "synthesis-manifest.yaml", add)
    html, _ = build_report(load_run(output))
    return str(html)


def _section(html: str, section_id: str) -> str:
    return html.split(f'<section id="{section_id}">')[1].split("</section>")[0]


def test_the_report_shows_each_check_in_its_own_section(tmp_path: Path) -> None:
    html = _report(
        tmp_path,
        [
            {
                "code": SLOT_HAZARD_MISMATCH_CODE,
                "detail": SLOT_DETAIL,
                "refs": ["RESP-8:CA-8-1:NOT_PROVIDED:1"],
            },
            {
                "code": UNINVOKED_HAZARD_OPERATION_CODE,
                "detail": COVERAGE_DETAIL,
                "refs": ["RESP-8:CA-8-1:INCORRECT:2"],
            },
            {
                "code": UNINVOKED_HAZARD_OPERATION_CODE,
                "detail": COVERAGE_DETAIL.replace(":2", ":3"),
                "refs": ["RESP-8:CA-8-1:INCORRECT:3"],
            },
        ],
    )

    metrics = read_metrics(html)
    assert metrics["slot_hazard.flags"]["value"] == "1"
    assert metrics["coverage.uninvoked_operations"]["value"] == "2"
    slot = _section(html, "slot-hazard-ties")
    coverage = _section(html, "uninvoked-operations")
    assert "RESP-8:CA-8-1:NOT_PROVIDED:1" in slot
    assert "no control action invokes" not in slot
    assert len(re.findall(r'<tr id="slot-hazard-\d+"', slot)) == 1
    assert "RESP-8:CA-8-1:INCORRECT:2" in coverage
    assert "the owning slot" not in coverage
    assert len(re.findall(r'<tr id="uninvoked-operation-\d+"', coverage)) == 2


def test_a_run_with_no_finding_says_so_in_both_sections(tmp_path: Path) -> None:
    html = _report(tmp_path, [])

    metrics = read_metrics(html)
    assert "slot_hazard.flags" not in metrics
    assert "coverage.uninvoked_operations" not in metrics
    assert "No slot/hazard flags." in _section(html, "slot-hazard-ties")
    assert "No hazards naming an operation no action invokes." in _section(
        html, "uninvoked-operations"
    )
