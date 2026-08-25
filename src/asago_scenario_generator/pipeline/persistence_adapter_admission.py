"""Terminal admission evidence assembly helpers."""

from __future__ import annotations

from typing import Any

from asago_scenario_generator.pipeline.finalization_contracts import (
    CandidateTerminalStatus,
)
from asago_scenario_generator.pipeline.finalization_admission import (
    PostbehaviorAdmissionReport,
)
from .persistence_evidence import _gate_report_records
from .persistence_journal import AdmittedTerminalPayload
from .persistence_models import GateResultRecord, ViolationRecord
from .persistence_adapter_state import _violations


def _expected_admitted(status: object) -> bool:
    return status is CandidateTerminalStatus.admitted


def _admission_agreement_valid(result: object, expected_admitted: bool) -> None:
    if result.admission is not None and result.admission.admitted != expected_admitted:
        raise TypeError("terminal status and AdmissionDecision.admitted must agree")


def _admitted_payload(
    result: object, admission_value: Any
) -> tuple[AdmittedTerminalPayload, PostbehaviorAdmissionReport]:
    if type(admission_value) is not AdmittedTerminalPayload:
        raise TypeError("admitted result requires typed report and publication payload")
    terminal_payload = admission_value
    return terminal_payload, terminal_payload.report


def _rejection_report(
    result: object, admission_value: Any
) -> PostbehaviorAdmissionReport | None:
    if result.admission is None:
        return None
    if type(admission_value) is not PostbehaviorAdmissionReport:
        raise TypeError("postbehavior rejection requires PostbehaviorAdmissionReport")
    return admission_value


def _report_violations_agree(
    gate_results: list[GateResultRecord], serialized_violations: list[ViolationRecord]
) -> None:
    if [
        violation for gate in gate_results for violation in gate.violations
    ] != serialized_violations:
        raise TypeError("typed admission report and terminal violations must agree")


def _admitted_gate_report_valid(
    gate_results: list[GateResultRecord],
    serialized_violations: list[ViolationRecord],
) -> None:
    if (
        not gate_results
        or any(not gate.passed for gate in gate_results)
        or serialized_violations
    ):
        raise TypeError("admitted result requires nonempty passing gate report")


def _terminal_report_for(
    result: object, admission_value: Any
) -> tuple[AdmittedTerminalPayload | None, PostbehaviorAdmissionReport | None]:
    if result.status is CandidateTerminalStatus.admitted:
        return _admitted_payload(result, admission_value)
    return None, _rejection_report(result, admission_value)


def _gate_records_and_agreement(
    report: PostbehaviorAdmissionReport | None,
    serialized_violations: list[ViolationRecord],
) -> list[GateResultRecord]:
    if report is None:
        return []
    gate_results = _gate_report_records(report)
    _report_violations_agree(gate_results, serialized_violations)
    return gate_results


def _admission_payload(
    result: object, candidate_id: str
) -> tuple[
    AdmittedTerminalPayload | None,
    PostbehaviorAdmissionReport | None,
    list[GateResultRecord],
    list[ViolationRecord],
    bool,
]:
    """Extract and validate the typed terminal evidence for one decision."""
    if result.candidate_id != candidate_id:
        raise ValueError("candidate terminal result identity mismatch")
    admission_value = result.admission.value if result.admission is not None else None
    expected_admitted = _expected_admitted(result.status)
    _admission_agreement_valid(result, expected_admitted)
    terminal_payload, report = _terminal_report_for(result, admission_value)
    serialized_violations = _violations(result.violations)
    gate_results = _gate_records_and_agreement(report, serialized_violations)
    if expected_admitted:
        _admitted_gate_report_valid(gate_results, serialized_violations)
    return (
        terminal_payload,
        report,
        gate_results,
        serialized_violations,
        expected_admitted,
    )
