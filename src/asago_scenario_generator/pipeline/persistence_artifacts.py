"""Artifact receipt contracts and terminal receipt projections."""

from __future__ import annotations

from pathlib import PurePosixPath

from pydantic import Field, field_validator, model_validator

from asago_scenario_generator.manifest import ArtifactRole
from asago_scenario_generator.pipeline.finalization_contracts import (
    CandidateTerminalStatus,
)
from asago_scenario_generator.pipeline.finalization_gates import (
    CONDITIONALLY_APPLICABLE_EVIDENCE_IDS,
    DIAGNOSTIC_BACKED_EVIDENCE_IDS,
    EXCEPTIONAL_ADMISSION_EVIDENCE_IDS,
    NORMAL_POSTBEHAVIOR_EVIDENCE_IDS,
)
from .persistence_common import SHA256_PATTERN
from .persistence_plan import StrictModel


def _path_component_safe(value: str) -> bool:
    path = PurePosixPath(value)
    return ".." in path.parts or "." in path.parts or "\\" in value


class ArtifactReceipt(StrictModel):
    candidate_id: str = Field(min_length=1)
    role: ArtifactRole
    path: str = Field(min_length=1)
    sha256: str = Field(pattern=SHA256_PATTERN)
    scenario_id: str | None

    @field_validator("path")
    @classmethod
    def _canonical_path(cls, value: str) -> str:
        path = PurePosixPath(value)
        if (
            not value
            or path.is_absolute()
            or path.as_posix() != value
            or _path_component_safe(value)
        ):
            raise ValueError("artifact receipt path must be canonical and relative")
        return value

    @model_validator(mode="after")
    def _role_identity(self) -> ArtifactReceipt:
        if self.role in {ArtifactRole.SCENARIO_YAML, ArtifactRole.SCENARIO_FEATURE}:
            if not self.scenario_id:
                raise ValueError("normal scenario receipts require scenario_id")
        elif self.role is ArtifactRole.QUARANTINE_BUNDLE:
            if self.scenario_id is not None:
                raise ValueError("quarantine receipts forbid scenario_id")
        else:
            raise ValueError("unsupported finalization artifact receipt role")
        return self


def _admitted_flag_matches(status: object, admitted: bool) -> None:
    if admitted != (status is CandidateTerminalStatus.admitted):
        raise ValueError("admitted flag must match terminal candidate status")


def _gate_evidence_unique(gate_results: list[object]) -> None:
    evidence_ids = [gate.gate for gate in gate_results]
    if len(evidence_ids) != len(set(evidence_ids)):
        raise ValueError("admission evidence IDs must be unique")


def _exceptional_evidence_singleton(evidence_ids: list[object]) -> None:
    exceptional = set(evidence_ids) & EXCEPTIONAL_ADMISSION_EVIDENCE_IDS
    if exceptional and len(evidence_ids) != 1:
        raise ValueError("exceptional admission evidence must be a singleton")


def _admitted_canonical_evidence(admitted: bool, evidence_ids: list[object]) -> None:
    if admitted and set(evidence_ids) != set(NORMAL_POSTBEHAVIOR_EVIDENCE_IDS):
        raise ValueError("admitted decision requires canonical gate evidence")


def _admitted_gate_applicability(admitted: bool, gate_results: list[object]) -> None:
    if admitted and any(
        not gate.applicable
        for gate in gate_results
        if gate.gate not in CONDITIONALLY_APPLICABLE_EVIDENCE_IDS
    ):
        raise ValueError("intrinsic admitted evidence must be applicable")


def _authoritative_violations(gate_results: list[object]) -> list[object]:
    return [violation for gate in gate_results for violation in gate.violations]


def _category_diagnostics(gate_results: list[object]) -> list[object]:
    return [
        diagnostic
        for gate in gate_results
        if gate.gate in DIAGNOSTIC_BACKED_EVIDENCE_IDS
        for diagnostic in gate.diagnostics
    ]


def _diagnostics_copy_authoritative(gate_results: list[object]) -> None:
    authoritative = _authoritative_violations(gate_results)
    diagnostics = _category_diagnostics(gate_results)
    if any(diagnostic not in authoritative for diagnostic in diagnostics):
        raise ValueError("category diagnostic must copy an authoritative violation")


def _admitted_snapshot_digests(
    admitted: bool, snapshots: tuple[str | None, ...]
) -> None:
    if admitted and any(digest is None for digest in snapshots):
        raise ValueError("admitted decision requires all four snapshot digests")


def _receipt_roles_mismatched(
    receipts: list[object], expected_roles: set[object]
) -> bool:
    roles = {receipt.role for receipt in receipts}
    return roles != expected_roles or len(receipts) != len(expected_roles)


def _receipt_identity_mismatched(receipts: list[object], candidate_id: str) -> bool:
    return any(receipt.candidate_id != candidate_id for receipt in receipts)


def _admitted_scenario_ids(receipts: list[object]) -> set[str | None]:
    return {receipt.scenario_id for receipt in receipts}


def _terminal_receipt_violation(
    receipts: list[object], admitted: bool, candidate_id: str
) -> str | None:
    expected_roles = (
        {ArtifactRole.SCENARIO_YAML, ArtifactRole.SCENARIO_FEATURE}
        if admitted
        else {ArtifactRole.QUARANTINE_BUNDLE}
    )
    if _receipt_roles_mismatched(receipts, expected_roles):
        return "terminal receipts do not match candidate terminal status"
    if _receipt_identity_mismatched(receipts, candidate_id):
        return "terminal receipts do not match candidate terminal status"
    if admitted and len(_admitted_scenario_ids(receipts)) != 1:
        return "admitted terminal receipts require one scenario_id"
    return None


def _terminal_receipt_projection(
    receipts: list[ArtifactReceipt],
) -> list[dict[str, str | None]]:
    return [
        {
            "role": receipt.role.value,
            "path": receipt.path,
            "candidate_id": receipt.candidate_id,
            "scenario_id": receipt.scenario_id,
            "sha256": receipt.sha256,
        }
        for receipt in sorted(receipts, key=lambda item: (item.role.value, item.path))
    ]
