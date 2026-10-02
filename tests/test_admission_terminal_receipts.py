"""Terminal receipts recorded on an admission decision match its outcome."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from asago_scenario_generator.manifest import ArtifactRole
from asago_scenario_generator.pipeline.finalization_contracts import (
    CandidateTerminalStatus,
)
from asago_scenario_generator.pipeline.finalization_gate_contracts import (
    NORMAL_POSTBEHAVIOR_EVIDENCE_IDS,
)
from asago_scenario_generator.pipeline.persistence import AdmissionDecisionRecord

_CANDIDATE = "cand:v2:c1ce1e48c8fcea147f0c57d7552d041a"
_SHA = "a" * 64
_MISMATCH = "terminal receipts do not match candidate terminal status"


def _receipt(
    role: ArtifactRole,
    *,
    candidate_id: str = _CANDIDATE,
    scenario_id: str | None = "SCN-1",
) -> dict:
    return {
        "candidate_id": candidate_id,
        "role": role.value,
        "path": f"out/{role.value}/{scenario_id or 'bundle'}",
        "sha256": _SHA,
        "scenario_id": scenario_id,
    }


def _yaml(**kwargs) -> dict:
    return _receipt(ArtifactRole.SCENARIO_YAML, **kwargs)


def _feature(**kwargs) -> dict:
    return _receipt(ArtifactRole.SCENARIO_FEATURE, **kwargs)


def _bundle(**kwargs) -> dict:
    return _receipt(ArtifactRole.QUARANTINE_BUNDLE, scenario_id=None, **kwargs)


def _admitted(receipts: list[dict]) -> AdmissionDecisionRecord:
    return AdmissionDecisionRecord.model_validate(
        {
            "event_id": _SHA,
            "payload_sha256": _SHA,
            "sequence": 0,
            "candidate_id": _CANDIDATE,
            "status": CandidateTerminalStatus.admitted.value,
            "admitted": True,
            "gate_results": [
                {
                    "gate": gate.value,
                    "passed": True,
                    "violations": [],
                    "diagnostics": [],
                    "applicable": True,
                }
                for gate in sorted(NORMAL_POSTBEHAVIOR_EVIDENCE_IDS)
            ],
            "candidate_snapshot_sha256": _SHA,
            "actor_snapshot_sha256": _SHA,
            "narrative_snapshot_sha256": _SHA,
            "final_tree_snapshot_sha256": _SHA,
            "violations": [],
            "terminal_receipts": receipts,
        }
    )


def _rejected(receipts: list[dict]) -> AdmissionDecisionRecord:
    return AdmissionDecisionRecord.model_validate(
        {
            "event_id": _SHA,
            "payload_sha256": _SHA,
            "sequence": 0,
            "candidate_id": _CANDIDATE,
            "status": CandidateTerminalStatus.rejected.value,
            "admitted": False,
            "gate_results": [],
            "violations": [],
            "terminal_receipts": receipts,
        }
    )


def test_admitted_decision_accepts_one_scenario_yaml_and_feature() -> None:
    record = _admitted([_yaml(), _feature()])

    assert {receipt.role for receipt in record.terminal_receipts} == {
        ArtifactRole.SCENARIO_YAML,
        ArtifactRole.SCENARIO_FEATURE,
    }


def test_rejected_decision_accepts_one_quarantine_bundle() -> None:
    record = _rejected([_bundle()])

    assert [receipt.role for receipt in record.terminal_receipts] == [
        ArtifactRole.QUARANTINE_BUNDLE
    ]


@pytest.mark.parametrize(
    "receipts",
    [
        pytest.param([_yaml()], id="missing-feature"),
        pytest.param([_yaml(), _feature(), _bundle()], id="extra-bundle"),
        pytest.param([_bundle()], id="bundle-only"),
        pytest.param(
            [_yaml(), _feature(), _feature(scenario_id="SCN-2")],
            id="duplicate-role",
        ),
        pytest.param(
            [_yaml(), _feature(candidate_id="cand:v2:other")],
            id="foreign-candidate",
        ),
    ],
)
def test_admitted_decision_rejects_mismatched_receipts(receipts) -> None:
    with pytest.raises(ValidationError, match=_MISMATCH):
        _admitted(receipts)


def test_admitted_receipts_must_share_one_scenario_id() -> None:
    with pytest.raises(
        ValidationError, match="admitted terminal receipts require one scenario_id"
    ):
        _admitted([_yaml(scenario_id="SCN-1"), _feature(scenario_id="SCN-2")])


@pytest.mark.parametrize(
    "receipts",
    [
        pytest.param([], id="no-receipt"),
        pytest.param([_yaml(), _feature()], id="scenario-receipts"),
        pytest.param([_bundle(candidate_id="cand:v2:other")], id="foreign-candidate"),
    ],
)
def test_rejected_decision_rejects_mismatched_receipts(receipts) -> None:
    with pytest.raises(ValidationError, match=_MISMATCH):
        _rejected(receipts)
