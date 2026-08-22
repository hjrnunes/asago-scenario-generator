"""cmps.5 Phase 4 persistence contract and v3 activation tests."""

from __future__ import annotations

import json
import math
from pathlib import Path

import pytest
from jsonschema import validate as validate_json_schema
from pydantic import ValidationError

from asago_scenario_generator.llm.client import LLMResult
from asago_scenario_generator.manifest import (
    ArtifactRole,
    ManifestIntegrityError,
    ManifestInventoryResolver,
    RunManifest,
    RunStatus,
    atomic_write_yaml,
    build_artifact_entry,
    finalize_manifest,
    load_manifest,
    load_strict_resolver,
    required_singleton_roles,
)
from asago_scenario_generator.models.scenario import CallMetadata, CallName, RiskCardRef
from asago_scenario_generator.pipeline.candidates import FilteredSeed
from asago_scenario_generator.pipeline.coverage_planning import (
    AcceptedFilterRecord,
    CoveragePlanEntry,
    QualifiedCandidate,
    deserialize_qualified_candidate,
)
from asago_scenario_generator.pipeline.finalization import (
    GENERATION_ORDER,
    AdmissionDecision,
    CandidateTerminalResult,
    CandidateTerminalStatus,
    CandidateValidation,
    GeneratedStage,
    GeneratedStageResult,
    LifecycleState,
    LifecycleTransition,
    LifecycleViolation,
    PrebehaviorFinalizationResult,
    TargetFinalizationMachine,
)
from asago_scenario_generator.pipeline.finalization_admission import (
    PostbehaviorAdmissionReport,
)
from asago_scenario_generator.pipeline.finalization_gates import (
    CONDITIONALLY_APPLICABLE_EVIDENCE_IDS,
    DIAGNOSTIC_BACKED_EVIDENCE_IDS,
    EXCEPTIONAL_ADMISSION_EVIDENCE_IDS,
    NORMAL_POSTBEHAVIOR_EVIDENCE_IDS,
    AdmissionEvidenceId,
    GateCode,
    GateResult,
    GateViolation,
    RepairRecord,
)
from asago_scenario_generator.pipeline.generate.stages import StageCallEvidence
from asago_scenario_generator.pipeline.persistence import (
    AdmissionDecisionRecord,
    AdmittedArtifactPublication,
    AdmittedTerminalPayload,
    ArtifactReceipt,
    CandidateAttemptRecord,
    CoveragePlanV2,
    CoverageTargetEntry,
    FinalizationInventoryV1,
    GateResultRecord,
    PlanningCheckpointV1,
    QualifiedCandidateRef,
    QuarantineBundleV1,
    TargetState,
    TransitionRecord,
    ViolationRecord,
    canonical_sha256,
    make_finalization_persistence_adapter,
    read_coverage_plan,
    read_finalization_inventory,
    read_quarantine_bundle,
    write_coverage_plan,
    write_finalization_inventory,
    write_planning_checkpoint,
    write_quarantine_bundle,
)
from asago_scenario_generator.pipeline.projection import canonical_json_bytes
from tests.helpers.projection_factory import get_projected_candidates

RUN_ID = "20260101T000000_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
HASH = "0" * 64
SCHEMA_DIR = (
    Path(__file__).resolve().parents[1] / "src/asago_scenario_generator/data/schemas"
)


_PROJECTED_CANDIDATES = get_projected_candidates()
_BASE_CANDIDATE = _PROJECTED_CANDIDATES[0]
ENTRY_POINT_ID = _BASE_CANDIDATE.canonical_ingress.entry_point_id
PRIMARY_ID = _PROJECTED_CANDIDATES[0].candidate_id
FALLBACK_ID = _PROJECTED_CANDIDATES[1].candidate_id


def _choice(candidate_id: str, rank: int = 0) -> QualifiedCandidateRef:
    projected = next(
        item for item in _PROJECTED_CANDIDATES if item.candidate_id == candidate_id
    )
    seed = FilteredSeed(
        seed_id=projected.pattern_id,
        threat_id="T1",
        threat_name="Test threat",
        attack_pattern_name="Test pattern",
        attack_pattern_description="Test attack pattern description.",
        risk_card_ref=RiskCardRef(
            risk_id="risk-1",
            risk_name="Test risk",
            risk_description="Test risk description.",
            taxonomy="ibm-risk-atlas",
            confidence=0.9,
            grounding_confidence="high",
        ),
        owasp_llm_ids=["LLM01"],
        agentic_threat_ids=["T1"],
        pinned_entry_point="user prompt",
        pinned_technique_ids=["AML.T0051"],
        pinned_technique_names=["Technique"],
        entry_point_id=ENTRY_POINT_ID,
        candidate_id=f"filter-{rank}",
        accepted_rationale="accepted",
    )
    ref = QualifiedCandidate(
        projected=projected,
        accepted_filters=(AcceptedFilterRecord.from_seed(seed),),
        rank=rank,
    ).to_plan_ref()
    return QualifiedCandidateRef.model_validate(ref)


def _plan(*, attempted: list[str] | None = None) -> CoveragePlanV2:
    choices = [
        _choice(PRIMARY_ID, 0),
        _choice(FALLBACK_ID, 1),
    ]
    attempted = attempted or []
    return CoveragePlanV2(
        schema_version="2",
        completeness="not_applicable",
        evidence_refs=[],
        targets=[
            CoverageTargetEntry(
                entry_point_id=ENTRY_POINT_ID,
                entry_point_name="input",
                ordered_choices=choices,
                primary_candidate_id=PRIMARY_ID,
                attempted_candidate_ids=attempted,
                admitted_candidate_id=None,
                target_state=TargetState.selected,
                fallback_available=[
                    choice for choice in choices if choice.candidate_id not in attempted
                ],
            )
        ],
        selection_limitation_target_ids=[],
    )


def test_plan_allows_distinct_targets_for_candidates_sharing_an_ingress() -> None:
    first = _choice(PRIMARY_ID, 0)
    second = _choice(FALLBACK_ID, 0)

    plan = CoveragePlanV2(
        schema_version="2",
        completeness="not_applicable",
        evidence_refs=[],
        targets=[
            CoverageTargetEntry(
                target_id="candidate-target:first",
                entry_point_id=ENTRY_POINT_ID,
                entry_point_name="input",
                ordered_choices=[first],
                primary_candidate_id=first.candidate_id,
                attempted_candidate_ids=[],
                admitted_candidate_id=None,
                target_state=TargetState.selected,
                fallback_available=[first],
            ),
            CoverageTargetEntry(
                target_id="candidate-target:second",
                entry_point_id=ENTRY_POINT_ID,
                entry_point_name="input",
                ordered_choices=[second],
                primary_candidate_id=second.candidate_id,
                attempted_candidate_ids=[],
                admitted_candidate_id=None,
                target_state=TargetState.selected,
                fallback_available=[second],
            ),
        ],
        selection_limitation_target_ids=[],
    )

    assert [target.effective_target_id for target in plan.targets] == [
        "candidate-target:first",
        "candidate-target:second",
    ]


def test_plan_rejects_duplicate_durable_target_ids() -> None:
    first = _choice(PRIMARY_ID, 0)
    second = _choice(FALLBACK_ID, 0)
    first_target = CoverageTargetEntry(
        target_id="candidate-target:duplicate",
        entry_point_id=ENTRY_POINT_ID,
        entry_point_name="input",
        ordered_choices=[first],
        primary_candidate_id=first.candidate_id,
        attempted_candidate_ids=[],
        admitted_candidate_id=None,
        target_state=TargetState.selected,
        fallback_available=[first],
    )
    second_target = CoverageTargetEntry(
        target_id="candidate-target:duplicate",
        entry_point_id=ENTRY_POINT_ID,
        entry_point_name="input",
        ordered_choices=[second],
        primary_candidate_id=second.candidate_id,
        attempted_candidate_ids=[],
        admitted_candidate_id=None,
        target_state=TargetState.selected,
        fallback_available=[second],
    )

    with pytest.raises(ValueError, match="duplicate target IDs"):
        CoveragePlanV2(
            schema_version="2",
            completeness="not_applicable",
            evidence_refs=[],
            targets=[first_target, second_target],
            selection_limitation_target_ids=[],
        )


def _inventory(coverage_hash: str = HASH) -> FinalizationInventoryV1:
    return FinalizationInventoryV1(
        schema_version="1",
        run_id=RUN_ID,
        coverage_plan_sha256=coverage_hash,
        candidate_attempts=[],
        stage_attempts=[],
        transitions=[],
        repairs=[],
        admission_decisions=[],
        admitted_inventory=[],
        quarantine_inventory=[],
    )


def _write_planning_for_plan(tmp_path: Path, plan: CoveragePlanV2):
    primary_ids = [
        target.primary_candidate_id
        for target in plan.targets
        if target.primary_candidate_id is not None
    ]
    checkpoint = PlanningCheckpointV1(
        stage_events=[],
        projection_limitation_target_ids=[],
        selected_candidate_ids=primary_ids,
        capped_count=0,
        uncovered_target_ids=sorted(
            target.entry_point_id
            for target in plan.targets
            if not target.ordered_choices
        ),
        per_pattern_counts={},
        primary_candidate_ids={
            target.entry_point_id: target.primary_candidate_id
            for target in plan.targets
            if target.primary_candidate_id is not None
        },
        attempted_candidate_ids=sorted(primary_ids),
        selection_limitation_target_ids=sorted(plan.selection_limitation_target_ids),
        fallback_candidate_ids={
            target.entry_point_id: [
                choice.candidate_id for choice in target.ordered_choices
            ]
            for target in plan.targets
        },
    )
    write_planning_checkpoint(tmp_path, checkpoint)
    return build_artifact_entry(
        ArtifactRole.PLANNING_CHECKPOINT,
        tmp_path,
        "planning-checkpoint.json",
    )


def _event(sequence: int, label: str) -> dict[str, object]:
    return {
        "event_id": canonical_sha256({"event": label}),
        "payload_sha256": canonical_sha256({"payload": label}),
        "sequence": sequence,
    }


def _durable_event(
    sequence: int, kind: str, identity: object, payload: object
) -> dict[str, object]:
    return {
        "event_id": canonical_sha256({"kind": kind, "identity": identity}),
        "payload_sha256": canonical_sha256(payload),
        "sequence": sequence,
    }


@pytest.mark.parametrize(
    ("model", "filename"),
    [
        (CoveragePlanV2, "coverage-plan-v2.schema.json"),
        (FinalizationInventoryV1, "finalization-inventory-v1.schema.json"),
        (QuarantineBundleV1, "quarantine-bundle-v1.schema.json"),
        (PlanningCheckpointV1, "planning-checkpoint-v1.schema.json"),
    ],
)
def test_generated_schema_has_exact_hand_schema_parity(model, filename):
    assert json.loads((SCHEMA_DIR / filename).read_text()) == model.model_json_schema()


def test_models_reject_extra_missing_and_wrong_version():
    raw = _plan().model_dump(mode="json")
    raw["extra"] = True
    with pytest.raises(ValidationError, match="extra"):
        CoveragePlanV2.model_validate(raw)
    raw.pop("extra")
    raw.pop("targets")
    with pytest.raises(ValidationError, match="targets"):
        CoveragePlanV2.model_validate(raw)
    raw["targets"] = []
    raw["schema_version"] = "1"
    with pytest.raises(ValidationError, match="schema_version"):
        CoveragePlanV2.model_validate(raw)

    with pytest.raises(ValidationError, match="outcome must match diagnostics"):
        GateResultRecord(
            gate=AdmissionEvidenceId.capability_grounding,
            passed=False,
            violations=[],
            diagnostics=[],
            applicable=True,
        )


def test_planning_checkpoint_is_immutable_and_idempotent(tmp_path: Path):
    checkpoint = PlanningCheckpointV1(
        stage_events=[],
        projection_limitation_target_ids=[],
        selected_candidate_ids=[PRIMARY_ID],
        capped_count=0,
        uncovered_target_ids=[],
        per_pattern_counts={_BASE_CANDIDATE.pattern_id: 1},
        primary_candidate_ids={ENTRY_POINT_ID: PRIMARY_ID},
        attempted_candidate_ids=[PRIMARY_ID],
        selection_limitation_target_ids=[],
        fallback_candidate_ids={ENTRY_POINT_ID: [PRIMARY_ID, FALLBACK_ID]},
    )
    write_planning_checkpoint(tmp_path, checkpoint)
    write_planning_checkpoint(tmp_path, checkpoint)

    conflicting = checkpoint.model_copy(update={"capped_count": 1})
    with pytest.raises(ManifestIntegrityError, match="Immutable evidence collision"):
        write_planning_checkpoint(tmp_path, conflicting)


def test_qualified_candidate_requires_complete_canonical_provenance():
    raw = _choice(PRIMARY_ID).model_dump(mode="json")
    raw["accepted_filters"][0]["seed"]["accepted_rationale"] = "tampered"
    with pytest.raises(ValidationError, match="canonical|rationale|embedded"):
        QualifiedCandidateRef.model_validate(raw)


def test_external_json_schema_validation_uses_generated_contracts():
    bundle = QuarantineBundleV1(
        schema_version="1",
        run_id=RUN_ID,
        attempt_id="attempt-schema",
        candidate_id=PRIMARY_ID,
        target_entry_point_id=ENTRY_POINT_ID,
        actor=None,
        narrative=None,
        tree=None,
        behavior=None,
        artifact_sha256={},
        violations=[
            ViolationRecord(
                code="schema", detail="evidence", owner=None, retryable=False
            )
        ],
    )
    for filename, value in (
        ("coverage-plan-v2.schema.json", _plan()),
        ("finalization-inventory-v1.schema.json", _inventory()),
        ("quarantine-bundle-v1.schema.json", bundle),
    ):
        validate_json_schema(
            instance=value.model_dump(mode="json"),
            schema=json.loads((SCHEMA_DIR / filename).read_text()),
        )


def test_public_canonical_serializer_rejects_ambiguous_or_unsupported_values():
    assert canonical_json_bytes({"name": "e\u0301"}) == canonical_json_bytes(
        {"name": "é"}
    )
    with pytest.raises(TypeError, match="keys must be strings"):
        canonical_json_bytes({1: "value"})
    with pytest.raises(ValueError, match="collide"):
        canonical_json_bytes({"é": 1, "e\u0301": 2})
    with pytest.raises(ValueError):
        canonical_json_bytes({"value": math.nan})
    with pytest.raises(TypeError):
        canonical_json_bytes({"value": {"unsupported"}})


def test_fallback_excludes_attempted_and_preserves_order():
    assert [
        choice.candidate_id
        for choice in _plan(attempted=[PRIMARY_ID]).targets[0].fallback_available
    ] == [FALLBACK_ID]
    raw = _plan().model_dump(mode="json")
    raw["targets"][0]["attempted_candidate_ids"] = [PRIMARY_ID]
    with pytest.raises(ValidationError, match="fallback_available"):
        CoveragePlanV2.model_validate(raw)


def test_coverage_plan_limits_choices_and_requires_increasing_rank():
    raw = _plan().model_dump(mode="json")
    raw["targets"][0]["ordered_choices"][1]["rank"] = 0
    raw["targets"][0]["fallback_available"][1]["rank"] = 0
    with pytest.raises(ValidationError, match="rank"):
        CoveragePlanV2.model_validate(raw)
    raw = _plan().model_dump(mode="json")
    raw["targets"][0]["ordered_choices"] *= 2
    with pytest.raises(ValidationError, match="3 items"):
        CoveragePlanV2.model_validate(raw)


def test_atomic_model_roundtrip_and_hash_reconciliation(tmp_path: Path):
    plan = _plan()
    entry = write_coverage_plan(tmp_path, plan)
    assert read_coverage_plan(tmp_path, entry) == plan
    (tmp_path / entry.path).write_text("{}")
    with pytest.raises(ManifestIntegrityError, match="Hash mismatch"):
        read_coverage_plan(tmp_path, entry)


def test_atomic_interruption_leaves_previous_valid_document(
    tmp_path: Path, monkeypatch
):
    import asago_scenario_generator.manifest as manifest_module

    original = _plan()
    write_coverage_plan(tmp_path, original)

    def interrupted_replace(source, destination):
        raise OSError("simulated interruption")

    monkeypatch.setattr(manifest_module.os, "replace", interrupted_replace)
    with pytest.raises(OSError, match="interruption"):
        write_coverage_plan(tmp_path, original)
    assert read_coverage_plan(tmp_path) == original
    assert not list(tmp_path.glob("*.tmp"))


def test_quarantine_roundtrip_has_only_json_bundle_role(tmp_path: Path):
    actor = {"actor": "partial"}
    bundle = QuarantineBundleV1(
        schema_version="1",
        run_id=RUN_ID,
        attempt_id="attempt-1",
        candidate_id=PRIMARY_ID,
        target_entry_point_id=ENTRY_POINT_ID,
        actor=actor,
        narrative=None,
        tree=None,
        behavior=None,
        artifact_sha256={GeneratedStage.actor: canonical_sha256(actor)},
        violations=[
            ViolationRecord(
                code="actor_access",
                detail="failed hard gate",
                owner=GeneratedStage.actor,
                retryable=True,
            )
        ],
    )
    entry = write_quarantine_bundle(tmp_path, bundle)
    assert entry.role is ArtifactRole.QUARANTINE_BUNDLE
    assert entry.path == "quarantine/attempt-1.json"
    assert read_quarantine_bundle(tmp_path, entry) == bundle
    assert not list(tmp_path.rglob("*.yaml"))
    assert not list(tmp_path.rglob("*.feature"))


def test_quarantine_is_exclusive_and_safe_reads_reject_symlinks(tmp_path: Path):
    actor = {"actor": "partial"}
    bundle = QuarantineBundleV1(
        schema_version="1",
        run_id=RUN_ID,
        attempt_id="attempt-1",
        candidate_id=PRIMARY_ID,
        target_entry_point_id=ENTRY_POINT_ID,
        actor=actor,
        narrative=None,
        tree=None,
        behavior=None,
        artifact_sha256={GeneratedStage.actor: canonical_sha256(actor)},
        violations=[
            ViolationRecord(code="failed", detail="failed", owner=None, retryable=False)
        ],
    )
    entry = write_quarantine_bundle(tmp_path, bundle)
    write_quarantine_bundle(tmp_path, bundle)
    conflicting = bundle.model_copy(update={"run_id": RUN_ID.replace("a", "b")})
    with pytest.raises(ManifestIntegrityError, match="collision"):
        write_quarantine_bundle(tmp_path, conflicting)
    (tmp_path / entry.path).unlink()
    (tmp_path / entry.path).symlink_to(tmp_path / "coverage-plan.json")
    with pytest.raises(ManifestIntegrityError, match="safely read"):
        read_quarantine_bundle(tmp_path, entry)


def test_quarantine_writer_rejects_symlinked_parent(tmp_path: Path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (tmp_path / "quarantine").symlink_to(outside, target_is_directory=True)
    bundle = QuarantineBundleV1(
        schema_version="1",
        run_id=RUN_ID,
        attempt_id="attempt-1",
        candidate_id=PRIMARY_ID,
        target_entry_point_id=ENTRY_POINT_ID,
        actor=None,
        narrative=None,
        tree=None,
        behavior=None,
        artifact_sha256={},
        violations=[
            ViolationRecord(code="failed", detail="failed", owner=None, retryable=False)
        ],
    )
    with pytest.raises(OSError):
        write_quarantine_bundle(tmp_path, bundle)
    assert not list(outside.iterdir())


@pytest.mark.parametrize(
    "path", ["/absolute.json", "./relative.json", "a/../b.json", r"a\b.json"]
)
def test_receipts_reject_noncanonical_paths(path: str):
    with pytest.raises(ValidationError, match="canonical"):
        ArtifactReceipt(
            candidate_id=PRIMARY_ID,
            role=ArtifactRole.QUARANTINE_BUNDLE,
            path=path,
            sha256=HASH,
            scenario_id=None,
        )


def test_finalization_rejects_duplicate_and_noncontiguous_records():
    attempt = CandidateAttemptRecord(
        **_event(0, "candidate"),
        attempt_id="attempt-1",
        candidate_id=PRIMARY_ID,
        target_entry_point_id=ENTRY_POINT_ID,
        queue_rank=0,
        is_primary=True,
        stage_attempt_ids=[],
    )
    raw = _inventory().model_dump(mode="json")
    raw["candidate_attempts"] = [
        attempt.model_dump(mode="json"),
        attempt.model_dump(mode="json"),
    ]
    with pytest.raises(ValidationError, match="duplicate"):
        FinalizationInventoryV1.model_validate(raw)


def test_transition_indexes_and_chains_are_target_local():
    transitions = []
    for sequence, target_id in enumerate((ENTRY_POINT_ID, "ep:v1:other")):
        payload = {
            "previous": "pending",
            "current": "exhausted",
            "candidate_id": None,
            "reason": "empty queue",
            "transition_index": 0,
            "target_entry_point_id": target_id,
        }
        transitions.append(
            TransitionRecord(
                **_durable_event(sequence, "transition", [target_id, 0], payload),
                target_entry_point_id=target_id,
                index=0,
                previous=LifecycleState.pending,
                current=LifecycleState.exhausted,
                candidate_id=None,
                reason="empty queue",
            )
        )
    inventory = _inventory().model_copy(update={"transitions": transitions})
    assert (
        FinalizationInventoryV1.model_validate(
            inventory.model_dump(mode="python")
        ).transitions
        == transitions
    )
    raw = _inventory().model_dump(mode="json")
    raw["transitions"] = [
        {
            **_event(0, "transition"),
            "target_entry_point_id": ENTRY_POINT_ID,
            "index": 1,
            "previous": "pending",
            "current": "revalidating_candidate",
            "candidate_id": PRIMARY_ID,
            "reason": "start",
        }
    ]
    with pytest.raises(ValidationError, match="contiguous"):
        FinalizationInventoryV1.model_validate(raw)


def test_v2_default_roles_and_strict_v3_request_compatibility(tmp_path: Path):
    assert ArtifactRole.COVERAGE_PLAN not in required_singleton_roles(
        eval_enabled=False
    )
    assert ArtifactRole.COVERAGE_PLAN in required_singleton_roles(
        eval_enabled=False, manifest_version="3"
    )
    assert ArtifactRole.PLANNING_CHECKPOINT in required_singleton_roles(
        eval_enabled=False, manifest_version="3"
    )
    atomic_write_yaml(
        tmp_path / "run-manifest.yaml",
        RunManifest(
            manifest_version="2",
            status=RunStatus.COMPLETED,
            run_id=RUN_ID,
            timestamp_start="2026-01-01T00:00:00Z",
        ).model_dump(mode="json"),
    )
    assert load_manifest(tmp_path).manifest_version == "2"
    with pytest.raises(ManifestIntegrityError, match="explicitly requested"):
        load_manifest(tmp_path, requested_version="3")


def test_v3_requires_persistence_singletons(tmp_path: Path):
    finalize_manifest(
        tmp_path,
        RunManifest(
            manifest_version="3",
            status=RunStatus.COMPLETED,
            run_id=RUN_ID,
            timestamp_start="2026-01-01T00:00:00Z",
        ),
    )
    with pytest.raises(ManifestIntegrityError, match="requires exactly one"):
        load_strict_resolver(tmp_path, manifest_version="3")


def test_v2_rejects_v3_only_roles(tmp_path: Path):
    entry = write_coverage_plan(tmp_path, _plan())
    manifest = RunManifest(
        manifest_version="2",
        status=RunStatus.COMPLETED,
        run_id=RUN_ID,
        timestamp_start="2026-01-01T00:00:00Z",
        inventory=[entry],
    )
    with pytest.raises(ManifestIntegrityError, match="v3-only role"):
        ManifestInventoryResolver(tmp_path, manifest, check_orphans=False)


def test_v3_rejects_legacy_lifecycle_authority(tmp_path: Path):
    coverage_entry = write_coverage_plan(
        tmp_path,
        CoveragePlanV2(
            schema_version="2",
            completeness="not_applicable",
            evidence_refs=[],
            targets=[],
            selection_limitation_target_ids=[],
        ),
    )
    final_entry = write_finalization_inventory(
        tmp_path, _inventory(coverage_entry.sha256)
    )
    manifest = RunManifest(
        manifest_version="3",
        status=RunStatus.COMPLETED,
        run_id=RUN_ID,
        timestamp_start="2026-01-01T00:00:00Z",
        inventory=[coverage_entry, final_entry],
        stage_records=[{"legacy": True}],
    )
    with pytest.raises(ManifestIntegrityError, match="finalization_inventory"):
        ManifestInventoryResolver(tmp_path, manifest, check_orphans=False)


def test_valid_empty_v3_inventory(tmp_path: Path):
    plan = CoveragePlanV2(
        schema_version="2",
        completeness="not_applicable",
        evidence_refs=[],
        targets=[],
        selection_limitation_target_ids=[],
    )
    coverage_entry = write_coverage_plan(tmp_path, plan)
    planning_entry = _write_planning_for_plan(tmp_path, plan)
    final_entry = write_finalization_inventory(
        tmp_path, _inventory(coverage_entry.sha256)
    )
    finalize_manifest(
        tmp_path,
        RunManifest(
            manifest_version="3",
            status=RunStatus.COMPLETED,
            run_id=RUN_ID,
            timestamp_start="2026-01-01T00:00:00Z",
            inventory=[planning_entry, coverage_entry, final_entry],
        ),
    )
    resolver = load_strict_resolver(tmp_path, manifest_version="3")
    assert resolver.entry_by_role(ArtifactRole.COVERAGE_PLAN) == coverage_entry


def test_completed_v3_rejects_missing_planning_checkpoint(tmp_path: Path):
    plan = CoveragePlanV2(
        schema_version="2",
        completeness="not_applicable",
        evidence_refs=[],
        targets=[],
        selection_limitation_target_ids=[],
    )
    coverage_entry = write_coverage_plan(tmp_path, plan)
    final_entry = write_finalization_inventory(
        tmp_path, _inventory(coverage_entry.sha256)
    )
    finalize_manifest(
        tmp_path,
        RunManifest(
            manifest_version="3",
            status=RunStatus.COMPLETED_WITH_ERRORS,
            run_id=RUN_ID,
            timestamp_start="2026-01-01T00:00:00Z",
            inventory=[coverage_entry, final_entry],
        ),
    )
    with pytest.raises(ManifestIntegrityError, match="planning_checkpoint"):
        load_strict_resolver(tmp_path, manifest_version="3")


def _quarantine_v3_parts(tmp_path: Path):
    choice = _choice(PRIMARY_ID)
    plan = CoveragePlanV2(
        schema_version="2",
        completeness="not_applicable",
        evidence_refs=[],
        targets=[
            CoverageTargetEntry(
                entry_point_id=ENTRY_POINT_ID,
                entry_point_name="input",
                ordered_choices=[choice],
                primary_candidate_id=choice.candidate_id,
                attempted_candidate_ids=[choice.candidate_id],
                admitted_candidate_id=None,
                target_state=TargetState.exhausted,
                fallback_available=[],
            )
        ],
        selection_limitation_target_ids=[],
    )
    coverage_entry = write_coverage_plan(tmp_path, plan)
    violation = ViolationRecord(
        code="actor_access",
        detail="terminal hard-gate failure",
        owner=GeneratedStage.actor,
        retryable=False,
    )
    bundle_entry = write_quarantine_bundle(
        tmp_path,
        QuarantineBundleV1(
            schema_version="1",
            run_id=RUN_ID,
            attempt_id="attempt-1",
            candidate_id=choice.candidate_id,
            target_entry_point_id=ENTRY_POINT_ID,
            actor=None,
            narrative=None,
            tree=None,
            behavior=None,
            artifact_sha256={},
            violations=[violation],
        ),
    )
    receipt = ArtifactReceipt(
        candidate_id=choice.candidate_id,
        role=bundle_entry.role,
        path=bundle_entry.path,
        sha256=bundle_entry.sha256,
        scenario_id=None,
    )
    final = _inventory(coverage_entry.sha256)
    candidate_payload = {
        "candidate_id": choice.candidate_id,
        "target_entry_point_id": ENTRY_POINT_ID,
        "queue_rank": 0,
    }
    final.candidate_attempts.append(
        CandidateAttemptRecord(
            **_durable_event(
                0, "candidate_attempt", choice.candidate_id, candidate_payload
            ),
            attempt_id="attempt-1",
            candidate_id=choice.candidate_id,
            target_entry_point_id=ENTRY_POINT_ID,
            queue_rank=0,
            is_primary=True,
            stage_attempt_ids=[],
        )
    )
    final.transitions.extend(
        [
            TransitionRecord(
                **_durable_event(
                    1,
                    "transition",
                    [ENTRY_POINT_ID, 0],
                    {
                        "previous": "pending",
                        "current": "revalidating_candidate",
                        "candidate_id": choice.candidate_id,
                        "reason": "start",
                        "transition_index": 0,
                        "target_entry_point_id": ENTRY_POINT_ID,
                    },
                ),
                target_entry_point_id=ENTRY_POINT_ID,
                index=0,
                previous=LifecycleState.pending,
                current=LifecycleState.revalidating_candidate,
                candidate_id=choice.candidate_id,
                reason="start",
            ),
            TransitionRecord(
                **_durable_event(
                    2,
                    "transition",
                    [ENTRY_POINT_ID, 1],
                    {
                        "previous": "revalidating_candidate",
                        "current": "rejected",
                        "candidate_id": choice.candidate_id,
                        "reason": "terminal",
                        "transition_index": 1,
                        "target_entry_point_id": ENTRY_POINT_ID,
                    },
                ),
                target_entry_point_id=ENTRY_POINT_ID,
                index=1,
                previous=LifecycleState.revalidating_candidate,
                current=LifecycleState.rejected,
                candidate_id=choice.candidate_id,
                reason="terminal",
            ),
        ]
    )
    decision_payload = {
        "candidate_id": choice.candidate_id,
        "status": "rejected",
        "violations": [violation.model_dump(mode="json")],
        "gate_results": [],
        "snapshots": {
            "candidate_snapshot_sha256": None,
            "actor_snapshot_sha256": None,
            "narrative_snapshot_sha256": None,
            "final_tree_snapshot_sha256": None,
        },
        "terminal_receipts": [
            {
                "role": receipt.role.value,
                "path": receipt.path,
                "candidate_id": receipt.candidate_id,
                "scenario_id": receipt.scenario_id,
                "sha256": receipt.sha256,
            }
        ],
    }
    final.admission_decisions.append(
        AdmissionDecisionRecord(
            **_durable_event(
                3, "candidate_result", choice.candidate_id, decision_payload
            ),
            candidate_id=choice.candidate_id,
            status=CandidateTerminalStatus.rejected,
            admitted=False,
            gate_results=[],
            violations=[violation],
            terminal_receipts=[receipt],
        )
    )
    exhausted_payload = {
        "previous": "rejected",
        "current": "exhausted",
        "candidate_id": None,
        "reason": "candidate choices exhausted",
        "transition_index": 2,
        "target_entry_point_id": ENTRY_POINT_ID,
    }
    final.transitions.append(
        TransitionRecord(
            **_durable_event(4, "transition", [ENTRY_POINT_ID, 2], exhausted_payload),
            target_entry_point_id=ENTRY_POINT_ID,
            index=2,
            previous=LifecycleState.rejected,
            current=LifecycleState.exhausted,
            candidate_id=None,
            reason="candidate choices exhausted",
        )
    )
    final.quarantine_inventory.append(receipt)
    final_entry = write_finalization_inventory(tmp_path, final)
    return coverage_entry, final_entry, bundle_entry, final


def _finalize_v3(tmp_path: Path, inventory):
    planning_entry = _write_planning_for_plan(tmp_path, read_coverage_plan(tmp_path))
    finalize_manifest(
        tmp_path,
        RunManifest(
            manifest_version="3",
            status=RunStatus.COMPLETED_WITH_ERRORS,
            run_id=RUN_ID,
            timestamp_start="2026-01-01T00:00:00Z",
            inventory=[planning_entry, *inventory],
        ),
    )


def test_valid_v3_quarantine_sets_completed_with_errors(tmp_path: Path):
    coverage, final, bundle, _ = _quarantine_v3_parts(tmp_path)
    _finalize_v3(tmp_path, [coverage, final, bundle])
    resolver = load_strict_resolver(tmp_path, manifest_version="3")
    assert resolver.manifest.status is RunStatus.COMPLETED_WITH_ERRORS


def test_v3_rejects_admitted_quarantine_overlap(tmp_path: Path):
    _coverage, _, _bundle, final = _quarantine_v3_parts(tmp_path)
    final.admitted_inventory.append(final.quarantine_inventory[0])
    with pytest.raises(ValidationError, match="must match exactly"):
        write_finalization_inventory(tmp_path, final)


@pytest.mark.parametrize(
    "leak_role", [ArtifactRole.SCENARIO_YAML, ArtifactRole.EVAL_SCORECARD]
)
def test_v3_rejects_quarantine_normal_or_eval_role(tmp_path: Path, leak_role):
    coverage, final, bundle, _ = _quarantine_v3_parts(tmp_path)
    candidate_id = bundle.candidate_id
    if leak_role is ArtifactRole.SCENARIO_YAML:
        scenarios = tmp_path / "scenarios"
        scenarios.mkdir()
        (scenarios / "scenario-1.yaml").write_text(
            f"scenario_id: scenario-1\ncandidate_id: {candidate_id}\n"
        )
        (scenarios / "scenario-1.feature").write_text("Feature: leaked\n")
        leaked = [
            build_artifact_entry(
                ArtifactRole.SCENARIO_YAML,
                tmp_path,
                "scenarios/scenario-1.yaml",
                scenario_id="scenario-1",
                candidate_id=candidate_id,
            ),
            build_artifact_entry(
                ArtifactRole.SCENARIO_FEATURE,
                tmp_path,
                "scenarios/scenario-1.feature",
                scenario_id="scenario-1",
                candidate_id=candidate_id,
            ),
        ]
        match = "match exactly"
    else:
        (tmp_path / "eval-scorecard.yaml").write_text("evaluation: {}\n")
        leaked = [
            build_artifact_entry(
                ArtifactRole.EVAL_SCORECARD,
                tmp_path,
                "eval-scorecard.yaml",
                candidate_id=candidate_id,
            )
        ]
        match = "Evaluation inventory"
    _finalize_v3(tmp_path, [coverage, final, bundle, *leaked])
    with pytest.raises(ManifestIntegrityError, match=match):
        load_strict_resolver(tmp_path, manifest_version="3")


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("nonpending", "start from pending"),
        ("candidate_exhaustion", "candidate-free and final"),
        ("duplicate_segment", "duplicate candidate trace segment"),
    ],
)
def test_inventory_rejects_noncausal_target_trace(
    tmp_path: Path, mutation: str, message: str
):
    _coverage, _final_entry, _bundle, final = _quarantine_v3_parts(tmp_path)
    raw = final.model_dump(mode="json")
    if mutation == "nonpending":
        raw["transitions"][0]["previous"] = "rejected"
    elif mutation == "candidate_exhaustion":
        raw["transitions"][-1]["candidate_id"] = PRIMARY_ID
    else:
        raw["transitions"][-1].update(
            {
                "current": "revalidating_candidate",
                "candidate_id": PRIMARY_ID,
            }
        )
    with pytest.raises(ValidationError, match=message):
        FinalizationInventoryV1.model_validate(raw)


def test_inventory_rejects_terminal_decision_reverse_sequence(tmp_path: Path):
    _coverage, _final_entry, _bundle, final = _quarantine_v3_parts(tmp_path)
    raw = final.model_dump(mode="json")
    terminal = next(
        item for item in raw["transitions"] if item["current"] == "rejected"
    )
    decision = raw["admission_decisions"][0]
    terminal["sequence"], decision["sequence"] = (
        decision["sequence"],
        terminal["sequence"],
    )
    with pytest.raises(ValidationError, match="terminal edge must precede"):
        FinalizationInventoryV1.model_validate(raw)

    raw = final.model_dump(mode="json")
    exhaustion = next(
        item for item in raw["transitions"] if item["current"] == "exhausted"
    )
    decision = raw["admission_decisions"][0]
    exhaustion["sequence"], decision["sequence"] = (
        decision["sequence"],
        exhaustion["sequence"],
    )
    with pytest.raises(ValidationError, match="precede the next target transition"):
        FinalizationInventoryV1.model_validate(raw)


def test_adapter_persists_each_port_event_exactly_once(tmp_path: Path):
    plan = _plan()
    adapter = make_finalization_persistence_adapter(
        tmp_path, run_id=RUN_ID, coverage_plan=plan
    )
    transition = LifecycleTransition(
        LifecycleState.pending,
        LifecycleState.revalidating_candidate,
        PRIMARY_ID,
        "start",
    )
    adapter.record_transition(transition)
    adapter.record_transition(transition)
    restarted = make_finalization_persistence_adapter(
        tmp_path, run_id=RUN_ID, coverage_plan=adapter.coverage_plan
    )
    restarted.record_transition(transition)
    with pytest.raises(ManifestIntegrityError, match="Conflicting duplicate"):
        restarted.record_transition(
            LifecycleTransition(
                LifecycleState.pending,
                LifecycleState.revalidating_candidate,
                PRIMARY_ID,
                "conflicting payload",
            )
        )
    reloaded = read_finalization_inventory(tmp_path)
    assert len(reloaded.transitions) == 1
    assert len(reloaded.candidate_attempts) == 1


def test_factory_maps_coverage_choices_for_machine_dependency_injection(
    tmp_path: Path,
):
    plan = _plan()
    adapter = make_finalization_persistence_adapter(
        tmp_path,
        run_id=RUN_ID,
        coverage_plan=plan,
    )
    adapter.record_transition(
        LifecycleTransition(
            LifecycleState.pending,
            LifecycleState.revalidating_candidate,
            PRIMARY_ID,
            "authoritative revalidation",
        )
    )
    reloaded = read_finalization_inventory(tmp_path)
    assert len(reloaded.candidate_attempts) == 1
    attempt = reloaded.candidate_attempts[0]
    assert attempt.attempt_id == f"{PRIMARY_ID}:candidate"
    assert attempt.candidate_id == PRIMARY_ID
    assert attempt.target_entry_point_id == ENTRY_POINT_ID
    assert attempt.queue_rank == 0
    assert attempt.is_primary


def test_adapter_persists_authoritative_phase3_repair_record(tmp_path: Path):
    adapter = make_finalization_persistence_adapter(
        tmp_path, run_id=RUN_ID, coverage_plan=_plan()
    )
    adapter.record_transition(
        LifecycleTransition(
            LifecycleState.pending,
            LifecycleState.revalidating_candidate,
            PRIMARY_ID,
            "start",
        )
    )
    repair = RepairRecord(
        before_digest="1" * 64,
        after_digest="2" * 64,
        removed_ids=("node-2",),
        preserved_projected_ids=("step-1",),
        accepted=True,
        detail="removed redundant leaf",
    )
    adapter.record_repair(PRIMARY_ID, repair)
    persisted = read_finalization_inventory(tmp_path).repairs[0]
    assert persisted.before_digest == repair.before_digest
    assert persisted.after_digest == repair.after_digest
    assert persisted.removed_ids == list(repair.removed_ids)
    assert "owner_retry_index" not in type(persisted).model_fields


def _stage_evidence(stage: GeneratedStage) -> StageCallEvidence:
    call = {
        GeneratedStage.actor: CallName.actor_profile,
        GeneratedStage.narrative: CallName.narrative,
        GeneratedStage.tree: CallName.attack_tree,
        GeneratedStage.behavior: CallName.behavior_spec,
    }[stage]
    return StageCallEvidence(
        call_name=call,
        result=LLMResult(
            content={"stage": stage.value},
            prompt_tokens=1,
            completion_tokens=1,
            duration_ms=1,
            system_prompt=f"system-{stage.value}",
            user_prompt=f"user-{stage.value}",
        ),
        metadata=CallMetadata(
            call=call, prompt_tokens=1, completion_tokens=1, duration_ms=1
        ),
    )


def _passing_normal_gate_results() -> tuple[GateResult, ...]:
    return tuple(
        GateResult(
            evidence_id,
            outcome=True if evidence_id in DIAGNOSTIC_BACKED_EVIDENCE_IDS else None,
        )
        for evidence_id in sorted(
            NORMAL_POSTBEHAVIOR_EVIDENCE_IDS, key=lambda item: item.value
        )
    )


def test_real_machine_adapter_primary_rejection_then_fallback_admission(
    tmp_path: Path,
):
    plan = _plan()
    adapter = make_finalization_persistence_adapter(
        tmp_path, run_id=RUN_ID, coverage_plan=plan
    )

    class Snapshot:
        def __init__(self, tree):
            self.tree = tree
            self.digest = canonical_sha256(tree)

        def verify_digest(self):
            assert self.digest == canonical_sha256(self.tree)

    def revalidate(ref):
        if ref["candidate_id"] == PRIMARY_ID:
            return CandidateValidation(
                None,
                (
                    LifecycleViolation(
                        detail="primary rejected",
                        code="candidate_invalid",
                        retryable=False,
                    ),
                ),
            )
        return CandidateValidation(deserialize_qualified_candidate(ref).projected)

    def stage(candidate, invocation):
        return GeneratedStageResult(
            artifact={
                "candidate_id": candidate.candidate_id,
                "stage": invocation.stage.value,
                "index": invocation.invocation_index,
            },
            evidence=_stage_evidence(invocation.stage),
        )

    target = plan.targets[0]
    machine = TargetFinalizationMachine(
        entry=CoveragePlanEntry(
            entry_point_id=target.entry_point_id,
            entry_point_name=target.entry_point_name,
            ordered_choices=[
                item.model_dump(mode="json") for item in target.ordered_choices
            ],
            primary_candidate_id=target.primary_candidate_id,
            primary_state="selected",
            fallback_available=[target.ordered_choices[1].model_dump(mode="json")],
        ),
        stage_callbacks={item: stage for item in GENERATION_ORDER},
        candidate_revalidator=revalidate,
        prebehavior_finalizer=lambda candidate, artifacts: (
            PrebehaviorFinalizationResult(Snapshot(artifacts.tree))
        ),
        admission_callback=lambda candidate, artifacts, snapshot: AdmissionDecision(
            True,
            value=AdmittedTerminalPayload(
                report=PostbehaviorAdmissionReport(
                    envelope=object(),
                    gate_results=_passing_normal_gate_results(),
                ),
                publication=AdmittedArtifactPublication(
                    candidate_id=candidate.candidate_id,
                    scenario_id="scenario-admitted",
                    yaml_text=(
                        "scenario_id: scenario-admitted\n"
                        f"candidate_id: {candidate.candidate_id}\n"
                    ),
                    feature_text="Feature: admitted\n",
                ),
            ),
        ),
        persistence=adapter,
        attempted_candidate_ids=set(),
    )
    result = machine.run()
    assert result.state is LifecycleState.admitted
    assert result.candidate_id == FALLBACK_ID

    inventory = read_finalization_inventory(tmp_path)
    current_plan = read_coverage_plan(tmp_path)
    assert [item.candidate_id for item in inventory.candidate_attempts] == [
        PRIMARY_ID,
        FALLBACK_ID,
    ]
    assert [item.invocation_index for item in inventory.stage_attempts] == [0, 0, 0, 0]
    assert current_plan.targets[0].attempted_candidate_ids == [PRIMARY_ID, FALLBACK_ID]
    assert current_plan.targets[0].admitted_candidate_id == FALLBACK_ID
    assert current_plan.targets[0].target_state is TargetState.admitted
    assert len(inventory.quarantine_inventory) == 1
    assert (tmp_path / "scenarios/scenario-admitted.yaml").is_file()
    assert (tmp_path / "scenarios/scenario-admitted.feature").is_file()
    assert len(inventory.admitted_inventory) == 2

    admitted = next(item for item in inventory.admission_decisions if item.admitted)
    assert {gate.gate for gate in admitted.gate_results} == set(
        NORMAL_POSTBEHAVIOR_EVIDENCE_IDS
    )
    admitted_raw = admitted.model_dump(mode="json")
    identity_only = dict(admitted_raw)
    identity_only["gate_results"] = [
        gate
        for gate in admitted_raw["gate_results"]
        if gate["gate"] == AdmissionEvidenceId.identity.value
    ]
    with pytest.raises(ValidationError, match="canonical gate evidence"):
        AdmissionDecisionRecord.model_validate(identity_only)

    for missing_id in NORMAL_POSTBEHAVIOR_EVIDENCE_IDS:
        mutated = dict(admitted_raw)
        mutated["gate_results"] = [
            gate
            for gate in admitted_raw["gate_results"]
            if gate["gate"] != missing_id.value
        ]
        with pytest.raises(ValidationError, match="canonical gate evidence"):
            AdmissionDecisionRecord.model_validate(mutated)

    for intrinsic_id in (
        NORMAL_POSTBEHAVIOR_EVIDENCE_IDS - CONDITIONALLY_APPLICABLE_EVIDENCE_IDS
    ):
        mutated = json.loads(json.dumps(admitted_raw))
        next(
            gate
            for gate in mutated["gate_results"]
            if gate["gate"] == intrinsic_id.value
        )["applicable"] = False
        with pytest.raises(ValidationError, match="intrinsic.*must be applicable"):
            AdmissionDecisionRecord.model_validate(mutated)

    duplicated = dict(admitted_raw)
    duplicated["gate_results"] = [
        *admitted_raw["gate_results"],
        admitted_raw["gate_results"][0],
    ]
    with pytest.raises(ValidationError, match="must be unique"):
        AdmissionDecisionRecord.model_validate(duplicated)

    for exceptional_id in EXCEPTIONAL_ADMISSION_EVIDENCE_IDS:
        exceptional = dict(admitted_raw)
        exceptional["gate_results"] = [
            *admitted_raw["gate_results"],
            {
                "gate": exceptional_id.value,
                "passed": True,
                "violations": [],
                "diagnostics": [],
                "applicable": True,
            },
        ]
        with pytest.raises(ValidationError, match="exceptional admission evidence"):
            AdmissionDecisionRecord.model_validate(exceptional)

    restarted = make_finalization_persistence_adapter(
        tmp_path, run_id=RUN_ID, coverage_plan=current_plan
    )
    assert result.admission is not None
    original_payload = result.admission.value
    exact_terminal = CandidateTerminalResult(
        FALLBACK_ID,
        CandidateTerminalStatus.admitted,
        admission=AdmissionDecision(True, value=original_payload),
    )
    restarted.record_candidate_result(FALLBACK_ID, exact_terminal)
    restarted.record_candidate_result(
        PRIMARY_ID,
        CandidateTerminalResult(
            PRIMARY_ID,
            CandidateTerminalStatus.rejected,
            violations=(
                LifecycleViolation(
                    detail="primary rejected",
                    code="candidate_invalid",
                    retryable=False,
                ),
            ),
        ),
    )

    changed_publications = [
        original_payload.publication.model_copy(
            update={
                "yaml_text": (
                    "scenario_id: scenario-admitted\n"
                    f"candidate_id: {FALLBACK_ID}\nchanged: true\n"
                )
            }
        ),
        original_payload.publication.model_copy(
            update={"feature_text": "Feature: changed admitted\n"}
        ),
        original_payload.publication.model_copy(
            update={
                "scenario_id": "scenario-changed",
                "yaml_text": (
                    f"scenario_id: scenario-changed\ncandidate_id: {FALLBACK_ID}\n"
                ),
            }
        ),
    ]
    for publication in changed_publications:
        conflicting = CandidateTerminalResult(
            FALLBACK_ID,
            CandidateTerminalStatus.admitted,
            admission=AdmissionDecision(
                True,
                value=AdmittedTerminalPayload(
                    report=original_payload.report,
                    publication=publication,
                ),
            ),
        )
        with pytest.raises(ManifestIntegrityError, match="Conflicting duplicate"):
            restarted.record_candidate_result(FALLBACK_ID, conflicting)

    mismatched_publication = changed_publications[-1]
    journal = {
        "schema_version": "1",
        "coverage_plan": current_plan.model_dump(mode="json"),
        "finalization_inventory": inventory.model_dump(mode="json"),
        "quarantine_bundle": None,
        "admitted_publication": mismatched_publication.model_dump(mode="json"),
    }
    (tmp_path / "scenarios/scenario-admitted.yaml").unlink()
    (tmp_path / "scenarios/scenario-admitted.feature").unlink()
    (tmp_path / ".finalization-state.json").write_bytes(canonical_json_bytes(journal))
    with pytest.raises(ManifestIntegrityError, match="publication does not match"):
        make_finalization_persistence_adapter(
            tmp_path, run_id=RUN_ID, coverage_plan=current_plan
        )
    assert not (tmp_path / "scenarios/scenario-changed.yaml").exists()
    assert not (tmp_path / "scenarios/scenario-changed.feature").exists()


def test_second_repair_can_precede_its_retried_behavior_attempt(tmp_path: Path):
    plan = _plan()
    adapter = make_finalization_persistence_adapter(
        tmp_path, run_id=RUN_ID, coverage_plan=plan
    )

    class Snapshot:
        def __init__(self, tree):
            self.tree = tree
            self.digest = canonical_sha256(tree)

        def verify_digest(self):
            assert self.digest == canonical_sha256(self.tree)

    def stage(candidate, invocation):
        return GeneratedStageResult(
            artifact={
                "candidate_id": candidate.candidate_id,
                "stage": invocation.stage.value,
                "index": invocation.invocation_index,
            },
            evidence=_stage_evidence(invocation.stage),
        )

    def finalize(_candidate, artifacts):
        digest = canonical_sha256(artifacts.tree)
        return PrebehaviorFinalizationResult(
            Snapshot(artifacts.tree),
            repair_record=RepairRecord(
                before_digest=digest,
                after_digest=digest,
                removed_ids=(),
                preserved_projected_ids=("step-1",),
                accepted=True,
                detail="already within budget",
            ),
        )

    admission_calls = 0

    def admit(candidate, _artifacts, _snapshot):
        nonlocal admission_calls
        admission_calls += 1
        if admission_calls == 1:
            return AdmissionDecision(
                False,
                (
                    LifecycleViolation(
                        detail="regenerate narrative and downstream artifacts",
                        owner=GeneratedStage.narrative,
                        code="semantic_validity",
                    ),
                ),
            )
        return AdmissionDecision(
            True,
            value=AdmittedTerminalPayload(
                report=PostbehaviorAdmissionReport(
                    envelope=object(),
                    gate_results=_passing_normal_gate_results(),
                ),
                publication=AdmittedArtifactPublication(
                    candidate_id=candidate.candidate_id,
                    scenario_id="scenario-retried",
                    yaml_text=(
                        "scenario_id: scenario-retried\n"
                        f"candidate_id: {candidate.candidate_id}\n"
                    ),
                    feature_text="Feature: retried\n",
                ),
            ),
        )

    target = plan.targets[0]
    machine = TargetFinalizationMachine(
        entry=CoveragePlanEntry(
            entry_point_id=target.entry_point_id,
            entry_point_name=target.entry_point_name,
            ordered_choices=[
                item.model_dump(mode="json") for item in target.ordered_choices
            ],
            primary_candidate_id=target.primary_candidate_id,
            primary_state="selected",
            fallback_available=[target.ordered_choices[1].model_dump(mode="json")],
        ),
        stage_callbacks={item: stage for item in GENERATION_ORDER},
        candidate_revalidator=lambda ref: CandidateValidation(
            deserialize_qualified_candidate(ref).projected
        ),
        prebehavior_finalizer=finalize,
        admission_callback=admit,
        persistence=adapter,
        attempted_candidate_ids=set(),
    )

    result = machine.run()

    assert result.state is LifecycleState.admitted
    assert result.candidate_id == PRIMARY_ID
    inventory = read_finalization_inventory(tmp_path)
    assert len(inventory.repairs) == 2
    assert [
        item.invocation_index
        for item in inventory.stage_attempts
        if item.stage is GeneratedStage.behavior
    ] == [0, 1]


def test_interrupted_second_document_write_recovers_from_journal(
    tmp_path: Path, monkeypatch
):
    import asago_scenario_generator.pipeline.persistence as persistence_module

    plan = _plan()
    adapter = make_finalization_persistence_adapter(
        tmp_path, run_id=RUN_ID, coverage_plan=plan
    )
    original = persistence_module.write_coverage_plan
    monkeypatch.setattr(
        persistence_module,
        "write_coverage_plan",
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError("second write")),
    )
    with pytest.raises(RuntimeError, match="second write"):
        adapter.record_transition(
            LifecycleTransition(
                LifecycleState.pending,
                LifecycleState.revalidating_candidate,
                PRIMARY_ID,
                "start",
            )
        )
    with pytest.raises(RuntimeError, match="recovery"):
        adapter.record_transition(
            LifecycleTransition(
                LifecycleState.pending,
                LifecycleState.revalidating_candidate,
                PRIMARY_ID,
                "later event",
            )
        )
    assert (tmp_path / ".finalization-state.json").exists()
    monkeypatch.setattr(persistence_module, "write_coverage_plan", original)
    restarted = make_finalization_persistence_adapter(
        tmp_path, run_id=RUN_ID, coverage_plan=plan
    )
    assert not (tmp_path / ".finalization-state.json").exists()
    assert restarted.coverage_plan.targets[0].attempted_candidate_ids == [PRIMARY_ID]
    assert len(restarted.inventory.transitions) == 1


def test_recovery_rejects_mismatched_quarantine_journal_before_write(
    tmp_path: Path, monkeypatch
):
    import asago_scenario_generator.pipeline.persistence as persistence_module

    adapter = make_finalization_persistence_adapter(
        tmp_path, run_id=RUN_ID, coverage_plan=_plan()
    )
    adapter.record_transition(
        LifecycleTransition(
            LifecycleState.pending,
            LifecycleState.revalidating_candidate,
            PRIMARY_ID,
            "start",
        )
    )
    original = persistence_module.write_quarantine_bundle
    monkeypatch.setattr(
        persistence_module,
        "write_quarantine_bundle",
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError("bundle write")),
    )
    violation = LifecycleViolation(
        code="pre_admission_failure", detail="failed before admission", retryable=False
    )
    with pytest.raises(RuntimeError, match="bundle write"):
        adapter.record_candidate_result(
            PRIMARY_ID,
            CandidateTerminalResult(
                PRIMARY_ID,
                CandidateTerminalStatus.rejected,
                violations=(violation,),
            ),
        )
    monkeypatch.setattr(persistence_module, "write_quarantine_bundle", original)
    journal_path = tmp_path / ".finalization-state.json"
    raw = json.loads(journal_path.read_text())
    raw["quarantine_bundle"]["candidate_id"] = FALLBACK_ID
    journal_path.write_bytes(canonical_json_bytes(raw))
    expected_path = tmp_path / f"quarantine/{PRIMARY_ID}:candidate.json"
    assert not expected_path.exists()
    with pytest.raises(
        ManifestIntegrityError, match="quarantine bundle does not match"
    ):
        make_finalization_persistence_adapter(
            tmp_path, run_id=RUN_ID, coverage_plan=_plan()
        )
    assert not expected_path.exists()


def test_malformed_admitted_report_is_rejected(tmp_path: Path):
    adapter = make_finalization_persistence_adapter(
        tmp_path, run_id=RUN_ID, coverage_plan=_plan()
    )
    adapter.record_transition(
        LifecycleTransition(
            LifecycleState.pending,
            LifecycleState.revalidating_candidate,
            PRIMARY_ID,
            "start",
        )
    )
    with pytest.raises(TypeError, match="typed report"):
        adapter.record_candidate_result(
            PRIMARY_ID,
            CandidateTerminalResult(
                PRIMARY_ID,
                CandidateTerminalStatus.admitted,
                admission=AdmissionDecision(True, value={"gate_results": []}),
            ),
        )
    failed_gate = GateViolation(GateCode.semantic, "failed gate", None)
    publication = AdmittedArtifactPublication(
        candidate_id=PRIMARY_ID,
        scenario_id="malformed-admission",
        yaml_text=(f"scenario_id: malformed-admission\ncandidate_id: {PRIMARY_ID}\n"),
        feature_text="Feature: malformed admission\n",
    )
    with pytest.raises(TypeError, match="passing gate report"):
        adapter.record_candidate_result(
            PRIMARY_ID,
            CandidateTerminalResult(
                PRIMARY_ID,
                CandidateTerminalStatus.admitted,
                violations=(failed_gate.lifecycle(),),
                admission=AdmissionDecision(
                    True,
                    (failed_gate.lifecycle(),),
                    value=AdmittedTerminalPayload(
                        report=PostbehaviorAdmissionReport(
                            envelope=object(),
                            gate_results=(
                                GateResult(
                                    AdmissionEvidenceId.identity, (failed_gate,)
                                ),
                            ),
                        ),
                        publication=publication,
                    ),
                ),
            ),
        )


@pytest.mark.parametrize("admission_exception", [False, True])
def test_machine_adapter_persists_complete_postbehavior_rejection_report(
    tmp_path: Path, admission_exception: bool
):
    choice = _choice(PRIMARY_ID)
    plan = CoveragePlanV2(
        schema_version="2",
        completeness="not_applicable",
        evidence_refs=[],
        targets=[
            CoverageTargetEntry(
                entry_point_id=ENTRY_POINT_ID,
                entry_point_name="input",
                ordered_choices=[choice],
                primary_candidate_id=PRIMARY_ID,
                attempted_candidate_ids=[],
                admitted_candidate_id=None,
                target_state=TargetState.selected,
                fallback_available=[choice],
            )
        ],
        selection_limitation_target_ids=[],
    )
    adapter = make_finalization_persistence_adapter(
        tmp_path, run_id=RUN_ID, coverage_plan=plan
    )

    class Snapshot:
        def __init__(self, tree):
            self.tree = tree
            self.digest = canonical_sha256(tree)

        def verify_digest(self):
            assert self.digest == canonical_sha256(self.tree)

    def stage(candidate, invocation):
        return GeneratedStageResult(
            artifact={"stage": invocation.stage.value},
            evidence=_stage_evidence(invocation.stage),
        )

    violation = GateViolation(GateCode.semantic, "hard admission failure", None)
    diagnostic = GateViolation(
        GateCode.zone_difference, "retained gate diagnostic", GeneratedStage.tree
    )
    report = PostbehaviorAdmissionReport(
        envelope=object(),
        gate_results=(
            GateResult(
                AdmissionEvidenceId.semantic_validity,
                (violation,),
                (diagnostic,),
            ),
        ),
    )

    def admit(candidate, artifacts, snapshot):
        if admission_exception:
            raise RuntimeError("admission callback exploded")
        with pytest.raises(TypeError, match="requires PostbehaviorAdmissionReport"):
            adapter.record_candidate_result(
                PRIMARY_ID,
                CandidateTerminalResult(
                    PRIMARY_ID,
                    CandidateTerminalStatus.rejected,
                ),
            )
        return AdmissionDecision(False, (violation.lifecycle(),), value=report)

    machine = TargetFinalizationMachine(
        entry=CoveragePlanEntry(
            entry_point_id=ENTRY_POINT_ID,
            entry_point_name="input",
            ordered_choices=[choice.model_dump(mode="json")],
            primary_candidate_id=PRIMARY_ID,
            primary_state="selected",
            fallback_available=[],
        ),
        stage_callbacks={item: stage for item in GENERATION_ORDER},
        candidate_revalidator=lambda ref: CandidateValidation(
            deserialize_qualified_candidate(ref).projected
        ),
        prebehavior_finalizer=lambda candidate, artifacts: (
            PrebehaviorFinalizationResult(Snapshot(artifacts.tree))
        ),
        admission_callback=admit,
        persistence=adapter,
        attempted_candidate_ids=set(),
    )

    result = machine.run()
    assert result.state is LifecycleState.exhausted
    persisted = read_finalization_inventory(tmp_path)
    decision = persisted.admission_decisions[0]
    if admission_exception:
        assert decision.gate_results[0].violations[0].code == "admission_exception"
        assert (
            decision.gate_results[0].violations[0].detail
            == "RuntimeError: admission callback exploded"
        )
        assert decision.gate_results[0].violations[0].owner is None
    else:
        assert decision.gate_results[0].violations[0].detail == "hard admission failure"
        assert (
            decision.gate_results[0].diagnostics[0].detail == "retained gate diagnostic"
        )
    assert len(persisted.quarantine_inventory) == 1

    missing_report = persisted.model_dump(mode="json")
    missing_report["admission_decisions"][0]["gate_results"] = []
    with pytest.raises(ValidationError, match="requires typed admission gate evidence"):
        FinalizationInventoryV1.model_validate(missing_report)

    reversed_trace = persisted.model_dump(mode="json")
    behavior_stage = next(
        item for item in reversed_trace["stage_attempts"] if item["stage"] == "behavior"
    )
    terminal_edge = next(
        item for item in reversed_trace["transitions"] if item["current"] == "rejected"
    )
    behavior_stage["sequence"], terminal_edge["sequence"] = (
        terminal_edge["sequence"],
        behavior_stage["sequence"],
    )
    with pytest.raises(ValidationError, match="transition indexes|stage evidence"):
        FinalizationInventoryV1.model_validate(reversed_trace)


def test_machine_state_does_not_advance_when_transition_persistence_fails(
    tmp_path: Path, monkeypatch
):
    import asago_scenario_generator.pipeline.persistence as persistence_module

    plan = _plan()
    adapter = make_finalization_persistence_adapter(
        tmp_path, run_id=RUN_ID, coverage_plan=plan
    )
    monkeypatch.setattr(
        persistence_module,
        "write_finalization_inventory",
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError("inventory fsync")),
    )
    target = plan.targets[0]
    machine = TargetFinalizationMachine(
        entry=CoveragePlanEntry(
            entry_point_id=target.entry_point_id,
            entry_point_name=target.entry_point_name,
            ordered_choices=[target.ordered_choices[0].model_dump(mode="json")],
            primary_candidate_id=PRIMARY_ID,
            primary_state="selected",
            fallback_available=[],
        ),
        stage_callbacks={},
        candidate_revalidator=lambda ref: CandidateValidation(None),
        prebehavior_finalizer=lambda candidate, artifacts: (
            PrebehaviorFinalizationResult(None)
        ),
        admission_callback=lambda candidate, artifacts, snapshot: AdmissionDecision(
            False
        ),
        persistence=adapter,
        attempted_candidate_ids=set(),
    )
    with pytest.raises(RuntimeError, match="inventory fsync"):
        machine.run()
    assert machine.state is LifecycleState.pending
    assert machine.transitions == []
    assert machine.attempted_candidate_ids == set()
