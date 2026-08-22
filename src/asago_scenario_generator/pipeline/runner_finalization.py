"""Production wiring for the manifest-v3 target finalization lifecycle."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Any

import yaml

from asago_scenario_generator.llm.client import LLMResult
from asago_scenario_generator.manifest import (
    _ROLE_METADATA,
    ArtifactEntry,
    ArtifactRole,
    build_artifact_entry,
)
from asago_scenario_generator.models.attack_tree import AttackTree
from asago_scenario_generator.models.scenario import (
    ActorProfile,
    BehaviorSpec,
    CallMetadata,
    CallName,
    NarrativeLayer,
)
from asago_scenario_generator.pipeline.coverage_planning import (
    CoveragePlan,
    CoveragePlanEntry,
    revalidate_qualified_candidate,
)
from asago_scenario_generator.pipeline.finalization import (
    COMPLETION_LENGTH_RETRY_SUFFIXES,
    COMPLETION_LENGTH_RETRY_CONTROLS,
    MAX_OWNER_RETRIES,
    AdmissionDecision,
    CandidateTerminalResult,
    CandidateTerminalStatus,
    CandidateValidation,
    GeneratedArtifacts,
    GeneratedStage,
    GeneratedStageResult,
    LifecycleState,
    LifecycleViolation,
    TargetFinalizationMachine,
    make_assertions_only_behavior_callback,
    retry_directive_for,
)
from asago_scenario_generator.pipeline.finalization_admission import (
    make_postbehavior_admission,
)
from asago_scenario_generator.pipeline.finalization_gates import (
    make_prebehavior_finalizer,
)
from asago_scenario_generator.pipeline.generation_contracts import (
    StageAttemptFailure,
    StageCallEvidence,
)
from asago_scenario_generator.pipeline.semantic_generation import (
    DraftViolation,
    StageAttemptEvidence,
    StageGenerationEvidence,
)
from asago_scenario_generator.pipeline.generate.stages import (
    GenerationRequest,
    assemble_final_envelope,
    generate_actor_stage,
    generate_narrative_stage,
    generate_tree_stage,
    prepare_generation,
)
from asago_scenario_generator.pipeline.persistence import (
    AdmittedArtifactPublication,
    CoveragePlanV2,
    CoverageTargetEntry,
    QualifiedCandidateRef,
    _causal_stage_artifacts,
    canonical_sha256,
    make_admitted_terminal_payload,
    make_finalization_persistence_adapter,
    read_coverage_plan,
)


def _hydrate_stage_evidence(record: Any) -> StageCallEvidence | None:
    """Restore committed call metadata needed for final envelope assembly."""
    if record.call is None:
        return None
    call = record.call
    semantic = call.semantic_evidence
    semantic_evidence = None
    if semantic is not None:
        semantic_evidence = StageGenerationEvidence(
            stage=semantic["stage"],
            compiler_name=semantic["compiler_name"],
            handle_map=semantic["handle_map"],
            attempts=tuple(
                StageAttemptEvidence(
                    attempt_index=attempt["attempt_index"],
                    request_digest=attempt["request_digest"],
                    response_digest=attempt["response_digest"],
                    finish_reason=attempt["finish_reason"],
                    result=attempt["result"],
                    effective_controls=attempt["effective_controls"],
                    validation_violations=tuple(
                        DraftViolation(
                            violation["code"],
                            violation["detail"],
                            tuple(violation["handles"]),
                        )
                        for violation in attempt["validation_violations"]
                    ),
                    retry_class=attempt["retry_class"],
                    failure_detail=attempt["failure_detail"],
                )
                for attempt in semantic["attempts"]
            ),
            accepted_draft_digest=semantic["accepted_draft_digest"],
            warnings=tuple(semantic.get("warnings", ())),
        )
    return StageCallEvidence(
        call_name=CallName(call.call_name),
        result=LLMResult.model_validate(call.result.model_dump(mode="json")),
        metadata=CallMetadata.model_validate(call.metadata.model_dump(mode="json")),
        semantic_evidence=semantic_evidence,
    )


def strict_v3_coverage_plan(plan: CoveragePlan) -> CoveragePlanV2:
    """Translate the cmps.4 queue contract into its strict durable form."""
    targets: list[CoverageTargetEntry] = []
    for target in plan.targets:
        # Queue-local rank is authority; never retain stale/source ranks.
        choices = [
            QualifiedCandidateRef.model_validate({**ref, "rank": rank})
            for rank, ref in enumerate(target.ordered_choices[:3])
        ]
        primary = target.primary_candidate_id
        if primary is not None:
            choices.sort(key=lambda ref: (ref.candidate_id != primary, ref.rank))
            choices = [
                ref.model_copy(update={"rank": rank})
                for rank, ref in enumerate(choices)
            ]
        empty = not choices
        targets.append(
            CoverageTargetEntry(
                target_id=target.effective_target_id,
                entry_point_id=target.entry_point_id,
                entry_point_name=target.entry_point_name,
                ordered_choices=choices,
                primary_candidate_id=None if empty else primary,
                attempted_candidate_ids=[],
                admitted_candidate_id=None,
                target_state="exhausted" if empty else "selected",
                # Before reservation every choice, including the primary, is
                # unattempted and therefore available.
                fallback_available=choices,
            )
        )
    return CoveragePlanV2(
        schema_version="2",
        completeness=plan.completeness,
        evidence_refs=plan.evidence_refs,
        targets=targets,
        selection_limitation_target_ids=plan.selection_limitation_target_ids,
    )


def build_v3_inventory(
    run_dir: Path,
    finalization_inventory: Any,
    *,
    include_coverage: bool = True,
    include_eval: bool = False,
    include_report: bool = False,
    include_log: bool = False,
    include_quarantine: bool = True,
) -> list[ArtifactEntry]:
    """Build an exact v3 inventory from typed receipts and known support roles."""
    entries: list[ArtifactEntry] = []

    def add(role: ArtifactRole, path: str, *, required: bool = True) -> None:
        if not (run_dir / path).is_file():
            if required:
                raise FileNotFoundError(f"required v3 artifact is missing: {path}")
            return
        entries.append(
            build_artifact_entry(
                role=role,
                run_dir=run_dir,
                rel_path=path,
                schema_version="2" if role is ArtifactRole.COVERAGE_PLAN else "1",
            )
        )

    add(ArtifactRole.USE_CASE, "use-case.txt")
    add(ArtifactRole.CAPABILITY_PROFILE, "capability-profile.yaml")
    add(ArtifactRole.THREAT_SURFACE, "threat-surface.yaml")
    add(ArtifactRole.PLANNING_CHECKPOINT, "planning-checkpoint.json")
    if include_coverage:
        add(ArtifactRole.COVERAGE_REPORT, "coverage-gaps.json")
    add(ArtifactRole.COVERAGE_PLAN, "coverage-plan.json")
    add(ArtifactRole.FINALIZATION_INVENTORY, "finalization-inventory.json")
    add(ArtifactRole.PIPELINE_CALL_LOG, "calls.jsonl", required=False)
    add(
        ArtifactRole.CANDIDATE_FILTER_QUARANTINE,
        "candidate-filter-quarantine.json",
        required=False,
    )
    if include_eval:
        add(ArtifactRole.EVAL_SCORECARD, "eval-scorecard.yaml")
    if include_report:
        add(ArtifactRole.REPORT, "report.html")
    if include_log:
        add(ArtifactRole.PIPELINE_LOG, "pipeline.log")

    receipts = list(finalization_inventory.admitted_inventory)
    if include_quarantine:
        receipts.extend(finalization_inventory.quarantine_inventory)
    for receipt in receipts:
        entry = ArtifactEntry(
            role=receipt.role,
            path=receipt.path,
            sha256=receipt.sha256,
            schema_version="1",
            media_type=_ROLE_METADATA[receipt.role]["media_type"],
            scenario_id=receipt.scenario_id,
            candidate_id=receipt.candidate_id,
        )
        entries.append(entry)
    return entries


def resume_completion_length_counts(
    candidate_stages: Sequence[Any],
) -> dict[GeneratedStage, int]:
    """Derive authorized completion-length retries from durable stage records.

    A durable ``completion_length`` violation on the latest stage record
    means the one length retry was already authorized: the resumed
    invocation re-runs with the approved suffix, and a further length
    failure is terminal.  Any other latest record leaves the count at zero.
    """
    latest = candidate_stages[-1] if candidate_stages else None
    return {
        stage: 1
        if (
            latest is not None
            and latest.stage is stage
            and any(
                violation.code == StageAttemptFailure.COMPLETION_LENGTH_CODE
                for violation in latest.violations
            )
        )
        else 0
        for stage in GeneratedStage
    }


def run_target_finalization(
    *,
    run_dir: Any,
    run_id: str,
    plan: CoveragePlan,
    profile: Any,
    client: Any,
    use_case: str,
    taxonomy_resolver: Any,
    capability_snapshot: Any,
    trusted_catalog: Sequence[dict[str, Any]],
    presentation_fallback: str = "allow",
) -> Any:
    """Finalize every persisted target; plan/inventory precede all candidate calls."""
    plan_path = Path(run_dir) / "coverage-plan.json"
    durable_plan = (
        read_coverage_plan(Path(run_dir))
        if plan_path.is_file()
        else strict_v3_coverage_plan(plan)
    )
    persistence = make_finalization_persistence_adapter(
        run_dir, run_id=run_id, coverage_plan=durable_plan
    )
    attempted = {item.candidate_id for item in persistence.inventory.candidate_attempts}

    terminal_ids = {
        item.candidate_id for item in persistence.inventory.admission_decisions
    }

    for target in list(persistence.coverage_plan.targets):
        if target.target_state == "admitted":
            continue
        if target.target_state == "exhausted" and any(
            item.target_entry_point_id == target.effective_target_id
            and item.current.value == "exhausted"
            for item in persistence.inventory.transitions
        ):
            continue
        prepared_by_id: dict[str, Any] = {}
        evidence_by_id: dict[str, dict[GeneratedStage, Any]] = {}
        ref_by_id = {ref.candidate_id: ref for ref in target.ordered_choices}
        active_attempt = next(
            (
                item
                for item in reversed(persistence.inventory.candidate_attempts)
                if item.target_entry_point_id == target.effective_target_id
                and item.candidate_id not in terminal_ids
            ),
            None,
        )
        resume_artifacts = GeneratedArtifacts()
        resume_stage: GeneratedStage | None = None
        resume_candidate_id: str | None = None
        if active_attempt is not None:
            candidate_stages = sorted(
                (
                    item
                    for item in persistence.inventory.stage_attempts
                    if item.candidate_id == active_attempt.candidate_id
                ),
                key=lambda item: item.sequence,
            )
            generating = [
                item
                for item in persistence.inventory.transitions
                if item.candidate_id == active_attempt.candidate_id
                and item.current.value.startswith("generating_")
            ]
            # A generating edge is written before the external call.  Without
            # its matching StageAttempt there is no safe evidence that the call
            # did or did not happen, so it is terminal and must never be reissued.
            if len(generating) == len(candidate_stages) + 1:
                violation = LifecycleViolation(
                    "durable generating transition has no matching stage result",
                    code="unknown_invocation_outcome",
                    retryable=False,
                )
                persistence.record_candidate_result(
                    active_attempt.candidate_id,
                    CandidateTerminalResult(
                        active_attempt.candidate_id,
                        CandidateTerminalStatus.generation_or_finalization_failed,
                        (violation,),
                    ),
                )
                terminal_ids.add(active_attempt.candidate_id)
            elif (
                candidate_stages
                and candidate_stages[-1].violations
                and candidate_stages[-1].owner_retry_index >= MAX_OWNER_RETRIES
            ):
                violation = LifecycleViolation(
                    "durable stage evidence exhausted the owner retry budget",
                    owner=candidate_stages[-1].stage,
                    code="owner_retry_exhausted",
                    retryable=False,
                )
                persistence.record_candidate_result(
                    active_attempt.candidate_id,
                    CandidateTerminalResult(
                        active_attempt.candidate_id,
                        CandidateTerminalStatus.generation_or_finalization_failed,
                        (violation,),
                    ),
                )
                terminal_ids.add(active_attempt.candidate_id)
            else:
                model_by_stage = {
                    GeneratedStage.actor: ActorProfile,
                    GeneratedStage.narrative: NarrativeLayer,
                    GeneratedStage.tree: AttackTree,
                    GeneratedStage.behavior: BehaviorSpec,
                }
                latest: dict[GeneratedStage, Any] = {}
                durable_feedback: dict[GeneratedStage, str] = {}
                durable_reasons: dict[GeneratedStage, str] = {}
                durable_controls: dict[GeneratedStage, Any] = {}
                durable_candidate = ref_by_id[
                    active_attempt.candidate_id
                ].projected_candidate
                _causal_stage_artifacts(
                    candidate_stages,
                    candidate_attempt_id=active_attempt.attempt_id,
                    durable_candidate=durable_candidate,
                    repairs=[
                        item
                        for item in persistence.inventory.repairs
                        if item.candidate_id == active_attempt.candidate_id
                    ],
                )
                for record in candidate_stages:
                    # Every invocation supersedes its owner and all downstream
                    # artifacts.  Replay the journal in sequence rather than
                    # selecting an independently-latest value for each stage.
                    for invalidated in tuple(GeneratedStage)[
                        tuple(GeneratedStage).index(record.stage) :
                    ]:
                        latest.pop(invalidated, None)
                        evidence_by_id.get(active_attempt.candidate_id, {}).pop(
                            invalidated, None
                        )
                    visible = dict(record.input.visible_artifacts)
                    if record.stage is GeneratedStage.behavior:
                        visible_tree = visible.get(GeneratedStage.tree.value)
                        if (
                            visible_tree is None
                            or record.final_tree_snapshot_sha256
                            != canonical_sha256(visible_tree)
                        ):
                            raise ValueError(
                                "behavior resume input is not bound to its final tree digest"
                            )
                        latest[GeneratedStage.tree] = AttackTree.model_validate(
                            visible_tree
                        )
                    expected_visible = {
                        stage.value: artifact.model_dump(mode="json")
                        for stage, artifact in latest.items()
                    }
                    if visible != expected_visible:
                        raise ValueError(
                            "stage resume input is not the contiguous causal artifact frontier"
                        )
                    if (
                        record.result is not None
                        and not record.violations
                        and record.call is not None
                    ):
                        latest[record.stage] = model_by_stage[
                            record.stage
                        ].model_validate(record.result)
                        evidence = _hydrate_stage_evidence(record)
                        if evidence is not None:
                            evidence_by_id.setdefault(active_attempt.candidate_id, {})[
                                record.stage
                            ] = evidence
                    if record.violations:
                        has_length_violation = any(
                            item.code == StageAttemptFailure.COMPLETION_LENGTH_CODE
                            for item in record.violations
                        )
                        if has_length_violation:
                            # Completion-length retries re-invoke with the
                            # approved suffix verbatim, never with rendered
                            # exception text or semantic-channel feedback.
                            durable_feedback[record.stage] = (
                                COMPLETION_LENGTH_RETRY_SUFFIXES[record.stage]
                            )
                            durable_reasons[record.stage] = "completion_length"
                            durable_controls[record.stage] = (
                                COMPLETION_LENGTH_RETRY_CONTROLS[record.stage]
                            )
                        else:
                            durable_feedback[record.stage] = (
                                "; ".join(
                                    f"{item.code}: {item.detail}"
                                    for item in record.violations
                                    if item.owner is record.stage
                                )
                                or f"Retry {record.stage.value} to correct validation failure"
                            )
                for stage, artifact in latest.items():
                    resume_artifacts.set(stage, artifact)
                if candidate_stages and candidate_stages[-1].violations:
                    resume_stage = candidate_stages[-1].stage
                    resume_artifacts.invalidate_from(resume_stage)
                    for downstream in GeneratedStage:
                        if list(GeneratedStage).index(downstream) >= list(
                            GeneratedStage
                        ).index(resume_stage):
                            evidence_by_id.get(active_attempt.candidate_id, {}).pop(
                                downstream, None
                            )
                else:
                    resume_stage = next(
                        (stage for stage in GeneratedStage if stage not in latest),
                        GeneratedStage.behavior,
                    )
                resume_candidate_id = active_attempt.candidate_id

        def revalidate(raw: dict[str, Any]) -> CandidateValidation:
            try:
                qualified = revalidate_qualified_candidate(
                    raw, taxonomy_resolver, capability_snapshot, trusted_catalog
                )
                accepted = qualified.accepted_filters[0]
                if accepted.seed is None:
                    raise ValueError("persisted candidate has no generation seed")
                prepared_by_id[qualified.candidate_id] = prepare_generation(  # noqa: B023
                    GenerationRequest(
                        seed=accepted.seed,
                        profile=profile,
                        client=client,
                        use_case=use_case,
                        pinned_entry_point_id=qualified.entry_point_id,
                        projected_candidate=qualified.projected,
                        capability_snapshot=capability_snapshot,
                        pinned_entry_point=accepted.pinned_entry_point,
                        pinned_technique_ids=accepted.pinned_technique_ids,
                        pinned_technique_names=accepted.pinned_technique_names,
                        run_id=run_id,
                        candidate_id=qualified.candidate_id,
                        presentation_fallback=presentation_fallback,
                    )
                )
                return CandidateValidation(qualified.projected)
            except Exception as exc:  # noqa: BLE001 - authoritative tamper evidence
                return CandidateValidation(
                    None,
                    (
                        LifecycleViolation(
                            str(exc),
                            code="candidate_revalidation_failed",
                            retryable=False,
                        ),
                    ),
                )

        def generated(stage: GeneratedStage):
            def callback(candidate: Any, invocation: Any) -> GeneratedStageResult:
                prepared = prepared_by_id[candidate.candidate_id]  # noqa: B023
                retry = retry_directive_for(invocation)
                if stage is GeneratedStage.actor:
                    result = generate_actor_stage(prepared, retry)
                elif stage is GeneratedStage.narrative:
                    result = generate_narrative_stage(
                        prepared, invocation.artifacts.actor, retry
                    )
                else:
                    result = generate_tree_stage(
                        prepared,
                        invocation.artifacts.actor,
                        invocation.artifacts.narrative,
                        retry,
                    )
                evidence_by_id.setdefault(candidate.candidate_id, {})[stage] = (  # noqa: B023
                    result.evidence
                )
                return GeneratedStageResult(result.artifact, result.evidence)

            return callback

        def behavior(candidate: Any, invocation: Any) -> GeneratedStageResult:
            result = make_assertions_only_behavior_callback(
                prepared_by_id[candidate.candidate_id]  # noqa: B023
            )(candidate, invocation)
            evidence_by_id.setdefault(candidate.candidate_id, {})[  # noqa: B023
                GeneratedStage.behavior
            ] = result.evidence
            return result

        def assembler(
            candidate: Any, actor: Any, narrative: Any, tree: Any, behavior: Any
        ):
            prepared = prepared_by_id[candidate.candidate_id]  # noqa: B023
            evidence = evidence_by_id[candidate.candidate_id]  # noqa: B023
            envelope = assemble_final_envelope(
                prepared,
                actor,
                narrative,
                tree,
                behavior,
                tuple(evidence[stage] for stage in GeneratedStage),
                notes=tuple(
                    warning
                    for stage in GeneratedStage
                    if evidence[stage].semantic_evidence is not None
                    for warning in evidence[stage].semantic_evidence.warnings
                ),
            )
            ref = ref_by_id[candidate.candidate_id]  # noqa: B023
            envelope.candidate_filter = {
                "candidate_id": candidate.candidate_id,
                "filter_candidate_id": ref.filter_candidate_id,
                "entry_point_id": ref.entry_point_id,
                "pinned_entry_point": ref.pinned_entry_point,
                "pinned_technique_ids": ref.pinned_technique_ids,
                "pinned_technique_names": ref.pinned_technique_names,
                "origins": ref.origins,
                "rejection_rationales": ref.rejection_rationales,
            }
            return envelope

        def admit(candidate: Any, artifacts: Any, snapshot: Any) -> AdmissionDecision:
            # Scenario identity is candidate-specific and becomes known only after
            # authoritative revalidation/prepare_generation.  Constructing the
            # port here avoids mutable identity shared by fallback candidates.
            admission_port = make_postbehavior_admission(
                assembler,
                trusted_catalog=trusted_catalog,
                taxonomy_resolver=taxonomy_resolver,
                capability_snapshot=capability_snapshot,
                expected_scenario_id=prepared_by_id[candidate.candidate_id].scenario_id,  # noqa: B023
            )
            decision = admission_port(candidate, artifacts, snapshot)
            if not decision.admitted:
                return decision
            report = decision.value
            envelope = report.envelope
            publication = AdmittedArtifactPublication(
                candidate_id=candidate.candidate_id,
                scenario_id=envelope.scenario_id,
                yaml_text=yaml.dump(envelope.model_dump(mode="json"), sort_keys=False),
                feature_text=envelope.behavior_spec.gherkin_text,
            )
            return AdmissionDecision(
                True, value=make_admitted_terminal_payload(report, publication)
            )

        # Restart authority is the durable CoveragePlanV2, including its exact
        # choice refs; never substitute freshly computed plan refs.
        available_refs = [
            item.model_dump(mode="json") for item in target.fallback_available
        ]
        if (
            resume_candidate_id is not None
            and resume_candidate_id != target.primary_candidate_id
        ):
            resumed_ref = ref_by_id[resume_candidate_id].model_dump(mode="json")
            available_refs = [
                resumed_ref,
                *[
                    item
                    for item in available_refs
                    if item["candidate_id"] != resume_candidate_id
                ],
            ]
        legacy_entry = CoveragePlanEntry(
            target_id=target.effective_target_id,
            entry_point_id=target.entry_point_id,
            entry_point_name=target.entry_point_name,
            ordered_choices=[
                item.model_dump(mode="json") for item in target.ordered_choices
            ],
            primary_candidate_id=target.primary_candidate_id,
            primary_state=target.target_state.value,
            fallback_available=available_refs,
        )
        machine = TargetFinalizationMachine(
            entry=legacy_entry,
            stage_callbacks={
                GeneratedStage.actor: generated(GeneratedStage.actor),
                GeneratedStage.narrative: generated(GeneratedStage.narrative),
                GeneratedStage.tree: generated(GeneratedStage.tree),
                GeneratedStage.behavior: behavior,
            },
            candidate_revalidator=revalidate,
            prebehavior_finalizer=make_prebehavior_finalizer(
                capability_snapshot, profile
            ),
            admission_callback=admit,
            persistence=persistence,
            attempted_candidate_ids=attempted,
            state=next(
                (
                    item.current
                    for item in reversed(persistence.inventory.transitions)
                    if item.target_entry_point_id == target.effective_target_id
                ),
                LifecycleState.pending,
            ),
            resume_candidate_id=resume_candidate_id,
            resume_next_stage=resume_stage,
            resume_artifacts=resume_artifacts,
            resume_invocation_counts={
                stage: sum(1 for item in candidate_stages if item.stage is stage)
                for stage in GeneratedStage
            }
            if active_attempt is not None
            else {},
            resume_owner_retry_counts={
                stage: max(
                    (
                        item.owner_retry_index
                        + (1 if item is candidate_stages[-1] and item.violations else 0)
                        for item in candidate_stages
                        if item.stage is stage
                    ),
                    default=0,
                )
                for stage in GeneratedStage
            }
            if active_attempt is not None
            else {},
            resume_length_retry_counts=resume_completion_length_counts(candidate_stages)
            if active_attempt is not None
            else {},
            resume_retry_feedback=durable_feedback
            if active_attempt is not None and resume_candidate_id is not None
            else {},
            resume_retry_reasons=durable_reasons
            if active_attempt is not None and resume_candidate_id is not None
            else {},
            resume_retry_controls=durable_controls
            if active_attempt is not None and resume_candidate_id is not None
            else {},
            transition_index_offset=(
                max(
                    (
                        item.index
                        for item in persistence.inventory.transitions
                        if item.target_entry_point_id == target.effective_target_id
                    ),
                    default=-1,
                )
                + 1
            ),
        )
        machine.run()
    return persistence
