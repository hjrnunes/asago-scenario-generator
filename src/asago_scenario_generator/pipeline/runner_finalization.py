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
    TargetFinalizationMachine,
    make_assertions_only_behavior_callback,
    retry_directive_for,
)
from asago_scenario_generator.pipeline.finalization_contracts import (
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
    targets = [_strict_target_entry(target) for target in plan.targets]
    return CoveragePlanV2(
        schema_version="2",
        completeness=plan.completeness,
        evidence_refs=plan.evidence_refs,
        targets=targets,
        selection_limitation_target_ids=plan.selection_limitation_target_ids,
    )


def _ranked_choices(target: Any) -> list[QualifiedCandidateRef]:
    """Re-rank the queue-local choices, primary first and bounded to three.

    Queue-local rank is authority; never retain stale/source ranks.
    """
    choices = [
        QualifiedCandidateRef.model_validate({**ref, "rank": rank})
        for rank, ref in enumerate(target.ordered_choices[:3])
    ]
    primary = target.primary_candidate_id
    if primary is not None:
        choices.sort(key=lambda ref: (ref.candidate_id != primary, ref.rank))
        choices = [
            ref.model_copy(update={"rank": rank}) for rank, ref in enumerate(choices)
        ]
    return choices


def _strict_target_entry(target: Any) -> CoverageTargetEntry:
    """Build one strict durable target entry from a queue contract entry."""
    choices = _ranked_choices(target)
    primary = target.primary_candidate_id
    empty = not choices
    return CoverageTargetEntry(
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
    entries = _support_artifacts(
        run_dir, include_coverage, include_eval, include_report, include_log
    )
    entries.extend(_finalization_receipts(finalization_inventory, include_quarantine))
    return entries


def _add_inventory_artifact(
    entries: list[ArtifactEntry],
    run_dir: Path,
    role: ArtifactRole,
    path: str,
    *,
    required: bool = True,
) -> None:
    """Append one support artifact entry when its file exists."""
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


def _support_artifacts(
    run_dir: Path,
    include_coverage: bool,
    include_eval: bool,
    include_report: bool,
    include_log: bool,
) -> list[ArtifactEntry]:
    """Build entries for the fixed v3 support artifacts and optional products."""
    entries: list[ArtifactEntry] = []
    _add_inventory_artifact(entries, run_dir, ArtifactRole.USE_CASE, "use-case.txt")
    _add_inventory_artifact(
        entries, run_dir, ArtifactRole.CAPABILITY_PROFILE, "capability-profile.yaml"
    )
    _add_inventory_artifact(
        entries, run_dir, ArtifactRole.THREAT_SURFACE, "threat-surface.yaml"
    )
    _add_inventory_artifact(
        entries, run_dir, ArtifactRole.PLANNING_CHECKPOINT, "planning-checkpoint.json"
    )
    if include_coverage:
        _add_inventory_artifact(
            entries, run_dir, ArtifactRole.COVERAGE_REPORT, "coverage-gaps.json"
        )
    _add_inventory_artifact(
        entries, run_dir, ArtifactRole.COVERAGE_PLAN, "coverage-plan.json"
    )
    _add_inventory_artifact(
        entries,
        run_dir,
        ArtifactRole.FINALIZATION_INVENTORY,
        "finalization-inventory.json",
    )
    _add_inventory_artifact(
        entries, run_dir, ArtifactRole.PIPELINE_CALL_LOG, "calls.jsonl", required=False
    )
    _add_inventory_artifact(
        entries,
        run_dir,
        ArtifactRole.CANDIDATE_FILTER_QUARANTINE,
        "candidate-filter-quarantine.json",
        required=False,
    )
    if include_eval:
        _add_inventory_artifact(
            entries, run_dir, ArtifactRole.EVAL_SCORECARD, "eval-scorecard.yaml"
        )
    if include_report:
        _add_inventory_artifact(entries, run_dir, ArtifactRole.REPORT, "report.html")
    if include_log:
        _add_inventory_artifact(
            entries, run_dir, ArtifactRole.PIPELINE_LOG, "pipeline.log"
        )
    return entries


def _finalization_receipts(
    finalization_inventory: Any, include_quarantine: bool
) -> list[ArtifactEntry]:
    """Append admitted and (optionally) quarantined durable receipts."""
    receipts = list(finalization_inventory.admitted_inventory)
    if include_quarantine:
        receipts.extend(finalization_inventory.quarantine_inventory)
    return [
        ArtifactEntry(
            role=receipt.role,
            path=receipt.path,
            sha256=receipt.sha256,
            schema_version="1",
            media_type=_ROLE_METADATA[receipt.role]["media_type"],
            scenario_id=receipt.scenario_id,
            candidate_id=receipt.candidate_id,
        )
        for receipt in receipts
    ]


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
    return {stage: _authorized_length_retry(stage, latest) for stage in GeneratedStage}


def _authorized_length_retry(stage: GeneratedStage, latest: Any) -> int:
    """Return 1 when the one completion-length retry is already authorized."""
    if (
        latest is not None
        and latest.stage is stage
        and _has_completion_length_violation(latest)
    ):
        return 1
    return 0


def _has_completion_length_violation(record: Any) -> bool:
    """True when the record carries a durable completion-length violation."""
    return any(
        violation.code == StageAttemptFailure.COMPLETION_LENGTH_CODE
        for violation in record.violations
    )


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
    durable_plan = _resolved_durable_plan(run_dir, plan)
    persistence = _build_finalization_persistence(run_dir, run_id, durable_plan)
    attempted = _attempted_candidate_ids(persistence)
    terminal_ids = _terminal_candidate_ids(persistence)
    for target in list(persistence.coverage_plan.targets):
        _finalize_target(
            target=target,
            persistence=persistence,
            profile=profile,
            client=client,
            use_case=use_case,
            taxonomy_resolver=taxonomy_resolver,
            capability_snapshot=capability_snapshot,
            trusted_catalog=trusted_catalog,
            run_id=run_id,
            presentation_fallback=presentation_fallback,
            attempted=attempted,
            terminal_ids=terminal_ids,
        )
    return persistence


class _TargetResumeState:
    """Per-target resume evidence and durable retry directives."""

    __slots__ = (
        "artifacts",
        "stage",
        "candidate_id",
        "feedback",
        "reasons",
        "controls",
        "invocation_counts",
        "owner_retry_counts",
        "length_retry_counts",
    )

    def __init__(self) -> None:
        self.artifacts = GeneratedArtifacts()
        self.stage: GeneratedStage | None = None
        self.candidate_id: str | None = None
        self.feedback: dict[GeneratedStage, str] = {}
        self.reasons: dict[GeneratedStage, str] = {}
        self.controls: dict[GeneratedStage, Any] = {}
        self.invocation_counts: dict[GeneratedStage, int] = {}
        self.owner_retry_counts: dict[GeneratedStage, int] = {}
        self.length_retry_counts: dict[GeneratedStage, int] = {}


def _resolved_durable_plan(run_dir: Any, plan: CoveragePlan) -> CoveragePlanV2:
    """Return the persisted coverage plan, or a strict projection of the fresh plan."""
    plan_path = Path(run_dir) / "coverage-plan.json"
    if plan_path.is_file():
        return read_coverage_plan(Path(run_dir))
    return strict_v3_coverage_plan(plan)


def _build_finalization_persistence(
    run_dir: Any, run_id: str, durable_plan: CoveragePlanV2
) -> Any:
    """Construct the durable finalization persistence adapter for the run."""
    return make_finalization_persistence_adapter(
        run_dir, run_id=run_id, coverage_plan=durable_plan
    )


def _attempted_candidate_ids(persistence: Any) -> set[str]:
    """Collect candidate_ids already attempted in the durable journal."""
    return {item.candidate_id for item in persistence.inventory.candidate_attempts}


def _terminal_candidate_ids(persistence: Any) -> set[str]:
    """Collect candidate_ids already settled by an admission decision."""
    return {item.candidate_id for item in persistence.inventory.admission_decisions}


def _finalize_target(
    *,
    target: CoverageTargetEntry,
    persistence: Any,
    profile: Any,
    client: Any,
    use_case: str,
    taxonomy_resolver: Any,
    capability_snapshot: Any,
    trusted_catalog: Sequence[dict[str, Any]],
    run_id: str,
    presentation_fallback: str,
    attempted: set[str],
    terminal_ids: set[str],
) -> None:
    """Drive one finalization-machine pass over a single coverage target."""
    if target.target_state == "admitted":
        return
    if _exhausted_by_persisted_transition(target, persistence):
        return
    prepared_by_id: dict[str, Any] = {}
    evidence_by_id: dict[str, dict[GeneratedStage, Any]] = {}
    ref_by_id = _choice_refs_by_candidate(target)
    active_attempt = _active_candidate_attempt(target, persistence, terminal_ids)
    resume = _TargetResumeState()
    if active_attempt is not None:
        resume = _recover_resume_candidate_state(
            persistence, active_attempt, terminal_ids, ref_by_id, evidence_by_id
        )
    revalidate = _target_revalidator(
        prepared_by_id,
        profile,
        client,
        use_case,
        run_id,
        presentation_fallback,
        taxonomy_resolver,
        capability_snapshot,
        trusted_catalog,
    )
    assembler = _assembler_factory(prepared_by_id, evidence_by_id, ref_by_id)
    # Restart authority is the durable CoveragePlanV2, including its exact
    # choice refs; never substitute freshly computed plan refs.
    available_refs = _target_available_refs(target, ref_by_id, resume.candidate_id)
    legacy_entry = _legacy_plan_entry(target, available_refs)
    machine = TargetFinalizationMachine(
        entry=legacy_entry,
        stage_callbacks={
            GeneratedStage.actor: _generated_callback_factory(
                GeneratedStage.actor, prepared_by_id, evidence_by_id
            ),
            GeneratedStage.narrative: _generated_callback_factory(
                GeneratedStage.narrative, prepared_by_id, evidence_by_id
            ),
            GeneratedStage.tree: _generated_callback_factory(
                GeneratedStage.tree, prepared_by_id, evidence_by_id
            ),
            GeneratedStage.behavior: _behavior_callback_factory(
                prepared_by_id, evidence_by_id
            ),
        },
        candidate_revalidator=revalidate,
        prebehavior_finalizer=make_prebehavior_finalizer(capability_snapshot, profile),
        admission_callback=_admit_factory(
            prepared_by_id,
            assembler,
            capability_snapshot,
            taxonomy_resolver,
            trusted_catalog,
        ),
        persistence=persistence,
        attempted_candidate_ids=attempted,
        state=_machine_initial_state(persistence, target),
        resume_candidate_id=resume.candidate_id,
        resume_next_stage=resume.stage,
        resume_artifacts=resume.artifacts,
        **_resume_counts_kwargs(resume, active_attempt),
        **_resume_retry_kwargs(resume, active_attempt),
        transition_index_offset=_transition_index_offset(persistence, target),
    )
    machine.run()


def _exhausted_by_persisted_transition(
    target: CoverageTargetEntry, persistence: Any
) -> bool:
    """A target is already exhausted when a durable transition says so."""
    if target.target_state == "exhausted" and any(
        item.target_entry_point_id == target.effective_target_id
        and item.current.value == "exhausted"
        for item in persistence.inventory.transitions
    ):
        return True
    return False


def _choice_refs_by_candidate(target: CoverageTargetEntry) -> dict[str, Any]:
    """Index the target's ordered choice refs by candidate_id."""
    return {ref.candidate_id: ref for ref in target.ordered_choices}


def _active_candidate_attempt(
    target: CoverageTargetEntry, persistence: Any, terminal_ids: set[str]
) -> Any | None:
    """Return the most recent non-terminal candidate attempt for the target."""
    return next(
        (
            item
            for item in reversed(persistence.inventory.candidate_attempts)
            if item.target_entry_point_id == target.effective_target_id
            and item.candidate_id not in terminal_ids
        ),
        None,
    )


def _target_revalidator(
    prepared_by_id: dict[str, Any],
    profile: Any,
    client: Any,
    use_case: str,
    run_id: str,
    presentation_fallback: str,
    taxonomy_resolver: Any,
    capability_snapshot: Any,
    trusted_catalog: Sequence[dict[str, Any]],
) -> Any:
    """Build the candidate revalidation callback for one target."""

    def revalidate(raw: dict[str, Any]) -> CandidateValidation:
        return _revalidate_persisted_candidate(
            raw,
            prepared_by_id,
            profile,
            client,
            use_case,
            run_id,
            presentation_fallback,
            taxonomy_resolver,
            capability_snapshot,
            trusted_catalog,
        )

    return revalidate


def _revalidate_persisted_candidate(
    raw: dict[str, Any],
    prepared_by_id: dict[str, Any],
    profile: Any,
    client: Any,
    use_case: str,
    run_id: str,
    presentation_fallback: str,
    taxonomy_resolver: Any,
    capability_snapshot: Any,
    trusted_catalog: Sequence[dict[str, Any]],
) -> CandidateValidation:
    """Authoritatively revalidate a persisted candidate, recording tamper evidence."""
    try:
        qualified = revalidate_qualified_candidate(
            raw, taxonomy_resolver, capability_snapshot, trusted_catalog
        )
        accepted = qualified.accepted_filters[0]
        if accepted.seed is None:
            raise ValueError("persisted candidate has no generation seed")
        prepared_by_id[qualified.candidate_id] = prepare_generation(
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
                    code=getattr(
                        exc,
                        "stage_failure_code",
                        "candidate_revalidation_failed",
                    ),
                    retryable=False,
                ),
            ),
        )


def _generated_callback_factory(
    stage: GeneratedStage,
    prepared_by_id: dict[str, Any],
    evidence_by_id: dict[str, dict[GeneratedStage, Any]],
) -> Any:
    """Build the stage-generation callback for one target."""

    def callback(candidate: Any, invocation: Any) -> GeneratedStageResult:
        return _generated_stage_callback(
            stage, candidate, invocation, prepared_by_id, evidence_by_id
        )

    return callback


def _generated_stage_callback(
    stage: GeneratedStage,
    candidate: Any,
    invocation: Any,
    prepared_by_id: dict[str, Any],
    evidence_by_id: dict[str, dict[GeneratedStage, Any]],
) -> GeneratedStageResult:
    """Generate the requested stage and record its evidence for the candidate."""
    prepared = prepared_by_id[candidate.candidate_id]
    retry = retry_directive_for(invocation)
    if stage is GeneratedStage.actor:
        result = generate_actor_stage(prepared, retry)
    elif stage is GeneratedStage.narrative:
        result = generate_narrative_stage(prepared, invocation.artifacts.actor, retry)
    else:
        result = generate_tree_stage(
            prepared,
            invocation.artifacts.actor,
            invocation.artifacts.narrative,
            retry,
        )
    evidence_by_id.setdefault(candidate.candidate_id, {})[stage] = result.evidence
    return GeneratedStageResult(result.artifact, result.evidence)


def _behavior_callback_factory(
    prepared_by_id: dict[str, Any],
    evidence_by_id: dict[str, dict[GeneratedStage, Any]],
) -> Any:
    """Build the behavior-stage callback for one target."""

    def callback(candidate: Any, invocation: Any) -> GeneratedStageResult:
        return _behavior_stage_callback(
            candidate, invocation, prepared_by_id, evidence_by_id
        )

    return callback


def _behavior_stage_callback(
    candidate: Any,
    invocation: Any,
    prepared_by_id: dict[str, Any],
    evidence_by_id: dict[str, dict[GeneratedStage, Any]],
) -> GeneratedStageResult:
    """Run the assertions-only behavior callback and record its evidence."""
    result = make_assertions_only_behavior_callback(
        prepared_by_id[candidate.candidate_id]
    )(candidate, invocation)
    evidence_by_id.setdefault(candidate.candidate_id, {})[GeneratedStage.behavior] = (
        result.evidence
    )
    return result


def _assembler_factory(
    prepared_by_id: dict[str, Any],
    evidence_by_id: dict[str, dict[GeneratedStage, Any]],
    ref_by_id: dict[str, Any],
) -> Any:
    """Build the final-envelope assembler callback for one target."""

    def assembler(
        candidate: Any, actor: Any, narrative: Any, tree: Any, behavior: Any
    ) -> Any:
        return _assemble_target_envelope(
            candidate,
            actor,
            narrative,
            tree,
            behavior,
            prepared_by_id,
            evidence_by_id,
            ref_by_id,
        )

    return assembler


def _assemble_target_envelope(
    candidate: Any,
    actor: Any,
    narrative: Any,
    tree: Any,
    behavior: Any,
    prepared_by_id: dict[str, Any],
    evidence_by_id: dict[str, dict[GeneratedStage, Any]],
    ref_by_id: dict[str, Any],
) -> Any:
    """Assemble the final scenario envelope with its choice-ref provenance."""
    prepared = prepared_by_id[candidate.candidate_id]
    evidence = evidence_by_id[candidate.candidate_id]
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
    ref = ref_by_id[candidate.candidate_id]
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


def _admit_factory(
    prepared_by_id: dict[str, Any],
    assembler: Any,
    capability_snapshot: Any,
    taxonomy_resolver: Any,
    trusted_catalog: Sequence[dict[str, Any]],
) -> Any:
    """Build the post-behavior admission callback for one target."""

    def admit(candidate: Any, artifacts: Any, snapshot: Any) -> AdmissionDecision:
        return _admit_target_candidate(
            candidate,
            artifacts,
            snapshot,
            assembler,
            prepared_by_id,
            capability_snapshot,
            taxonomy_resolver,
            trusted_catalog,
        )

    return admit


def _admit_target_candidate(
    candidate: Any,
    artifacts: Any,
    snapshot: Any,
    assembler: Any,
    prepared_by_id: dict[str, Any],
    capability_snapshot: Any,
    taxonomy_resolver: Any,
    trusted_catalog: Sequence[dict[str, Any]],
) -> AdmissionDecision:
    """Admit a candidate with its candidate-specific scenario identity port."""
    admission_port = make_postbehavior_admission(
        assembler,
        trusted_catalog=trusted_catalog,
        taxonomy_resolver=taxonomy_resolver,
        capability_snapshot=capability_snapshot,
        expected_scenario_id=prepared_by_id[candidate.candidate_id].scenario_id,
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


def _target_available_refs(
    target: CoverageTargetEntry,
    ref_by_id: dict[str, Any],
    resume_candidate_id: str | None,
) -> list[dict[str, Any]]:
    """Compute the restart authority refs, giving the resumed candidate priority."""
    return _with_resumed_candidate_first(
        [item.model_dump(mode="json") for item in target.fallback_available],
        target,
        resume_candidate_id,
        ref_by_id,
    )


def _with_resumed_candidate_first(
    available_refs: list[dict[str, Any]],
    target: CoverageTargetEntry,
    resume_candidate_id: str | None,
    ref_by_id: dict[str, Any],
) -> list[dict[str, Any]]:
    """Move the resumed candidate's choice ref to the head of the ref list."""
    if (
        resume_candidate_id is not None
        and resume_candidate_id != target.primary_candidate_id
    ):
        resumed_ref = ref_by_id[resume_candidate_id].model_dump(mode="json")
        return [
            resumed_ref,
            *[
                item
                for item in available_refs
                if item["candidate_id"] != resume_candidate_id
            ],
        ]
    return available_refs


def _legacy_plan_entry(
    target: CoverageTargetEntry, available_refs: list[dict[str, Any]]
) -> CoveragePlanEntry:
    """Build the machine's legacy entry from durable coverage-plan state."""
    return CoveragePlanEntry(
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


def _machine_initial_state(
    persistence: Any, target: CoverageTargetEntry
) -> LifecycleState:
    """Derive the machine's initial lifecycle state from durable transitions."""
    return next(
        (
            item.current
            for item in reversed(persistence.inventory.transitions)
            if item.target_entry_point_id == target.effective_target_id
        ),
        LifecycleState.pending,
    )


def _transition_index_offset(persistence: Any, target: CoverageTargetEntry) -> int:
    """Compute the next transition index for the target's journal."""
    return (
        max(
            (
                item.index
                for item in persistence.inventory.transitions
                if item.target_entry_point_id == target.effective_target_id
            ),
            default=-1,
        )
        + 1
    )


def _recover_resume_candidate_state(
    persistence: Any,
    active_attempt: Any,
    terminal_ids: set[str],
    ref_by_id: dict[str, Any],
    evidence_by_id: dict[str, dict[GeneratedStage, Any]],
) -> _TargetResumeState:
    """Rebuild resume state for an interrupted candidate attempt."""
    candidate_stages, generating = _resume_candidate_stages(persistence, active_attempt)
    state = _TargetResumeState()
    state.invocation_counts = _resume_invocation_counts(candidate_stages)
    state.owner_retry_counts = _resume_owner_retry_counts(candidate_stages)
    state.length_retry_counts = _resume_length_retry_counts(candidate_stages)
    if _generating_edge_without_result(candidate_stages, generating):
        _record_terminal_generation_violation(persistence, active_attempt)
        terminal_ids.add(active_attempt.candidate_id)
        return state
    if _owner_retry_budget_exhausted(candidate_stages):
        _record_owner_retry_exhausted_violation(
            persistence, active_attempt, candidate_stages
        )
        terminal_ids.add(active_attempt.candidate_id)
        return state
    _build_resume_state(
        state,
        persistence,
        active_attempt,
        ref_by_id,
        candidate_stages,
        evidence_by_id,
    )
    return state


def _resume_candidate_stages(
    persistence: Any, active_attempt: Any
) -> tuple[Any, list[Any]]:
    """Return the candidate's stage attempts and in-flight generating transitions."""
    candidate_stages = sorted(
        (
            item
            for item in persistence.inventory.stage_attempts
            if item.candidate_id == active_attempt.candidate_id
        ),
        key=lambda item: item.sequence,
    )
    generating = _in_flight_generating_transitions(
        persistence.inventory.transitions, active_attempt.candidate_id
    )
    return candidate_stages, generating


def _in_flight_generating_transitions(
    transitions: list[Any], candidate_id: str
) -> list[Any]:
    """Return transitions still in a generating_ state for one candidate."""
    return [
        item
        for item in transitions
        if item.candidate_id == candidate_id
        and item.current.value.startswith("generating_")
    ]


def _generating_edge_without_result(
    candidate_stages: list[Any], generating: list[Any]
) -> bool:
    """A generating edge with no matching stage result is terminal."""
    return len(generating) == len(candidate_stages) + 1


def _record_terminal_generation_violation(
    persistence: Any, active_attempt: Any
) -> None:
    """Record the orphaned generating-edge violation as terminal."""
    persistence.record_candidate_result(
        active_attempt.candidate_id,
        CandidateTerminalResult(
            active_attempt.candidate_id,
            CandidateTerminalStatus.generation_or_finalization_failed,
            (
                LifecycleViolation(
                    "durable generating transition has no matching stage result",
                    code="unknown_invocation_outcome",
                    retryable=False,
                ),
            ),
        ),
    )


def _owner_retry_budget_exhausted(candidate_stages: list[Any]) -> bool:
    """The candidate's last stage violated with no owner retries remaining."""
    return (
        candidate_stages
        and candidate_stages[-1].violations
        and candidate_stages[-1].owner_retry_index >= MAX_OWNER_RETRIES
    )


def _record_owner_retry_exhausted_violation(
    persistence: Any, active_attempt: Any, candidate_stages: list[Any]
) -> None:
    """Record the owner-retry-exhaustion violation as terminal."""
    persistence.record_candidate_result(
        active_attempt.candidate_id,
        CandidateTerminalResult(
            active_attempt.candidate_id,
            CandidateTerminalStatus.generation_or_finalization_failed,
            (
                LifecycleViolation(
                    "durable stage evidence exhausted the owner retry budget",
                    owner=candidate_stages[-1].stage,
                    code="owner_retry_exhausted",
                    retryable=False,
                ),
            ),
        ),
    )


def _build_resume_state(
    state: _TargetResumeState,
    persistence: Any,
    active_attempt: Any,
    ref_by_id: dict[str, Any],
    candidate_stages: list[Any],
    evidence_by_id: dict[str, dict[GeneratedStage, Any]],
) -> None:
    """Rebuild the durable causal frontier and retry directives for one candidate."""
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
    durable_candidate = ref_by_id[active_attempt.candidate_id].projected_candidate
    _causal_stage_artifacts(
        candidate_stages,
        candidate_attempt_id=active_attempt.attempt_id,
        durable_candidate=durable_candidate,
        repairs=_candidate_repairs(persistence, active_attempt.candidate_id),
    )
    _replay_causal_stage_artifacts(
        candidate_stages,
        candidate_id=active_attempt.candidate_id,
        evidence_by_id=evidence_by_id,
        latest=latest,
        durable_feedback=durable_feedback,
        durable_reasons=durable_reasons,
        durable_controls=durable_controls,
        model_by_stage=model_by_stage,
    )
    for stage, artifact in latest.items():
        state.artifacts.set(stage, artifact)
    if candidate_stages and candidate_stages[-1].violations:
        state.stage = candidate_stages[-1].stage
        state.artifacts.invalidate_from(state.stage)
        _drop_downstream_evidence(
            state.stage, active_attempt.candidate_id, evidence_by_id
        )
    else:
        state.stage = _next_resume_stage(latest)
    state.candidate_id = active_attempt.candidate_id
    state.feedback = durable_feedback
    state.reasons = durable_reasons
    state.controls = durable_controls


def _candidate_repairs(persistence: Any, candidate_id: str) -> list[Any]:
    """Return the durable repairs recorded for one candidate."""
    return [
        item
        for item in persistence.inventory.repairs
        if item.candidate_id == candidate_id
    ]


def _replay_causal_stage_artifacts(
    candidate_stages: list[Any],
    candidate_id: str,
    evidence_by_id: dict[str, dict[GeneratedStage, Any]],
    latest: dict[GeneratedStage, Any],
    durable_feedback: dict[GeneratedStage, str],
    durable_reasons: dict[GeneratedStage, str],
    durable_controls: dict[GeneratedStage, Any],
    model_by_stage: dict[GeneratedStage, Any],
) -> None:
    """Replay every stage journal entry in invocation sequence."""
    for record in candidate_stages:
        _replay_one_stage_record(
            record,
            candidate_id,
            evidence_by_id,
            latest,
            durable_feedback,
            durable_reasons,
            durable_controls,
            model_by_stage,
        )


def _replay_one_stage_record(
    record: Any,
    candidate_id: str,
    evidence_by_id: dict[str, dict[GeneratedStage, Any]],
    latest: dict[GeneratedStage, Any],
    durable_feedback: dict[GeneratedStage, str],
    durable_reasons: dict[GeneratedStage, str],
    durable_controls: dict[GeneratedStage, Any],
    model_by_stage: dict[GeneratedStage, Any],
) -> None:
    """Apply one stage journal entry: invalidation, digest, evidence, retries."""
    _invalidate_downstream_artifacts(record.stage, candidate_id, evidence_by_id, latest)
    if record.stage is GeneratedStage.behavior:
        _bind_behavior_tree_digest(record, latest)
    _require_causal_frontier(record, latest)
    _adopt_successful_stage_result(
        record, candidate_id, evidence_by_id, latest, model_by_stage
    )
    if record.violations:
        _apply_stage_violation_retry_directives(
            record, durable_feedback, durable_reasons, durable_controls
        )


def _invalidate_downstream_artifacts(
    record_stage: GeneratedStage,
    candidate_id: str,
    evidence_by_id: dict[str, dict[GeneratedStage, Any]],
    latest: dict[GeneratedStage, Any],
) -> None:
    """Every invocation supersedes its owner and all downstream artifacts."""
    for invalidated in tuple(GeneratedStage)[
        tuple(GeneratedStage).index(record_stage) :
    ]:
        latest.pop(invalidated, None)
        evidence_by_id.get(candidate_id, {}).pop(invalidated, None)


def _bind_behavior_tree_digest(record: Any, latest: dict[GeneratedStage, Any]) -> None:
    """Require the behavior resume input to match its final tree digest."""
    visible = dict(record.input.visible_artifacts)
    visible_tree = visible.get(GeneratedStage.tree.value)
    if visible_tree is None or record.final_tree_snapshot_sha256 != canonical_sha256(
        visible_tree
    ):
        raise ValueError("behavior resume input is not bound to its final tree digest")
    latest[GeneratedStage.tree] = AttackTree.model_validate(visible_tree)


def _require_causal_frontier(record: Any, latest: dict[GeneratedStage, Any]) -> None:
    """Require the stage input to be the contiguous causal artifact frontier."""
    visible = dict(record.input.visible_artifacts)
    expected_visible = {
        stage.value: artifact.model_dump(mode="json")
        for stage, artifact in latest.items()
    }
    if visible != expected_visible:
        raise ValueError(
            "stage resume input is not the contiguous causal artifact frontier"
        )


def _adopt_successful_stage_result(
    record: Any,
    candidate_id: str,
    evidence_by_id: dict[str, dict[GeneratedStage, Any]],
    latest: dict[GeneratedStage, Any],
    model_by_stage: dict[GeneratedStage, Any],
) -> None:
    """Adopt a clean stage result and its hydrated evidence, when present."""
    if record.result is not None and not record.violations and record.call is not None:
        latest[record.stage] = model_by_stage[record.stage].model_validate(
            record.result
        )
        evidence = _hydrate_stage_evidence(record)
        if evidence is not None:
            evidence_by_id.setdefault(candidate_id, {})[record.stage] = evidence


def _apply_stage_violation_retry_directives(
    record: Any,
    durable_feedback: dict[GeneratedStage, str],
    durable_reasons: dict[GeneratedStage, str],
    durable_controls: dict[GeneratedStage, Any],
) -> None:
    """Record the durable retry directive for a violated stage."""
    if _has_completion_length_violation(record):
        _apply_completion_length_retry_directives(
            record, durable_feedback, durable_reasons, durable_controls
        )
    else:
        _apply_failure_retry_directives(record, durable_feedback)


def _has_completion_length_violation(record: Any) -> bool:
    """A stage failed with the completion-length outcome code."""
    return any(
        item.code == StageAttemptFailure.COMPLETION_LENGTH_CODE
        for item in record.violations
    )


def _apply_completion_length_retry_directives(
    record: Any,
    durable_feedback: dict[GeneratedStage, str],
    durable_reasons: dict[GeneratedStage, str],
    durable_controls: dict[GeneratedStage, Any],
) -> None:
    """Re-invoke with the approved suffix verbatim for completion-length retries."""
    durable_feedback[record.stage] = COMPLETION_LENGTH_RETRY_SUFFIXES[record.stage]
    durable_reasons[record.stage] = "completion_length"
    durable_controls[record.stage] = COMPLETION_LENGTH_RETRY_CONTROLS[record.stage]


def _apply_failure_retry_directives(
    record: Any, durable_feedback: dict[GeneratedStage, str]
) -> None:
    """Record the owner-scoped failure directive for a violated stage."""
    durable_feedback[record.stage] = (
        "; ".join(
            f"{item.code}: {item.detail}"
            for item in record.violations
            if item.owner is record.stage
        )
        or f"Retry {record.stage.value} to correct validation failure"
    )


def _drop_downstream_evidence(
    resume_stage: GeneratedStage,
    candidate_id: str,
    evidence_by_id: dict[str, dict[GeneratedStage, Any]],
) -> None:
    """Discard evidence for the resume stage and every downstream stage."""
    for downstream in GeneratedStage:
        if list(GeneratedStage).index(downstream) >= list(GeneratedStage).index(
            resume_stage
        ):
            evidence_by_id.get(candidate_id, {}).pop(downstream, None)


def _next_resume_stage(latest: dict[GeneratedStage, Any]) -> GeneratedStage:
    """Return the first stage with no durable artifact, defaulting to behavior."""
    return next(
        (stage for stage in GeneratedStage if stage not in latest),
        GeneratedStage.behavior,
    )


def _resume_invocation_counts(candidate_stages: list[Any]) -> dict[GeneratedStage, int]:
    """Count durable invocations per stage for one candidate."""
    return {
        stage: sum(1 for item in candidate_stages if item.stage is stage)
        for stage in GeneratedStage
    }


def _owner_retry_credit(item: Any, candidate_stages: list[Any]) -> int:
    """Owner retry index, crediting an in-progress final-stage violation."""
    return item.owner_retry_index + (
        1 if item is candidate_stages[-1] and item.violations else 0
    )


def _resume_owner_retry_counts(
    candidate_stages: list[Any],
) -> dict[GeneratedStage, int]:
    """Current owner retry index per stage for one candidate."""
    return {
        stage: max(
            (
                _owner_retry_credit(item, candidate_stages)
                for item in candidate_stages
                if item.stage is stage
            ),
            default=0,
        )
        for stage in GeneratedStage
    }


def _resume_length_retry_counts(
    candidate_stages: list[Any],
) -> dict[GeneratedStage, int]:
    """Current completion-length retry count per stage for one candidate."""
    return resume_completion_length_counts(candidate_stages)


def _resume_counts_kwargs(
    resume: _TargetResumeState, active_attempt: Any
) -> dict[str, Any]:
    """Machine kwargs for resume counters, empty when no active attempt exists."""
    if active_attempt is not None:
        return {
            "resume_invocation_counts": resume.invocation_counts,
            "resume_owner_retry_counts": resume.owner_retry_counts,
            "resume_length_retry_counts": resume.length_retry_counts,
        }
    return {
        "resume_invocation_counts": {},
        "resume_owner_retry_counts": {},
        "resume_length_retry_counts": {},
    }


def _resume_retry_kwargs(
    resume: _TargetResumeState, active_attempt: Any
) -> dict[str, Any]:
    """Machine kwargs for durable retry bundles, empty on no resume candidate."""
    if active_attempt is not None and resume.candidate_id is not None:
        return {
            "resume_retry_feedback": resume.feedback,
            "resume_retry_reasons": resume.reasons,
            "resume_retry_controls": resume.controls,
        }
    return {
        "resume_retry_feedback": {},
        "resume_retry_reasons": {},
        "resume_retry_controls": {},
    }
