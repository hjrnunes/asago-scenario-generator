"""Planning-checkpoint serialization and coverage-plan binding."""

from __future__ import annotations

from pathlib import Path

from asago_scenario_generator.manifest import ManifestIntegrityError
from .persistence_common import canonical_json_bytes
from .persistence_files import _exclusive_create
from .persistence_plan import CoveragePlanV2, PlanningCheckpointV1


def write_planning_checkpoint(run_dir: Path, checkpoint: PlanningCheckpointV1) -> Path:
    checkpoint = PlanningCheckpointV1.model_validate(
        checkpoint.model_dump(mode="python")
    )
    _exclusive_create(
        run_dir,
        "planning-checkpoint.json",
        canonical_json_bytes(checkpoint.model_dump(mode="json", exclude_none=True)),
    )
    return run_dir / "planning-checkpoint.json"


def read_planning_checkpoint_bytes(content: bytes) -> PlanningCheckpointV1:
    try:
        return PlanningCheckpointV1.model_validate_json(content)
    except Exception as exc:
        raise ManifestIntegrityError(f"Invalid planning checkpoint: {exc}") from exc


def _expected_fallback_queues(plan: CoveragePlanV2) -> dict[str, list[str]]:
    return {
        target.effective_target_id: [
            choice.candidate_id for choice in target.ordered_choices
        ]
        for target in plan.targets
    }


def _expected_primaries(plan: CoveragePlanV2) -> dict[str, str]:
    return {
        target.effective_target_id: target.primary_candidate_id
        for target in plan.targets
        if target.primary_candidate_id is not None
    }


def _checkpoint_fallbacks_match(
    checkpoint: PlanningCheckpointV1, expected: dict[str, list[str]]
) -> None:
    if checkpoint.fallback_candidate_ids != expected:
        raise ManifestIntegrityError(
            "planning checkpoint fallback queues mismatch plan"
        )


def _checkpoint_primaries_match(
    checkpoint: PlanningCheckpointV1, expected: dict[str, str]
) -> None:
    if checkpoint.primary_candidate_ids != expected:
        raise ManifestIntegrityError("planning checkpoint primaries mismatch plan")


def _checkpoint_selection_matches(
    checkpoint: PlanningCheckpointV1, primaries: dict[str, str]
) -> None:
    if sorted(checkpoint.selected_candidate_ids) != sorted(primaries.values()):
        raise ManifestIntegrityError("planning checkpoint selection mismatch plan")


def _checkpoint_attempted_matches(checkpoint: PlanningCheckpointV1) -> None:
    if checkpoint.attempted_candidate_ids != sorted(checkpoint.selected_candidate_ids):
        raise ManifestIntegrityError("planning checkpoint attempted selection mismatch")


def _checkpoint_uncovered_matches(
    checkpoint: PlanningCheckpointV1, plan: CoveragePlanV2
) -> None:
    if checkpoint.uncovered_target_ids != sorted(
        target.effective_target_id
        for target in plan.targets
        if not target.ordered_choices
    ):
        raise ManifestIntegrityError(
            "planning checkpoint uncovered targets mismatch plan"
        )


def _checkpoint_limitations_match(
    checkpoint: PlanningCheckpointV1, plan: CoveragePlanV2
) -> None:
    plan_target_ids = {target.effective_target_id for target in plan.targets}
    if not set(checkpoint.projection_limitation_target_ids) <= plan_target_ids:
        raise ManifestIntegrityError(
            "planning checkpoint projection limitations are absent from plan"
        )
    if checkpoint.selection_limitation_target_ids != sorted(
        plan.selection_limitation_target_ids
    ):
        raise ManifestIntegrityError(
            "planning checkpoint selection limitations mismatch plan"
        )


def validate_planning_checkpoint(
    checkpoint: PlanningCheckpointV1, plan: CoveragePlanV2
) -> None:
    """Bind immutable completion-tail evidence to the durable target plan."""
    _checkpoint_fallbacks_match(checkpoint, _expected_fallback_queues(plan))
    expected_primaries = _expected_primaries(plan)
    _checkpoint_primaries_match(checkpoint, expected_primaries)
    _checkpoint_selection_matches(checkpoint, expected_primaries)
    _checkpoint_attempted_matches(checkpoint)
    _checkpoint_uncovered_matches(checkpoint, plan)
    _checkpoint_limitations_match(checkpoint, plan)
