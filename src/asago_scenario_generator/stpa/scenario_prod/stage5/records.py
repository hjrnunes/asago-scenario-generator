"""Stage 5 normalization and outcome-grounding evidence records."""

from __future__ import annotations

from pathlib import Path
from collections.abc import Sequence
from typing import Any
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictStr,
)
from asago_scenario_generator.stpa.infra.yaml_io import write_yaml
from asago_scenario_generator.stpa.scenario_prod.outcome_grounding import (
    OutcomeGroundingRecord,
    OutcomeGroundingResolution,
)
from asago_scenario_generator.stpa.models.scenario_context import (
    ScenarioGenerationContext,
)
from ..target_observations import TargetObservationSnapshot
from .conditions import (
    _materialize_provider_condition,
)


STAGE5_NORMALIZATIONS_DIRNAME = "stage5-normalizations"


class Stage5Normalization(BaseModel):
    """One code-owned correction applied to a provider draft during validation."""

    model_config = ConfigDict(extra="forbid")

    field: StrictStr
    original: Any
    normalized: Any
    reason: StrictStr


class Stage5NormalizationRecord(BaseModel):
    """Per-scenario provenance for fields code changed in the provider draft.

    The published scenario carries the corrected values; this record keeps
    them distinguishable from what the model returned.
    """

    model_config = ConfigDict(extra="forbid")

    scenario_id: StrictStr
    context_digest: StrictStr
    normalizations: list[Stage5Normalization] = Field(min_length=1)


def _write_stage5_normalization_record(
    normalizations: Sequence[Stage5Normalization],
    context: ScenarioGenerationContext,
    run_dir: Path,
) -> None:
    if not normalizations:
        return
    record = Stage5NormalizationRecord(
        scenario_id=context.scenario_identity.scenario_id,
        context_digest=context.context_digest,
        normalizations=list(normalizations),
    )
    write_yaml(
        record,
        run_dir / STAGE5_NORMALIZATIONS_DIRNAME / f"{context.context_digest}.yaml",
        # A null original or normalized value is meaningful here.
        post_process=lambda _data: record.model_dump(mode="json"),
    )


def _write_outcome_grounding_record(
    draft,
    result,
    context,
    run_dir,
    *,
    target_observations: TargetObservationSnapshot | None = None,
    grounding: OutcomeGroundingResolution,
) -> None:
    evidence = draft.unsafe_outcome.comparison_evidence
    # Temporal drafts use local handles and have no scalar-comparison evidence.
    if draft.unsafe_outcome.condition.type not in {"action_value", "state_value"}:
        return
    record = OutcomeGroundingRecord(
        scenario_id=context.scenario_identity.scenario_id,
        context_digest=context.context_digest,
        target_observation_digest=(
            target_observations.content_digest
            if target_observations is not None
            else None
        ),
        proposed_condition=_materialize_provider_condition(
            draft.unsafe_outcome.condition
        ),
        compiled_condition=result.unsafe_outcome.condition,
        evidence=evidence,
        source_text=grounding.source_text,
        grounding_origin=grounding.origin,
        grounding_status=grounding.status,
        matched_observation_refs=grounding.matched_observation_refs,
        matched_json_paths=grounding.matched_json_paths,
    )
    write_yaml(
        record,
        run_dir / "outcome-grounding" / f"{context.context_digest}.yaml",
    )
