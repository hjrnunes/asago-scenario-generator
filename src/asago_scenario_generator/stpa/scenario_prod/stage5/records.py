"""Stage 5 normalization evidence records."""

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
from asago_scenario_generator.stpa.models.scenario_context import (
    ScenarioGenerationContext,
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
