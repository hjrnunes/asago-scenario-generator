"""Deterministic scenario identity and duplicate marking."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictStr

from asago_scenario_generator.stpa.discriminating_condition import (
    canonical_comparisons,
)
from asago_scenario_generator.stpa.models.attack_shape import ShapeSource
from asago_scenario_generator.stpa.models.scenario_spec import ScenarioSpec

DeduplicationStatus = Literal["canonical", "duplicate", "analytical_only"]
DeduplicationClaimLevel = Literal[
    "command_attempt",
    "reply",
    "returned_result",
    "state_effect",
    "unknown",
]


class ScenarioDeduplicationKey(BaseModel):
    """The stable identity used to collapse equivalent executable scenarios."""

    model_config = ConfigDict(extra="forbid")

    uca_id: StrictStr = Field(min_length=1)
    control_action_id: StrictStr = Field(min_length=1)
    operation_name: StrictStr | None = Field(default=None, min_length=1)
    claim_level: DeduplicationClaimLevel
    # Canonical sorted JSON of the discriminating-condition comparisons, so
    # scenarios that test different conditions do not collapse.  Omitted when
    # absent so keys without a condition keep their historical shape.
    condition: StrictStr | None = Field(
        default=None,
        min_length=1,
        exclude_if=lambda value: value is None,
    )

    # The sorted safety-constraint ids the scenario answers to, so two
    # scenarios that differ only in the constraint they test keep separate
    # canonicals.  Omitted when empty so keys without constraints keep their
    # historical shape.
    constraint_ids: tuple[Annotated[StrictStr, Field(min_length=1)], ...] = Field(
        default=(),
        exclude_if=lambda value: not value,
    )

    def as_tuple(
        self,
    ) -> tuple[str, str, str | None, str, str | None, tuple[str, ...]]:
        """Return the hashable identity used for deterministic grouping."""

        return (
            self.uca_id,
            self.control_action_id,
            self.operation_name,
            self.claim_level,
            self.condition,
            self.constraint_ids,
        )


class ScenarioDeduplication(BaseModel):
    """One scenario's canonical/duplicate disposition."""

    model_config = ConfigDict(extra="forbid")

    scenario_id: StrictStr = Field(min_length=1)
    status: DeduplicationStatus
    duplicate_of: StrictStr | None = Field(default=None, min_length=1)
    key: ScenarioDeduplicationKey


def scenario_deduplication_key(spec: ScenarioSpec) -> ScenarioDeduplicationKey:
    """Build the key from deterministic lineage and safe-outcome metadata."""

    safe_outcome = spec.safe_observable_outcome
    claim_level = (
        safe_outcome.claim_level
        if safe_outcome is not None and safe_outcome.observable
        else "unknown"
    )
    operation_name = (
        safe_outcome.operation_name
        if safe_outcome is not None and safe_outcome.observable
        else None
    )
    return ScenarioDeduplicationKey(
        # ``ica_id`` identifies one enumerated occurrence and can differ for
        # equivalent scenarios.  The slot is the stable UCA identity used for
        # deterministic collapse.
        uca_id=spec.threat_source.ica_slot_id,
        control_action_id=spec.target_control_action,
        operation_name=operation_name,
        claim_level=claim_level,
        condition=(
            canonical_comparisons(spec.discriminating_condition)
            if spec.discriminating_condition is not None
            else None
        ),
        constraint_ids=tuple(sorted(set(spec.unsafe_outcome_constraint_refs))),
    )


def deduplicate_scenario_specs(
    specs: Sequence[ScenarioSpec],
) -> dict[str, ScenarioDeduplication]:
    """Mark executable duplicates while leaving analytical scenarios alone.

    Call this after the shape step. A group's canonical is the smallest
    scenario ID among its members whose shape the model proposed and code
    validated; a group with no such member takes its smallest ID. The rule
    never reads provider or worker completion order.
    """

    keys = {spec.scenario_id: scenario_deduplication_key(spec) for spec in specs}
    validated = {spec.scenario_id for spec in specs if _has_validated_shape(spec)}
    groups: dict[
        tuple[str, str, str | None, str, str | None, tuple[str, ...]], list[str]
    ] = defaultdict(list)
    records: dict[str, ScenarioDeduplication] = {}
    for spec in specs:
        key = keys[spec.scenario_id]
        record = _ungrouped_record(spec, key)
        if record is None:
            groups[key.as_tuple()].append(spec.scenario_id)
        else:
            records[spec.scenario_id] = record

    for scenario_ids in groups.values():
        canonical = _canonical_id(scenario_ids, validated)
        for scenario_id in scenario_ids:
            records[scenario_id] = ScenarioDeduplication(
                scenario_id=scenario_id,
                status="canonical" if scenario_id == canonical else "duplicate",
                duplicate_of=None if scenario_id == canonical else canonical,
                key=keys[scenario_id],
            )
    return records


def _has_validated_shape(spec: ScenarioSpec) -> bool:
    shape = spec.attack_shape
    return shape is not None and shape.source is ShapeSource.STAGE5_VALIDATED


def _canonical_id(scenario_ids: Sequence[str], validated: set[str]) -> str:
    """Pick the smallest ID among validated members, else the smallest ID."""

    return min([item for item in scenario_ids if item in validated] or scenario_ids)


def _ungrouped_record(
    spec: ScenarioSpec, key: ScenarioDeduplicationKey
) -> ScenarioDeduplication | None:
    """Return the record of a scenario that never joins a duplicate group."""

    assessment = spec.observation_assessment
    if assessment is not None and assessment.disposition == "analytical_only":
        status = "analytical_only"
    elif key.claim_level == "command_attempt" and key.operation_name is None:
        # A command-attempt observation without an operation is incomplete
        # evidence, not a stable equivalence class. Keep each scenario as
        # its own canonical so one missing operation cannot collapse
        # unrelated actions or scenarios.
        status = "canonical"
    else:
        return None
    return ScenarioDeduplication(scenario_id=spec.scenario_id, status=status, key=key)


def build_testability_summary(
    records: dict[str, ScenarioDeduplication],
) -> dict[str, object]:
    """Build the deterministic run-level testability and deduplication view."""

    counts = {
        "total": len(records),
        "canonical": sum(item.status == "canonical" for item in records.values()),
        "duplicates": sum(item.status == "duplicate" for item in records.values()),
        "analytical_only": sum(
            item.status == "analytical_only" for item in records.values()
        ),
    }
    counts["executable"] = counts["canonical"] + counts["duplicates"]
    return {
        "schema_version": "scenario-testability-v1",
        "summary": counts,
        "scenarios": [
            records[scenario_id].model_dump(mode="json")
            for scenario_id in sorted(records)
        ],
    }


__all__ = [
    "DeduplicationClaimLevel",
    "DeduplicationStatus",
    "ScenarioDeduplication",
    "ScenarioDeduplicationKey",
    "build_testability_summary",
    "deduplicate_scenario_specs",
    "scenario_deduplication_key",
]
