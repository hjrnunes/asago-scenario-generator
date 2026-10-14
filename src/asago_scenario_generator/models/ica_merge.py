"""The ICA findings that code folded into one ICA when it compiled a fill reply.

A fill reply may repeat one deviation once per context row or per pair. Code
keeps one ICA for the repeats and records each merge here, so a reader can see
which as-written findings an ICA stands for. The record is run evidence only:
no model request carries it.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import Field, model_validator

from asago_scenario_generator.models.canonical import (
    CanonicalYamlMixin,
    ClosedCanonicalModel,
)

ICA_MERGE_SCHEMA_VERSION = "stpa-ica-merges-v1"
ICA_MERGES_FILENAME = "ica-merges.yaml"


class IcaMergedFinding(ClosedCanonicalModel):
    """One as-written finding folded into a merged ICA."""

    finding_index: int = Field(ge=0, strict=True)
    context_row: str | None = None
    related_hazard_ids: tuple[str, ...]
    related_constraint_ids: tuple[str, ...]


class IcaMerge(ClosedCanonicalModel):
    """One merged ICA: the findings behind it, the kept one first."""

    target_id: str = Field(min_length=1)
    slot_id: str = Field(min_length=1)
    ica_id: str = Field(min_length=1)
    findings: tuple[IcaMergedFinding, ...] = Field(min_length=2)


class IcaMergeReport(CanonicalYamlMixin, ClosedCanonicalModel):
    """Every merged ICA of a run, ordered by target, slot, and ICA."""

    schema_version: Literal["stpa-ica-merges-v1"] = ICA_MERGE_SCHEMA_VERSION
    merges: tuple[IcaMerge, ...] = ()

    @model_validator(mode="after")
    def order_and_check(self) -> "IcaMergeReport":
        ordered = tuple(
            sorted(self.merges, key=lambda m: (m.target_id, m.slot_id, m.ica_id))
        )
        object.__setattr__(self, "merges", ordered)
        self.assert_integrity()
        return self

    def assert_integrity(self) -> None:
        """Require each merged ICA to appear once."""
        keys = [(m.target_id, m.slot_id, m.ica_id) for m in self.merges]
        if len(keys) != len(set(keys)):
            raise ValueError("ICA merge record must name each merged ICA once")

    @classmethod
    def _load_checked(cls, data: dict[str, Any]) -> "IcaMergeReport":
        if data.get("schema_version") != ICA_MERGE_SCHEMA_VERSION:
            raise ValueError(
                f"Unsupported schema version: '{data.get('schema_version')}'"
            )
        return cls.model_validate(data)


__all__ = [
    "ICA_MERGES_FILENAME",
    "ICA_MERGE_SCHEMA_VERSION",
    "IcaMerge",
    "IcaMergeReport",
    "IcaMergedFinding",
]
