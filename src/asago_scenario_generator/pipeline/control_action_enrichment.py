"""Enrichment grounding: observed operations enrich logical control actions.

Owner decision for the M2 unified adaptive path: known operations enrich the
logical control actions; they never replace the control model with tool
enumeration.  When an observed (non-simulation) execution target profile is
supplied, this seam runs the target-realization operation-matching discipline
— the bounded interpreter call and independent verification of
:func:`realize_baseline_rows` — before ICA enumeration, and specializes each
supported match's logical control action description with the exact documented
operation identity.  This is the run's only matching: post-ICA
:func:`realize_target_operations` adopts the returned ``rows`` instead of
matching again.  ICA slot filling,
Stage 5 and Stage 6 then associate the failure with the documented operation
where the association is supported.

The seam is strictly additive: an unmatched action keeps its exact
description, an enriched description always carries the original text as its
prefix, no STPA record is deleted or retyped, and every matching row —
matched or not — is recorded in the run's ``control-action-enrichment.yaml``
sidecar.  A selected operation must be present in the observed inventory, and
an unverified selection never specializes an action.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from asago_scenario_generator.models.canonical import (
    ClosedCanonicalModel,
    compute_framed_digest,
)
from asago_scenario_generator.models.target_realization import (
    SystemicStpaBaseline,
    TargetRealizationRow,
)
from asago_scenario_generator.pipeline.target_realization import (
    observed_operations,
    realize_baseline_rows,
)
from asago_scenario_generator.stpa.models.control_structure import (
    ControlStructure,
)
from asago_scenario_generator.stpa.models.execution_classification import (
    ExecutionTargetProfile,
)
from asago_scenario_generator.stpa.models.ica_enumeration import ICAEnumeration
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis

CONTROL_ACTION_ENRICHMENT_FILENAME = "control-action-enrichment.yaml"
ENRICHMENT_SCHEMA_VERSION = "control-action-operation-enrichment-v1"
CONTROL_STRUCTURE_DIGEST_DOMAIN = (
    "asago-scenario-generator:control-structure-content:v1"
)

__all__ = [
    "CONTROL_ACTION_ENRICHMENT_FILENAME",
    "ControlActionEnrichment",
    "ControlActionOperationEnrichmentRecord",
    "ENRICHMENT_SCHEMA_VERSION",
    "enrich_control_actions",
    "verified_enriched_operations",
]


class ControlActionEnrichmentRow(ClosedCanonicalModel):
    """One recorded action-to-operation match and whether it enriched."""

    control_action_id: str
    controller_id: str
    disposition: str
    resource_id: str | None = None
    operation_id: str | None = None
    verification_status: str | None = None
    evidence_refs: tuple[str, ...] = ()
    enriched: bool
    enriched_description: str | None = None


class ControlActionOperationEnrichmentRecord(ClosedCanonicalModel):
    """Closed sidecar record of one enrichment pass over one run."""

    schema_version: Literal["control-action-operation-enrichment-v1"] = (
        ENRICHMENT_SCHEMA_VERSION
    )
    profile_digest: str
    control_structure_digest: str
    observed_operations: int
    rows: tuple[ControlActionEnrichmentRow, ...] = ()
    enriched_action_ids: tuple[str, ...] = ()
    diagnostics: tuple[str, ...] = ()


@dataclass(frozen=True)
class ControlActionEnrichment:
    """The enriched control structure plus its closed evidence record."""

    control_structure: ControlStructure
    record: ControlActionOperationEnrichmentRecord
    rows: tuple[TargetRealizationRow, ...]


def control_structure_content_digest(control_structure: ControlStructure) -> str:
    """Return the version-framed content digest of one control structure."""
    return compute_framed_digest(
        CONTROL_STRUCTURE_DIGEST_DOMAIN,
        control_structure.model_dump(mode="json", exclude_none=True),
    )


def enrich_control_actions(
    *,
    loss_analysis: LossAnalysis,
    control_structure: ControlStructure,
    profile: ExecutionTargetProfile,
    interpreter: Any,
) -> ControlActionEnrichment:
    """Match observed operations to the logical control actions and enrich.

    Every action reaches the same bounded interpreter and independent
    verification used by the post-ICA target-realization pass.  Only a
    supported, verified match specializes its action's description with the
    exact documented operation identity; every other row stays visible in the
    record with its typed disposition.
    """
    if not isinstance(profile, ExecutionTargetProfile):
        raise TypeError("profile must be an ExecutionTargetProfile")
    profile.assert_integrity()
    if not isinstance(control_structure, ControlStructure):
        raise TypeError("control_structure must be a typed ControlStructure")
    if not isinstance(loss_analysis, LossAnalysis):
        raise TypeError("loss_analysis must be a typed LossAnalysis")

    observations = observed_operations(profile)
    # The matching discipline consumes only the loss analysis and the control
    # structure; the baseline's ICA enumeration is empty because enrichment
    # runs before ICA enumeration.
    baseline = SystemicStpaBaseline.from_stpa(
        loss_analysis=loss_analysis,
        control_structure=control_structure,
        ica_enumeration=ICAEnumeration(slots=[]),
    )
    rows, diagnostics = realize_baseline_rows(
        baseline,
        observations,
        interpreter if observations else None,
    )
    enriched_structure, enriched_ids, record_rows = _specialize_supported_actions(
        control_structure,
        rows,
    )
    record = ControlActionOperationEnrichmentRecord(
        profile_digest=profile.semantic_digest,
        control_structure_digest=control_structure_content_digest(control_structure),
        observed_operations=len(observations),
        rows=tuple(record_rows),
        enriched_action_ids=enriched_ids,
        diagnostics=tuple(diagnostics),
    )
    return ControlActionEnrichment(
        control_structure=enriched_structure,
        record=record,
        rows=tuple(rows),
    )


def verified_enriched_operations(enrichment: Any | None) -> dict[str, str]:
    """Map each verified, enriched action to its documented operation ID.

    ``enrichment`` is the enrichment value or its record; reads are duck-typed
    so plain test doubles agree with the typed record.
    """
    if enrichment is None:
        return {}
    record = getattr(enrichment, "record", enrichment)
    return {
        getattr(row, "control_action_id"): operation_id
        for row in tuple(getattr(record, "rows", ()) or ())
        if getattr(row, "enriched", False) is True
        and (operation_id := getattr(row, "operation_id", None))
        and getattr(row, "verification_status", None) == "verified"
    }


def _specialize_supported_actions(
    control_structure: ControlStructure,
    rows: tuple[TargetRealizationRow, ...],
) -> tuple[ControlStructure, tuple[str, ...], list[ControlActionEnrichmentRow]]:
    """Copy the structure and name the documented operation on supported matches."""
    from asago_scenario_generator.models.target_realization import (
        TargetRealizationDisposition,
    )

    supported = {
        row.control_action_id: row
        for row in rows
        if row.disposition is TargetRealizationDisposition.supported
        and row.selected_operation is not None
    }
    record_rows: list[ControlActionEnrichmentRow] = []
    enriched_ids: list[str] = []
    responsibilities = []
    for responsibility in control_structure.responsibilities:
        actions = []
        for action in responsibility.control_actions:
            row = supported.get(action.ca_id)
            if row is None or row.selected_operation is None:
                actions.append(action.model_copy(deep=True))
                record_rows.append(_record_row(responsibility.resp_id, action, row))
                continue
            operation_id = row.selected_operation.operation_id
            enriched_description = (
                f"{action.description} (documented operation: {operation_id})"
            )
            actions.append(
                action.model_copy(update={"description": enriched_description})
            )
            enriched_ids.append(action.ca_id)
            record_rows.append(
                _record_row(
                    responsibility.resp_id,
                    action,
                    row,
                    enriched=True,
                    enriched_description=enriched_description,
                )
            )
        responsibilities.append(
            responsibility.model_copy(update={"control_actions": actions})
        )
    enriched_structure = ControlStructure.model_validate(
        {
            "responsibilities": responsibilities,
            "controlled_processes": control_structure.controlled_processes,
            "coordination_links": control_structure.coordination_links,
        }
    )
    return enriched_structure, tuple(enriched_ids), record_rows


def _record_row(
    controller_id: str,
    action: Any,
    row: TargetRealizationRow | None,
    *,
    enriched: bool = False,
    enriched_description: str | None = None,
) -> ControlActionEnrichmentRow:
    selected = row.selected_operation if row is not None else None
    verifier_status = (
        row.verifier.status if row is not None and row.verifier is not None else None
    )
    return ControlActionEnrichmentRow(
        control_action_id=action.ca_id,
        controller_id=controller_id,
        disposition=row.disposition.value if row is not None else "unmapped",
        resource_id=selected.resource_id if selected is not None else None,
        operation_id=selected.operation_id if selected is not None else None,
        verification_status=verifier_status,
        evidence_refs=tuple(row.evidence_refs) if row is not None else (),
        enriched=enriched,
        enriched_description=enriched_description,
    )
