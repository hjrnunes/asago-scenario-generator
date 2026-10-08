"""Targeted Stage 1a repair (owner authorization 2026-09-11, freeze exception).

The former bounded whole-object retry embedded the entire original prompt,
the prior structured object, and the validation feedback in one correction
prompt.  Measured on the two saved 2026-09-11 failures those retry prompts
reached 22,214 and 24,490 estimated input tokens against a 21,299-token
budget, so the preflight blocked them before dispatch, and a
hypothetical response would also have replaced whole collections
(``list(correction) or list(prior)``), discarding valid rows wholesale.

This module replaces that retry with a narrowly scoped targeted repair for
exactly three approved failure classes:

1. missing or malformed ``risk_dispositions`` entries;
2. malformed obligation entries within an otherwise preserved constraint; and
3. duplicate IDs in a hazard's ``related_losses`` or a security constraint's
   ``related_hazards`` when the draft names no unknown ID (decision 47b,
   2026-10-04).  Each repeated entry may only be removed or replaced with a
   valid ID the list does not already name; a draft that also names an
   unknown ID stops with a typed failure and no repair call.

Contract (owner authorization 2026-09-11; narrowed per the approved
correction specification revision 2, 2026-09-11):

- Deterministic code selects the repair identities and the single permitted
  correction per identity.  A known channel value in the wrong field
  relocates to the correct field unchanged; the repair never selects a new
  channel meaning, and a known channel is never dropped to reach the wire
  default ``unknown``.  Conflicting or unrepresentable channel values, and
  any defect outside the permitted-change table, are typed unsupported
  outcomes with no repair call.
- Every initial wire error is classified before any salvage, repair, or
  cleanup: container-presence, container-type, and container-bounds errors
  are typed terminal failures, never silently converted to empty
  collections; only record-level errors are salvageable.
- The response wire carries nothing outside the repair scope, so a response
  cannot rewrite a constraint's rule, conditions, or hazard links, and every
  record outside the scope is preserved byte-identically.
- Duplicate, unknown, unexpected, or out-of-scope identities, and any edit
  outside the permitted correction, are rejected with a typed reason before
  the merge.
- The corrected original wire object re-validates against the original
  provider schema before the domain merge (boundary 1), and the merged
  draft re-validates against the complete original inputs (boundary 2).
- Exactly one repair call follows one failed first attempt, and the repair is
  never retried.  Every transformation (salvage drop, deterministic
  cleanup, repair, unsupported outcome) is recorded in one run-level,
  cross-stage, accumulating ``loss-analysis-repair.yaml`` artifact that
  distinguishes proposed from applied changes.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Container, Iterable
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Union

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PrivateAttr,
    ValidationError,
    model_validator,
)

from asago_scenario_generator.models.risk_card import RiskCard
from asago_scenario_generator.request_schema import (
    uses_guided_decoding,
    with_keyed_rows,
)
from asago_scenario_generator.stpa.infra.llm import LLMClient, LLMResult
from asago_scenario_generator.stpa.infra.llm_helpers import (
    StageError,
    _decode_json_text,
    parse_llm_result,
    CorrectionPolicy,
    call_with_policy,
)
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.infra.yaml_io import write_yaml
from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossAnalysisDraft,
    Obligation,
    RiskDisposition,
    SecurityConstraint,
)
from asago_scenario_generator.stpa.system_model.rule_span_repair import (
    rule_span_requirement,
)

DISPOSITION_REPAIR_SYSTEM_TEMPLATE = "stage1a_disposition_repair_system.j2"
DISPOSITION_REPAIR_USER_TEMPLATE = "stage1a_disposition_repair_user.j2"
OBLIGATION_REPAIR_SYSTEM_TEMPLATE = "stage1a_obligation_repair_system.j2"
OBLIGATION_REPAIR_USER_TEMPLATE = "stage1a_obligation_repair_user.j2"
REFERENCE_REPAIR_SYSTEM_TEMPLATE = "stage1a_reference_repair_system.j2"
REFERENCE_REPAIR_USER_TEMPLATE = "stage1a_reference_repair_user.j2"

# Repair steps append this suffix in the durable call log so repair calls are
# individually countable without changing the first-attempt step names.
_REPAIR_STEP_SUFFIX = "_repair"

# An obligation the repair dropped because its span stays outside the rule.
RULE_SPAN_DROPPED_KIND = "rule_span_dropped"

# A reference list cut after its one correction failed to resolve it.
REFERENCE_DROPPED_KIND = "reference_dropped"

# The run-level, cross-stage record of every Stage 1a transformation (R3).
REPAIR_RECORD_FILENAME = "loss-analysis-repair.yaml"
REPAIR_RECORD_SCHEMA_VERSION = "loss-analysis-repair-record-v2"

# The five provider wire collections; locations at exactly one of these
# names are container locations, everything beneath them is record-level.
_WIRE_COLLECTIONS = (
    "risk_card_losses",
    "use_case_losses",
    "hazards",
    "security_constraints",
    "risk_dispositions",
)

# Obligation identities are O-numbered (the production wire pattern).
_OBLIGATION_ID_PATTERN = re.compile(r"^O[1-9][0-9]*$")

# Channels representable on a required entry's ``realized_by`` field.  A
# forbidden-entry ``violated_via`` value outside this set cannot relocate
# (R1.2: unrepresentable channel relocation).
_REALIZATION_CHANNELS = frozenset({"tool_call", "reply", "unknown"})

# Every field of an obligation entry the merge compares when it is not part
# of the permitted correction.
_OBLIGATION_FIELDS = (
    "behavior",
    "rule_span",
    "realized_by",
    "violated_via",
    "observation_role",
    "source_outcome",
    "completion",
    "projection",
    "residual",
    "note",
)


class RepairRejected(ValueError):
    """Deterministic rejection of an out-of-scope, duplicate, or partial repair.

    The message is the typed reason recorded with the failed repair call.
    """


# ---------------------------------------------------------------------------
# Closed repair wire
# ---------------------------------------------------------------------------


class RepairRiskDisposition(RiskDisposition):
    """One disposition row on the repair wire; no unexpected fields."""

    model_config = ConfigDict(extra="forbid")


class DispositionRepairResponse(BaseModel):
    """The complete risk-disposition repair wire.

    Only the identities deterministic code selected may appear, exactly once
    each; the merge enforces that and preserves every unselected row.
    """

    model_config = ConfigDict(extra="forbid")

    risk_dispositions: list[RepairRiskDisposition] = Field(min_length=1)


class RepairObligation(Obligation):
    """One obligation entry on the repair wire; no unexpected fields.

    ``omitted_channels`` names the kind-exclusive channel fields the
    response left out.  The base model fills an absent channel with
    ``unknown``, which would otherwise be indistinguishable from an explicit
    ``unknown`` that overwrites a known channel.
    """

    model_config = ConfigDict(extra="forbid")

    _omitted_channels: frozenset[str] = PrivateAttr(default=frozenset())

    @model_validator(mode="wrap")
    @classmethod
    def _record_omitted_channels(cls, data: Any, handler: Any) -> RepairObligation:
        entry = handler(data)
        if isinstance(data, dict):
            entry._omitted_channels = frozenset(
                name for name in ("realized_by", "violated_via") if name not in data
            )
        return entry

    @property
    def omitted_channels(self) -> frozenset[str]:
        return self._omitted_channels


class RepairObligationConstraint(BaseModel):
    """One selected constraint's obligations; nothing else is on the wire.

    The constraint's ``rule``, ``applies_when``, and ``related_hazards`` are
    deliberately absent, so a repair response cannot rewrite them.
    """

    model_config = ConfigDict(extra="forbid")

    constraint_id: str = Field(min_length=1)
    obligations: list[RepairObligation] = Field(default_factory=list)


class ObligationRepairResponse(BaseModel):
    """The complete obligation-entry repair wire.

    Only the constraints deterministic code selected may appear, exactly once
    each, with their complete obligations collection.
    """

    model_config = ConfigDict(extra="forbid")

    constraints: list[RepairObligationConstraint] = Field(min_length=1)


class RepairHazardReferences(BaseModel):
    """One selected hazard's corrected ``related_losses``; nothing else."""

    model_config = ConfigDict(extra="forbid")

    hazard_id: str = Field(min_length=1)
    related_losses: list[str] = Field(min_length=1)


class RepairConstraintReferences(BaseModel):
    """One selected constraint's corrected ``related_hazards``; nothing else."""

    model_config = ConfigDict(extra="forbid")

    constraint_id: str = Field(min_length=1)
    related_hazards: list[str] = Field(min_length=1)


class ReferenceRepairResponse(BaseModel):
    """The complete reference-list repair wire.

    Descriptions, rules, conditions, obligations, losses, and dispositions are
    deliberately absent, so a response can change only the selected lists.
    """

    model_config = ConfigDict(extra="forbid")

    hazards: list[RepairHazardReferences] = Field(default_factory=list)
    security_constraints: list[RepairConstraintReferences] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Cut-off risk-derivation recovery (owner approval 2026-09-30)
# ---------------------------------------------------------------------------

TRUNCATED_DISPOSITION_RECOVERY_KIND = "truncated_disposition_recovery"

_DISPOSITIONS_ARRAY = re.compile(r'"risk_dispositions"\s*:\s*\[')


@dataclass(frozen=True)
class TruncatedDispositionRecovery:
    """What recovery kept from a response cut off inside ``risk_dispositions``."""

    completion_tokens: int
    complete_rows: int
    kept_rows: int
    collapsed_refs: tuple[str, ...]


def _truncated_completion_tokens(result: LLMResult) -> int | None:
    """Return the completion tokens used when the response hit its cap undecodable."""
    content = result.content
    cap = result.request_controls.get("max_completion_tokens")
    used = result.completion_tokens
    if (
        not isinstance(content, str)
        or not isinstance(cap, int)
        or used is None
        or used < cap
    ):
        return None
    try:
        json.loads(content)
    except json.JSONDecodeError:
        return used
    return None


def _graph_before_dispositions(content: str) -> tuple[dict, list[Any]] | None:
    """Decode every collection before ``risk_dispositions`` and its complete rows."""
    for match in _DISPOSITIONS_ARRAY.finditer(content):
        head = content[: match.start()].rstrip()
        if head.endswith(","):
            head = head[:-1]
        try:
            graph = json.loads(head + "}")
        except json.JSONDecodeError:
            continue
        if isinstance(graph, dict) and "risk_dispositions" not in graph:
            return graph, _complete_array_rows(content, match.end())
    return None


def recover_truncated_risk_dispositions(
    result: LLMResult,
) -> tuple[LLMResult, TruncatedDispositionRecovery] | None:
    """Recover a risk-derivation response cut off inside its disposition list.

    Models can loop on the long disposition list until the completion cap
    stops them mid-row.  Recovery applies only when the response reached its
    completion cap, does not decode, and every collection before
    ``risk_dispositions`` decodes completely.  It keeps the complete
    disposition rows, collapses duplicate rows that agree on disposition and
    losses, and leaves missing or conflicting cards to the approved
    disposition repair.  The logged provider response is never mutated.
    """
    used = _truncated_completion_tokens(result)
    if used is None:
        return None
    found = _graph_before_dispositions(result.content)
    if found is None:
        return None
    graph, rows = found
    kept, collapsed = _collapse_agreeing_duplicate_rows(rows)
    recovered = {**graph, "risk_dispositions": kept}
    return (
        result.model_copy(
            update={"content": json.dumps(recovered, ensure_ascii=False)}
        ),
        TruncatedDispositionRecovery(
            completion_tokens=used,
            complete_rows=len(rows),
            kept_rows=len(kept),
            collapsed_refs=collapsed,
        ),
    )


def _complete_array_rows(text: str, start: int) -> list[Any]:
    """Decode array elements from ``start`` until the array ends or is cut."""
    decoder = json.JSONDecoder()
    rows: list[Any] = []
    index = start
    while True:
        while index < len(text) and text[index] in " \t\r\n,":
            index += 1
        if index >= len(text) or text[index] == "]":
            return rows
        try:
            row, index = decoder.raw_decode(text, index)
        except json.JSONDecodeError:
            return rows
        rows.append(row)


def _disposition_signature(row: dict) -> tuple[Any, tuple[str, ...]]:
    losses = row.get("loss_ids") or []
    return row.get("disposition"), tuple(sorted(map(str, losses)))


def _agreeing_duplicate_refs(groups: dict[Any, list[dict]]) -> set[Any]:
    return {
        ref
        for ref, group in groups.items()
        if len(group) > 1 and len({_disposition_signature(row) for row in group}) == 1
    }


def _collapse_agreeing_duplicate_rows(
    rows: list[Any],
) -> tuple[list[Any], tuple[str, ...]]:
    """Keep the first row of each card whose duplicate rows all agree."""
    groups: dict[Any, list[dict]] = {}
    for row in rows:
        if isinstance(row, dict):
            groups.setdefault(row.get("risk_ref"), []).append(row)
    collapsible = _agreeing_duplicate_refs(groups)
    kept: list[Any] = []
    seen: set[Any] = set()
    for row in rows:
        ref = row.get("risk_ref") if isinstance(row, dict) else None
        if ref in collapsible:
            if ref in seen:
                continue
            seen.add(ref)
        kept.append(row)
    return kept, tuple(str(ref) for ref in groups if ref in collapsible)


def record_truncated_disposition_recovery(
    repair_record: RepairRecord | None,
    *,
    step: str,
    recovery: TruncatedDispositionRecovery,
) -> None:
    """Record one cut-off recovery in the cross-stage repair artifact."""
    if repair_record is None:
        return
    repair_record.add(
        stage=step,
        attempt="first",
        kind=TRUNCATED_DISPOSITION_RECOVERY_KIND,
        identity="risk_dispositions",
        reason=(
            f"the response reached its {recovery.completion_tokens}-token "
            "completion cap inside risk_dispositions after every other "
            "collection was complete; complete rows were kept, agreeing "
            "duplicates collapsed, and missing or conflicting cards were left "
            "to the disposition repair"
        ),
        proposed={"complete_rows": recovery.complete_rows},
        applied={
            "kept_rows": recovery.kept_rows,
            "collapsed_refs": list(recovery.collapsed_refs),
        },
        outcome="applied",
        raw_step=step,
    )


# ---------------------------------------------------------------------------
# Wire-error classification (R2.1/R2.2): before any salvage or cleanup
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class WireErrorClassification:
    """Every error of one failed first parse, classified by kind."""

    record_errors: tuple[str, ...]
    unsupported_reason: str | None


def _format_validation_errors(
    exc: ValidationError, *, limit: int = 3
) -> tuple[str, ...]:
    """Format a pydantic error's items as ``location: message`` strings."""
    return tuple(
        f"{'.'.join(str(part) for part in item.get('loc', ())) or 'row'}: "
        f"{item.get('msg', '')}"
        for item in exc.errors()[:limit]
    )


def _container_error(collection: str, error_type: str, message: str) -> str:
    if error_type == "missing":
        return f"container-presence: collection '{collection}' is missing"
    if error_type in ("too_long", "too_short"):
        return f"container-bounds: collection '{collection}' {message}"
    return f"container-type: collection '{collection}' {message}"


def _classify_wire_error(item: Any) -> tuple[bool, str]:
    """Return whether one pydantic error is a record error, and its text."""
    location = tuple(str(part) for part in item.get("loc", ()))
    error_type = str(item.get("type", ""))
    message = str(item.get("msg", ""))
    if len(location) == 1 and location[0] in _WIRE_COLLECTIONS:
        # The gap contract deliberately omits risk accounting, but owner
        # policy C1 permits deterministic row cleanup when a gap response
        # nevertheless includes a malformed ``risk_dispositions`` list.
        # Keep this one extra top-level collection in the row salvage path;
        # every other unknown top-level field remains terminal.
        if location[0] == "risk_dispositions" and error_type == "extra_forbidden":
            return True, f"{'.'.join(location)}: {message}"
        return False, _container_error(location[0], error_type, message)
    if location and location[0] in _WIRE_COLLECTIONS:
        return True, f"{'.'.join(location)}: {message}"
    return False, f"top-level shape: {'.'.join(location) or error_type} {message}"


def classify_wire_validation_errors(exc: ValidationError) -> WireErrorClassification:
    """Classify every error of the first parse's ValidationError.

    Container-presence (``missing`` at a collection location), container-type
    (a non-list value at a collection location), container-bounds
    (``too_short``/``too_long`` at a collection location), and top-level
    shape errors are typed terminal failures.  Locations beneath a
    collection are record errors, the only salvageable or repairable class.
    Mixed supported and unsupported errors are unsupported.
    """
    record_errors: list[str] = []
    unsupported: list[str] = []
    for item in exc.errors():
        is_record, text = _classify_wire_error(item)
        (record_errors if is_record else unsupported).append(text)
    if unsupported:
        reason = (
            "non-record wire errors are outside the approved repair scope "
            "(container and shape errors are typed terminal failures): "
            + "; ".join(unsupported)
        )
        return WireErrorClassification(
            record_errors=tuple(record_errors), unsupported_reason=reason
        )
    return WireErrorClassification(
        record_errors=tuple(record_errors), unsupported_reason=None
    )


class _SalvageReadError(ValueError):
    """A collection the salvage tried to read is absent or not a list."""


def _fail_closed_rows(
    content: dict,
    name: str,
    response_format: type[BaseModel],
) -> list:
    """Read one wire collection without ever converting damage to empty.

    A value that is present but not a list, or a required collection that is
    absent, is a deterministic read failure.  Only a collection the provider
    schema itself declares optional may be absent (the gap call's
    ``risk_dispositions``); the error classification has already rejected
    every schema-violating absence before the salvage runs, so a read
    failure here is a fail-closed backstop, not a repair route.
    """
    if name in content:
        value = content[name]
        if not isinstance(value, list):
            raise _SalvageReadError(f"collection '{name}' is not a list")
        return value
    model_field = response_format.model_fields.get(name)
    if model_field is not None and not model_field.is_required():
        return []
    raise _SalvageReadError(f"collection '{name}' is absent from the response")


# ---------------------------------------------------------------------------
# Run-level, cross-stage repair record (R3)
# ---------------------------------------------------------------------------


class RepairRecordEntryModel(BaseModel):
    """One per-stage, per-attempt transformation record entry."""

    model_config = ConfigDict(extra="forbid")

    stage: str
    attempt: str
    kind: str
    identity: str
    reason: str
    proposed: dict[str, Any] = Field(default_factory=dict)
    applied: dict[str, Any] = Field(default_factory=dict)
    outcome: str
    raw_step: str


class LossAnalysisRepairRecordArtifact(BaseModel):
    """The persisted ``loss-analysis-repair.yaml`` payload."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str
    records: list[RepairRecordEntryModel] = Field(min_length=1)


@dataclass
class RepairRecord:
    """One run-level, cross-stage, accumulating transformation record.

    Both Stage 1a calls append entries; a later write never removes or
    rewrites an earlier entry (the artifact always carries every entry in
    order); a terminal failure still writes the record with the failing
    outcome while preserving every earlier entry.
    """

    entries: list[RepairRecordEntryModel] = field(default_factory=list)

    def add(
        self,
        *,
        stage: str,
        attempt: str,
        kind: str,
        identity: str,
        reason: str,
        outcome: str,
        raw_step: str,
        proposed: dict[str, Any] | None = None,
        applied: dict[str, Any] | None = None,
    ) -> None:
        """Append one entry; entries are immutable once recorded."""
        self.entries.append(
            RepairRecordEntryModel(
                stage=stage,
                attempt=attempt,
                kind=kind,
                identity=identity,
                reason=reason,
                proposed=proposed or {},
                applied=applied or {},
                outcome=outcome,
                raw_step=raw_step,
            )
        )

    def counts_by_stage(self) -> dict[str, dict[str, int]]:
        """Per-stage outcome counts for run manifests."""
        counts: dict[str, dict[str, int]] = {}
        for entry in self.entries:
            stage_counts = counts.setdefault(entry.stage, {})
            stage_counts[entry.outcome] = stage_counts.get(entry.outcome, 0) + 1
        return counts

    def write(self, run_dir: Path) -> Path | None:
        """Persist the record; a run with no transformations writes nothing."""
        if not self.entries:
            return None
        artifact = LossAnalysisRepairRecordArtifact(
            schema_version=REPAIR_RECORD_SCHEMA_VERSION,
            records=list(self.entries),
        )
        return write_yaml(artifact, run_dir / REPAIR_RECORD_FILENAME)


# ---------------------------------------------------------------------------
# Salvage: deterministic row-level recovery of a wire-invalid response
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SalvageReport:
    """What deterministic salvage kept, dropped, and retained verbatim.

    Each dropped disposition row is recorded as a
    ``(label, reason, original_risk_ref)`` triple: ``label`` names the row by
    its identity when present and by position otherwise, and
    ``original_risk_ref`` carries the row's own usable identity (``None``
    when the malformed row carried none), so later classification works from
    the original identity rather than the positional label.
    """

    dropped_losses: tuple[str, ...] = ()
    dropped_hazards: tuple[str, ...] = ()
    dropped_constraint_fields: tuple[str, ...] = ()
    dropped_dispositions: tuple[tuple[str, str, str | None], ...] = ()
    obligation_salvage: tuple[
        tuple[str, tuple[tuple[dict, tuple[str, ...]], ...]], ...
    ] = ()
    scope_errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()

    @property
    def out_of_scope_wire_failures(self) -> tuple[str, ...]:
        """Failures outside the two approved repair classes."""
        return (
            *self.dropped_losses,
            *self.dropped_hazards,
            *self.dropped_constraint_fields,
        )

    @property
    def obligation_constraint_ids(self) -> tuple[str, ...]:
        """Constraints whose failures are confined to obligation entries."""
        return tuple(constraint_id for constraint_id, _ in self.obligation_salvage)

    def dropped_disposition_warnings(self) -> tuple[str, ...]:
        """Render the dropped disposition rows as recorded warnings."""
        return tuple(
            f"dropped malformed risk_dispositions row for '{label}': {reason}"
            for label, reason, _ in self.dropped_dispositions
        )


def _row_identity(row: object, id_field: str) -> str | None:
    """Return the row's usable string identity, when it carries one."""
    if isinstance(row, dict):
        identity = row.get(id_field)
        if isinstance(identity, str) and identity.strip():
            return identity
    return None


def _row_label(row: object, index: int, id_field: str) -> str:
    """Name a dropped row by its identity when present, else by position."""
    identity = _row_identity(row, id_field)
    return identity if identity is not None else f"row {index}"


def _salvage_rows(
    rows: Iterable[object],
    model: type[BaseModel],
    id_field: str,
    dropped: list,
    *,
    label_pairs: bool = False,
) -> list[BaseModel]:
    """Keep the rows that validate individually; record the others.

    With ``label_pairs`` the caller receives
    ``(label, reason, original_risk_ref)`` triples (dispositions), so the
    repair plan can classify each dropped row by its original identity and
    carry the exact salvage reason into the prompt; otherwise plain
    ``"identity: reason"`` strings.
    """
    kept: list[BaseModel] = []
    for index, row in enumerate(rows):
        try:
            kept.append(model.model_validate(row))
        except ValidationError as exc:
            reason = "; ".join(_format_validation_errors(exc))
            label = _row_label(row, index, id_field)
            if label_pairs:
                dropped.append((label, reason, _row_identity(row, id_field)))
            else:
                dropped.append(f"{label}: {reason}")
    return kept


def _rule_span_defect(entry: dict, rule: str) -> bool:
    """Whether the entry's rule_span is not a substring of the rule, ignoring case."""
    span = entry.get("rule_span")
    return not (
        isinstance(span, str) and span.strip() and span.casefold() in rule.casefold()
    )


def salvage_provider_response(
    content: dict,
    *,
    constraint_wire_model: type[SecurityConstraint],
    response_format: type[BaseModel],
    gap_wire: bool = False,
) -> tuple[LossAnalysisDraft, SalvageReport]:
    """Recover the valid rows of a wire-invalid Stage 1a response.

    Salvage is deterministic and touches no model: every row is validated
    independently against the same wire models the stage uses, valid rows are
    kept, and dropped rows are recorded with their typed reasons.  A
    constraint whose own fields fail is recorded as out of scope; a constraint
    whose failure is confined to its obligation entries keeps its valid
    entries, and every malformed entry is retained verbatim (the raw dict as
    received) together with its exact validation errors for the targeted
    repair, so the repair anchor is the original entry, not a description of
    it.  Duplicate obligation ids in one original collection cannot define a
    safe repair scope and are recorded as scope errors.
    """

    dropped_losses: list[str] = []
    dropped_hazards: list[str] = []
    dropped_dispositions: list[tuple[str, str, str | None]] = []

    risk_losses = _salvage_rows(
        _fail_closed_rows(content, "risk_card_losses", response_format),
        Loss,
        "loss_id",
        dropped_losses,
    )
    use_case_losses = _salvage_rows(
        _fail_closed_rows(content, "use_case_losses", response_format),
        Loss,
        "loss_id",
        dropped_losses,
    )
    hazards = _salvage_rows(
        _fail_closed_rows(content, "hazards", response_format),
        Hazard,
        "hazard_id",
        dropped_hazards,
    )
    # The gap provider contract has no risk-accounting collection.  If a
    # malformed gap response nevertheless carries one, preserve only its
    # malformed rows as deterministic C1 cleanup evidence. A valid-looking
    # out-of-contract row is terminal; it must never become authoritative or
    # be silently removed. Risk-stage responses still validate and salvage
    # this collection normally.
    if gap_wire and "risk_dispositions" in content:
        _drop_gap_dispositions(content["risk_dispositions"], dropped_dispositions)
        dispositions = []
    else:
        dispositions = _salvage_rows(
            _fail_closed_rows(content, "risk_dispositions", response_format),
            RiskDisposition,
            "risk_ref",
            dropped_dispositions,
            label_pairs=True,
        )

    salvage = _ConstraintSalvage(constraint_wire_model)
    for index, row in enumerate(
        _fail_closed_rows(content, "security_constraints", response_format)
    ):
        salvage.add_row(row, index)

    draft = LossAnalysisDraft.model_validate(
        {
            "risk_card_losses": [item.model_dump(mode="json") for item in risk_losses],
            "use_case_losses": [
                item.model_dump(mode="json") for item in use_case_losses
            ],
            "hazards": [item.model_dump(mode="json") for item in hazards],
            "security_constraints": [
                item.model_dump(mode="json") for item in salvage.constraints
            ],
            "risk_dispositions": [
                item.model_dump(mode="json") for item in dispositions
            ],
        }
    )
    report = SalvageReport(
        dropped_losses=tuple(dropped_losses),
        dropped_hazards=tuple(dropped_hazards),
        dropped_constraint_fields=tuple(salvage.dropped_constraint_fields),
        dropped_dispositions=tuple(dropped_dispositions),
        obligation_salvage=tuple(salvage.obligation_salvage),
        scope_errors=tuple(salvage.scope_errors),
        warnings=tuple(salvage.warnings),
    )
    return draft, report


def _drop_gap_dispositions(
    disposition_rows: object,
    dropped_dispositions: list[tuple[str, str, str | None]],
) -> None:
    """Record a gap response's malformed disposition rows as dropped rows."""
    if not isinstance(disposition_rows, list):
        raise _SalvageReadError("collection 'risk_dispositions' is not a list")
    valid_out_of_contract: list[str] = []
    for index, row in enumerate(disposition_rows):
        label = _row_label(row, index, "risk_ref")
        row_reason = _gap_disposition_defect(row)
        if row_reason is None:
            valid_out_of_contract.append(label)
            continue
        dropped_dispositions.append(
            (
                label,
                row_reason + "; risk_dispositions is not part of the gap response wire",
                _row_identity(row, "risk_ref"),
            )
        )
    if valid_out_of_contract:
        raise _SalvageReadError(
            "gap risk_dispositions contains valid out-of-contract row(s): "
            + ", ".join(valid_out_of_contract)
        )


def _gap_disposition_defect(row: object) -> str | None:
    """Return why a gap disposition row is malformed, or ``None`` if valid."""
    if not isinstance(row, dict):
        return "row is not an object"
    unknown_fields = sorted(set(row) - set(RiskDisposition.model_fields))
    if unknown_fields:
        return "extra fields are not permitted: " + ", ".join(unknown_fields)
    try:
        RiskDisposition.model_validate(row)
    except ValidationError as exc:
        return "; ".join(_format_validation_errors(exc))
    return None


@dataclass
class _ConstraintSalvage:
    """The salvaged constraints and the drops, scope errors, and warnings."""

    constraint_wire_model: type[SecurityConstraint]
    constraints: list[SecurityConstraint] = field(default_factory=list)
    dropped_constraint_fields: list[str] = field(default_factory=list)
    obligation_salvage: list[tuple[str, tuple[tuple[dict, tuple[str, ...]], ...]]] = (
        field(default_factory=list)
    )
    scope_errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def add_row(self, row: object, index: int) -> None:
        """Salvage one constraint row, keeping its valid obligation entries."""
        if not isinstance(row, dict):
            self.dropped_constraint_fields.append(f"row {index}: not an object")
            return
        try:
            self.constraints.append(self.constraint_wire_model.model_validate(row))
            return
        except ValidationError:
            pass
        # The full constraint failed.  When the constraint without its
        # obligation entries is valid, the failure is confined to the
        # entries and the constraint joins the obligation repair scope.
        bare = {key: value for key, value in row.items() if key != "obligations"}
        try:
            bare_constraint = self.constraint_wire_model.model_validate(bare)
        except ValidationError as exc:
            reason = "; ".join(_format_validation_errors(exc))
            self.dropped_constraint_fields.append(
                f"{_row_label(row, index, 'constraint_id')}: {reason}"
            )
            return
        self._add_obligation_salvage(bare_constraint, row.get("obligations"))

    def _add_obligation_salvage(
        self, bare_constraint: SecurityConstraint, obligation_rows: object
    ) -> None:
        constraint_id = bare_constraint.constraint_id
        scope_error = _obligation_collection_scope_error(constraint_id, obligation_rows)
        if scope_error is not None:
            self.scope_errors.append(scope_error)
            return
        assert isinstance(obligation_rows, list)
        kept_entries, retained = _partition_obligation_entries(
            constraint_id, bare_constraint.rule, obligation_rows, self.scope_errors
        )
        payload = bare_constraint.model_dump(mode="json")
        payload["obligations"] = [
            entry.model_dump(mode="json") for entry in kept_entries
        ]
        try:
            salvaged = SecurityConstraint.model_validate(payload)
        except ValidationError:
            self.scope_errors.append(
                f"constraint '{constraint_id}': its retained valid entries "
                "still violate a constraint-level rule"
            )
            return
        self.constraints.append(salvaged)
        if retained:
            self.obligation_salvage.append((constraint_id, tuple(retained)))
            self.warnings.append(_obligation_salvage_warning(constraint_id, retained))


def _partition_obligation_entries(
    constraint_id: str,
    rule: str,
    obligation_rows: list,
    scope_errors: list[str],
) -> tuple[list[Obligation], list[tuple[dict, tuple[str, ...]]]]:
    """Split entries into valid obligations and rows kept for the repair scope."""
    kept_entries: list[Obligation] = []
    retained: list[tuple[dict, tuple[str, ...]]] = []
    for entry in obligation_rows:
        if not isinstance(entry, dict):
            scope_errors.append(
                f"an obligation entry of constraint '{constraint_id}' is not an object"
            )
            continue
        kept_candidate, errors = _check_obligation_entry(entry, rule)
        if errors:
            retained.append((dict(entry), errors))
        else:
            assert kept_candidate is not None
            kept_entries.append(kept_candidate)
    return kept_entries, retained


def _obligation_collection_scope_error(
    constraint_id: str, obligation_rows: object
) -> str | None:
    """Name why an obligations collection cannot define a repair scope."""
    if not isinstance(obligation_rows, list):
        return (
            f"constraint '{constraint_id}' carries an obligations "
            "collection that is not a list"
        )
    string_ids = [
        entry.get("obligation_id")
        for entry in obligation_rows
        if isinstance(entry, dict) and isinstance(entry.get("obligation_id"), str)
    ]
    if len(string_ids) != len(set(string_ids)):
        duplicated = sorted(
            {identity for identity in string_ids if string_ids.count(identity) > 1}
        )
        return (
            f"constraint '{constraint_id}' carries duplicate obligation "
            "ids in its original collection: " + ", ".join(duplicated)
        )
    return None


def _check_obligation_entry(
    entry: dict, rule: str
) -> tuple[Obligation | None, tuple[str, ...]]:
    """Validate one obligation entry; return it when valid, and its errors."""
    errors: list[str] = []
    unknown_fields = sorted(set(entry) - set(Obligation.model_fields))
    if unknown_fields:
        errors.append("extra fields are not permitted: " + ", ".join(unknown_fields))
    try:
        kept_candidate: Obligation | None = Obligation.model_validate(entry)
    except ValidationError as exc:
        errors.extend(_format_validation_errors(exc, limit=4))
        kept_candidate = None
    if _rule_span_defect(entry, rule):
        errors.append(
            "rule_span must be a contiguous substring of the constraint rule, "
            "compared case-insensitively"
        )
    return kept_candidate, tuple(errors)


def _obligation_salvage_warning(
    constraint_id: str, retained: list[tuple[dict, tuple[str, ...]]]
) -> str:
    """Describe a salvaged constraint and its retained malformed entries."""
    summary = "; ".join(
        f"{entry_raw.get('obligation_id', f'entry {position}')}: {entry_errors[0]}"
        for position, (entry_raw, entry_errors) in enumerate(retained)
    )
    return (
        f"salvaged constraint '{constraint_id}' with its valid "
        f"obligation entries retained; {len(retained)} malformed "
        f"entr{'y' if len(retained) == 1 else 'ies'} dropped from "
        "the working draft and retained verbatim for the targeted "
        f"repair: {summary}"
    )


# ---------------------------------------------------------------------------
# Permitted corrections for obligation entries (R1.2)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PermittedChange:
    """One deterministic correction the repair may apply to an entry."""

    kind: str
    source_field: str = ""
    destination_field: str = ""
    value: str = ""
    fields: tuple[str, ...] = ()


@dataclass(frozen=True)
class SelectedObligation:
    """One selected ``(constraint_id, obligation_id)`` repair pair.

    Carries the original entry verbatim, its exact validation errors, and
    the permitted changes deterministic code derived from the defect class.
    """

    constraint_id: str
    obligation_id: str
    original_entry_raw: dict
    validation_errors: tuple[str, ...]
    permitted_changes: tuple[PermittedChange, ...]
    constraint_rule: str

    @property
    def identity(self) -> str:
        return f"{self.constraint_id}/{self.obligation_id}"

    @property
    def correction_instruction(self) -> str:
        """The permitted change as exact edits.

        Only an entry whose two readings code cannot decide offers a choice,
        and then between two named edits the merge verifies.
        """
        parts: list[str] = []
        for change in self.permitted_changes:
            if change.kind == "relocate_channel":
                parts.append(
                    f"move `{change.source_field}: {change.value}` to "
                    f"`{change.destination_field}` unchanged"
                )
            elif change.kind == "remove_fields":
                names = " and ".join(f"`{name}`" for name in change.fields)
                parts.append(
                    f"remove the field{'s' if len(change.fields) > 1 else ''} {names}"
                )
            elif change.kind == "set_source_outcome":
                parts.append(
                    "set `source_outcome` to the source outcome this proxy "
                    "observation stands for"
                )
            elif change.kind == "set_rule_span":
                parts.append(
                    "set `rule_span` to a quote of the constraint rule. "
                    + rule_span_requirement()
                )
            elif change.kind == "resolve_source_outcome":
                parts.append(
                    "make exactly one of these two edits: set `observation_role` "
                    "to `proxy` and keep `source_outcome` unchanged, when the "
                    "observed behavior stands in for that outcome; or remove "
                    "`source_outcome` and keep `observation_role` unchanged, "
                    "when the behavior is observed directly"
                )
        return "; ".join(parts)

    @property
    def defect_reason(self) -> str:
        """The entry's validation errors, for the record and the prompt."""
        return "; ".join(self.validation_errors)


def _apply_permitted_changes(
    raw: dict,
    changes: tuple[PermittedChange, ...],
    *,
    rule: str,
) -> dict:
    """Apply the permitted changes to the original entry (validation probe)."""
    corrected = dict(raw)
    for change in changes:
        if change.kind == "relocate_channel":
            corrected.pop(change.source_field, None)
            corrected[change.destination_field] = change.value
        elif change.kind == "remove_fields":
            for name in change.fields:
                corrected.pop(name, None)
        elif change.kind == "set_source_outcome":
            corrected["source_outcome"] = (
                "the source outcome this proxy observation stands for"
            )
        elif change.kind == "set_rule_span":
            corrected["rule_span"] = rule
        elif change.kind == "resolve_source_outcome":
            corrected["observation_role"] = "proxy"
    return corrected


def classify_obligation_defects(
    raw: dict,
    *,
    rule: str,
) -> tuple[tuple[PermittedChange, ...], str | None]:
    """Derive the permitted changes for one retained malformed entry.

    Returns the permitted changes and ``None`` when the entry is repairable,
    or empty changes and the specific unsupported reason when it is not
    (R1.5: the scope is not deterministically definable).
    """
    shape_defect = _obligation_shape_defect(raw)
    if shape_defect is not None:
        return (), shape_defect
    changes = (
        _forbidden_entry_changes(raw)
        if raw.get("kind") == "forbidden"
        else _required_entry_changes(raw)
    )
    if isinstance(changes, str):
        return (), changes
    if _rule_span_defect(raw, rule):
        changes.append(PermittedChange(kind="set_rule_span"))

    # Completeness check: applying the permitted changes must produce a
    # valid entry.  Any defect outside the table (a bad literal, an invalid
    # field type, an empty behavior) fails here, so it can never reach a
    # repair call.
    corrected = _apply_permitted_changes(raw, tuple(changes), rule=rule)
    try:
        Obligation.model_validate(corrected)
    except ValidationError as exc:
        first = _format_validation_errors(exc, limit=1)[0]
        return (), f"the defect is outside the permitted repair table: {first}"
    return tuple(changes), None


def _obligation_shape_defect(raw: dict) -> str | None:
    """Name a defect in the entry's fields, identity, kind, or behavior."""
    raw_id = raw.get("obligation_id")
    unknown_fields = sorted(set(raw) - set(Obligation.model_fields))
    if unknown_fields:
        return (
            "the defect is outside the permitted repair table: unknown "
            "obligation field(s): " + ", ".join(unknown_fields)
        )
    if not isinstance(raw_id, str) or not _OBLIGATION_ID_PATTERN.match(raw_id):
        return "obligation_id is missing, blank, or not an O-numbered identity"
    if raw.get("kind") not in ("required", "forbidden"):
        return "kind is not 'required' or 'forbidden'"
    behavior = raw.get("behavior")
    if not isinstance(behavior, str) or not behavior.strip():
        return "behavior is empty"
    return None


def _forbidden_entry_changes(raw: dict) -> list[PermittedChange] | str:
    """Return a forbidden entry's permitted changes, or the unsupported reason."""
    changes: list[PermittedChange] = []
    realized = raw.get("realized_by")
    if realized is not None:
        channel_change = _realized_channel_change(realized, raw.get("violated_via"))
        if isinstance(channel_change, str):
            return channel_change
        changes.append(channel_change)
    if raw.get("completion") is not None:
        changes.append(PermittedChange(kind="remove_fields", fields=("completion",)))
    changes.extend(_source_outcome_changes(raw))
    return changes


def _realized_channel_change(realized: Any, violated: Any) -> PermittedChange | str:
    if violated is None:
        # Every realized_by value is in the violated_via vocabulary,
        # so relocation is always representable here.
        return PermittedChange(
            kind="relocate_channel",
            source_field="realized_by",
            destination_field="violated_via",
            value=realized,
        )
    if violated == realized:
        return PermittedChange(kind="remove_fields", fields=("realized_by",))
    return (
        f"conflicting channel values: realized_by={realized!r} and "
        f"violated_via={violated!r}"
    )


def _source_outcome_changes(raw: dict) -> list[PermittedChange]:
    role = raw.get("observation_role")
    outcome = raw.get("source_outcome")
    has_outcome = isinstance(outcome, str) and bool(outcome.strip())
    if role == "proxy" and not has_outcome:
        return [PermittedChange(kind="set_source_outcome")]
    if has_outcome and role != "proxy":
        # Declaring the proxy and removing the outcome are different
        # readings of the entry, so the model chooses; code verifies
        # that exactly one of the two named edits was made.
        return [PermittedChange(kind="resolve_source_outcome")]
    return []


def _required_entry_changes(raw: dict) -> list[PermittedChange] | str:
    """Return a required entry's permitted changes, or the unsupported reason."""
    changes: list[PermittedChange] = []
    violated = raw.get("violated_via")
    if violated is not None:
        realized = raw.get("realized_by")
        if realized is None:
            if violated not in _REALIZATION_CHANNELS:
                return (
                    f"unrepresentable channel relocation: violated_via="
                    f"{violated!r} is not a realized_by channel"
                )
            changes.append(
                PermittedChange(
                    kind="relocate_channel",
                    source_field="violated_via",
                    destination_field="realized_by",
                    value=violated,
                )
            )
        elif realized == violated:
            changes.append(
                PermittedChange(kind="remove_fields", fields=("violated_via",))
            )
        else:
            return (
                f"conflicting channel values: violated_via={violated!r} and "
                f"realized_by={realized!r}"
            )
    foreign = tuple(
        name
        for name in ("observation_role", "source_outcome")
        if raw.get(name) is not None
    )
    if foreign:
        changes.append(PermittedChange(kind="remove_fields", fields=foreign))
    return changes


# ---------------------------------------------------------------------------
# Repair plans
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class UnsupportedRepair:
    """An explicit, documented outcome for failure classes outside the scope."""

    reason: str
    scope: str = "response"


@dataclass(frozen=True)
class DeterministicCleanup:
    """A salvaged draft that needs no model call.

    The failure reduced to rows deterministic code removed (out-of-contract
    disposition rows on the gap call, or rows referencing unsupplied risk
    cards); the caller re-validates the draft with the full stage validators
    before accepting it.  ``removed_rows`` carries one ``(identity, reason)``
    pair per removed row for the transformation record.
    """

    draft: LossAnalysisDraft
    warnings: tuple[str, ...]
    removed_rows: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class DispositionRepairPlan:
    """One targeted repair of missing or malformed risk-disposition entries.

    ``removed_unknown`` carries one ``(risk reference, removal reason)`` pair
    per unsupplied-card row the repair application removes (C2), whether the
    row was wire-valid or malformed; the reason names the cleanup policy that
    authorizes the removal.
    """

    prior: LossAnalysisDraft
    selected: tuple[str, ...]
    reasons: tuple[tuple[str, str], ...]
    removed_unknown: tuple[tuple[str, str], ...]
    salvage_warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class ObligationRepairPlan:
    """One targeted repair of malformed obligation entries.

    ``selected`` carries one :class:`SelectedObligation` per selected
    ``(constraint_id, obligation_id)`` pair: the original entry verbatim, its
    exact validation errors, and the permitted changes derived from the
    defect class.  Selecting a constraint never authorizes replacing its
    obligations collection.
    """

    prior: LossAnalysisDraft
    selected: tuple[SelectedObligation, ...]
    salvage_warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class DroppedObligation:
    """An obligation the repair dropped because its span stays outside the rule.

    ``constraint_dropped`` is true when the drop left its constraint without
    any obligation, so the merge dropped the constraint too.
    """

    constraint_id: str
    obligation_id: str
    rule_span: str
    rule: str
    constraint_dropped: bool = False

    @property
    def identity(self) -> str:
        return f"{self.constraint_id}/{self.obligation_id}"


_REFERENCE_LIST_FIELDS = {
    "hazards": ("related_losses", "hazard_id"),
    "security_constraints": ("related_hazards", "constraint_id"),
}


@dataclass(frozen=True)
class SelectedReferenceList:
    """One reference list that names an ID more than once or an unknown ID.

    ``unknown`` are the listed IDs that no declared record has.
    ``replacement_ids`` are the IDs valid for this list at this step that the
    list does not already name; a repeated or unknown entry may become one of
    them or be removed.
    """

    collection: str
    owner_id: str
    original: tuple[str, ...]
    replacement_ids: tuple[str, ...]
    unknown: tuple[str, ...] = ()

    @property
    def field_name(self) -> str:
        return _REFERENCE_LIST_FIELDS[self.collection][0]

    @property
    def identity(self) -> str:
        return f"{self.owner_id}.{self.field_name}"

    @property
    def repeated(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                {
                    ref
                    for ref in self.original
                    if self.original.count(ref) > 1 and ref not in self.unknown
                }
            )
        )

    @property
    def kept(self) -> tuple[str, ...]:
        """Each known original ID once, in first-occurrence order."""
        return tuple(dict.fromkeys(r for r in self.original if r not in self.unknown))

    @property
    def replaceable_count(self) -> int:
        """How many entries (repeats and unknown IDs) a repair may replace."""
        return len(self.original) - len(self.kept)

    @property
    def entry_kind(self) -> str:
        """The defective entries this list holds, as the request names them."""
        if not self.unknown:
            return "repeated"
        return "repeated or unknown" if self.repeated else "unknown"

    @property
    def defect_reason(self) -> str:
        prefix = f"{self.collection}.{self.field_name}"
        findings = [
            (f"{prefix} unknown IDs: ", self.unknown),
            (f"{prefix} duplicate IDs: ", self.repeated),
        ]
        return "; ".join(
            label + ", ".join(f"{self.owner_id} -> {ref}" for ref in refs)
            for label, refs in findings
            if refs
        )

    @property
    def correction_instruction(self) -> str:
        if not self.unknown:
            return (
                "for each repeated entry, remove the repeat or replace it with one "
                "listed replacement ID; keep "
                + ", ".join(self.kept)
                + " once each in this order; name no ID outside the kept and "
                "replacement IDs"
            )
        if not self.kept:
            return (
                f"for each {self.entry_kind} entry, remove it or replace it with "
                "one listed replacement ID; the list has no other ID to keep; "
                "name no ID outside the replacement IDs and return at least one ID"
            )
        return (
            f"for each {self.entry_kind} entry, remove it or replace it with one "
            "listed replacement ID; keep "
            + ", ".join(self.kept)
            + " once each in this order; name no ID outside the kept and "
            "replacement IDs"
        )


@dataclass(frozen=True)
class ReferenceRepairPlan:
    """One targeted repair of repeated or unknown hazard or constraint references.

    ``meanings`` maps every loss and hazard ID the request names to its
    description, including IDs an earlier call established.  ``feedback``
    is the reference validator's finding the request carries.
    """

    prior: LossAnalysisDraft
    selected: tuple[SelectedReferenceList, ...]
    meanings: tuple[tuple[str, str], ...] = ()
    salvage_warnings: tuple[str, ...] = ()
    feedback: str = ""


RepairPlan = Union[DispositionRepairPlan, ObligationRepairPlan, ReferenceRepairPlan]
RepairOutcome = Union[RepairPlan, UnsupportedRepair, DeterministicCleanup]


def select_reference_repairs(
    draft: LossAnalysisDraft,
    *,
    valid_loss_ids: set[str],
    valid_hazard_ids: set[str],
) -> tuple[SelectedReferenceList, ...]:
    """Select each hazard or constraint list with a repeated or unknown ID."""
    rows = (
        ("hazards", hazard.hazard_id, hazard.related_losses, valid_loss_ids)
        for hazard in draft.hazards
    )
    constraint_rows = (
        (
            "security_constraints",
            constraint.constraint_id,
            constraint.related_hazards,
            valid_hazard_ids,
        )
        for constraint in draft.security_constraints
    )
    selected = (
        SelectedReferenceList(
            collection=collection,
            owner_id=owner_id,
            original=tuple(references),
            replacement_ids=tuple(sorted(valid_ids - set(references))),
            unknown=tuple(dict.fromkeys(r for r in references if r not in valid_ids)),
        )
        for collection, owner_id, references, valid_ids in (*rows, *constraint_rows)
    )
    return tuple(item for item in selected if item.replaceable_count)


def select_disposition_repairs(
    draft: LossAnalysisDraft,
    risk_cards: list[RiskCard],
) -> tuple[tuple[str, ...], tuple[tuple[str, str], ...], tuple[str, ...]]:
    """Select the disposition identities deterministic code allows to change.

    Returns the selected card IDs in supplied order, one reason per selected
    ID, and the unsupplied risk references whose rows deterministic code
    removes.  A selected identity is a supplied card that is missing, double
    counted, or whose row cites losses the response never declared; the merge
    replaces exactly those rows and preserves every other row.
    """
    supplied_ids = [card.risk_id for card in risk_cards]
    counts, undeclared, unknown = _tally_disposition_rows(draft, set(supplied_ids))
    reasons = _disposition_repair_reasons(supplied_ids, counts, undeclared)
    selected = tuple(card_id for card_id in supplied_ids if card_id in reasons)
    reason_pairs = tuple((card_id, "; ".join(reasons[card_id])) for card_id in selected)
    return selected, reason_pairs, tuple(sorted(unknown))


def _tally_disposition_rows(
    draft: LossAnalysisDraft,
    supplied: set[str],
) -> tuple[dict[str, int], dict[str, list[str]], set[str]]:
    """Count rows per supplied card, collect undeclared cited losses and unknown refs."""
    declared_losses = {
        loss.loss_id for loss in draft.risk_card_losses + draft.use_case_losses
    }
    counts: dict[str, int] = {}
    undeclared: dict[str, list[str]] = {}
    unknown: set[str] = set()
    for row in draft.risk_dispositions:
        if row.risk_ref not in supplied:
            unknown.add(row.risk_ref)
            continue
        counts[row.risk_ref] = counts.get(row.risk_ref, 0) + 1
        if row.disposition == "cited":
            missing = [
                loss_id for loss_id in row.loss_ids if loss_id not in declared_losses
            ]
            if missing:
                undeclared.setdefault(row.risk_ref, []).extend(missing)
    return counts, undeclared, unknown


def _disposition_repair_reasons(
    supplied_ids: list[str],
    counts: dict[str, int],
    undeclared: dict[str, list[str]],
) -> dict[str, list[str]]:
    """Return the repair reasons of each supplied card that needs one."""
    reasons: dict[str, list[str]] = {}
    for card_id in supplied_ids:
        if counts.get(card_id, 0) == 0:
            reasons.setdefault(card_id, []).append(
                "no risk_dispositions entry was returned for this supplied card"
            )
        elif counts[card_id] > 1:
            reasons.setdefault(card_id, []).append(
                f"{counts[card_id]} duplicate risk_dispositions entries were "
                "returned; exactly one is required"
            )
        if card_id in undeclared:
            reasons.setdefault(card_id, []).append(
                "the cited entry names losses the response never declared: "
                + ", ".join(sorted(set(undeclared[card_id])))
            )
    return reasons


def _without_unknown_disposition_rows(
    draft: LossAnalysisDraft,
    risk_cards: list[RiskCard],
) -> LossAnalysisDraft:
    """Return a copy whose disposition rows all reference supplied cards.

    Rows referencing unsupplied risk cards are wire-valid but fail the
    deterministic accounting gate, so a cleanup that only records them would
    still fail re-validation.  The cleanup removes them, exactly as the
    disposition merge does for a repaired draft.
    """
    supplied = {card.risk_id for card in risk_cards}
    kept = [row for row in draft.risk_dispositions if row.risk_ref in supplied]
    if len(kept) == len(draft.risk_dispositions):
        return draft
    return draft.model_copy(
        update={"risk_dispositions": [row.model_copy(deep=True) for row in kept]}
    )


def _record_salvage_drops(
    report: SalvageReport,
    *,
    step: str,
    repair_record: RepairRecord | None,
    repair_identities: Container[str] | None = None,
) -> None:
    """Record every salvage drop that feeds a repair as a record entry.

    When ``repair_identities`` is provided, only dropped disposition rows
    whose original identity joins the repair selection are recorded; rows
    routed to the deterministic cleanup record their own cleanup entry, so
    no removed row is ever recorded twice.
    """
    if repair_record is None:
        return
    for label, reason, original_ref in report.dropped_dispositions:
        if repair_identities is not None and (
            original_ref is None or original_ref not in repair_identities
        ):
            continue
        repair_record.add(
            stage=step,
            attempt="first",
            kind="salvage",
            identity=label,
            reason=reason,
            proposed={"dropped_entries": [label]},
            applied={"dropped_entries": [label]},
            outcome="removed",
            raw_step=step,
        )
    for constraint_id, retained in report.obligation_salvage:
        for entry_raw, entry_errors in retained:
            entry_id = entry_raw.get("obligation_id")
            identity = entry_id if isinstance(entry_id, str) else "unnamed entry"
            repair_record.add(
                stage=step,
                attempt="first",
                kind="salvage",
                identity=f"{constraint_id}/{identity}",
                reason="; ".join(entry_errors),
                proposed={"dropped_entries": [identity]},
                applied={"dropped_entries": [identity]},
                outcome="removed",
                raw_step=step,
            )


def build_repair_plan(
    *,
    step: str,
    response_format: type[LossAnalysisDraft],
    first_result: LLMResult | None,
    first_parse_failed: bool,
    failure_class: str,
    risk_cards: list[RiskCard],
    require_risk_accounting: bool,
    constraint_wire_model: type[SecurityConstraint],
    first_wire_error: ValidationError | None = None,
    repair_record: RepairRecord | None = None,
    gap_wire: bool = False,
) -> RepairOutcome:
    """Classify one failed Stage 1a attempt and select its repair plan.

    ``failure_class`` is the caller's typed label for the first failure:
    ``wire_schema`` (the response never parsed), ``risk_accounting`` (the
    deterministic accounting validator), ``draft_references``, or
    ``draft_semantics``.  Only the first two can produce a repair, and the
    wire path is further scoped by the initial error classification and
    row-level salvage.
    """
    if first_result is None:
        return UnsupportedRepair("no provider response is available to repair")
    if first_parse_failed:
        return _wire_repair_plan(
            step=step,
            response_format=response_format,
            first_result=first_result,
            failure_class=failure_class,
            risk_cards=risk_cards,
            require_risk_accounting=require_risk_accounting,
            constraint_wire_model=constraint_wire_model,
            first_wire_error=first_wire_error,
            repair_record=repair_record,
            gap_wire=gap_wire,
        )
    if failure_class == "risk_accounting":
        return _accounting_repair_plan(
            first_result,
            response_format=response_format,
            risk_cards=risk_cards,
            require_risk_accounting=require_risk_accounting,
        )
    return UnsupportedRepair(
        f"the {failure_class} failure class is outside the approved repair "
        "scope; no repair call is made"
    )


def _absent_reference_rows(
    removed_unknown: Iterable[str],
) -> tuple[tuple[str, str], ...]:
    """Pair each unsupplied risk reference with its removal reason."""
    return tuple(
        (reference, "risk reference absent from the supplied set")
        for reference in removed_unknown
    )


def _wire_repair_plan(
    *,
    step: str,
    response_format: type[LossAnalysisDraft],
    first_result: LLMResult,
    failure_class: str,
    risk_cards: list[RiskCard],
    require_risk_accounting: bool,
    constraint_wire_model: type[SecurityConstraint],
    first_wire_error: ValidationError | None,
    repair_record: RepairRecord | None,
    gap_wire: bool,
) -> RepairOutcome:
    """Select the repair for a first response that never parsed."""
    unsupported = _unsupported_initial_wire_error(first_wire_error)
    if unsupported is not None:
        return unsupported
    salvaged = _salvage_first_response(
        first_result,
        constraint_wire_model=constraint_wire_model,
        response_format=response_format,
        gap_wire=gap_wire,
    )
    if isinstance(salvaged, UnsupportedRepair):
        return salvaged
    prior, report = salvaged
    unsupported = _unsupported_salvage_report(report)
    if unsupported is not None:
        return unsupported
    if report.obligation_constraint_ids:
        return _obligation_repair_plan(
            prior, report, step=step, repair_record=repair_record
        )
    if report.dropped_dispositions:
        return _dropped_disposition_plan(
            prior,
            report,
            step=step,
            risk_cards=risk_cards,
            repair_record=repair_record,
        )
    if failure_class == "draft_references" and require_risk_accounting:
        # The provider compiler rejected an unresolved reference, and the
        # caller already proved the hazard and constraint edges resolve.
        # The only remaining reference collection is disposition
        # ``loss_ids``, so the undeclared citations reduce to the approved
        # disposition repair of exactly the rows that carry them.
        selected, reason_pairs, removed_unknown = select_disposition_repairs(
            prior, risk_cards
        )
        if selected:
            return DispositionRepairPlan(
                prior=prior,
                selected=selected,
                reasons=reason_pairs,
                removed_unknown=_absent_reference_rows(removed_unknown),
                salvage_warnings=report.warnings,
            )
    return UnsupportedRepair(
        "the wire failure is not confined to the approved repair scope"
    )


def _unsupported_initial_wire_error(
    first_wire_error: ValidationError | None,
) -> UnsupportedRepair | None:
    """Fail closed when the first parse error names an unsupported failure."""
    if first_wire_error is None:
        return None
    classification = classify_wire_validation_errors(first_wire_error)
    if classification.unsupported_reason is None:
        return None
    scope = next(
        (
            collection
            for collection in _WIRE_COLLECTIONS
            if collection in classification.unsupported_reason
        ),
        "response",
    )
    return UnsupportedRepair(classification.unsupported_reason, scope=scope)


def _salvage_first_response(
    first_result: LLMResult,
    *,
    constraint_wire_model: type[SecurityConstraint],
    response_format: type[LossAnalysisDraft],
    gap_wire: bool,
) -> UnsupportedRepair | tuple[LossAnalysisDraft, SalvageReport]:
    """Decode the first response body and salvage its valid rows."""
    content = first_result.content
    if isinstance(content, BaseModel):
        content = content.model_dump(mode="json")
    if isinstance(content, str):
        try:
            content = _decode_json_text(content)
        except ValueError as exc:
            return UnsupportedRepair(f"the response body never decoded as JSON ({exc})")
    if not isinstance(content, dict):
        return UnsupportedRepair(
            "the response body is not a JSON object, so no rows can be salvaged"
        )
    try:
        return salvage_provider_response(
            content,
            constraint_wire_model=constraint_wire_model,
            response_format=response_format,
            gap_wire=gap_wire,
        )
    except _SalvageReadError as exc:
        return UnsupportedRepair(
            f"wire violation outside the approved repair scope: {exc}",
            scope="response",
        )


def _unsupported_salvage_report(report: SalvageReport) -> UnsupportedRepair | None:
    """Fail closed when salvage found failures no single repair can fix."""
    if report.out_of_scope_wire_failures:
        return UnsupportedRepair(
            "wire violation outside the approved repair scope: "
            + "; ".join(report.out_of_scope_wire_failures)
        )
    if report.scope_errors:
        return UnsupportedRepair(
            "obligation repair scope is not deterministically definable: "
            + "; ".join(report.scope_errors),
            scope="obligation entries",
        )
    if report.obligation_constraint_ids and report.dropped_dispositions:
        return UnsupportedRepair(
            "the response mixes obligation-entry and risk-disposition "
            "wire failures; the targeted repair fixes one class per attempt"
        )
    return None


def _obligation_repair_plan(
    prior: LossAnalysisDraft,
    report: SalvageReport,
    *,
    step: str,
    repair_record: RepairRecord | None,
) -> RepairOutcome:
    """Select every salvaged obligation entry with its permitted correction."""
    selected_entries: list[SelectedObligation] = []
    prior_constraints = {
        constraint.constraint_id: constraint
        for constraint in prior.security_constraints
    }
    for constraint_id, retained in report.obligation_salvage:
        prior_constraint = prior_constraints.get(constraint_id)
        if prior_constraint is None:
            return UnsupportedRepair(
                "obligation repair scope is not deterministically "
                f"definable: salvaged constraint '{constraint_id}' is "
                "not present in the working draft"
            )
        for entry_raw, entry_errors in retained:
            selected = _select_obligation_entry(
                constraint_id, prior_constraint.rule, entry_raw, entry_errors
            )
            if isinstance(selected, UnsupportedRepair):
                return selected
            selected_entries.append(selected)
    if not selected_entries:
        return UnsupportedRepair(
            "the wire failure is not confined to the approved repair scope"
        )
    _record_salvage_drops(report, step=step, repair_record=repair_record)
    return ObligationRepairPlan(
        prior=prior,
        selected=tuple(selected_entries),
        salvage_warnings=report.warnings,
    )


def _select_obligation_entry(
    constraint_id: str,
    rule: str,
    entry_raw: dict,
    entry_errors: tuple[str, ...],
) -> SelectedObligation | UnsupportedRepair:
    """Select one salvaged entry, or fail closed when its fix is undefined."""
    changes, unsupported_reason = classify_obligation_defects(entry_raw, rule=rule)
    if unsupported_reason is not None:
        entry_id = entry_raw.get("obligation_id")
        identity = (
            f"{constraint_id}/{entry_id}"
            if isinstance(entry_id, str)
            else f"{constraint_id}/unnamed entry"
        )
        return UnsupportedRepair(
            "obligation repair scope is not deterministically "
            f"definable: {identity}: {unsupported_reason}",
            scope=identity,
        )
    return SelectedObligation(
        constraint_id=constraint_id,
        obligation_id=entry_raw["obligation_id"],
        original_entry_raw=entry_raw,
        validation_errors=entry_errors,
        permitted_changes=changes,
        constraint_rule=rule,
    )


def _dropped_repair_selection(
    prior: LossAnalysisDraft,
    risk_cards: list[RiskCard],
    supplied_order: list[str],
    supplied_drop_reasons: dict[str, list[str]],
    unknown_reasons: dict[str, str],
) -> tuple[dict[str, str], tuple[str, ...], tuple[tuple[str, str], ...]]:
    """Return the repair reasons, the selected cards, and the unknown rows to remove."""
    _, reason_pairs, removed_unknown = select_disposition_repairs(prior, risk_cards)
    reason_map = _with_malformed_row_notes(reason_pairs, supplied_drop_reasons)
    selected = tuple(card_id for card_id in supplied_order if card_id in reason_map)
    for reference in removed_unknown:
        unknown_reasons.setdefault(
            reference, "risk reference absent from the supplied set"
        )
    return reason_map, selected, tuple(sorted(unknown_reasons.items()))


def _unknown_rows_cleanup(
    prior: LossAnalysisDraft,
    risk_cards: list[RiskCard],
    warnings: tuple[str, ...],
    removed_unknown_rows: tuple[tuple[str, str], ...],
) -> DeterministicCleanup:
    return DeterministicCleanup(
        draft=_without_unknown_disposition_rows(prior, risk_cards),
        warnings=(
            *warnings,
            "removed risk_dispositions rows for unsupplied risk references: "
            + ", ".join(reference for reference, _ in removed_unknown_rows),
        ),
        removed_rows=removed_unknown_rows,
    )


def _dropped_disposition_plan(
    prior: LossAnalysisDraft,
    report: SalvageReport,
    *,
    step: str,
    risk_cards: list[RiskCard],
    repair_record: RepairRecord | None,
) -> RepairOutcome:
    """Route the salvaged draft's dropped disposition rows to repair or cleanup."""
    warnings = report.dropped_disposition_warnings()
    if step == "gap_analysis":
        # The gap call's contract carries no risk accounting; its
        # disposition rows are out of contract and are removed
        # (owner-approved cleanup policy C1, 2026-09-11).
        return DeterministicCleanup(
            draft=prior,
            warnings=warnings,
            removed_rows=tuple(
                (label, reason) for label, reason, _ in report.dropped_dispositions
            ),
        )
    supplied_order = [card.risk_id for card in risk_cards]
    classified = _classify_dropped_dispositions(report, set(supplied_order))
    if isinstance(classified, UnsupportedRepair):
        return classified
    supplied_drop_reasons, unknown_reasons = classified
    reason_map, selected, removed_unknown_rows = _dropped_repair_selection(
        prior, risk_cards, supplied_order, supplied_drop_reasons, unknown_reasons
    )
    if not selected and not removed_unknown_rows:
        return UnsupportedRepair(
            "the salvaged response has no repairable disposition rows"
        )
    if not selected:
        return _unknown_rows_cleanup(prior, risk_cards, warnings, removed_unknown_rows)
    _record_salvage_drops(
        report,
        step=step,
        repair_record=repair_record,
        repair_identities=frozenset(supplied_drop_reasons),
    )
    return DispositionRepairPlan(
        prior=prior,
        selected=selected,
        reasons=tuple((card_id, reason_map[card_id]) for card_id in selected),
        removed_unknown=removed_unknown_rows,
        salvage_warnings=warnings,
    )


def _classify_dropped_dispositions(
    report: SalvageReport,
    supplied: set[str],
) -> UnsupportedRepair | tuple[dict[str, list[str]], dict[str, str]]:
    """Split dropped disposition rows by their original identity.

    Classify every dropped row by its original identity before any
    selection runs (owner correction, 2026-09-12): a supplied card's
    malformed row must join the repair selection, because a supplied
    card's missing, duplicate, or malformed state may never be
    silently resolved by cleanup, and an unsupplied identity routes
    to the C2 cleanup policy even when the row itself was malformed.
    A malformed row with no usable identity cannot be classified
    and fails closed with a typed reason.
    """
    supplied_drop_reasons: dict[str, list[str]] = {}
    unknown_reasons: dict[str, str] = {}
    for _, reason, original_ref in report.dropped_dispositions:
        if original_ref is None:
            return UnsupportedRepair(
                "a malformed risk_dispositions row carries no usable "
                "risk_ref identity, so neither a repair selection nor "
                "a cleanup scope can be derived for it",
                scope="risk_dispositions",
            )
        if original_ref in supplied:
            supplied_drop_reasons.setdefault(original_ref, []).append(reason)
        else:
            unknown_reasons[original_ref] = (
                "risk reference absent from the supplied set; the "
                f"returned row was also malformed: {reason}"
            )
    return supplied_drop_reasons, unknown_reasons


def _with_malformed_row_notes(
    reason_pairs: Iterable[tuple[str, str]],
    supplied_drop_reasons: dict[str, list[str]],
) -> dict[str, str]:
    """Append each supplied card's dropped-row reasons to its repair reason."""
    reason_map = dict(reason_pairs)
    for card_id, drop_reasons in supplied_drop_reasons.items():
        malformed_note = (
            "a malformed risk_dispositions row was returned for this "
            "supplied card and dropped: " + "; ".join(drop_reasons)
        )
        reason_map[card_id] = (
            f"{reason_map[card_id]}; {malformed_note}"
            if card_id in reason_map
            else malformed_note
        )
    return reason_map


def _accounting_repair_plan(
    first_result: LLMResult,
    *,
    response_format: type[LossAnalysisDraft],
    risk_cards: list[RiskCard],
    require_risk_accounting: bool,
) -> RepairOutcome:
    """Select the disposition repair for a failed risk-accounting gate."""
    if not require_risk_accounting:
        return UnsupportedRepair("risk accounting is not required for this call")
    prior = parse_llm_result(first_result, response_format)
    selected, reason_pairs, removed_unknown = select_disposition_repairs(
        prior, risk_cards
    )
    if not selected and not removed_unknown:
        return UnsupportedRepair(
            "the accounting failure named no repairable disposition rows"
        )
    if not selected:
        return DeterministicCleanup(
            draft=_without_unknown_disposition_rows(prior, risk_cards),
            warnings=(
                f"removed risk_dispositions rows for unsupplied risk "
                f"references: {', '.join(removed_unknown)}",
            ),
            removed_rows=_absent_reference_rows(removed_unknown),
        )
    return DispositionRepairPlan(
        prior=prior,
        selected=selected,
        reasons=reason_pairs,
        removed_unknown=_absent_reference_rows(removed_unknown),
    )


# ---------------------------------------------------------------------------
# Boundary 1: the corrected original provider object (R2.4)
# ---------------------------------------------------------------------------


def revalidate_provider_object(
    draft: LossAnalysisDraft,
    model: type[BaseModel] | None,
    *,
    step: str,
) -> None:
    """Re-validate the corrected wire object against the original schema.

    After salvage and any repair or cleanup, the original collections with
    only the authorized corrections applied must still satisfy the original
    provider schema before the domain merge.
    """
    if model is None:
        return
    try:
        model.model_validate(draft.model_dump(mode="json"))
    except ValidationError as exc:
        first = _format_validation_errors(exc, limit=3)
        raise ValueError(
            f"{step}: the corrected response no longer satisfies the original "
            "provider schema: " + "; ".join(first)
        ) from exc


# ---------------------------------------------------------------------------
# Merges
# ---------------------------------------------------------------------------


def _repair_rows_by_ref(
    plan: DispositionRepairPlan,
    rows: list[RepairRiskDisposition],
) -> dict[str, RepairRiskDisposition]:
    """Index repair rows by card, rejecting unknown, duplicate, or missing rows."""
    selected = set(plan.selected)
    by_ref: dict[str, RepairRiskDisposition] = {}
    for row in rows:
        if row.risk_ref not in selected:
            raise RepairRejected(
                f"unknown or out-of-scope repair identity '{row.risk_ref}'; "
                "only the selected risk cards may be returned"
            )
        if row.risk_ref in by_ref:
            raise RepairRejected(
                f"duplicate repair row for '{row.risk_ref}'; return exactly "
                "one row per selected card"
            )
        by_ref[row.risk_ref] = row
    missing = [ref for ref in plan.selected if ref not in by_ref]
    if missing:
        raise RepairRejected(
            "incomplete repair; no row was returned for: " + ", ".join(missing)
        )
    return by_ref


def _reject_undeclared_repair_citations(
    plan: DispositionRepairPlan,
    by_ref: dict[str, RepairRiskDisposition],
) -> None:
    """Reject a cited repair row that names a loss the prior draft lacks."""
    declared_losses = {
        loss.loss_id
        for loss in plan.prior.risk_card_losses + plan.prior.use_case_losses
    }
    for ref, row in by_ref.items():
        if row.disposition == "cited":
            undeclared = [
                loss_id for loss_id in row.loss_ids if loss_id not in declared_losses
            ]
            if undeclared:
                raise RepairRejected(
                    f"the repair row for '{ref}' cites losses the response "
                    "never declared: " + ", ".join(undeclared)
                )


def merge_disposition_repair(
    plan: DispositionRepairPlan,
    rows: list[RepairRiskDisposition],
    *,
    risk_cards: list[RiskCard],
) -> LossAnalysisDraft:
    """Apply one validated disposition repair and preserve every other row.

    Rejects duplicate, unknown, out-of-scope, and incomplete responses with a
    typed reason, and rejects cited rows naming losses the prior draft never
    declared.  Unselected rows keep their exact payloads; rows for unsupplied
    risk references are removed deterministically.
    """
    selected = set(plan.selected)
    supplied_order = [card.risk_id for card in risk_cards]
    supplied = set(supplied_order)
    by_ref = _repair_rows_by_ref(plan, rows)
    _reject_undeclared_repair_citations(plan, by_ref)
    kept = {
        row.risk_ref: row
        for row in plan.prior.risk_dispositions
        if row.risk_ref in supplied and row.risk_ref not in selected
    }
    ordered_rows = [
        (kept[card_id] if card_id in kept else by_ref[card_id]).model_copy(deep=True)
        for card_id in supplied_order
        if card_id in kept or card_id in by_ref
    ]
    return _draft_with_dispositions(plan.prior, ordered_rows)


def _draft_with_dispositions(
    prior: LossAnalysisDraft,
    rows: list[RiskDisposition],
) -> LossAnalysisDraft:
    """Revalidate *prior*'s graph with *rows* as its disposition list."""
    return LossAnalysisDraft.model_validate(
        {
            "risk_card_losses": [
                item.model_dump(mode="json") for item in prior.risk_card_losses
            ],
            "use_case_losses": [
                item.model_dump(mode="json") for item in prior.use_case_losses
            ],
            "hazards": [item.model_dump(mode="json") for item in prior.hazards],
            "security_constraints": [
                item.model_dump(mode="json") for item in prior.security_constraints
            ],
            "risk_dispositions": [item.model_dump(mode="json") for item in rows],
        }
    )


def _check_resolved_source_outcome(
    identity: str, original: dict, returned: RepairObligation
) -> None:
    """Accept only the declared proxy or the removed outcome, nothing else."""
    declared_proxy = (
        returned.observation_role == "proxy"
        and returned.source_outcome == original.get("source_outcome")
    )
    removed_outcome = (
        returned.source_outcome is None
        and returned.observation_role == original.get("observation_role")
    )
    if declared_proxy or removed_outcome:
        return
    if returned.source_outcome not in (None, original.get("source_outcome")):
        field = "source_outcome"
    else:
        field = "observation_role"
    raise RepairRejected(
        f"repair_unrelated_field_edit: the corrected entry for '{identity}' "
        f"changed field '{field}' outside the two permitted edits: declare "
        "the proxy and keep source_outcome, or remove source_outcome and keep "
        "observation_role"
    )


def _verify_corrected_entry(
    selected: SelectedObligation,
    returned: RepairObligation,
) -> RepairObligation | None:
    """Verify one corrected entry against its original and permitted change.

    Every field outside the permitted correction must match the original
    entry exactly; the relocated channel value must move unchanged; a known
    channel may never be replaced with another channel or dropped to the
    wire default ``unknown``; an already-valid destination field may never
    be overwritten.  A channel field outside the permitted correction that
    the response omits entirely is restored from the original entry.
    Returns the entry to merge, or ``None`` when the entry passes every
    check except a ``rule_span`` that still is not part of the rule: that
    slip drops the obligation instead of stopping the run.
    """
    identity = selected.identity
    original = selected.original_entry_raw
    if returned.kind != original.get("kind"):
        raise RepairRejected(
            f"repair_unrelated_field_edit: the corrected entry for "
            f"'{identity}' changed field 'kind'"
        )
    changed_fields, relocation = _permitted_change_scope(selected.permitted_changes)
    if relocation is not None:
        _check_relocated_channel(identity, relocation, returned)
    restored = _unchanged_field_restorations(
        identity, original, returned, changed_fields
    )
    span_slips = False
    for change in selected.permitted_changes:
        try:
            _check_permitted_value(selected, change, returned)
        except RepairRejected:
            if change.kind != "set_rule_span":
                raise
            span_slips = True
    if span_slips:
        return None
    if restored:
        return returned.model_copy(update=restored)
    return returned


def _permitted_change_scope(
    permitted_changes: Iterable[PermittedChange],
) -> tuple[set[str], PermittedChange | None]:
    """Return the fields the permitted changes may edit, and any relocation."""
    changed_fields: set[str] = set()
    relocation: PermittedChange | None = None
    for change in permitted_changes:
        if change.kind == "relocate_channel":
            relocation = change
            changed_fields.update((change.source_field, change.destination_field))
        elif change.kind == "remove_fields":
            changed_fields.update(change.fields)
        elif change.kind == "set_source_outcome":
            changed_fields.add("source_outcome")
        elif change.kind == "set_rule_span":
            changed_fields.add("rule_span")
        elif change.kind == "resolve_source_outcome":
            changed_fields.update(("observation_role", "source_outcome"))
    return changed_fields, relocation


def _check_relocated_channel(
    identity: str, relocation: PermittedChange, returned: RepairObligation
) -> None:
    """Reject a relocated channel that was dropped or replaced."""
    destination_value = getattr(returned, relocation.destination_field)
    if destination_value == relocation.value:
        return
    if destination_value == "unknown" and relocation.value != "unknown":
        raise RepairRejected(
            f"repair_channel_omitted: the corrected entry for "
            f"'{identity}' dropped the known channel "
            f"{relocation.value!r} to the default 'unknown'"
        )
    raise RepairRejected(
        f"repair_channel_replaced: the corrected entry for "
        f"'{identity}' replaced the channel {relocation.value!r} "
        f"with {destination_value!r}"
    )


def _unchanged_field_restorations(
    identity: str,
    original: dict,
    returned: RepairObligation,
    changed_fields: set[str],
) -> dict[str, Any]:
    """Check every field outside the permitted change against the original.

    Returns the omitted channel values to restore from the original entry.
    """
    # The comparison baseline is the original entry as it would parse: the
    # wire model defaults an absent channel field to ``unknown`` per kind, so
    # an original that omits the field and a response that omits it are the
    # same value, not an edit.
    baseline = dict(original)
    for kind, channel in (("required", "realized_by"), ("forbidden", "violated_via")):
        if baseline.get("kind") == kind and baseline.get(channel) is None:
            baseline[channel] = "unknown"
    restored: dict[str, Any] = {}
    for name in _OBLIGATION_FIELDS:
        if name in changed_fields:
            continue
        original_value = baseline.get(name)
        returned_value = getattr(returned, name, None)
        if original_value == returned_value:
            continue
        if name in returned.omitted_channels:
            # An untouched channel the response left out is preserved
            # material, not an overwrite: code restores the original value.
            restored[name] = original_value
            continue
        if name in ("violated_via", "realized_by") and original_value is not None:
            raise RepairRejected(
                f"repair_destination_overwritten: the corrected entry for "
                f"'{identity}' overwrote the already-valid destination "
                f"field '{name}'"
            )
        raise RepairRejected(
            f"repair_unrelated_field_edit: the corrected entry for "
            f"'{identity}' changed field '{name}'"
        )
    return restored


def _check_permitted_value(
    selected: SelectedObligation,
    change: PermittedChange,
    returned: RepairObligation,
) -> None:
    """Check that the corrected entry carries the value one change requires."""
    identity = selected.identity
    if change.kind == "set_source_outcome":
        outcome = getattr(returned, "source_outcome")
        if not (isinstance(outcome, str) and outcome.strip()):
            raise RepairRejected(
                f"repair_unrelated_field_edit: the corrected entry for "
                f"'{identity}' did not set a non-empty source_outcome"
            )
    elif change.kind == "resolve_source_outcome":
        _check_resolved_source_outcome(identity, selected.original_entry_raw, returned)
    elif change.kind == "set_rule_span":
        span = getattr(returned, "rule_span")
        if not (
            isinstance(span, str)
            and span.strip()
            and span.casefold() in selected.constraint_rule.casefold()
        ):
            raise RepairRejected(
                f"repair_unrelated_field_edit: the corrected entry for "
                f"'{identity}' still has a rule_span that is not a contiguous "
                "substring of the constraint rule, compared case-insensitively"
            )


def _restore_preserved_channels(
    returned: RepairObligation,
    preserved: dict[str, Any],
) -> RepairObligation:
    """Restore the channel fields a preserved entry's echo left out."""
    if returned.kind != preserved.get("kind"):
        return returned
    restored = {
        name: preserved.get(name)
        for name in returned.omitted_channels
        if preserved.get(name) != getattr(returned, name)
    }
    if restored:
        return returned.model_copy(update=restored)
    return returned


def _merge_selected_constraints(
    plan: ObligationRepairPlan,
    selected_constraint_order: list[str],
    by_id: dict[str, RepairObligationConstraint],
    dropped: list[DroppedObligation],
) -> dict[str, list[RepairObligation]]:
    prior_by_id = {
        constraint.constraint_id: constraint
        for constraint in plan.prior.security_constraints
    }
    merged_by_constraint: dict[str, list[RepairObligation]] = {}
    for constraint_id in selected_constraint_order:
        prior_constraint = prior_by_id.get(constraint_id)
        if prior_constraint is None:
            raise RepairRejected(
                f"selected constraint '{constraint_id}' is not present in the "
                "prior draft"
            )
        merged_by_constraint[constraint_id] = _merge_constraint_obligations(
            plan, prior_constraint, by_id[constraint_id], dropped
        )
    return merged_by_constraint


def _drop_emptied_constraints(
    merged_by_constraint: dict[str, list[RepairObligation]],
    dropped: list[DroppedObligation],
) -> set[str]:
    """Mark and return the constraints whose last obligation was dropped."""
    emptied = {
        constraint_id
        for constraint_id, entries in merged_by_constraint.items()
        if not entries and any(item.constraint_id == constraint_id for item in dropped)
    }
    dropped[:] = [
        replace(item, constraint_dropped=item.constraint_id in emptied)
        for item in dropped
    ]
    return emptied


def _constraint_payload_with_obligations(
    constraint: SecurityConstraint,
    merged_by_constraint: dict[str, list[RepairObligation]],
) -> dict:
    payload = constraint.model_dump(mode="json")
    if constraint.constraint_id in merged_by_constraint:
        payload["obligations"] = [
            entry.model_dump(mode="json")
            for entry in merged_by_constraint[constraint.constraint_id]
        ]
    return payload


def merge_obligation_repair(
    plan: ObligationRepairPlan,
    items: list[RepairObligationConstraint],
    dropped: list[DroppedObligation] | None = None,
) -> LossAnalysisDraft:
    """Apply one validated obligation repair and preserve everything else.

    Rejects duplicate, unknown, out-of-scope, and incomplete responses with a
    typed reason.  Every previously valid obligation entry of a selected
    constraint must appear byte-identically, so a repair cannot silently
    rewrite or drop a preserved entry, and every corrected entry must carry
    exactly its permitted correction: no deletion, no renaming, no addition,
    no kind change, no unrelated field edit, no channel replacement, no
    channel omission to the default ``unknown``, and no destination
    overwrite.  The constraint's own rule, conditions, and hazard links are
    never on the wire.

    A corrected entry whose ``rule_span`` still is not part of the rule is
    dropped, and a constraint left without any obligation is dropped with it.
    Both are appended to *dropped*, which is emptied first, so the caller can
    record them.
    """
    dropped = dropped if dropped is not None else []
    dropped.clear()
    selected_constraint_order = list(
        dict.fromkeys(selected.constraint_id for selected in plan.selected)
    )
    by_id = _index_returned_constraints(items, selected_constraint_order)
    merged_by_constraint = _merge_selected_constraints(
        plan, selected_constraint_order, by_id, dropped
    )
    emptied = _drop_emptied_constraints(merged_by_constraint, dropped)
    merged_constraints = [
        _constraint_payload_with_obligations(constraint, merged_by_constraint)
        for constraint in plan.prior.security_constraints
        if constraint.constraint_id not in emptied
    ]
    return LossAnalysisDraft.model_validate(
        {
            "risk_card_losses": [
                item.model_dump(mode="json") for item in plan.prior.risk_card_losses
            ],
            "use_case_losses": [
                item.model_dump(mode="json") for item in plan.prior.use_case_losses
            ],
            "hazards": [item.model_dump(mode="json") for item in plan.prior.hazards],
            "security_constraints": merged_constraints,
            "risk_dispositions": [
                item.model_dump(mode="json") for item in plan.prior.risk_dispositions
            ],
        }
    )


def _index_returned_constraints(
    items: list[RepairObligationConstraint],
    selected_constraint_order: list[str],
) -> dict[str, RepairObligationConstraint]:
    """Index the returned constraints; reject unknown, repeated, or missing ones."""
    selected_constraints = set(selected_constraint_order)
    by_id: dict[str, RepairObligationConstraint] = {}
    for item in items:
        if item.constraint_id not in selected_constraints:
            raise RepairRejected(
                f"unknown or out-of-scope repair identity "
                f"'{item.constraint_id}'; only the selected constraints may "
                "be returned"
            )
        if item.constraint_id in by_id:
            raise RepairRejected(
                f"duplicate repair entry for constraint '{item.constraint_id}'"
            )
        by_id[item.constraint_id] = item
    missing = [
        constraint_id
        for constraint_id in selected_constraint_order
        if constraint_id not in by_id
    ]
    if missing:
        raise RepairRejected(
            "incomplete repair; no obligations were returned for: " + ", ".join(missing)
        )
    return by_id


def _merge_constraint_obligations(
    plan: ObligationRepairPlan,
    prior_constraint: SecurityConstraint,
    returned: RepairObligationConstraint,
    dropped: list[DroppedObligation],
) -> list[RepairObligation]:
    """Merge one selected constraint's returned entries over its prior entries."""
    constraint_id = prior_constraint.constraint_id
    selected_entries = {
        selected.obligation_id: selected
        for selected in plan.selected
        if selected.constraint_id == constraint_id
    }
    _check_returned_obligation_ids(
        constraint_id,
        [entry.obligation_id for entry in returned.obligations],
        expected_ids={entry.obligation_id for entry in prior_constraint.obligations}
        | set(selected_entries),
        selected_ids=selected_entries,
    )
    preserved_by_id = {
        entry.obligation_id: entry.model_dump(mode="json")
        for entry in prior_constraint.obligations
    }
    merged_entries = _verified_entries(
        prior_constraint, returned, selected_entries, preserved_by_id, dropped
    )
    repaired_payloads = [entry.model_dump(mode="json") for entry in merged_entries]
    for preserved in prior_constraint.obligations:
        if preserved.model_dump(mode="json") not in repaired_payloads:
            raise RepairRejected(
                f"the repair for constraint '{constraint_id}' altered or "
                f"dropped the preserved obligation entry "
                f"{preserved.obligation_id}; preserved entries must be "
                "returned byte-identically"
            )
    return merged_entries


def _verified_entries(
    prior_constraint: SecurityConstraint,
    returned: RepairObligationConstraint,
    selected_entries: dict[str, SelectedObligation],
    preserved_by_id: dict[str, dict],
    dropped: list[DroppedObligation],
) -> list[RepairObligation]:
    """Verify each returned entry; list the ones whose span stays outside the rule."""
    verified_entries: list[RepairObligation] = []
    for entry in returned.obligations:
        verified = _verified_or_restored_entry(entry, selected_entries, preserved_by_id)
        if verified is not None:
            verified_entries.append(verified)
            continue
        dropped.append(
            DroppedObligation(
                constraint_id=prior_constraint.constraint_id,
                obligation_id=entry.obligation_id,
                rule_span=entry.rule_span,
                rule=prior_constraint.rule,
            )
        )
    return verified_entries


def _verified_or_restored_entry(
    returned_entry: RepairObligation,
    selected_entries: dict[str, SelectedObligation],
    preserved_by_id: dict[str, dict],
) -> RepairObligation | None:
    selected_entry = selected_entries.get(returned_entry.obligation_id)
    if selected_entry is not None:
        return _verify_corrected_entry(selected_entry, returned_entry)
    if returned_entry.obligation_id in preserved_by_id:
        return _restore_preserved_channels(
            returned_entry, preserved_by_id[returned_entry.obligation_id]
        )
    return returned_entry


def _check_returned_obligation_ids(
    constraint_id: str,
    returned_ids: list[str],
    *,
    expected_ids: set[str],
    selected_ids: Iterable[str],
) -> None:
    """Reject repeated, unknown, or missing obligation ids in one repair."""
    if len(returned_ids) != len(set(returned_ids)):
        duplicated = sorted(
            {identity for identity in returned_ids if returned_ids.count(identity) > 1}
        )
        raise RepairRejected(
            "repair_identity_duplicate: the repair for constraint "
            f"'{constraint_id}' returns obligation "
            + ", ".join(duplicated)
            + " more than once"
        )
    for identity in returned_ids:
        if identity not in expected_ids:
            raise RepairRejected(
                f"repair_identity_unknown: the returned entry '{identity}' "
                f"is neither a preserved nor a selected obligation of "
                f"constraint '{constraint_id}'"
            )
    for obligation_id in selected_ids:
        if obligation_id not in returned_ids:
            raise RepairRejected(
                f"repair_delete_forbidden: no corrected entry was returned "
                f"for selected obligation '{constraint_id}/{obligation_id}'"
            )


def reference_repair_proposals(
    response: ReferenceRepairResponse,
) -> dict[str, list[str]]:
    """Return each returned list keyed by its repair identity."""
    proposals = {
        f"{item.hazard_id}.related_losses": list(item.related_losses)
        for item in response.hazards
    }
    proposals.update(
        {
            f"{item.constraint_id}.related_hazards": list(item.related_hazards)
            for item in response.security_constraints
        }
    )
    return proposals


def _index_returned_reference_lists(
    plan: ReferenceRepairPlan,
    response: ReferenceRepairResponse,
) -> dict[str, list[str]]:
    """Index the returned lists; reject unknown, repeated, or missing ones."""
    returned = [
        (f"{item.hazard_id}.related_losses", list(item.related_losses))
        for item in response.hazards
    ] + [
        (f"{item.constraint_id}.related_hazards", list(item.related_hazards))
        for item in response.security_constraints
    ]
    selected = {item.identity for item in plan.selected}
    by_identity: dict[str, list[str]] = {}
    for identity, references in returned:
        if identity not in selected:
            raise RepairRejected(
                f"repair_identity_unknown: '{identity}' is not a selected "
                "reference list; only the selected lists may be returned"
            )
        if identity in by_identity:
            raise RepairRejected(
                f"repair_identity_duplicate: '{identity}' is returned more than once"
            )
        by_identity[identity] = references
    missing = [
        item.identity for item in plan.selected if item.identity not in by_identity
    ]
    if missing:
        raise RepairRejected(
            "incomplete repair; no list was returned for: " + ", ".join(missing)
        )
    return by_identity


def _check_reference_list(selected: SelectedReferenceList, returned: list[str]) -> None:
    """Reject any returned list outside the permitted correction."""
    repeated = sorted({ref for ref in returned if returned.count(ref) > 1})
    if repeated:
        raise RepairRejected(
            f"repair_duplicate_remaining: {selected.identity} still lists "
            + ", ".join(repeated)
            + " more than once"
        )
    keep = set(selected.kept)
    kept = tuple(ref for ref in returned if ref in keep)
    if kept != selected.kept:
        raise RepairRejected(
            f"repair_edit_forbidden: {selected.identity} must keep "
            + ", ".join(selected.kept)
            + " once each in this order; returned "
            + ", ".join(returned)
        )
    _check_added_references(selected, returned, keep)


def _check_added_references(
    selected: SelectedReferenceList, returned: list[str], keep: set[str]
) -> None:
    added = [ref for ref in returned if ref not in keep]
    invalid = [ref for ref in added if ref not in selected.replacement_ids]
    if invalid:
        raise RepairRejected(
            f"repair_reference_unknown: {selected.identity} adds "
            + ", ".join(invalid)
            + ", which is not a replacement ID valid for this list"
        )
    if len(added) > selected.replaceable_count:
        raise RepairRejected(
            f"repair_edit_forbidden: {selected.identity} adds {len(added)} IDs "
            f"but only {selected.replaceable_count} {selected.entry_kind} "
            "entries may be replaced"
        )


def merge_reference_repair(
    plan: ReferenceRepairPlan,
    response: ReferenceRepairResponse,
) -> LossAnalysisDraft:
    """Apply one validated reference repair and preserve everything else.

    Only the selected lists change; every other record and field keeps its
    exact payload.
    """
    by_identity = _index_returned_reference_lists(plan, response)
    replacements: dict[tuple[str, str], list[str]] = {}
    for selected in plan.selected:
        returned = by_identity[selected.identity]
        _check_reference_list(selected, returned)
        replacements[(selected.collection, selected.owner_id)] = returned
    payload = plan.prior.model_dump(mode="json")
    for collection, (field_name, id_field) in _REFERENCE_LIST_FIELDS.items():
        for row in payload[collection]:
            references = replacements.get((collection, row[id_field]))
            if references is not None:
                row[field_name] = references
    return LossAnalysisDraft.model_validate(payload)


@dataclass(frozen=True)
class DroppedReferences:
    """One reference list deterministic code cut after a failed correction.

    ``kept`` is what the list keeps; an empty ``kept`` drops the record that
    owns the list.
    """

    collection: str
    owner_id: str
    original: tuple[str, ...]
    kept: tuple[str, ...]
    reason: str

    @property
    def identity(self) -> str:
        return f"{self.owner_id}.{_REFERENCE_LIST_FIELDS[self.collection][0]}"

    @property
    def dropped_entries(self) -> tuple[str, ...]:
        """Each original entry the cut removed, in original order."""
        remaining = list(self.kept)
        dropped: list[str] = []
        for ref in self.original:
            if remaining and ref == remaining[0]:
                remaining.pop(0)
            else:
                dropped.append(ref)
        return tuple(dropped)


def drop_unresolved_references(
    plan: ReferenceRepairPlan,
) -> tuple[LossAnalysisDraft, tuple[DroppedReferences, ...]]:
    """Cut every selected list to its known IDs and drop emptied records.

    A hazard left without a valid loss is dropped; each constraint then loses
    its references to dropped hazards, and a constraint left without a hazard
    is dropped too.  Every other record and field keeps its exact payload.
    """
    selected = {(item.collection, item.owner_id): item for item in plan.selected}
    payload = plan.prior.model_dump(mode="json")
    drops: list[DroppedReferences] = []
    dropped_hazards: set[str] = set()
    # Hazards come first, so constraints see every hazard dropped before them.
    for collection, (field_name, id_field) in _REFERENCE_LIST_FIELDS.items():
        rows = []
        for row in payload[collection]:
            cut = _cut_reference_list(
                selected.get((collection, row[id_field])),
                collection=collection,
                owner_id=row[id_field],
                original=tuple(row[field_name]),
                gone=dropped_hazards if collection == "security_constraints" else set(),
            )
            if cut is None:
                rows.append(row)
                continue
            drops.append(cut)
            if cut.kept:
                row[field_name] = list(cut.kept)
                rows.append(row)
            elif collection == "hazards":
                dropped_hazards.add(cut.owner_id)
        payload[collection] = rows
    return LossAnalysisDraft.model_validate(payload), tuple(drops)


def _cut_reference_list(
    selected: SelectedReferenceList | None,
    *,
    collection: str,
    owner_id: str,
    original: tuple[str, ...],
    gone: set[str],
) -> DroppedReferences | None:
    base = selected.kept if selected is not None else original
    kept = tuple(ref for ref in base if ref not in gone)
    if selected is None and kept == original:
        return None
    reasons = [selected.defect_reason] if selected is not None else []
    lost = tuple(dict.fromkeys(ref for ref in original if ref in gone))
    if lost:
        reasons.append("dropped hazards: " + ", ".join(lost))
    return DroppedReferences(
        collection=collection,
        owner_id=owner_id,
        original=original,
        kept=kept,
        reason="; ".join(reasons),
    )


def _record_dropped_references(
    drops: Iterable[DroppedReferences],
    *,
    step: str,
    repair_record: RepairRecord | None,
    normalization_warnings: list[str] | None,
) -> None:
    """Record each list the drop cut and each record it dropped."""
    for item in drops:
        consequence = (
            ""
            if item.kept
            else f"; {item.owner_id} had no other valid ID and was dropped"
        )
        _record_warnings(
            (
                f"{step} reference {item.identity} dropped "
                + ", ".join(item.dropped_entries)
                + consequence,
            ),
            normalization_warnings,
        )
        if repair_record is None:
            continue
        repair_record.add(
            stage=step,
            attempt="repair",
            kind=REFERENCE_DROPPED_KIND,
            identity=item.identity,
            reason=(
                f"{item.reason}; the one correction did not resolve the list, "
                f"so deterministic code dropped the entries it could not keep"
                f"{consequence}."
            ),
            proposed={"references": list(item.original)},
            applied={
                "references": list(item.kept),
                "dropped_entries": list(item.dropped_entries),
                "dropped_records": [] if item.kept else [item.owner_id],
            },
            outcome="dropped",
            # The cut entries come from the first-attempt response.
            raw_step=step,
        )


def _drop_unresolved(
    plan: ReferenceRepairPlan,
    validation: _RepairValidation,
    *,
    step: str,
    error_msg: str | None,
    repair_record: RepairRecord | None,
) -> LossAnalysisDraft:
    """Accept the draft without what the correction left unresolved, or stop."""
    try:
        cut, drops = drop_unresolved_references(plan)
        draft = _finish_merged_draft(cut, validation, step=step)
    except ValueError as exc:
        raise StageError(
            stage="stage_1a",
            step=step,
            message=(
                f"targeted repair failed: {error_msg}; dropping the unresolved "
                f"references left an invalid draft: {exc}"
            ),
        ) from exc
    _record_dropped_references(
        drops,
        step=step,
        repair_record=repair_record,
        normalization_warnings=validation.normalization_warnings,
    )
    return draft


# ---------------------------------------------------------------------------
# One repair call
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _RepairValidation:
    """The callables one repaired draft must pass through before acceptance."""

    run_validators: Callable[[LossAnalysisDraft], None]
    normalizer: Callable[[LossAnalysisDraft], list[str]]
    authoritative_merge: Callable[[LossAnalysisDraft], LossAnalysisDraft] | None
    normalization_warnings: list[str] | None
    provider_draft_model: type[BaseModel] | None


def _record_warnings(
    warnings: Iterable[str],
    normalization_warnings: list[str] | None,
) -> None:
    for warning in warnings:
        if normalization_warnings is not None and warning not in normalization_warnings:
            normalization_warnings.append(warning)


def _finish_merged_draft(
    merged: LossAnalysisDraft,
    validation: _RepairValidation,
    *,
    step: str,
) -> LossAnalysisDraft:
    """Re-validate against the provider schema, then normalize and validate."""
    revalidate_provider_object(merged, validation.provider_draft_model, step=step)
    for warning in validation.normalizer(merged):
        _record_warnings((warning,), validation.normalization_warnings)
    if validation.authoritative_merge is not None:
        merged = validation.authoritative_merge(merged)
    validation.run_validators(merged)
    return merged


def _plan_identities(plan: RepairPlan) -> list[tuple[str, str]]:
    """Return each attempted identity of *plan* with its recorded reason."""
    if isinstance(plan, DispositionRepairPlan):
        reason_map = dict(plan.reasons)
        return [
            (card_id, reason_map.get(card_id, "selected risk-disposition row"))
            for card_id in plan.selected
        ]
    return [
        (
            selected.identity,
            f"{selected.defect_reason}; permitted correction: "
            f"{selected.correction_instruction}",
        )
        for selected in plan.selected
    ]


@dataclass(frozen=True)
class _RepairVerdict:
    """The terminal outcome a targeted repair reached, with its proposals."""

    outcome: str
    reason: str = ""
    proposals: dict[str, list[str]] | None = None


def _record_repair_outcome(
    plan: RepairPlan,
    *,
    step: str,
    repair_record: RepairRecord | None,
    outcome: str,
    reason: str = "",
    proposed_values: dict[str, list[str]] | None = None,
    dropped: Iterable[DroppedObligation] = (),
) -> None:
    """Record the repair attempt's proposed and applied changes per identity.

    A repaired entry records the identity as proposed and applied; a rejected
    or failed attempt records the identity as proposed with ``applied: {}``
    and the typed reason, so no failed attempt is ever recorded as applied.
    An identity the plan lists twice is recorded once, with its first
    reason.  ``proposed_values`` carries the returned reference list of
    each identity, when the repair class records one.  A dropped obligation
    is recorded by :func:`_record_dropped_obligations` as its one outcome.
    """
    if repair_record is None:
        return
    recorded: set[str] = {item.identity for item in dropped}
    for identity, identity_reason in _plan_identities(plan):
        if identity in recorded:
            continue
        recorded.add(identity)
        proposed: dict[str, Any] = {"entries": [identity]}
        if proposed_values is not None and identity in proposed_values:
            proposed["references"] = proposed_values[identity]
        repair_record.add(
            stage=step,
            attempt="repair",
            kind="repair",
            identity=identity,
            reason=(
                identity_reason
                if outcome == "repaired"
                else f"{identity_reason}; {reason}"
            ),
            proposed=proposed,
            applied=dict(proposed) if outcome == "repaired" else {},
            outcome=outcome,
            raw_step=step + _REPAIR_STEP_SUFFIX,
        )


def _record_dropped_obligations(
    dropped: Iterable[DroppedObligation],
    *,
    step: str,
    repair_record: RepairRecord | None,
    normalization_warnings: list[str] | None,
) -> None:
    """Record each obligation dropped for a span outside its rule."""
    for item in dropped:
        consequence = (
            "; its constraint had no other obligation, so the constraint was "
            "dropped with it"
            if item.constraint_dropped
            else ""
        )
        _record_warnings(
            (
                f"{step} rule_span {item.identity} dropped: "
                f"{item.rule_span!r} does not occur in the rule{consequence}",
            ),
            normalization_warnings,
        )
        if repair_record is None:
            continue
        applied: dict[str, Any] = {"dropped_entries": [item.obligation_id]}
        if item.constraint_dropped:
            applied["constraint_dropped"] = item.constraint_id
        repair_record.add(
            stage=step,
            attempt="repair",
            kind=RULE_SPAN_DROPPED_KIND,
            identity=item.identity,
            reason=(
                "the corrected rule_span is still not a contiguous substring "
                "of the constraint rule (compared case-insensitively), so the "
                f"obligation was dropped{consequence}."
            ),
            proposed={"rule_span": item.rule_span, "rule": item.rule},
            applied=applied,
            outcome="dropped",
            raw_step=step + _REPAIR_STEP_SUFFIX,
        )


def _record_removed_unknown_rows(
    plan: DispositionRepairPlan,
    *,
    step: str,
    repair_record: RepairRecord | None,
) -> None:
    """Record the unsupplied-card rows the repair application removes (C2).

    Every removed row exists only in the original first-attempt response, so
    the entry's source reference (``raw_step``) always points at the original
    response step, never at the repair response; ``attempt: repair`` records
    that the removal was applied together with the repair.
    """
    if repair_record is None:
        return
    for reference, removal_reason in plan.removed_unknown:
        repair_record.add(
            stage=step,
            attempt="repair",
            kind="cleanup",
            identity=reference,
            reason=removal_reason,
            proposed={"removed_rows": [reference]},
            applied={"removed_rows": [reference]},
            outcome="removed",
            raw_step=step,
        )


def record_cleanup_rows(
    removed_rows: tuple[tuple[str, str], ...],
    *,
    step: str,
    repair_record: RepairRecord | None,
    outcome: str,
    reason: str = "",
) -> None:
    """Record one deterministic cleanup's removed rows and its outcome.

    A completed cleanup records each removed row as proposed and applied
    with outcome ``removed``; a cleanup whose re-validation failed records
    the same rows as proposed with ``applied: {}`` and the failing reason.
    """
    if repair_record is None:
        return
    for identity, row_reason in removed_rows:
        repair_record.add(
            stage=step,
            attempt="first",
            kind="cleanup",
            identity=identity,
            reason=row_reason if outcome == "removed" else f"{row_reason}; {reason}",
            proposed={"removed_rows": [identity]},
            applied={"removed_rows": [identity]} if outcome == "removed" else {},
            outcome=outcome,
            raw_step=step,
        )


@dataclass(frozen=True)
class _RepairRequest:
    """One repair class's rendered prompts, wire, and merge.

    ``merge`` applies a parsed response to the plan's prior draft and raises
    :class:`RepairRejected` for any change outside the permitted correction;
    ``on_repaired`` records class-specific evidence after a successful merge.
    """

    system_prompt: str
    user_prompt: str
    response_format: type[BaseModel]
    wire_model: type[BaseModel]
    merge: Callable[[Any], LossAnalysisDraft]
    proposals: Callable[[Any], dict[str, list[str]]] | None = None
    on_repaired: Callable[[], None] | None = None
    # Filled by ``merge`` with the obligations it dropped.
    dropped: list[DroppedObligation] = field(default_factory=list)


def _disposition_request(
    plan: DispositionRepairPlan,
    *,
    loader: TemplateLoader,
    llm_client: LLMClient,
    use_case_text: str,
    risk_cards: list[RiskCard],
    on_repaired: Callable[[], None],
) -> _RepairRequest:
    response_format: type[BaseModel] = DispositionRepairResponse
    if uses_guided_decoding(llm_client):
        selected_ids = set(plan.selected)
        response_format = with_keyed_rows(
            DispositionRepairResponse,
            array_field="risk_dispositions",
            key_field="risk_ref",
            keys=(card.risk_id for card in risk_cards if card.risk_id in selected_ids),
        )
    return _RepairRequest(
        system_prompt=loader.render_prompt(DISPOSITION_REPAIR_SYSTEM_TEMPLATE),
        user_prompt=loader.render_prompt(
            DISPOSITION_REPAIR_USER_TEMPLATE,
            use_case_text=use_case_text,
            selected_cards=_selected_card_views(plan, risk_cards),
            declared_losses=_declared_loss_views(plan.prior),
            reasons=plan.reasons,
        ),
        response_format=response_format,
        wire_model=DispositionRepairResponse,
        merge=lambda response: merge_disposition_repair(
            plan, list(response.risk_dispositions), risk_cards=risk_cards
        ),
        on_repaired=on_repaired,
    )


def _obligation_request(
    plan: ObligationRepairPlan,
    *,
    loader: TemplateLoader,
    use_case_text: str,
) -> _RepairRequest:
    dropped: list[DroppedObligation] = []
    return _RepairRequest(
        system_prompt=loader.render_prompt(OBLIGATION_REPAIR_SYSTEM_TEMPLATE),
        user_prompt=loader.render_prompt(
            OBLIGATION_REPAIR_USER_TEMPLATE,
            use_case_text=use_case_text,
            selected_constraints=_selected_constraint_views(plan),
        ),
        response_format=ObligationRepairResponse,
        wire_model=ObligationRepairResponse,
        merge=lambda response: merge_obligation_repair(
            plan, list(response.constraints), dropped
        ),
        dropped=dropped,
    )


def _reference_request(
    plan: ReferenceRepairPlan,
    *,
    loader: TemplateLoader,
    use_case_text: str,
) -> _RepairRequest:
    return _RepairRequest(
        system_prompt=loader.render_prompt(
            REFERENCE_REPAIR_SYSTEM_TEMPLATE,
            unknown_ids=any(selected.unknown for selected in plan.selected),
        ),
        user_prompt=loader.render_prompt(
            REFERENCE_REPAIR_USER_TEMPLATE,
            use_case_text=use_case_text,
            selected_lists=_selected_reference_views(plan),
            feedback=plan.feedback,
        ),
        response_format=ReferenceRepairResponse,
        wire_model=ReferenceRepairResponse,
        merge=lambda response: merge_reference_repair(plan, response),
        proposals=reference_repair_proposals,
    )


def _disposition_cleanup_recorder(
    plan: DispositionRepairPlan,
    *,
    step: str,
    repair_record: RepairRecord | None,
    normalization_warnings: list[str] | None,
) -> Callable[[], None]:
    """Record the unsupplied-card rows a successful disposition repair removes."""

    def record() -> None:
        if not plan.removed_unknown:
            return
        _record_warnings(
            (
                "removed risk_dispositions rows for unsupplied risk references: "
                + ", ".join(reference for reference, _ in plan.removed_unknown),
            ),
            normalization_warnings,
        )
        _record_removed_unknown_rows(plan, step=step, repair_record=repair_record)

    return record


def run_targeted_repair(
    plan: RepairPlan,
    *,
    llm_client: LLMClient,
    loader: TemplateLoader,
    run_dir: Path,
    step: str,
    temperature: float,
    use_case_text: str,
    risk_cards: list[RiskCard],
    run_validators: Callable[[LossAnalysisDraft], None],
    normalizer: Callable[[LossAnalysisDraft], list[str]],
    authoritative_merge: Callable[[LossAnalysisDraft], LossAnalysisDraft] | None = None,
    normalization_warnings: list[str] | None = None,
    max_completion_tokens: int = 8192,
    provider_draft_model: type[BaseModel] | None = None,
    repair_record: RepairRecord | None = None,
) -> LossAnalysisDraft:
    """Make exactly one targeted repair call and return the re-validated draft.

    The repair prompt is preflighted by the shared call wrapper, so an
    oversized repair fails closed before dispatch.  Any rejection or
    validation failure raises :class:`StageError`; the repair is never
    retried.  The attempt's proposed and applied changes are recorded in the
    run-level repair record with exactly one terminal outcome (``repaired``,
    ``rejected``, or ``failed``) per attempted identity, even when it fails.
    """
    validation = _RepairValidation(
        run_validators=run_validators,
        normalizer=normalizer,
        authoritative_merge=authoritative_merge,
        normalization_warnings=normalization_warnings,
        provider_draft_model=provider_draft_model,
    )
    # The parser reports the typed outcome it reached; the caller records
    # exactly one terminal outcome per attempted identity after the call.
    verdicts: list[_RepairVerdict] = []
    # The deterministic salvage that produced this plan is recorded evidence:
    # it names exactly which rows or entries were dropped before the repair.
    _record_warnings(plan.salvage_warnings, normalization_warnings)
    if isinstance(plan, DispositionRepairPlan):
        request = _disposition_request(
            plan,
            loader=loader,
            llm_client=llm_client,
            use_case_text=use_case_text,
            risk_cards=risk_cards,
            on_repaired=_disposition_cleanup_recorder(
                plan,
                step=step,
                repair_record=repair_record,
                normalization_warnings=normalization_warnings,
            ),
        )
    elif isinstance(plan, ObligationRepairPlan):
        request = _obligation_request(plan, loader=loader, use_case_text=use_case_text)
    else:
        request = _reference_request(plan, loader=loader, use_case_text=use_case_text)

    def parse_repair(result: LLMResult) -> LossAnalysisDraft:
        response = parse_llm_result(result, request.wire_model)
        proposals = request.proposals(response) if request.proposals else None
        try:
            merged = _finish_merged_draft(
                request.merge(response), validation, step=step
            )
        except RepairRejected as exc:
            verdicts.append(_RepairVerdict("rejected", str(exc), proposals))
            raise
        except ValueError as exc:
            verdicts.append(_RepairVerdict("failed", str(exc), proposals))
            raise
        if request.on_repaired is not None:
            request.on_repaired()
        verdicts.append(_RepairVerdict("repaired", proposals=proposals))
        return merged

    outcome = call_with_policy(
        llm_client=llm_client,
        system_prompt=request.system_prompt,
        user_prompt=request.user_prompt,
        response_format=request.response_format,
        run_dir=run_dir,
        stage="stage_1a",
        step=step + _REPAIR_STEP_SUFFIX,
        policy=CorrectionPolicy(),
        temperature=temperature,
        max_completion_tokens=max_completion_tokens,
        result_parser=parse_repair,
    )
    draft, error_msg = outcome.value, outcome.error
    # No typed outcome means the call failed outside the merge's typed errors:
    # a transport failure, an undecodable response, or an unexpected error.
    # A parser that ran more than once keeps its first outcome.
    verdict = (
        verdicts[0]
        if verdicts
        else _RepairVerdict("failed", error_msg or "no provider response was returned")
    )
    _record_repair_outcome(
        plan,
        step=step,
        repair_record=repair_record,
        outcome=verdict.outcome,
        reason=verdict.reason,
        proposed_values=verdict.proposals,
        dropped=request.dropped if verdict.outcome == "repaired" else (),
    )
    if verdict.outcome == "repaired":
        _record_dropped_obligations(
            request.dropped,
            step=step,
            repair_record=repair_record,
            normalization_warnings=normalization_warnings,
        )
    if error_msg is None and draft is not None:
        return draft
    return _finish_failed_repair(
        plan,
        validation,
        step=step,
        error_msg=error_msg,
        answered=bool(verdicts),
        repair_record=repair_record,
    )


def _finish_failed_repair(
    plan: RepairPlan,
    validation: _RepairValidation,
    *,
    step: str,
    error_msg: str | None,
    answered: bool,
    repair_record: RepairRecord | None,
) -> LossAnalysisDraft:
    """Drop what a failed unknown-reference correction left unresolved, or stop.

    ``answered`` means the parser reached a typed verdict: a response came
    back and was rejected or failed validation.  A transport or undecodable
    failure has nothing to resolve, and a duplicate-only plan keeps its stop
    (decision 47b).
    """
    if (
        isinstance(plan, ReferenceRepairPlan)
        and answered
        and any(selected.unknown for selected in plan.selected)
    ):
        return _drop_unresolved(
            plan,
            validation,
            step=step,
            error_msg=error_msg,
            repair_record=repair_record,
        )
    raise StageError(
        stage="stage_1a",
        step=step,
        message=f"targeted repair failed: {error_msg}",
    )


def _selected_card_views(
    plan: DispositionRepairPlan,
    risk_cards: list[RiskCard],
) -> list[dict]:
    """The full text of every selected risk card, in supplied order."""
    selected = set(plan.selected)
    return [
        {
            "risk_id": card.risk_id,
            "risk_name": card.risk_name,
            "risk_description": card.risk_description,
            "consequence": card.consequence,
        }
        for card in risk_cards
        if card.risk_id in selected
    ]


def _selected_reference_views(plan: ReferenceRepairPlan) -> list[dict]:
    """Each selected list with its owner's text, repeats, and replacement IDs.

    Every ID the view names carries its meaning, so the model can tell a
    repeat meant for a different record from a plain repeat.
    """
    meanings = dict(plan.meanings)
    owners = {
        ("hazards", hazard.hazard_id): hazard.description
        for hazard in plan.prior.hazards
    }
    owners.update(
        {
            ("security_constraints", constraint.constraint_id): constraint.rule
            for constraint in plan.prior.security_constraints
        }
    )

    def described(ids: Iterable[str]) -> list[dict]:
        return [{"id": ref, "meaning": meanings.get(ref, "")} for ref in ids]

    return [
        {
            "identity": selected.identity,
            "owner_id": selected.owner_id,
            "owner_kind": (
                "hazard" if selected.collection == "hazards" else "security constraint"
            ),
            "owner_text": owners[(selected.collection, selected.owner_id)],
            "field_name": selected.field_name,
            "original": list(selected.original),
            "validation_error": selected.defect_reason,
            "kept": described(selected.kept),
            "repeated": list(selected.repeated),
            "unknown": list(selected.unknown),
            "entry_kind": selected.entry_kind,
            "replacements": described(selected.replacement_ids),
            "permitted_change": selected.correction_instruction,
        }
        for selected in plan.selected
    ]


def _declared_loss_views(draft: LossAnalysisDraft) -> list[dict]:
    """The declared loss registry with its meanings."""
    return [
        {
            "loss_id": loss.loss_id,
            "description": loss.description,
            "provenance": loss.provenance.value,
            "source_risk_cards": loss.source_risk_cards,
        }
        for loss in draft.risk_card_losses + draft.use_case_losses
    ]


def _selected_constraint_views(plan: ObligationRepairPlan) -> list[dict]:
    """The full text of every selected constraint with its repair scope.

    Each view carries the constraint's retained context, its preserved valid
    entries, and one repair item per selected entry: the original entry
    verbatim, its exact validation errors, and the permitted correction
    stated as relocation or removal of named fields, never as a choice.
    """
    selected_constraints = {selected.constraint_id for selected in plan.selected}
    losses_by_id = {
        loss.loss_id: loss
        for loss in plan.prior.risk_card_losses + plan.prior.use_case_losses
    }
    hazards_by_id = {hazard.hazard_id: hazard for hazard in plan.prior.hazards}
    return [
        _selected_constraint_view(plan, constraint, hazards_by_id, losses_by_id)
        for constraint in plan.prior.security_constraints
        if constraint.constraint_id in selected_constraints
    ]


def _selected_constraint_view(
    plan: ObligationRepairPlan,
    constraint: SecurityConstraint,
    hazards_by_id: dict[str, Hazard],
    losses_by_id: dict[str, Loss],
) -> dict:
    repair_entries = [
        {
            "obligation_id": selected.obligation_id,
            "original_entry": selected.original_entry_raw,
            "validation_errors": list(selected.validation_errors),
            "permitted_change": selected.correction_instruction,
        }
        for selected in plan.selected
        if selected.constraint_id == constraint.constraint_id
    ]
    return {
        "constraint_id": constraint.constraint_id,
        "rule": constraint.rule,
        "applies_when": constraint.applies_when,
        "related_hazards": [
            {"hazard_id": hazard.hazard_id, "description": hazard.description}
            for hazard in (
                hazards_by_id.get(hazard_id) for hazard_id in constraint.related_hazards
            )
            if hazard is not None
        ],
        "related_loss_meanings": _related_loss_meanings(
            constraint, hazards_by_id, losses_by_id
        ),
        "preserved_entries": [
            entry.model_dump(mode="json", exclude_none=True)
            for entry in constraint.obligations
        ],
        "repair_entries": repair_entries,
    }


def _related_loss_meanings(
    constraint: SecurityConstraint,
    hazards_by_id: dict[str, Hazard],
    losses_by_id: dict[str, Loss],
) -> list[dict]:
    """The losses a constraint reaches through its known hazards, in edge order."""
    related_loss_meanings: list[dict] = []
    for hazard_id in constraint.related_hazards:
        hazard = hazards_by_id.get(hazard_id)
        if hazard is None:
            continue
        for loss_id in hazard.related_losses:
            loss = losses_by_id.get(loss_id)
            if loss is not None:
                related_loss_meanings.append(
                    {
                        "loss_id": loss.loss_id,
                        "description": loss.description,
                        "via_hazard": hazard.hazard_id,
                    }
                )
    return related_loss_meanings
