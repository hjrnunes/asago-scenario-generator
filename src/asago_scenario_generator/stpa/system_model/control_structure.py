"""Stage 2 — Control Structure derivation.

Four sequential LLM calls:
  Call 1  — Requirements
  Call 2a — Responsibilities + Responsibility Constraints + Process Model parts
  Call 2b — Control Actions + Feedback Channels + Controlled Processes
  Call 3  — Coordination links + integrity findings
"""

from __future__ import annotations

import copy
import json
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field, StrictStr, create_model

from asago_scenario_generator.models.capability_profile import (
    ZONE_DISPLAY_NAMES,
    CapabilityProfile,
    build_kc_subcodes_display,
)
from asago_scenario_generator.stpa.infra.llm import LLMClient
from asago_scenario_generator.stpa.infra.llm_helpers import (
    StageError,
    _decode_llm_content,
    log_llm_call_failure,
    safe_llm_call,
)
from asago_scenario_generator.stpa._model_data import raw_model_data
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.infra.yaml_io import write_yaml
from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlActionEffectKind,
    ControlActionTemporality,
    ControlStructure,
    CoordinationLink,
    ControlledProcess,
    ElementRef,
    FeedbackChannel,
    ReferenceType,
    Responsibility,
    check_structural_heuristics,
    _is_valid_element_ref,
    normalize_control_action_effect_kind,
)
from asago_scenario_generator.stpa.models.loss_analysis import (
    LossAnalysis,
    compose_constraint_description,
)
from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.system_model.id_normalization import (
    normalize_control_structure_payload,
    validate_normalized_control_structure,
)
from asago_scenario_generator.stpa.system_model.semantic_review import (
    ActionEffectReview,
    ConstraintHazardReview,
    ControlStructureSemanticReview,
    HazardSemanticReview,
    ResponsibilityReview,
    SourceEvidence,
    apply_control_structure_semantic_review,
)

STAGE = "stage_2"
STAGE_2_CALL_COUNT = 4
JSON_DECODE_RETRIES = 1
DEFAULT_TEMPERATURE = 0.4
_INTERMEDIATE_VALIDATION_RETRY_FEEDBACK = (
    "\n\nThe prior response was semantically empty or invalid. Return a concise "
    "schema-matching response and populate every required collection. In "
    "particular, requirements and responsibilities must contain at least one "
    "item when the requested schema includes them. Repair the reported defect "
    "without redesigning valid records: preserve established use-case functions, "
    "descriptions, identities and governing constraint links unless that defect "
    "requires changing them. A collection-name or extra-field repair must not "
    "replace a functional responsibility with only its safeguard."
)


@dataclass(frozen=True)
class ControlStructureDerivationResult:
    """Named Stage 2 result carrying the reviewed upstream loss graph."""

    loss_analysis: LossAnalysis
    control_structure: ControlStructure
    warnings: list[str] = field(default_factory=list)


def _assembly_source_id_maps(
    responsibility_set: ResponsibilitySet,
    control_element_set: ControlElementSet,
) -> dict[str, dict[str, str]]:
    """Capture source-ID maps before the assembled structure is canonicalized."""
    raw_payload = {
        "responsibilities": [
            raw_model_data(resp) for resp in responsibility_set.responsibilities
        ],
        "controlled_processes": [
            raw_model_data(process)
            for process in control_element_set.controlled_processes
        ],
        "coordination_links": [],
    }
    return normalize_control_structure_payload(raw_payload).mappings


# ---------------------------------------------------------------------------
# Internal models
# ---------------------------------------------------------------------------


class Requirement(BaseModel):
    """A solution-neutral requirement derived from a security constraint."""

    req_id: str  # REQ-1, REQ-2, ...
    description: str
    classification: Literal["control", "constraint"]
    source_constraint: str  # SC-* ref


class RequirementSet(BaseModel):
    """A non-empty set of requirements derived from security constraints."""

    requirements: list[Requirement] = Field(min_length=1)


class ResponsibilitySet(BaseModel):
    """Call 2a output: one or more responsibilities with RCs and PM parts.

    No control actions, feedback channels, or controlled processes —
    those are derived in Call 2b.
    """

    model_config = ConfigDict(extra="forbid")

    responsibilities: list[Responsibility] = Field(min_length=1)


class ControlElementSet(BaseModel):
    """Call 2b output: control actions, feedback channels, and controlled processes."""

    # This is an internal response envelope, not the durable control-structure
    # model.  The provider-facing contract calls this collection ``feedback``
    # (the canonical domain attribute remains ``feedback_channels``), while
    # accepting the historical name on input for compatibility with existing
    # fixtures and callers.
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    control_actions: list[ControlAction] = []
    feedback_channels: list[FeedbackChannel] = Field(
        default_factory=list,
        validation_alias="feedback",
    )
    controlled_processes: list[ControlledProcess] = []


class _ResponsibilityTarget(ElementRef):
    type: Literal[ReferenceType.responsibility]


class _ProcessTarget(ElementRef):
    type: Literal[ReferenceType.controlled_process]


class _ResponsibilityAction(ControlAction):
    """Internal controller messages cannot claim external observable effects."""

    target: _ResponsibilityTarget
    effect_kind: Literal[ControlActionEffectKind.agent_message]
    temporality: ControlActionTemporality


class _ProcessAction(ControlAction):
    """An external effect must name its controlled process, not a controller."""

    target: _ProcessTarget
    effect_kind: ControlActionEffectKind
    temporality: ControlActionTemporality


class _ControlElementProviderSet(ControlElementSet):
    """Constrain provider choices without changing legacy domain readers.

    The parser still owns identity and semantic validation. This union exposes
    the existing target/effect invariant to constrained generation instead of
    permitting combinations that can only fail after the model responds.
    """

    control_actions: list[_ResponsibilityAction | _ProcessAction]


class CoordinationAnalysis(BaseModel):
    """Call 3 output: coordination links and integrity findings."""

    coordination_links: list[CoordinationLink] = []
    integrity_findings: list[str] = []
    semantic_review: ControlStructureSemanticReview | None = None


class _CoordinationProviderEnvelope(BaseModel):
    """Current Call 3 wire, excluding deterministic integrity bookkeeping."""

    model_config = ConfigDict(extra="forbid")

    coordination_links: list[CoordinationLink] = Field(default_factory=list)


@dataclass(frozen=True)
class _Call3SourceExcerpt:
    """One exact source slice offered to the Call 3 provider."""

    local_ref: str
    canonical_ref: str
    text: str
    meaning: str


class _ProviderSourceSelection(BaseModel):
    """Call 3 wire evidence: select a displayed excerpt, do not transcribe it."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_ref: StrictStr
    meaning: StrictStr = Field(min_length=1)


def _build_call3_source_excerpts(
    use_case_text: str,
    loss_analysis: LossAnalysis,
) -> tuple[_Call3SourceExcerpt, ...]:
    """Build stable local handles for exact use-case and loss source text."""
    excerpts: list[_Call3SourceExcerpt] = []
    next_ref = 1
    for paragraph in re.split(r"\n\s*\n", use_case_text):
        paragraph = paragraph.strip()
        if not paragraph:
            continue
        excerpts.append(
            _Call3SourceExcerpt(
                local_ref=f"source_{next_ref}",
                canonical_ref="USE_CASE",
                text=paragraph,
                meaning=(
                    "Exact supplied USE_CASE text; use it to explain the decision "
                    "without adding unstated facts."
                ),
            )
        )
        next_ref += 1
    for loss in loss_analysis.risk_card_losses + loss_analysis.use_case_losses:
        excerpts.append(
            _Call3SourceExcerpt(
                local_ref=f"source_{next_ref}",
                canonical_ref=loss.loss_id,
                text=loss.description,
                meaning=(
                    f"Exact supplied description for loss {loss.loss_id}; use it "
                    "only for the supplied loss meaning."
                ),
            )
        )
        next_ref += 1
    return tuple(excerpts)


def _call3_source_ref_map(
    excerpts: Sequence[_Call3SourceExcerpt],
) -> dict[str, _Call3SourceExcerpt]:
    """Index offered local source handles without normalizing their text."""
    return {excerpt.local_ref: excerpt for excerpt in excerpts}


def _validate_call3_review_collections(
    review: dict[str, Any],
    structure: ControlStructure,
    loss_analysis: LossAnalysis,
) -> set[str]:
    """Validate raw review identities before applying unresolved closure."""
    expected_collections = {
        "hazards": (
            "hazard_id",
            {hazard.hazard_id for hazard in loss_analysis.hazards},
        ),
        "constraints": (
            "constraint_id",
            {
                constraint.constraint_id
                for constraint in loss_analysis.security_constraints
            },
        ),
        "responsibilities": (
            "responsibility_id",
            {responsibility.resp_id for responsibility in structure.responsibilities},
        ),
        "actions": (
            "control_action_id",
            {
                action.ca_id
                for responsibility in structure.responsibilities
                for action in responsibility.control_actions
            },
        ),
    }
    rows_by_collection: dict[str, list[dict[str, Any]]] = {}
    for collection_name, (identity_field, expected_ids) in expected_collections.items():
        rows = review.get(collection_name)
        if not isinstance(rows, (list, tuple)):
            raise ValueError(f"semantic_review.{collection_name} must be a collection")
        normalized_rows: list[dict[str, Any]] = []
        identities: list[Any] = []
        for index, row in enumerate(rows):
            if not isinstance(row, dict):
                raise ValueError(
                    f"semantic_review.{collection_name}[{index}] must be an object"
                )
            identity = row.get(identity_field)
            if identity not in expected_ids:
                raise ValueError(
                    f"semantic_review.{collection_name} contains unknown "
                    f"{identity_field} {identity!r}"
                )
            identities.append(identity)
            normalized_rows.append(row)
        if len(identities) != len(expected_ids) or set(identities) != expected_ids:
            raise ValueError(
                f"semantic_review must cover each {identity_field} exactly once"
            )
        review[collection_name] = normalized_rows
        rows_by_collection[collection_name] = normalized_rows

    constraint_ids = expected_collections["constraints"][1]
    hazard_ids = expected_collections["hazards"][1]
    for index, row in enumerate(rows_by_collection["constraints"]):
        related_hazards = row.get("related_hazards")
        if not isinstance(related_hazards, (list, tuple)):
            raise ValueError(
                "semantic_review.constraints[{}].related_hazards must be a "
                "collection".format(index)
            )
        unknown_hazards = set(related_hazards) - hazard_ids
        if unknown_hazards:
            raise ValueError(
                "semantic_review.constraints contains unknown hazard reference(s): "
                + ", ".join(sorted(str(item) for item in unknown_hazards))
            )
    for index, row in enumerate(rows_by_collection["responsibilities"]):
        constraint_refs = row.get("constraint_refs")
        if not isinstance(constraint_refs, (list, tuple)):
            raise ValueError(
                "semantic_review.responsibilities[{}].constraint_refs must be a "
                "collection".format(index)
            )
        unknown_constraints = set(constraint_refs) - constraint_ids
        if unknown_constraints:
            raise ValueError(
                "semantic_review.responsibilities contains unknown constraint "
                "reference(s): "
                + ", ".join(sorted(str(item) for item in unknown_constraints))
            )

    return {
        row["constraint_id"]
        for row in rows_by_collection["constraints"]
        if row.get("disposition") == "unresolved"
    }


def _exact_review_rows(record_type, identity_field, identities):
    """Constrain provider choices/counts; semantic validation checks uniqueness."""
    row_type = record_type
    if identities:
        row_type = create_model(
            f"Provider{record_type.__name__}",
            __base__=record_type,
            **{identity_field: (Literal[tuple(identities)], ...)},
        )
    return (
        tuple[row_type, ...],
        Field(min_length=len(identities), max_length=len(identities)),
    )


def _coordination_provider_schema(
    structure: ControlStructure,
    loss_analysis: LossAnalysis | None = None,
    *,
    use_case_text: str = "",
    source_excerpts: Sequence[_Call3SourceExcerpt] | None = None,
):
    """Require the same complete review that the Call 3 consumer validates."""
    constraint_ids = (
        [sc.constraint_id for sc in loss_analysis.security_constraints]
        if loss_analysis is not None
        else []
    )
    hazard_ids = (
        [hazard.hazard_id for hazard in loss_analysis.hazards]
        if loss_analysis is not None
        else []
    )
    evidence_type = SourceEvidence
    if loss_analysis is not None:
        excerpts = tuple(
            source_excerpts
            if source_excerpts is not None
            else _build_call3_source_excerpts(use_case_text, loss_analysis)
        )
        source_refs = tuple(excerpt.local_ref for excerpt in excerpts)
        if not source_refs:
            # Literal[()] is not a useful provider contract.  The parser still
            # fails closed if evidence is selected without an actual excerpt.
            source_refs = ("source_1",)
        evidence_type = create_model(
            "ProviderSourceEvidence",
            __base__=_ProviderSourceSelection,
            source_ref=(Literal[tuple(source_refs)], ...),
        )

    def evidence_field():
        return (
            tuple[evidence_type, ...],
            Field(min_length=0),
        )

    constraint_rows = _exact_review_rows(
        ConstraintHazardReview,
        "constraint_id",
        constraint_ids,
    )
    if loss_analysis is not None:
        constraint_row_type = create_model(
            "ProviderConstraintHazardReview",
            __base__=ConstraintHazardReview,
            constraint_id=(Literal[tuple(constraint_ids)], ...),
            source_evidence=evidence_field(),
            related_hazards=(
                tuple[Literal[tuple(hazard_ids)], ...],
                Field(
                    min_length=0,
                    max_length=len(hazard_ids),
                ),
            ),
        )
        constraint_rows = (
            tuple[constraint_row_type, ...],
            Field(
                min_length=len(constraint_ids),
                max_length=len(constraint_ids),
            ),
        )
        hazard_row_type = create_model(
            "ProviderHazardSemanticReview",
            __base__=HazardSemanticReview,
            hazard_id=(Literal[tuple(hazard_ids)], ...),
            source_evidence=evidence_field(),
        )
        hazard_rows = (
            tuple[hazard_row_type, ...],
            Field(min_length=len(hazard_ids), max_length=len(hazard_ids)),
        )
    else:
        hazard_rows = _exact_review_rows(HazardSemanticReview, "hazard_id", hazard_ids)
    review_type = create_model(
        "ProviderControlStructureSemanticReview",
        __base__=ControlStructureSemanticReview,
        hazards=hazard_rows,
        constraints=constraint_rows,
        responsibilities=_exact_review_rows(
            ResponsibilityReview,
            "responsibility_id",
            [resp.resp_id for resp in structure.responsibilities],
        ),
        actions=_exact_review_rows(
            ActionEffectReview,
            "control_action_id",
            [
                action.ca_id
                for resp in structure.responsibilities
                for action in resp.control_actions
            ],
        ),
    )
    return create_model(
        "ProviderCoordinationAnalysis",
        __base__=_CoordinationProviderEnvelope,
        semantic_review=(review_type, ...),
    )


def _parse_call3_source_selection(
    result: Any,
    source_excerpts: Sequence[_Call3SourceExcerpt],
    *,
    structure: ControlStructure | None = None,
    loss_analysis: LossAnalysis | None = None,
) -> CoordinationAnalysis:
    """Map provider-local source selections to immutable final evidence."""
    payload = _decode_llm_content(result)
    if not isinstance(payload, dict):
        raise ValueError("Call 3 response must be one JSON object")
    unexpected = set(payload) - {"coordination_links", "semantic_review"}
    if unexpected:
        raise ValueError(
            "Call 3 response contains code-owned or unknown fields: "
            + ", ".join(sorted(unexpected))
        )
    payload = copy.deepcopy(payload)
    review = payload.get("semantic_review")
    if not isinstance(review, dict):
        return CoordinationAnalysis.model_validate(payload)

    unresolved_constraint_ids: set[str] = set()
    if structure is not None or loss_analysis is not None:
        if structure is None or loss_analysis is None:
            raise ValueError(
                "Call 3 parser requires both structure and loss_analysis authorities"
            )
        unresolved_constraint_ids = _validate_call3_review_collections(
            review,
            structure,
            loss_analysis,
        )
        # Phase 1.3 as amended: Call 3 displays the authored rule with the
        # composed conditions shown separately, so an unchanged echo of
        # either the rule or the full composed statement means "preserve".
        original_descriptions = {
            "hazards": {
                hazard.hazard_id: hazard.description for hazard in loss_analysis.hazards
            },
            "constraints": {
                constraint.constraint_id: compose_constraint_description(
                    constraint.rule, constraint.applies_when
                )
                for constraint in loss_analysis.security_constraints
            },
            "constraint_rules": {
                constraint.constraint_id: constraint.rule
                for constraint in loss_analysis.security_constraints
            },
        }
        identity_fields = {
            "hazards": "hazard_id",
            "constraints": "constraint_id",
        }
        for collection_name, identity_field in identity_fields.items():
            for row in review[collection_name]:
                revised_description = row.get("revised_description")
                original_description = original_descriptions[collection_name][
                    row[identity_field]
                ]
                unchanged_values = {original_description.strip()}
                if collection_name == "constraints":
                    unchanged_values.add(
                        original_descriptions["constraint_rules"][
                            row[identity_field]
                        ].strip()
                    )
                if (
                    row.get("disposition") == "revise"
                    and row.get("missing_fact") is None
                    and isinstance(revised_description, str)
                    and revised_description.strip() in unchanged_values
                ):
                    row["disposition"] = "preserve"
                    row["revised_description"] = None
        for row in review["constraints"]:
            if row["constraint_id"] in unresolved_constraint_ids:
                row["related_hazards"] = []
        for row in review["responsibilities"]:
            row["constraint_refs"] = [
                constraint_id
                for constraint_id in row["constraint_refs"]
                if constraint_id not in unresolved_constraint_ids
            ]

    excerpts = _call3_source_ref_map(source_excerpts)
    for collection_name in ("hazards", "constraints"):
        rows = review.get(collection_name)
        if not isinstance(rows, (list, tuple)):
            continue
        rows = list(rows)
        review[collection_name] = rows
        for row_index, row in enumerate(rows):
            if not isinstance(row, dict):
                continue
            evidence = row.get("source_evidence")
            if not isinstance(evidence, (list, tuple)):
                continue
            normalized: list[dict[str, Any]] = []
            for evidence_index, item in enumerate(evidence):
                if not isinstance(item, dict):
                    normalized.append(item)
                    continue
                unexpected = set(item) - {"source_ref", "meaning"}
                if unexpected:
                    names = ", ".join(sorted(str(name) for name in unexpected))
                    raise ValueError(
                        "Call 3 source_evidence must select source_ref and meaning "
                        f"only at {collection_name}[{row_index}].source_evidence["
                        f"{evidence_index}]; unexpected field(s): {names}"
                    )
                local_ref = item.get("source_ref")
                excerpt = excerpts.get(local_ref)
                if excerpt is None:
                    raise ValueError(
                        "Call 3 source_evidence source_ref must select one of the "
                        f"displayed local excerpts; got {local_ref!r}"
                    )
                normalized.append(
                    {
                        "source_ref": excerpt.canonical_ref,
                        "quote": excerpt.text,
                        "meaning": item.get("meaning"),
                    }
                )
            row["source_evidence"] = normalized
    return CoordinationAnalysis.model_validate(payload)


def _validate_stage2_intermediate(model: BaseModel) -> None:
    """Reject semantically empty Stage 2 inputs after tolerant decoding.

    Calls 2a and 2b use tolerant decoding so malformed nested references can
    be repaired deterministically. That path intentionally bypasses Pydantic
    validators, including ``Field(min_length=1)``. Keep the semantic
    cardinality checks at the shared LLM boundary so an empty set cannot reach
    control-structure assembly while preserving tolerant nested decoding.
    """
    if isinstance(model, RequirementSet) and not model.requirements:
        raise ValueError("requirements must contain at least one item")
    if isinstance(model, ResponsibilitySet) and not model.responsibilities:
        raise ValueError("responsibilities must contain at least one item")


def _validate_responsibility_payload(value: Any) -> None:
    """Reject Call 2a fields tolerant decoding would silently discard.

    Call 2a deliberately retains tolerant ID normalization for malformed
    nested IDs, but its top-level collection and security-trace fields are
    normative. Validate those raw fields before the tolerant parser can drop
    unknown responsibility collections or omitted constraint references.
    """
    if not isinstance(value, dict):
        return
    unexpected = set(value) - {"responsibilities"}
    if unexpected:
        names = ", ".join(sorted(str(item) for item in unexpected))
        raise ValueError(f"unexpected responsibility collection(s): {names}")
    responsibilities = value.get("responsibilities")
    if not isinstance(responsibilities, list):
        return
    allowed_fields = {
        "resp_id",
        "id",
        "description",
        "responsibility_constraints",
        "security_constraint_refs",
        "process_model_parts",
    }
    for index, responsibility in enumerate(responsibilities):
        if not isinstance(responsibility, dict):
            continue
        unexpected_fields = set(responsibility) - allowed_fields
        if unexpected_fields:
            names = ", ".join(sorted(str(item) for item in unexpected_fields))
            raise ValueError(
                f"unexpected responsibility collection field(s) at index {index}: "
                f"{names}"
            )
        if "security_constraint_refs" not in responsibility:
            raise ValueError(
                f"responsibility is missing security_constraint_refs at index {index}"
            )
        if not isinstance(responsibility["security_constraint_refs"], list):
            raise ValueError(
                f"security_constraint_refs must be a list at index {index}"
            )


# ---------------------------------------------------------------------------
# Stage-local Call 2b response contract
# ---------------------------------------------------------------------------


_CONTROL_ELEMENT_TOP_LEVEL_FIELDS = {
    "control_actions",
    "feedback",
    "feedback_channels",  # historical input spelling; normalized below
    "controlled_processes",
}
_CONTROL_ACTION_FIELDS = {
    "ca_id",
    "description",
    "target",
    "effect_kind",
    "temporality",
    # Accept this descriptive spelling on input while serializing the
    # canonical ``temporality`` field.  It keeps hand-authored legacy/live
    # payloads readable without adding a second durable field.
    "action_temporality",
}
_FEEDBACK_FIELDS = {"fb_id", "description", "updates", "source"}
_CONTROLLED_PROCESS_FIELDS = {"cp_id", "description"}
_ELEMENT_REF_FIELDS = {"type", "id"}


def _decode_control_element_payload(value: Any) -> dict[str, Any]:
    """Decode one Call 2b response without applying tolerant field defaults."""
    if isinstance(value, BaseModel):
        value = raw_model_data(value)
    elif isinstance(value, str):
        text = value.strip()
        lines = text.splitlines()
        if (
            len(lines) >= 3
            and lines[0].strip().lower() in {"```json", "```"}
            and lines[-1].strip() == "```"
        ):
            text = "\n".join(lines[1:-1])
        value = json.loads(text)
    if not isinstance(value, dict):
        raise ValueError(
            "Call 2b response must be one JSON object containing control_actions, "
            "feedback, and controlled_processes"
        )
    return raw_model_data(value)


def _require_stage2_string(
    value: Any,
    *,
    field_name: str,
    item_label: str,
) -> str:
    """Require a semantic string while preserving the supplied text exactly."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{item_label} requires a non-empty {field_name}")
    return value


def _reject_unexpected_fields(
    item: dict[str, Any],
    *,
    allowed: set[str],
    item_label: str,
) -> None:
    """Reject unknown fields before Pydantic's permissive nested models see them."""
    unexpected = set(item) - allowed
    if not unexpected:
        return
    names = ", ".join(sorted(str(name) for name in unexpected))
    if "action" in unexpected:
        raise ValueError(
            f"{item_label} uses combined action field 'action'; return separate "
            "ca_id and description fields"
        )
    raise ValueError(f"{item_label} contains unexpected semantic field(s): {names}")


def _validate_stage2_element_id(
    value: Any,
    *,
    prefix: str,
    item_label: str,
) -> str:
    """Validate an ID carries an explicit, recoverable responsibility owner."""
    identifier = _require_stage2_string(
        value,
        field_name=f"{prefix.lower()}_id",
        item_label=item_label,
    )
    # Canonical IDs are CA-X-Y/FB-X-Y.  A one-suffix CA-X or FB-X is accepted
    # only as a narrowly recoverable source ID: its numeric prefix still
    # states the owner unambiguously and canonicalization can supply Y.  An
    # arbitrary value such as ``first-action`` has no ownership information
    # and must not be distributed by response-array order.
    if not re.fullmatch(rf"{prefix}-\d+(?:-\d+)?", identifier):
        raise ValueError(
            f"{item_label} {prefix.lower()}_id must encode an explicit owner "
            f"using {prefix}-X-Y; got {identifier!r}"
        )
    return identifier


def _owner_number(identifier: str, *, prefix: str) -> int:
    """Return the responsibility number encoded by one CA/FB ID."""
    match = re.fullmatch(rf"{prefix}-(\d+)(?:-\d+)?", identifier)
    if match is None:  # pragma: no cover - guarded by _validate_stage2_element_id
        raise ValueError(f"{prefix} ID does not encode an owner: {identifier!r}")
    return int(match.group(1))


def _stage2_element_ref(value: Any, *, field_name: str, item_label: str) -> ElementRef:
    """Parse one explicit control-structure element reference."""
    if isinstance(value, str):
        identifier = _require_stage2_string(
            value,
            field_name=field_name,
            item_label=item_label,
        )
        if re.fullmatch(r"RESP-\d+", identifier):
            reference_type = ReferenceType.responsibility
        elif re.fullmatch(r"CP-\d+", identifier):
            reference_type = ReferenceType.controlled_process
        else:
            raise ValueError(
                f"{item_label} {field_name} must name RESP-N or CP-N; "
                f"got {identifier!r}"
            )
        return ElementRef(type=reference_type, id=identifier)
    if not isinstance(value, dict):
        raise ValueError(f"{item_label} {field_name} must be an ID or object")
    _reject_unexpected_fields(
        value,
        allowed=_ELEMENT_REF_FIELDS,
        item_label=f"{item_label} {field_name}",
    )
    if "type" not in value or "id" not in value:
        raise ValueError(f"{item_label} {field_name} requires type and id")
    try:
        return ElementRef.model_validate(value)
    except Exception as exc:
        raise ValueError(f"{item_label} has invalid {field_name}: {exc}") from exc


def _stage2_optional_enum(
    value: Any,
    *,
    enum_type: type[ControlActionEffectKind] | type[ControlActionTemporality],
    field_name: str,
    item_label: str,
) -> ControlActionEffectKind | ControlActionTemporality | None:
    """Parse an optional typed Stage 2 action field without tolerant coercion."""
    if value is None:
        return None
    try:
        return enum_type(value)
    except (TypeError, ValueError) as exc:
        allowed = ", ".join(item.value for item in enum_type)
        raise ValueError(
            f"{item_label} {field_name} must be one of: {allowed}; got {value!r}"
        ) from exc


def _stage2_control_action(
    value: Any,
    *,
    index: int,
    owner_numbers: set[int] | None,
) -> ControlAction:
    """Parse one semantic control action for the Call 2b wire contract."""
    item_label = f"control_actions[{index}]"
    if not isinstance(value, dict):
        raise ValueError(f"{item_label} must be an object")
    _reject_unexpected_fields(
        value,
        allowed=_CONTROL_ACTION_FIELDS,
        item_label=item_label,
    )
    if "ca_id" not in value:
        raise ValueError(f"{item_label} is missing ca_id")
    if "description" not in value:
        raise ValueError(f"{item_label} is missing description")
    if "target" not in value or value["target"] is None:
        raise ValueError(f"{item_label} is missing target")
    ca_id = _validate_stage2_element_id(
        value["ca_id"], prefix="CA", item_label=item_label
    )
    if (
        owner_numbers is not None
        and _owner_number(ca_id, prefix="CA") not in owner_numbers
    ):
        raise ValueError(
            f"{item_label} {ca_id!r} has no matching responsibility owner; "
            "ownership cannot be recovered from array order"
        )
    description = _require_stage2_string(
        value["description"], field_name="description", item_label=item_label
    )
    normalized_description = " ".join(description.split()).lower()
    normalized_id = " ".join(ca_id.split()).lower()
    if normalized_description in {normalized_id, f"control action {normalized_id}"}:
        raise ValueError(
            f"{item_label} description must be meaningful, not a generated placeholder"
        )
    target = _stage2_element_ref(
        value["target"], field_name="target", item_label=item_label
    )
    if "temporality" in value and "action_temporality" in value:
        if value["temporality"] != value["action_temporality"]:
            raise ValueError(
                f"{item_label} must provide one matching temporality field, not "
                "conflicting temporality and action_temporality values"
            )
    effect_kind = _stage2_optional_enum(
        value.get("effect_kind"),
        enum_type=ControlActionEffectKind,
        field_name="effect_kind",
        item_label=item_label,
    )
    temporality = _stage2_optional_enum(
        value.get("temporality", value.get("action_temporality")),
        enum_type=ControlActionTemporality,
        field_name="temporality",
        item_label=item_label,
    )
    effect_kind = normalize_control_action_effect_kind(target, effect_kind)
    return ControlAction.model_construct(
        ca_id=ca_id,
        description=description,
        target=target,
        effect_kind=effect_kind,
        temporality=temporality,
    )


def _stage2_feedback_channel(
    value: Any,
    *,
    index: int,
    owner_numbers: set[int] | None,
) -> FeedbackChannel:
    """Parse one semantic feedback channel for the Call 2b wire contract."""
    item_label = f"feedback[{index}]"
    if not isinstance(value, dict):
        raise ValueError(f"{item_label} must be an object")
    _reject_unexpected_fields(value, allowed=_FEEDBACK_FIELDS, item_label=item_label)
    for field_name in ("fb_id", "description", "updates", "source"):
        if field_name not in value:
            raise ValueError(f"{item_label} is missing {field_name}")
    fb_id = _validate_stage2_element_id(
        value["fb_id"], prefix="FB", item_label=item_label
    )
    if (
        owner_numbers is not None
        and _owner_number(fb_id, prefix="FB") not in owner_numbers
    ):
        raise ValueError(
            f"{item_label} {fb_id!r} has no matching responsibility owner; "
            "ownership cannot be recovered from array order"
        )
    description = _require_stage2_string(
        value["description"], field_name="description", item_label=item_label
    )
    updates = _require_stage2_string(
        value["updates"], field_name="updates", item_label=item_label
    )
    if value["source"] is None:
        raise ValueError(f"{item_label} requires a non-null source")
    source = _stage2_element_ref(
        value["source"], field_name="source", item_label=item_label
    )
    return FeedbackChannel.model_construct(
        fb_id=fb_id,
        description=description,
        updates=updates,
        source=source,
    )


def _stage2_controlled_process(value: Any, *, index: int) -> ControlledProcess:
    """Parse one controlled process for the Call 2b wire contract."""
    item_label = f"controlled_processes[{index}]"
    if not isinstance(value, dict):
        raise ValueError(f"{item_label} must be an object")
    _reject_unexpected_fields(
        value,
        allowed=_CONTROLLED_PROCESS_FIELDS,
        item_label=item_label,
    )
    for field_name in ("cp_id", "description"):
        if field_name not in value:
            raise ValueError(f"{item_label} is missing {field_name}")
    cp_id = _validate_stage2_element_id(
        value["cp_id"], prefix="CP", item_label=item_label
    )
    description = _require_stage2_string(
        value["description"], field_name="description", item_label=item_label
    )
    return ControlledProcess.model_construct(cp_id=cp_id, description=description)


def parse_control_element_set_response(
    value: Any,
    *,
    responsibilities: Sequence[Responsibility] | None = None,
) -> ControlElementSet:
    """Strictly parse a Call 2b response while preserving semantic content.

    The ordinary ``stpa.infra.unvalidated_decode`` helper is deliberately not
    used here.  This response is semantic model output: every carrier field is
    checked, descriptions cannot be empty or generated placeholders, and CA/FB
    IDs must carry an explicit responsibility owner.  Source IDs may still be
    canonicalized later by ``id_normalization`` when their owner is explicit.

    ``feedback`` is the normative provider-facing collection name.  The
    historical ``feedback_channels`` spelling is accepted only as an input
    compatibility alias and never silently merged when both are supplied.
    """
    payload = _decode_control_element_payload(value)
    _reject_unexpected_fields(
        payload,
        allowed=_CONTROL_ELEMENT_TOP_LEVEL_FIELDS,
        item_label="Call 2b response",
    )
    required_top_level = {"control_actions", "controlled_processes"}
    missing_top_level = required_top_level - set(payload)
    if "feedback" not in payload and "feedback_channels" not in payload:
        missing_top_level.add("feedback")
    if missing_top_level:
        names = ", ".join(sorted(missing_top_level))
        raise ValueError(
            f"Call 2b response is missing top-level collection(s): {names}"
        )
    if "feedback" in payload and "feedback_channels" in payload:
        raise ValueError(
            "Call 2b response must use one feedback collection, not both feedback "
            "and feedback_channels"
        )
    for collection_name in ("control_actions", "controlled_processes"):
        if not isinstance(payload[collection_name], list):
            raise ValueError(f"{collection_name} must be a list")
    feedback_key = "feedback" if "feedback" in payload else "feedback_channels"
    if not isinstance(payload[feedback_key], list):
        raise ValueError(f"{feedback_key} must be a list")
    if not payload["control_actions"]:
        raise ValueError("control_actions must contain at least one action")
    if not payload[feedback_key]:
        raise ValueError(f"{feedback_key} must contain at least one feedback channel")

    owner_numbers: set[int] | None = None
    if responsibilities is not None:
        owner_numbers = set()
        for responsibility in responsibilities:
            match = re.fullmatch(r"RESP-(\d+)", responsibility.resp_id)
            if match is None:
                raise ValueError(
                    f"responsibility {responsibility.resp_id!r} has no numeric owner identity"
                )
            number = int(match.group(1))
            if number in owner_numbers:
                raise ValueError(
                    f"responsibilities contain ambiguous numeric owner {number}"
                )
            owner_numbers.add(number)

    actions = [
        _stage2_control_action(
            item,
            index=index,
            owner_numbers=owner_numbers,
        )
        for index, item in enumerate(payload["control_actions"])
    ]
    feedback_channels = [
        _stage2_feedback_channel(
            item,
            index=index,
            owner_numbers=owner_numbers,
        )
        for index, item in enumerate(payload[feedback_key])
    ]
    controlled_processes = [
        _stage2_controlled_process(item, index=index)
        for index, item in enumerate(payload["controlled_processes"])
    ]
    if responsibilities is not None:
        responsibility_ids = {resp.resp_id for resp in responsibilities}
        controlled_process_ids = {process.cp_id for process in controlled_processes}
        known_pm_ids = {
            pm.pm_id
            for responsibility in responsibilities
            for pm in responsibility.process_model_parts
        }
        action_owners = {_owner_number(action.ca_id, prefix="CA") for action in actions}
        missing_action_owners = owner_numbers - action_owners
        if missing_action_owners:
            raise ValueError(
                "every responsibility requires a control action; missing owners: "
                + ", ".join(
                    f"RESP-{number}" for number in sorted(missing_action_owners)
                )
            )
        updated_pm_ids = {channel.updates for channel in feedback_channels}
        missing_pm_ids = known_pm_ids - updated_pm_ids
        if missing_pm_ids:
            raise ValueError(
                "every process model part requires feedback updates; missing: "
                + ", ".join(sorted(missing_pm_ids))
            )
        for collection_name, elements, ref_field in (
            ("control action", actions, "target"),
            ("feedback channel", feedback_channels, "source"),
        ):
            for index, element in enumerate(elements):
                ref = getattr(element, ref_field)
                if ref is None:  # pragma: no cover - required above
                    raise ValueError(
                        f"{collection_name}[{index}] is missing {ref_field}"
                    )
                if ref.type.value == "responsibility":
                    known = ref.id in responsibility_ids
                else:
                    known = ref.id in controlled_process_ids
                if not known:
                    raise ValueError(
                        f"{collection_name}[{index}] {ref_field} reference "
                        f"{ref.id!r} is not present in the supplied structure"
                    )
        for index, channel in enumerate(feedback_channels):
            if channel.updates not in known_pm_ids:
                raise ValueError(
                    f"feedback[{index}] updates unknown process model part "
                    f"{channel.updates!r}"
                )

    return ControlElementSet.model_construct(
        control_actions=actions,
        feedback_channels=feedback_channels,
        controlled_processes=controlled_processes,
    )


# ---------------------------------------------------------------------------
# Assembly — merge Call 2a (ResponsibilitySet) with Call 2b (ControlElementSet)
# ---------------------------------------------------------------------------


def _extract_resp_num(element_id: str) -> int:
    """Extract the numeric suffix from a resp_id or element ID like 'RESP-3' or 'CA-3-1'."""
    match = re.search(r"\d+", element_id)
    return int(match.group()) if match else 0


def _assign_elements_to_responsibilities(
    elements: list,
    id_attr: str,
    resp_by_num: dict[int, Responsibility],
    target_attr: str,
    *,
    return_unmatched: bool = False,
) -> list | None:
    """Assign elements (CAs or FBs) to their parent responsibility by ID prefix.

    For each element, extracts the numeric prefix from its ``id_attr``
    (e.g. ``CA-3-1`` → 3) and appends it to the matching responsibility's
    ``target_attr`` list. Elements with no matching responsibility are
    silently dropped, matching the original assembly behavior.
    """
    unmatched = []
    for element in elements:
        resp = resp_by_num.get(_extract_resp_num(getattr(element, id_attr)))
        if resp is not None:
            getattr(resp, target_attr).append(element)
        else:
            unmatched.append(element)
    return unmatched if return_unmatched else None


def _enrich_responsibilities(
    responsibility_set: ResponsibilitySet,
    control_element_set: ControlElementSet,
    *,
    normalize_ids: bool = False,
) -> list[Responsibility]:
    """Deep-copy responsibilities and assign Call 2b CAs/FBs onto them by ID prefix.

    Returns a deep-copied list of the Call 2a responsibilities with the
    Call 2b ``control_actions`` and ``feedback_channels`` appended to the
    matching responsibility by ID prefix (CA-X-Y → RESP-X, FB-X-Y → RESP-X).

    ``resp_by_num`` keeps the FIRST occurrence of each responsibility number
    for the compatibility (non-normalizing) path.  The normalizing path
    rejects an unmatched element instead of recovering ownership from the
    response-array order.
    """
    enriched = copy.deepcopy(responsibility_set.responsibilities)
    resp_by_num: dict[int, Responsibility] = {}
    for resp in enriched:
        resp_by_num.setdefault(_extract_resp_num(resp.resp_id), resp)
    unmatched_cas = _assign_elements_to_responsibilities(
        control_element_set.control_actions,
        "ca_id",
        resp_by_num,
        "control_actions",
        return_unmatched=normalize_ids,
    )
    unmatched_fbs = _assign_elements_to_responsibilities(
        control_element_set.feedback_channels,
        "fb_id",
        resp_by_num,
        "feedback_channels",
        return_unmatched=normalize_ids,
    )
    if normalize_ids and (unmatched_cas or unmatched_fbs):
        unmatched_labels = [
            *[f"CA {item.ca_id}" for item in unmatched_cas or []],
            *[f"FB {item.fb_id}" for item in unmatched_fbs or []],
        ]
        raise ValueError(
            "unmatched control-element ownership; cannot distribute by response "
            f"order: {', '.join(unmatched_labels)}"
        )
    return enriched


def _assemble_control_structure(
    responsibility_set: ResponsibilitySet,
    control_element_set: ControlElementSet,
    *,
    normalize_ids: bool = False,
) -> ControlStructure:
    """Merge Call 2a (responsibilities + RCs + PMs) and Call 2b (CAs + FBs + CPs).

    Matches CAs and FBs to responsibilities by ID prefix (CA-X-Y → RESP-X,
    FB-X-Y → RESP-X). Produces and validates the final ControlStructure.
    """
    responsibilities = _enrich_responsibilities(
        responsibility_set,
        control_element_set,
        normalize_ids=normalize_ids,
    )
    controlled_processes = copy.deepcopy(control_element_set.controlled_processes)

    return _build_control_structure(
        responsibilities,
        controlled_processes,
        normalize_ids=normalize_ids,
    )


def _control_structure_payload(
    responsibilities: list[Responsibility],
    controlled_processes: list[ControlledProcess],
) -> dict[str, Any]:
    """Build a dictionary payload from assembled control-structure elements."""
    return {
        "responsibilities": [raw_model_data(resp) for resp in responsibilities],
        "controlled_processes": [
            raw_model_data(process) for process in controlled_processes
        ],
        "coordination_links": [],
    }


def _build_control_structure(
    responsibilities: list[Responsibility],
    controlled_processes: list[ControlledProcess],
    *,
    normalize_ids: bool,
) -> ControlStructure:
    """Construct a control structure, optionally normalizing its IDs."""
    if normalize_ids:
        return validate_normalized_control_structure(
            _control_structure_payload(responsibilities, controlled_processes)
        )
    return ControlStructure(
        responsibilities=responsibilities,
        controlled_processes=controlled_processes,
    )


# ---------------------------------------------------------------------------
# Fallback helpers — deterministic, no LLM dependency
# ---------------------------------------------------------------------------


def _iter_resp_ref_fields(
    resp: Responsibility,
) -> list[tuple[str, str, Any]]:
    """Yield (element_label, field_name, item) for each ElementRef-bearing field.

    Each tuple identifies a single ElementRef slot inside the
    responsibility: the PM feedback_source, CA target, and FB source.
    The caller can ``getattr``/``setattr`` *field_name* on *item* to
    read or nullify the ref.
    """
    return (
        [(f"PM {pm.pm_id}", "feedback_source", pm) for pm in resp.process_model_parts]
        + [(f"CA {ca.ca_id}", "target", ca) for ca in resp.control_actions]
        + [(f"FB {fb.fb_id}", "source", fb) for fb in resp.feedback_channels]
    )


def _nullify_invalid_refs_in_resp(
    resp: Responsibility,
    resp_ids: set[str],
    cp_ids: set[str],
) -> list[str]:
    """Nullify unresolvable ElementRefs in a single responsibility.

    Returns a warning string for each stripped ref.
    """
    warnings: list[str] = []
    for element_label, field_name, item in _iter_resp_ref_fields(resp):
        ref = getattr(item, field_name)
        if ref is not None and not _is_valid_element_ref(ref, resp_ids, cp_ids):
            warnings.append(
                f"Stripped invalid {field_name} from {element_label}: "
                f"{ref.type.value} '{ref.id}' "
                f"not found in responsibilities or controlled processes."
            )
            setattr(item, field_name, None)
    return warnings


def _drop_invalid_feedback_updates(resp: Responsibility) -> list[str]:
    """Drop feedback channels whose required local PM reference is unresolved."""
    pm_ids = {pm.pm_id for pm in resp.process_model_parts}
    valid_channels: list[FeedbackChannel] = []
    warnings: list[str] = []
    for channel in resp.feedback_channels:
        update_id = channel.updates
        if isinstance(update_id, str) and update_id in pm_ids:
            valid_channels.append(channel)
            continue
        warnings.append(
            f"Stripped invalid feedback channel {channel.fb_id}: updates "
            f"'{channel.updates}' does not reference a process model part "
            f"in responsibility {resp.resp_id}."
        )
    resp.feedback_channels = valid_channels
    return warnings


def _sanitize_for_fallback(
    responsibilities: list[Responsibility],
    controlled_processes: list[ControlledProcess],
) -> tuple[list[Responsibility], list[ControlledProcess], list[str]]:
    """Nullify ElementRefs that cannot be resolved against available IDs.

    Iterates deep-copied responsibilities and nullifies any
    ``feedback_source``, ``control_action.target``, or
    ``feedback_channel.source`` whose ElementRef id cannot be resolved
    against the available resp_ids and cp_ids.

    Args:
        responsibilities: Responsibilities from the ResponsibilitySet.
        controlled_processes: Controlled processes from the ControlElementSet.

    Returns:
        A tuple of (sanitized responsibilities, controlled processes,
        warnings). The warnings list contains one entry per stripped
        ElementRef.
    """
    resp_ids = {r.resp_id for r in responsibilities}
    cp_ids = {cp.cp_id for cp in controlled_processes}
    sanitized_resps = copy.deepcopy(responsibilities)
    sanitized_cps = copy.deepcopy(controlled_processes)
    warnings: list[str] = []

    for resp in sanitized_resps:
        warnings.extend(_nullify_invalid_refs_in_resp(resp, resp_ids, cp_ids))
        warnings.extend(_drop_invalid_feedback_updates(resp))

    return sanitized_resps, sanitized_cps, warnings


def _strip_all_refs_in_resp(resp: Responsibility) -> list[str]:
    """Strip ALL ElementRefs from a single responsibility, returning warnings."""
    warnings: list[str] = []
    for element_label, field_name, item in _iter_resp_ref_fields(resp):
        ref = getattr(item, field_name)
        if ref is not None:
            warnings.append(
                f"Further-degraded: stripped {field_name} from {element_label}."
            )
            setattr(item, field_name, None)
    warnings.extend(_drop_invalid_feedback_updates(resp))
    return warnings


def _strip_all_element_refs(
    responsibilities: list[Responsibility],
    controlled_processes: list[ControlledProcess],
) -> tuple[list[Responsibility], list[ControlledProcess], list[str]]:
    """Strip ALL ElementRefs from responsibilities (further-degraded fallback).

    Sets all feedback_source to None, removes all control_action targets,
    and sets all feedback_channel.source to None. Also deduplicates
    responsibilities by resp_id (keeping the first occurrence) so that
    the resulting ControlStructure can pass validation even when the
    original ResponsibilitySet had duplicate IDs.

    Args:
        responsibilities: Responsibilities to strip.
        controlled_processes: Controlled processes (deduplicated by cp_id).

    Returns:
        A tuple of (stripped responsibilities, controlled processes,
        warnings). The warnings list contains one entry per stripped
        ElementRef and per duplicate responsibility.
    """
    stripped_resps: list[Responsibility] = []
    seen_resp_ids: set[str] = set()
    warnings: list[str] = []

    for resp in copy.deepcopy(responsibilities):
        if resp.resp_id in seen_resp_ids:
            warnings.append(
                f"Further-degraded: removed duplicate responsibility {resp.resp_id}."
            )
            continue
        seen_resp_ids.add(resp.resp_id)
        warnings.extend(_strip_all_refs_in_resp(resp))
        stripped_resps.append(resp)

    # Deduplicate controlled processes by cp_id
    stripped_cps: list[ControlledProcess] = []
    seen_cp_ids: set[str] = set()
    for cp in copy.deepcopy(controlled_processes):
        if cp.cp_id not in seen_cp_ids:
            seen_cp_ids.add(cp.cp_id)
            stripped_cps.append(cp)

    return stripped_resps, stripped_cps, warnings


def _fallback_control_structure(
    enriched_responsibilities: list[Responsibility],
    controlled_processes: list[ControlledProcess],
    *,
    normalize_ids: bool,
) -> tuple[ControlStructure, list[str]]:
    """Build the sanitized fallback, degrading to stripped refs if needed."""
    warnings: list[str] = []
    try:
        sanitized_resps, sanitized_cps, sanitize_warnings = _sanitize_for_fallback(
            enriched_responsibilities,
            controlled_processes,
        )
        warnings.extend(sanitize_warnings)
        return (
            _build_control_structure(
                sanitized_resps,
                sanitized_cps,
                normalize_ids=normalize_ids,
            ),
            warnings,
        )
    except Exception:
        stripped_resps, stripped_cps, strip_warnings = _strip_all_element_refs(
            enriched_responsibilities,
            controlled_processes,
        )
        warnings.extend(strip_warnings)
        return (
            _build_control_structure(
                stripped_resps,
                stripped_cps,
                normalize_ids=normalize_ids,
            ),
            warnings,
        )


def _assemble_with_fallback(
    responsibility_set: ResponsibilitySet,
    control_element_set: ControlElementSet,
    run_dir: Path,
    model: str,
    *,
    normalize_ids: bool = False,
) -> tuple[ControlStructure, list[str]]:
    """Assemble ControlStructure from Call 2a + Call 2b, falling back on failure.

    On assembly failure (invalid cross-references in the ControlElementSet),
    the failure is logged to ``calls.jsonl`` and a fallback ControlStructure
    is built from the ResponsibilitySet alone (without coordination links).
    If both fallback tiers fail validation, a ``StageError`` is raised so the
    SP1 runner can preserve the partial artifacts and record a fatal stage
    diagnostic instead of leaking a raw Pydantic exception.

    Before falling back, the Call 2b control actions and feedback channels
    are assigned onto the Call 2a responsibilities via
    ``_enrich_responsibilities`` so they are preserved on the degraded
    path. The fallback path then sanitizes invalid ElementRefs via
    ``_sanitize_for_fallback``. If sanitization still fails (e.g. duplicate
    IDs), a further-degraded path strips ALL ElementRefs.

    This function is deterministic and has no LLM dependency, so it can
    be tested independently of the Stage 2 LLM call sequence.

    Args:
        responsibility_set: Responsibilities with RCs and PMs from Call 2a.
        control_element_set: CAs, FBs, and CPs from Call 2b.
        run_dir: Directory for failure logging.
        model: LLM model name (used in the call-log entry).
        normalize_ids: If true, assign canonical IDs and fail when a Call 2b
            element does not carry an addressable responsibility owner.

    Returns:
        A tuple of (ControlStructure, assembly_warnings). The warning list
        is empty when the assembly succeeds.
    """
    try:
        return (
            _assemble_control_structure(
                responsibility_set,
                control_element_set,
                normalize_ids=normalize_ids,
            ),
            [],
        )
    except Exception as exc:
        error_msg = f"{type(exc).__name__}: {exc}"
        log_llm_call_failure(
            model,
            run_dir,
            STAGE,
            "assemble_control_structure",
            error_msg,
        )
        warnings = [f"{STAGE}/assemble_control_structure: {error_msg}"]

        # Enrich Call 2a responsibilities with Call 2b control actions and
        # feedback channels before sanitization/stripping. Without this, the
        # fallback tiers silently discard all CAs and FBs (the
        # ``responsibility_set.responsibilities`` passed in only carry RCs
        # and PM parts). The enriched list is built once and reused for both
        # tiers; each tier deep-copies it internally, so there is no risk of
        # cross-tier mutation.
        try:
            enriched_resps = _enrich_responsibilities(
                responsibility_set,
                control_element_set,
                normalize_ids=normalize_ids,
            )
            fallback, fallback_warnings = _fallback_control_structure(
                enriched_resps,
                control_element_set.controlled_processes,
                normalize_ids=normalize_ids,
            )
        except Exception as fallback_exc:
            fallback_error = f"{type(fallback_exc).__name__}: {fallback_exc}"
            raise StageError(
                stage=STAGE,
                step="assemble_control_structure",
                message=(
                    f"{error_msg}; fallback construction failed: {fallback_error}"
                ),
            ) from fallback_exc
        warnings.extend(fallback_warnings)
        return fallback, warnings


# ---------------------------------------------------------------------------
# Coordination link addition — deterministic, no LLM dependency
# ---------------------------------------------------------------------------


def _add_coordination_links_with_fallback(
    control_structure: ControlStructure,
    coordination_analysis: CoordinationAnalysis,
    run_dir: Path,
    model: str,
    source_id_mappings: dict[str, dict[str, str]] | None = None,
) -> tuple[ControlStructure, list[str]]:
    """Add coordination links from Call 3 to the ControlStructure.

    On failure (invalid coordination link references), the failure is
    logged and the ControlStructure is returned without coordination links.

    Args:
        control_structure: The assembled ControlStructure (without links).
        coordination_analysis: Coordination links and integrity findings from Call 3.
        run_dir: Directory for failure logging.
        model: LLM model name (used in the call-log entry).

    Returns:
        A tuple of (ControlStructure, warnings). The warning list is empty
        when the coordination links are added successfully.
    """
    if not coordination_analysis.coordination_links:
        return control_structure, []

    try:
        payload = control_structure.model_dump(mode="python", exclude_none=False)
        links = [
            link.model_dump(mode="python", exclude_none=False)
            for link in coordination_analysis.coordination_links
        ]
        if source_id_mappings is not None:
            _rewrite_coordination_link_source_ids(links, source_id_mappings)
        payload["coordination_links"] = links
        return validate_normalized_control_structure(payload), []
    except Exception as exc:
        error_msg = f"{type(exc).__name__}: {exc}"
        log_llm_call_failure(
            model,
            run_dir,
            STAGE,
            "add_coordination_links",
            error_msg,
        )
        warnings = [f"{STAGE}/add_coordination_links: {error_msg}"]
        return control_structure, warnings


def _rewrite_coordination_link_source_ids(
    links: list[dict[str, Any]],
    source_id_mappings: dict[str, dict[str, str]],
) -> None:
    """Rewrite Call 3 references using the maps captured from Calls 2a/2b."""
    resp_map = source_id_mappings.get("responsibility", {})
    pm_map = source_id_mappings.get("process_model_part", {})
    canonical_ids = set(resp_map.values()) | set(pm_map.values())
    reference_maps = (
        ("source", resp_map),
        ("target", resp_map),
        ("shared_pm", pm_map),
    )
    for link in links:
        if isinstance(link, dict):
            _rewrite_coordination_link(link, reference_maps, canonical_ids)


def _rewrite_coordination_link(
    link: dict[str, Any],
    reference_maps: tuple[tuple[str, dict[str, str]], ...],
    canonical_ids: set[str],
) -> None:
    """Rewrite source IDs in one Call 3 coordination link."""
    for field_name, source_map in reference_maps:
        old_id = link.get(field_name)
        if (
            isinstance(old_id, str)
            and old_id not in canonical_ids
            and old_id in source_map
        ):
            link[field_name] = source_map[old_id]


# ---------------------------------------------------------------------------
# Orphan PM repair — deterministic, no LLM dependency
# ---------------------------------------------------------------------------


def _next_fb_num(resp: Responsibility) -> int:
    """Return the next available FB number for a responsibility.

    Scans existing feedback_channels and returns ``max(fb_nums) + 1``,
    or 1 when the responsibility has no feedback channels.
    """
    nums = []
    for fb in resp.feedback_channels:
        match = re.match(r"FB-\d+-(\d+)", fb.fb_id)
        if match:
            nums.append(int(match.group(1)))
    return max(nums, default=0) + 1


def _find_orphan_pms(resp: Responsibility) -> list[str]:
    """Return PM IDs in *resp* that no feedback channel updates."""
    updated_pms = {fb.updates for fb in resp.feedback_channels}
    return [pm.pm_id for pm in resp.process_model_parts if pm.pm_id not in updated_pms]


def _create_stub_fb(
    resp: Responsibility,
    pm_id: str,
    fb_num: int,
) -> FeedbackChannel:
    """Create a stub FeedbackChannel for an orphan PM.

    Args:
        resp: The responsibility containing the orphan PM.
        pm_id: The orphan PM's ID (e.g. 'PM-1-3').
        fb_num: The FB number to assign (e.g. 2 → 'FB-1-2').

    Returns:
        A FeedbackChannel with auto-generated description and updates
        referencing the orphan PM.
    """
    resp_num = _extract_resp_num(resp.resp_id)
    fb_id = f"FB-{resp_num}-{fb_num}"
    # Reuse an existing feedback_source if any FB has one
    source = None
    for fb in resp.feedback_channels:
        if fb.source is not None:
            source = fb.source
            break
    return FeedbackChannel(
        fb_id=fb_id,
        description=f"Auto-generated feedback for orphan {pm_id}",
        updates=pm_id,
        source=source,
    )


def repair_orphan_pms(
    control_structure: ControlStructure,
) -> tuple[ControlStructure, list[str]]:
    """Repair orphan PM parts by auto-generating stub feedback channels.

    For each responsibility, finds PM parts where no feedback channel has
    that PM in its ``updates`` list. For each orphan PM, creates a stub
    feedback channel:
      - ``fb_id``: ``FB-{resp_num}-{next_fb_num}``
      - ``description``: ``"Auto-generated feedback for orphan PM {pm_id}"``
      - ``updates``: ``[pm_id]``
      - ``source``: reuses an existing FB source if available, else None

    Args:
        control_structure: The assembled ControlStructure.

    Returns:
        A tuple of (repaired ControlStructure, warnings). Each warning
        mentions the orphan PM ID. If no orphans exist, the structure is
        returned unchanged with an empty warnings list.
    """
    warnings: list[str] = []
    any_repaired = False
    repaired_resps: list[Responsibility] = []

    for resp in control_structure.responsibilities:
        orphan_pm_ids = _find_orphan_pms(resp)
        if not orphan_pm_ids:
            repaired_resps.append(resp)
            continue

        any_repaired = True
        resp_copy = copy.deepcopy(resp)
        next_num = _next_fb_num(resp_copy)
        for pm_id in orphan_pm_ids:
            stub = _create_stub_fb(resp_copy, pm_id, next_num)
            resp_copy.feedback_channels.append(stub)
            warnings.append(
                f"Auto-generated feedback channel {stub.fb_id} "
                f"for orphan PM {pm_id} in responsibility {resp.resp_id}."
            )
            next_num += 1
        repaired_resps.append(resp_copy)

    if not any_repaired:
        return control_structure, warnings

    repaired_cs = control_structure.model_copy(
        update={"responsibilities": repaired_resps},
    )
    return repaired_cs, warnings


# ---------------------------------------------------------------------------
# Stage 2 — four sequential LLM calls
# ---------------------------------------------------------------------------


def derive_control_structure(
    *,
    llm_client: LLMClient,
    use_case_text: str,
    loss_analysis: LossAnalysis,
    capability_profile: CapabilityProfile | None = None,
    run_dir: Path,
    template_loader: TemplateLoader | None = None,
    temperature: float = DEFAULT_TEMPERATURE,
    post_review_density_check: Callable[[LossAnalysis], None] | None = None,
) -> ControlStructureDerivationResult:
    """Run all four Stage 2 calls in sequence and assemble the ControlStructure.

    Call 1  — Requirements (from security constraints)
    Call 2a — Responsibilities + RCs + PM parts (from requirements + capability profile)
    Call 2b — Control actions + feedback channels + controlled processes (from responsibilities)
    Call 3  — Coordination links + integrity findings (from full control structure)

    If the assembly of Call 2a + Call 2b fails due to invalid cross-references,
    the assembly failure is logged and a fallback ControlStructure is built
    from the ResponsibilitySet alone (without coordination links). The returned
    warning list is non-empty in that case.

    Args:
        llm_client: LLM client for making completion calls.
        use_case_text: Free-text use-case description.
        loss_analysis: LossAnalysis from Stage 1a (provides security constraints).
        capability_profile: Optional capability profile for zone-driven responsibilities.
        run_dir: Directory for output artifacts.
        template_loader: Optional template loader (defaults to SP1 prompts dir).
        temperature: LLM temperature (default 0.4).
        post_review_density_check: Optional offline gate re-applied to the
            reviewed loss graph after Call 3 and before it replaces the
            canonical artifact.  Raising here fails the derivation closed
            instead of persisting a regressed graph.

    Returns:
        A named result containing the reviewed ``LossAnalysis``, validated
        ``ControlStructure``, and warnings.  The warning tuple is empty when
        the assembly succeeds.
    """
    loader = template_loader or TemplateLoader(PROMPTS_DIR)

    # Call 1 — Requirements
    requirement_set = _call_1_requirements(
        llm_client=llm_client,
        use_case_text=use_case_text,
        loss_analysis=loss_analysis,
        run_dir=run_dir,
        loader=loader,
        temperature=temperature,
    )

    # Call 2a — Responsibilities + RCs + PM parts
    responsibility_set = _call_2a_responsibilities(
        llm_client=llm_client,
        use_case_text=use_case_text,
        requirement_set=requirement_set,
        capability_profile=capability_profile,
        run_dir=run_dir,
        loader=loader,
        temperature=temperature,
    )

    # Call 2b — CAs + FBs + CPs
    control_element_set = _call_2b_control_elements(
        llm_client=llm_client,
        use_case_text=use_case_text,
        responsibility_set=responsibility_set,
        run_dir=run_dir,
        loader=loader,
        temperature=temperature,
    )

    # Assembly: merge Call 2a + Call 2b → ControlStructure (with fallback)
    assembly_source_id_maps = _assembly_source_id_maps(
        responsibility_set, control_element_set
    )
    control_structure, assembly_warnings = _assemble_with_fallback(
        responsibility_set,
        control_element_set,
        run_dir,
        llm_client.model,
        normalize_ids=True,
    )

    # Repair orphan PMs — auto-generate stub FB channels before Call 3
    control_structure, repair_warnings = repair_orphan_pms(control_structure)

    # Preserve the merged, pre-review loss graph for audit.  Stage 2 may make
    # only the bounded semantic wording/edge decisions in Call 3; all source
    # texts and identities stay available in this draft artifact.
    write_yaml(loss_analysis, run_dir / "loss-analysis-draft.yaml")

    # Call 3 — Coordination + integrity (receives full assembled control structure)
    write_yaml(control_structure, run_dir / "control-structure-draft.yaml")
    coordination_analysis = _call_3_coordination(
        llm_client=llm_client,
        use_case_text=use_case_text,
        control_structure=control_structure,
        loss_analysis=loss_analysis,
        run_dir=run_dir,
        loader=loader,
        temperature=temperature,
    )

    write_yaml(coordination_analysis, run_dir / "control-structure-review.yaml")
    semantic_result = apply_control_structure_semantic_review(
        control_structure,
        loss_analysis,
        coordination_analysis.semantic_review,
        use_case_text=use_case_text,
    )
    reviewed_loss_analysis = semantic_result.loss_analysis
    control_structure = semantic_result.control_structure

    # The reviewed graph is the graph in force: it is what Stage 2 uses and
    # what replaces the canonical ``loss-analysis.yaml``.  Persist it before
    # the offline re-check so the published artifact is always the exact graph
    # the gate evaluated.  The pre-review merged graph stays available as
    # ``loss-analysis-draft.yaml``.  Failing closed after this write leaves an
    # internally consistent run: the gates artifact names the still-failing
    # checks and the canonical artifact holds that same graph, instead of a
    # stale pre-review graph that silently keeps an edge the gate rejected.
    write_yaml(reviewed_loss_analysis, run_dir / "loss-analysis.yaml")

    # Fail closed before completing the stage: the semantic review may reword
    # hazards or constraints, or replace constraint hazard edges, and could
    # silently undo the Phase 1 density gates that the Stage 1a artifact
    # recorded as passed.  The offline re-check records its second report in
    # the gates artifact and raises when the reviewed graph regresses.
    if post_review_density_check is not None:
        post_review_density_check(reviewed_loss_analysis)

    # Add coordination links to the ControlStructure (with fallback)
    control_structure, coord_warnings = _add_coordination_links_with_fallback(
        control_structure,
        coordination_analysis,
        run_dir,
        llm_client.model,
        assembly_source_id_maps,
    )

    write_yaml(control_structure, run_dir / "control-structure.yaml")
    return ControlStructureDerivationResult(
        loss_analysis=reviewed_loss_analysis,
        control_structure=control_structure,
        warnings=assembly_warnings + repair_warnings + coord_warnings,
    )


# ---------------------------------------------------------------------------
# Shared LLM call backbone for the four Stage 2 calls
# ---------------------------------------------------------------------------


_Stage2ModelT = TypeVar("_Stage2ModelT", bound=BaseModel)


def _run_stage2_llm_call(
    *,
    llm_client: LLMClient,
    run_dir: Path,
    loader: TemplateLoader,
    temperature: float,
    system_template: str,
    user_template: str,
    user_prompt_kwargs: dict[str, Any],
    response_format: type[_Stage2ModelT],
    step: str,
    allow_unvalidated: bool = False,
    raw_result_validator: Callable[[Any], None] | None = None,
    result_validator: Callable[[Any], None] | None = None,
    result_parser: Callable[[Any], _Stage2ModelT] | None = None,
) -> _Stage2ModelT:
    """Render prompts, call the LLM, validate, and raise StageError on failure.

    Shared backbone for the four Stage 2 LLM calls (Call 1, 2a, 2b, 3).
    Each call renders a system + user prompt, invokes the LLM via
    ``safe_llm_call``, and raises ``StageError`` if the call or validation
    fails.
    """
    system_prompt = loader.render_prompt(system_template)
    user_prompt = loader.render_prompt(user_template, **user_prompt_kwargs)

    result, _, error_msg = safe_llm_call(
        llm_client=llm_client,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        response_format=response_format,
        run_dir=run_dir,
        stage=STAGE,
        step=step,
        temperature=temperature,
        allow_unvalidated=allow_unvalidated,
        raw_result_validator=raw_result_validator,
        result_parser=result_parser,
        result_validator=result_validator or _validate_stage2_intermediate,
        json_decode_retries=JSON_DECODE_RETRIES,
        validation_retries=1,
        validation_retry_feedback=_INTERMEDIATE_VALIDATION_RETRY_FEEDBACK,
        validation_retry_include_schema=False,
        validation_retry_include_response=True,
    )
    if error_msg is not None:
        raise StageError(stage=STAGE, step=step, message=error_msg)
    return result  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Call 1 — Requirements
# ---------------------------------------------------------------------------


def _call_1_requirements(
    *,
    llm_client: LLMClient,
    use_case_text: str,
    loss_analysis: LossAnalysis,
    run_dir: Path,
    loader: TemplateLoader,
    temperature: float,
) -> RequirementSet:
    """Run Call 1: derive requirements from security constraints.

    Raises:
        StageError: If the LLM call fails or the response fails validation.
    """
    return _run_stage2_llm_call(
        llm_client=llm_client,
        run_dir=run_dir,
        loader=loader,
        temperature=temperature,
        system_template="stage2_call1_system.j2",
        user_template="stage2_call1_user.j2",
        user_prompt_kwargs={
            "use_case_text": use_case_text,
            "security_constraints": loss_analysis.security_constraints,
        },
        response_format=RequirementSet,
        step="call_1_requirements",
    )


# ---------------------------------------------------------------------------
# Call 2a — Responsibilities + RCs + PM parts
# ---------------------------------------------------------------------------


def _call_2a_responsibilities(
    *,
    llm_client: LLMClient,
    use_case_text: str,
    requirement_set: RequirementSet,
    capability_profile: CapabilityProfile | None = None,
    run_dir: Path,
    loader: TemplateLoader,
    temperature: float,
) -> ResponsibilitySet:
    """Run Call 2a: derive responsibilities, responsibility constraints, and PM parts.

    Raises:
        StageError: If the LLM call fails or the response fails validation.
    """
    return _run_stage2_llm_call(
        llm_client=llm_client,
        run_dir=run_dir,
        loader=loader,
        temperature=temperature,
        system_template="stage2_call2a_system.j2",
        user_template="stage2_call2a_user.j2",
        user_prompt_kwargs={
            "use_case_text": use_case_text,
            "requirements": requirement_set.requirements,
            "capability_profile": capability_profile,
            "zone_display_names": ZONE_DISPLAY_NAMES,
            "kc_subcodes_display": (
                build_kc_subcodes_display(capability_profile.kc_subcodes)
                if capability_profile is not None
                else {}
            ),
        },
        response_format=ResponsibilitySet,
        step="call_2a_responsibilities",
        allow_unvalidated=True,
        raw_result_validator=_validate_responsibility_payload,
    )


# ---------------------------------------------------------------------------
# Call 2b — Control Actions + Feedback Channels + Controlled Processes
# ---------------------------------------------------------------------------


def _call_2b_control_elements(
    *,
    llm_client: LLMClient,
    use_case_text: str,
    responsibility_set: ResponsibilitySet,
    run_dir: Path,
    loader: TemplateLoader,
    temperature: float,
) -> ControlElementSet:
    """Run Call 2b: derive control actions, feedback channels, and controlled processes.

    Raises:
        StageError: If the LLM call fails or the response fails validation.
    """
    return _run_stage2_llm_call(
        llm_client=llm_client,
        run_dir=run_dir,
        loader=loader,
        temperature=temperature,
        system_template="stage2_call2b_system.j2",
        user_template="stage2_call2b_user.j2",
        user_prompt_kwargs={
            "use_case_text": use_case_text,
            "responsibilities": responsibility_set.responsibilities,
        },
        response_format=_ControlElementProviderSet,
        step="call_2b_control_elements",
        # Call 2b is semantic output.  Its stage-local parser rejects unknown
        # carriers and missing meaning before canonical IDs are repaired; the
        # generic tolerant decoder is intentionally not enabled here.
        result_parser=lambda result: parse_control_element_set_response(
            result.content,
            responsibilities=responsibility_set.responsibilities,
        ),
    )


# ---------------------------------------------------------------------------
# Call 3 — Coordination + integrity
# ---------------------------------------------------------------------------


def _deterministic_integrity_findings(
    control_structure: ControlStructure,
    loss_analysis: LossAnalysis | None = None,
) -> tuple[str, ...]:
    """Return the structural diagnostics computed by deterministic code."""
    checks = check_structural_heuristics(control_structure, loss_analysis)
    return tuple(
        [f"error: {finding}" for finding in checks.errors]
        + [f"warning: {finding}" for finding in checks.warnings]
    )


def _call_3_coordination(
    *,
    llm_client: LLMClient,
    use_case_text: str,
    control_structure: ControlStructure,
    run_dir: Path,
    loader: TemplateLoader,
    temperature: float,
    loss_analysis: LossAnalysis | None = None,
) -> CoordinationAnalysis:
    """Run Call 3: identify coordination links using deterministic diagnostics.

    Returns a CoordinationAnalysis containing coordination links and the
    deterministic structural findings supplied to the prompt. The provider
    reviews coordination and semantic adequacy; it does not recompute or
    author the integrity list.

    Raises:
        StageError: If the LLM call fails or the response fails validation.
    """
    source_excerpts = (
        _build_call3_source_excerpts(use_case_text, loss_analysis)
        if loss_analysis is not None
        else ()
    )
    integrity_findings = _deterministic_integrity_findings(
        control_structure, loss_analysis
    )
    source_ref_by_canonical = {
        excerpt.canonical_ref: excerpt.local_ref for excerpt in source_excerpts
    }
    response_format = (
        _coordination_provider_schema(
            control_structure,
            loss_analysis,
            use_case_text=use_case_text,
            source_excerpts=source_excerpts,
        )
        if loss_analysis is not None
        else _CoordinationProviderEnvelope
    )
    analysis = _run_stage2_llm_call(
        llm_client=llm_client,
        run_dir=run_dir,
        loader=loader,
        temperature=temperature,
        system_template="stage2_call3_system.j2",
        user_template="stage2_call3_user.j2",
        user_prompt_kwargs={
            "use_case_text": use_case_text,
            "control_structure": control_structure,
            "loss_analysis": loss_analysis,
            "source_excerpts": source_excerpts,
            "source_ref_by_canonical": source_ref_by_canonical,
            "integrity_findings": integrity_findings,
        },
        response_format=response_format,
        step="call_3_coordination",
        allow_unvalidated=loss_analysis is None,
        result_validator=(
            lambda value: _validate_semantic_review_response(
                value,
                control_structure,
                loss_analysis,
                use_case_text=use_case_text,
            )
        )
        if loss_analysis is not None
        else None,
        result_parser=(
            lambda result: _parse_call3_source_selection(
                result,
                source_excerpts,
                structure=control_structure,
                loss_analysis=loss_analysis,
            )
        )
        if loss_analysis is not None
        else lambda result: CoordinationAnalysis(
            **_CoordinationProviderEnvelope.model_validate(
                _decode_llm_content(result)
            ).model_dump()
        ),
    )
    # The durable record receives the structural check actually performed
    # above; the current provider wire cannot supply integrity findings.
    return analysis.model_copy(update={"integrity_findings": list(integrity_findings)})


def _validate_semantic_review_response(
    value,
    structure,
    loss_analysis,
    *,
    use_case_text: str = "",
) -> None:
    """Use the normal bounded retry for a missing/invalid complete review."""
    if isinstance(value, BaseModel):
        value = raw_model_data(value)
    if not isinstance(value, dict) or value.get("semantic_review") is None:
        raise ValueError(
            "semantic_review is required: review every responsibility and action"
        )
    review = ControlStructureSemanticReview.model_validate(value["semantic_review"])
    apply_control_structure_semantic_review(
        structure,
        loss_analysis,
        review,
        use_case_text=use_case_text,
    )
    from asago_scenario_generator.stpa.models.control_structure import (
        coordination_process_model_owner,
    )

    analysis = CoordinationAnalysis.model_validate(value)
    for link in analysis.coordination_links:
        coordination_process_model_owner(structure, link)
