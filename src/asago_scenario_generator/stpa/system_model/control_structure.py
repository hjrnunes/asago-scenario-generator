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
from typing import Annotated, Any, Literal, TypeVar

from pydantic import (
    AliasChoices,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    StrictStr,
    ValidationInfo,
    create_model,
    field_validator,
    model_validator,
)

from asago_scenario_generator.models.capability_profile import (
    ZONE_DISPLAY_NAMES,
    CapabilityProfile,
    build_kc_subcodes_display,
)
from asago_scenario_generator.stpa.infra.llm import (
    DEFAULT_TEMPERATURE,
    LLMClient,
    LLMResult,
)
from asago_scenario_generator.stpa.infra.call_log import CallLog, call_log_of
from asago_scenario_generator.stpa.infra.llm_helpers import (
    CallOutcome,
    CorrectionPolicy,
    StageError,
    call_with_policy,
    correction_prompt,
    decode_content,
    log_llm_call_failure,
    strip_json_fence,
)
from asago_scenario_generator.stpa._model_data import raw_model_data
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.infra.yaml_io import write_yaml
from asago_scenario_generator.stpa.models.control_structure import (
    ASSEMBLY_DEFERRED,
    ControlAction,
    ControlActionEffectKind,
    ControlActionTemporality,
    ControlStructure,
    CoordinationLink,
    ControlledProcess,
    ElementRef,
    FeedbackChannel,
    FeedbackSourceKind,
    NonBlankStr,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
    ResponsibilityConstraint,
    check_structural_heuristics,
    normalize_control_action_effect_kind,
)
from asago_scenario_generator.stpa.models.loss_analysis import (
    LossAnalysis,
    compose_constraint_description,
)
from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.system_model.target_evidence import (
    TargetEvidence,
)
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
    apply_control_structure_semantic_review,
)

STAGE = "stage_2"
JSON_DECODE_RETRIES = 1
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
    expected_collections = _call3_expected_collections(structure, loss_analysis)
    rows_by_collection: dict[str, list[dict[str, Any]]] = {}
    for collection_name, (identity_field, expected_ids) in expected_collections.items():
        normalized_rows = _call3_collection_rows(
            review, collection_name, identity_field, expected_ids
        )
        review[collection_name] = normalized_rows
        rows_by_collection[collection_name] = normalized_rows

    _check_call3_row_references(
        rows_by_collection["constraints"],
        collection_name="constraints",
        field_name="related_hazards",
        known_ids=expected_collections["hazards"][1],
        reference_kind="hazard ",
    )
    _check_call3_row_references(
        rows_by_collection["responsibilities"],
        collection_name="responsibilities",
        field_name="constraint_refs",
        known_ids=expected_collections["constraints"][1],
        reference_kind="constraint ",
    )
    return {
        row["constraint_id"]
        for row in rows_by_collection["constraints"]
        if row.get("disposition") == "unresolved"
    }


def _call3_expected_collections(
    structure: ControlStructure,
    loss_analysis: LossAnalysis,
) -> dict[str, tuple[str, set[str]]]:
    """Map each review collection to its identity field and authoritative IDs."""
    return {
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


def _call3_collection_rows(
    review: dict[str, Any],
    collection_name: str,
    identity_field: str,
    expected_ids: set[str],
) -> list[dict[str, Any]]:
    """Return a review collection's rows once each expected ID appears exactly once."""
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
    return normalized_rows


def _check_call3_row_references(
    rows: list[dict[str, Any]],
    *,
    collection_name: str,
    field_name: str,
    known_ids: set[str],
    reference_kind: str,
) -> None:
    """Require each row's reference list to be a collection of known IDs."""
    for index, row in enumerate(rows):
        references = row.get(field_name)
        if not isinstance(references, (list, tuple)):
            raise ValueError(
                f"semantic_review.{collection_name}[{index}].{field_name} must be "
                "a collection"
            )
        unknown = set(references) - known_ids
        if unknown:
            raise ValueError(
                f"semantic_review.{collection_name} contains unknown "
                f"{reference_kind}reference(s): "
                + ", ".join(sorted(str(item) for item in unknown))
            )


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


def _provider_source_evidence_type(
    loss_analysis: LossAnalysis,
    use_case_text: str,
    source_excerpts: Sequence[_Call3SourceExcerpt] | None,
):
    """Return the evidence row type with ``source_ref`` restricted to the excerpts."""
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
    return create_model(
        "ProviderSourceEvidence",
        __base__=_ProviderSourceSelection,
        source_ref=(Literal[tuple(source_refs)], ...),
    )


def _coordination_provider_schema(
    structure: ControlStructure,
    loss_analysis: LossAnalysis,
    *,
    use_case_text: str = "",
    source_excerpts: Sequence[_Call3SourceExcerpt] | None = None,
):
    """Require the same complete review that the Call 3 consumer validates."""
    constraint_ids = [sc.constraint_id for sc in loss_analysis.security_constraints]
    hazard_ids = [hazard.hazard_id for hazard in loss_analysis.hazards]
    evidence_type = _provider_source_evidence_type(
        loss_analysis, use_case_text, source_excerpts
    )

    def evidence_field():
        return (
            tuple[evidence_type, ...],
            Field(min_length=0),
        )

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
    structure: ControlStructure,
    loss_analysis: LossAnalysis,
) -> CoordinationAnalysis:
    """Map provider-local source selections to immutable final evidence."""
    payload = _decode_call3_payload(result)
    review = payload.get("semantic_review")
    if not isinstance(review, dict):
        return CoordinationAnalysis.model_validate(payload)
    _apply_call3_review_authorities(review, structure, loss_analysis)
    _resolve_call3_source_evidence(review, _call3_source_ref_map(source_excerpts))
    return CoordinationAnalysis.model_validate(payload)


def _decode_call3_payload(result: Any) -> dict[str, Any]:
    """Decode a Call 3 response into a private copy of its one JSON object."""
    payload = decode_content(result)
    if not isinstance(payload, dict):
        raise ValueError("Call 3 response must be one JSON object")
    unexpected = set(payload) - {"coordination_links", "semantic_review"}
    if unexpected:
        raise ValueError(
            "Call 3 response contains code-owned or unknown fields: "
            + ", ".join(sorted(unexpected))
        )
    return copy.deepcopy(payload)


def _apply_call3_review_authorities(
    review: dict[str, Any],
    structure: ControlStructure,
    loss_analysis: LossAnalysis,
) -> None:
    """Validate the review rows and drop references to unresolved constraints."""
    unresolved_constraint_ids = _validate_call3_review_collections(
        review,
        structure,
        loss_analysis,
    )
    _preserve_unchanged_revisions(review, loss_analysis)
    for row in review["constraints"]:
        if row["constraint_id"] in unresolved_constraint_ids:
            row["related_hazards"] = []
    for row in review["responsibilities"]:
        row["constraint_refs"] = [
            constraint_id
            for constraint_id in row["constraint_refs"]
            if constraint_id not in unresolved_constraint_ids
        ]


def _preserve_unchanged_revisions(
    review: dict[str, Any], loss_analysis: LossAnalysis
) -> None:
    """Treat an unchanged echo of the original text as a plain ``preserve``.

    A ``revise`` row that echoes its original text becomes ``preserve``;
    a ``preserve`` row that echoes it loses the redundant
    ``revised_description``.  A ``preserve`` row that also carries a
    ``missing_fact`` is left for the strict review validation to reject.

    Phase 1.3 as amended: Call 3 displays the authored rule with the
    composed conditions shown separately, so an unchanged echo of
    either the rule or the full composed statement means "preserve".
    """
    unchanged_by_collection = {
        "hazards": (
            "hazard_id",
            {
                hazard.hazard_id: {hazard.description.strip()}
                for hazard in loss_analysis.hazards
            },
        ),
        "constraints": (
            "constraint_id",
            {
                constraint.constraint_id: {
                    compose_constraint_description(
                        constraint.rule, constraint.applies_when
                    ).strip(),
                    constraint.rule.strip(),
                }
                for constraint in loss_analysis.security_constraints
            },
        ),
    }
    for collection_name, (identity_field, unchanged) in unchanged_by_collection.items():
        for row in review[collection_name]:
            revised_description = row.get("revised_description")
            unchanged_values = unchanged[row[identity_field]]
            if (
                row.get("disposition") in ("revise", "preserve")
                and row.get("missing_fact") is None
                and isinstance(revised_description, str)
                and revised_description.strip() in unchanged_values
            ):
                row["disposition"] = "preserve"
                row["revised_description"] = None


def _resolve_call3_source_evidence(
    review: dict[str, Any],
    excerpts: dict[str, _Call3SourceExcerpt],
) -> None:
    """Replace each row's local source selections with exact final evidence."""
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
            row["source_evidence"] = [
                _resolve_call3_source_item(
                    item,
                    excerpts,
                    location=(
                        f"{collection_name}[{row_index}].source_evidence["
                        f"{evidence_index}]"
                    ),
                )
                for evidence_index, item in enumerate(evidence)
            ]


def _resolve_call3_source_item(
    item: Any,
    excerpts: dict[str, _Call3SourceExcerpt],
    *,
    location: str,
) -> Any:
    """Resolve one source selection; non-object items pass through unchanged."""
    if not isinstance(item, dict):
        return item
    unexpected = set(item) - {"source_ref", "meaning"}
    if unexpected:
        names = ", ".join(sorted(str(name) for name in unexpected))
        raise ValueError(
            "Call 3 source_evidence must select source_ref and meaning "
            f"only at {location}; unexpected field(s): {names}"
        )
    local_ref = item.get("source_ref")
    excerpt = excerpts.get(local_ref)
    if excerpt is None:
        raise ValueError(
            "Call 3 source_evidence source_ref must select one of the "
            f"displayed local excerpts; got {local_ref!r}"
        )
    return {
        "source_ref": excerpt.canonical_ref,
        "quote": excerpt.text,
        "meaning": item.get("meaning"),
    }


def _holds_nothing(value: Any) -> bool:
    return value in (None, "", [], {})


class _Call2aConstraint(ResponsibilityConstraint):
    """A responsibility constraint whose omitted ID normalization supplies.

    ``id_normalization`` numbers every RC by its position, so an RC whose ID
    key the model misspelled still has a position and keeps its meaning.
    """

    rc_id: str = ""


class _Call2aResponsibility(BaseModel):
    """One Call 2a responsibility; a field it does not declare is an error.

    A generic ``id`` stands for ``resp_id``.  An undeclared field that holds
    nothing carries no meaning to lose, so it is dropped instead of rejected;
    one that holds content fails with the list of fields to keep.
    """

    model_config = ConfigDict(extra="forbid")

    resp_id: StrictStr
    description: NonBlankStr
    responsibility_constraints: list[_Call2aConstraint] = Field(default_factory=list)
    security_constraint_refs: list[StrictStr]
    process_model_parts: list[ProcessModelPart] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def _read_generic_id_and_drop_empty_fields(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        record = {
            name: item
            for name, item in value.items()
            if name in cls.model_fields or name == "id" or not _holds_nothing(item)
        }
        unexpected = sorted(set(record) - {"id", *cls.model_fields})
        if unexpected:
            fields = list(cls.model_fields)
            raise ValueError(
                f"unexpected responsibility field(s): {', '.join(unexpected)}. "
                f"Remove them; each responsibility contains only "
                f"{', '.join(fields[:-1])}, and {fields[-1]}"
            )
        generic_id = record.pop("id", None)
        if "resp_id" not in record and generic_id is not None:
            record["resp_id"] = generic_id
        return record


class _Call2aResponse(BaseModel):
    """The Call 2a response as the model must write it."""

    model_config = ConfigDict(extra="forbid")

    responsibilities: list[_Call2aResponsibility] = Field(min_length=1)


def _validate_responsibility_wire(value: Any) -> None:
    """Check a decoded Call 2a response against its closed wire models."""
    _Call2aResponse.model_validate(value, context=ASSEMBLY_DEFERRED)


def parse_responsibility_set_response(value: Any) -> ResponsibilitySet:
    """Parse a Call 2a response; IDs stay as written for ``id_normalization``."""
    wire = _Call2aResponse.model_validate(value, context=ASSEMBLY_DEFERRED)
    return ResponsibilitySet.model_construct(
        responsibilities=[
            Responsibility.model_construct(
                resp_id=item.resp_id,
                description=item.description,
                responsibility_constraints=[
                    ResponsibilityConstraint.model_construct(
                        rc_id=constraint.rc_id, description=constraint.description
                    )
                    for constraint in item.responsibility_constraints
                ],
                security_constraint_refs=item.security_constraint_refs,
                process_model_parts=item.process_model_parts,
            )
            for item in wire.responsibilities
        ]
    )


def _parse_responsibility_result(
    result: LLMResult, cleanup_transformations: list[dict[str, Any]]
) -> ResponsibilitySet:
    return parse_responsibility_set_response(
        decode_content(result, cleanup_transformations=cleanup_transformations)
    )


# ---------------------------------------------------------------------------
# Stage-local Call 2b response contract
# ---------------------------------------------------------------------------


_OWNER_CONTEXT_KEY = "owner_numbers"


def _owner_number(identifier: str, *, prefix: str) -> int:
    """Return the responsibility number encoded by one CA/FB ID."""
    match = re.fullmatch(rf"{prefix}-(\d+)(?:-\d+)?", identifier)
    if match is None:  # pragma: no cover - guarded by the wire ID check
        raise ValueError(f"{prefix} ID does not encode an owner: {identifier!r}")
    return int(match.group(1))


def _require_owner_format(identifier: str, prefix: str) -> str:
    """Require ``PREFIX-X`` or ``PREFIX-X-Y``.

    Canonical IDs are CA-X-Y/FB-X-Y.  A one-suffix CA-X or FB-X is accepted
    only as a narrowly recoverable source ID: its numeric prefix still states
    the owner unambiguously and canonicalization can supply Y.  An arbitrary
    value such as ``first-action`` has no ownership information and must not
    be distributed by response-array order.
    """
    if not re.fullmatch(rf"{prefix}-\d+(?:-\d+)?", identifier):
        raise ValueError(
            f"must encode an explicit owner using {prefix}-X-Y; got {identifier!r}"
        )
    return identifier


def _require_known_owner(identifier: str, prefix: str, info: ValidationInfo) -> str:
    """Require an owned ID whose owner is a supplied responsibility."""
    _require_owner_format(identifier, prefix)
    owners = (info.context or {}).get(_OWNER_CONTEXT_KEY)
    if owners is not None and _owner_number(identifier, prefix=prefix) not in owners:
        raise ValueError(
            f"{identifier!r} has no matching responsibility owner; "
            "ownership cannot be recovered from array order"
        )
    return identifier


def _element_ref_from_text(value: Any) -> Any:
    """Read a compact ``RESP-N`` or ``CP-N`` reference as a typed object."""
    if not isinstance(value, str):
        return value
    if re.fullmatch(r"RESP-\d+", value):
        return {"type": ReferenceType.responsibility, "id": value}
    if re.fullmatch(r"CP-\d+", value):
        return {"type": ReferenceType.controlled_process, "id": value}
    raise ValueError(f"must name RESP-N or CP-N; got {value!r}")


class _Call2bWire(BaseModel):
    """A closed object of the Call 2b wire: unknown fields are errors."""

    model_config = ConfigDict(extra="forbid")


class _Call2bRef(_Call2bWire):
    type: ReferenceType
    id: str


_Call2bRefField = Annotated[_Call2bRef, BeforeValidator(_element_ref_from_text)]


class _Call2bAction(_Call2bWire):
    ca_id: NonBlankStr
    description: NonBlankStr
    target: _Call2bRefField
    effect_kind: ControlActionEffectKind | None = None
    temporality: ControlActionTemporality | None = None
    operation: Annotated[StrictStr, Field(min_length=1)] | None = None
    process_model_refs: list[Annotated[StrictStr, Field(min_length=1)]] | None = None

    @model_validator(mode="before")
    @classmethod
    def _name_the_combined_action(cls, value: Any) -> Any:
        if isinstance(value, dict) and "action" in value:
            raise ValueError(
                "uses combined action field 'action'; return separate ca_id and "
                "description fields"
            )
        return value

    @field_validator("ca_id")
    @classmethod
    def _owned_ca_id(cls, value: str, info: ValidationInfo) -> str:
        return _require_known_owner(value, "CA", info)

    @model_validator(mode="after")
    def _meaningful_and_consistent(self) -> _Call2bAction:
        normalized_description = " ".join(self.description.split()).lower()
        normalized_id = " ".join(self.ca_id.split()).lower()
        if normalized_description in {normalized_id, f"control action {normalized_id}"}:
            raise ValueError(
                "description must be meaningful, not a generated placeholder"
            )
        self.effect_kind = normalize_control_action_effect_kind(
            ElementRef(type=self.target.type, id=self.target.id), self.effect_kind
        )
        return self

    def to_domain(self) -> ControlAction:
        return ControlAction.model_construct(
            ca_id=self.ca_id,
            description=self.description,
            target=ElementRef(type=self.target.type, id=self.target.id),
            effect_kind=self.effect_kind,
            temporality=self.temporality,
            operation=self.operation,
            process_model_refs=list(dict.fromkeys(self.process_model_refs or [])),
        )


class _Call2bFeedback(_Call2bWire):
    fb_id: NonBlankStr
    description: NonBlankStr
    updates: NonBlankStr
    source: _Call2bRefField
    source_kind: FeedbackSourceKind | None = None

    @field_validator("fb_id")
    @classmethod
    def _owned_fb_id(cls, value: str, info: ValidationInfo) -> str:
        return _require_known_owner(value, "FB", info)

    def to_domain(self) -> FeedbackChannel:
        return FeedbackChannel.model_construct(
            fb_id=self.fb_id,
            description=self.description,
            updates=self.updates,
            source=ElementRef(type=self.source.type, id=self.source.id),
            source_kind=self.source_kind,
        )


class _Call2bProcess(_Call2bWire):
    """A controlled process; ``id_normalization`` numbers it by position.

    A controlled process has no owner to encode, so any non-blank ID that
    the response's references use is enough.
    """

    cp_id: NonBlankStr
    description: NonBlankStr

    def to_domain(self) -> ControlledProcess:
        return ControlledProcess.model_construct(
            cp_id=self.cp_id, description=self.description
        )


class _Call2bResponse(_Call2bWire):
    """The Call 2b response as the model must write it.

    ``feedback`` is the provider-facing collection name; the historical
    ``feedback_channels`` spelling is accepted on input, never both.
    """

    control_actions: list[_Call2bAction] = Field(min_length=1)
    feedback: list[_Call2bFeedback] = Field(
        min_length=1,
        validation_alias=AliasChoices("feedback", "feedback_channels"),
    )
    controlled_processes: list[_Call2bProcess]

    @model_validator(mode="before")
    @classmethod
    def _one_feedback_spelling(cls, value: Any) -> Any:
        if isinstance(value, dict) and {"feedback", "feedback_channels"} <= set(value):
            raise ValueError(
                "Call 2b response must use one feedback collection, not both "
                "feedback and feedback_channels"
            )
        return value


def _decode_control_element_payload(value: Any) -> Any:
    """Decode one Call 2b response into plain JSON data."""
    if isinstance(value, BaseModel):
        return raw_model_data(value)
    if isinstance(value, str):
        return json.loads(strip_json_fence(value))
    return raw_model_data(value)


def parse_control_element_set_response(
    value: Any,
    *,
    responsibilities: Sequence[Responsibility] | None = None,
) -> ControlElementSet:
    """Parse a Call 2b response through its closed wire models.

    The response is semantic model output: every carrier field is checked,
    descriptions cannot be empty or generated placeholders, and CA/FB IDs must
    carry an explicit responsibility owner.  Source IDs may still be
    canonicalized later by ``id_normalization`` when their owner is explicit.
    A shape error raises the wire models' ``ValidationError``; a reference
    to an element the supplied responsibilities lack raises ``ValueError``.
    """
    owner_numbers = (
        _responsibility_owner_numbers(responsibilities)
        if responsibilities is not None
        else None
    )
    wire = _Call2bResponse.model_validate(
        _decode_control_element_payload(value),
        context={_OWNER_CONTEXT_KEY: owner_numbers},
    )
    actions = [action.to_domain() for action in wire.control_actions]
    feedback_channels = [channel.to_domain() for channel in wire.feedback]
    controlled_processes = [
        process.to_domain() for process in wire.controlled_processes
    ]
    if responsibilities is not None:
        _check_control_elements_against_responsibilities(
            responsibilities,
            owner_numbers=owner_numbers or set(),
            actions=actions,
            feedback_channels=feedback_channels,
            controlled_processes=controlled_processes,
        )
    return ControlElementSet.model_construct(
        control_actions=actions,
        feedback_channels=feedback_channels,
        controlled_processes=controlled_processes,
    )


def _responsibility_owner_numbers(
    responsibilities: Sequence[Responsibility],
) -> set[int]:
    """Return each responsibility's unique numeric owner identity."""
    owner_numbers: set[int] = set()
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
    return owner_numbers


def _check_every_responsibility_is_served(
    owner_numbers: set[int],
    known_pm_ids: set[str],
    actions: Sequence[ControlAction],
    feedback_channels: Sequence[FeedbackChannel],
) -> None:
    """Require an action per responsibility and a feedback update per PM part."""
    action_owners = {_owner_number(action.ca_id, prefix="CA") for action in actions}
    missing_action_owners = owner_numbers - action_owners
    if missing_action_owners:
        raise ValueError(
            "every responsibility requires a control action; missing owners: "
            + ", ".join(f"RESP-{number}" for number in sorted(missing_action_owners))
        )
    updated_pm_ids = {channel.updates for channel in feedback_channels}
    missing_pm_ids = known_pm_ids - updated_pm_ids
    if missing_pm_ids:
        raise ValueError(
            "every process model part requires feedback updates; missing: "
            + ", ".join(sorted(missing_pm_ids))
        )


@dataclass(frozen=True)
class UnknownReference:
    """One Call 2b reference to an element the structure does not hold.

    ``owner`` names the responsibility whose process model parts a
    ``process_model_refs`` entry should have come from.
    """

    location: str
    value: str
    owner: str | None = None

    @property
    def message(self) -> str:
        if self.owner is not None:
            return (
                f"{self.location} {self.value!r} is not a process model part of "
                f"the action's own responsibility {self.owner}"
            )
        return (
            f"{self.location} reference {self.value!r} is not present in the "
            "supplied structure"
        )


class UnknownReferenceError(ValueError):
    """A Call 2b response names targets, sources or process model parts it lacks."""

    def __init__(
        self,
        references: Sequence[UnknownReference],
        controlled_processes: Sequence[ControlledProcess] = (),
    ) -> None:
        self.references = tuple(references)
        self.controlled_processes = tuple(controlled_processes)
        super().__init__("; ".join(item.message for item in self.references))


def _check_control_elements_against_responsibilities(
    responsibilities: Sequence[Responsibility],
    *,
    owner_numbers: set[int],
    actions: Sequence[ControlAction],
    feedback_channels: Sequence[FeedbackChannel],
    controlled_processes: Sequence[ControlledProcess],
) -> None:
    """Check the parsed Call 2b elements against the supplied responsibilities."""
    known_pm_ids = {
        pm.pm_id
        for responsibility in responsibilities
        for pm in responsibility.process_model_parts
    }
    _check_every_responsibility_is_served(
        owner_numbers, known_pm_ids, actions, feedback_channels
    )
    unknown = _unknown_element_refs(
        actions,
        feedback_channels,
        responsibility_ids={resp.resp_id for resp in responsibilities},
        controlled_process_ids={process.cp_id for process in controlled_processes},
    )
    if not unknown:
        for index, channel in enumerate(feedback_channels):
            if channel.updates not in known_pm_ids:
                raise ValueError(
                    f"feedback[{index}] updates unknown process model part "
                    f"{channel.updates!r}"
                )
    unknown += _foreign_process_model_refs(actions, responsibilities)
    if unknown:
        raise UnknownReferenceError(unknown, controlled_processes)


def _unknown_element_refs(
    actions: Sequence[ControlAction],
    feedback_channels: Sequence[FeedbackChannel],
    *,
    responsibility_ids: set[str],
    controlled_process_ids: set[str],
) -> list[UnknownReference]:
    """Return each action target or feedback source absent from the structure."""
    unknown: list[UnknownReference] = []
    for collection_name, elements, ref_field in (
        ("control_actions", actions, "target"),
        ("feedback", feedback_channels, "source"),
    ):
        for index, element in enumerate(elements):
            ref = getattr(element, ref_field)
            known_ids = (
                responsibility_ids
                if ref.type is ReferenceType.responsibility
                else controlled_process_ids
            )
            if ref.id not in known_ids:
                unknown.append(
                    UnknownReference(f"{collection_name}[{index}].{ref_field}", ref.id)
                )
    return unknown


def _foreign_process_model_refs(
    actions: Sequence[ControlAction],
    responsibilities: Sequence[Responsibility],
) -> list[UnknownReference]:
    """Return each action reference to another responsibility's process model."""
    pm_ids_by_owner = {
        _extract_resp_num(responsibility.resp_id): {
            pm.pm_id for pm in responsibility.process_model_parts
        }
        for responsibility in responsibilities
    }
    unknown: list[UnknownReference] = []
    for index, action in enumerate(actions):
        owner = _owner_number(action.ca_id, prefix="CA")
        owner_pm_ids = pm_ids_by_owner.get(owner, set())
        unknown.extend(
            UnknownReference(
                f"control_actions[{index}].process_model_refs", ref, f"RESP-{owner}"
            )
            for ref in action.process_model_refs
            if ref not in owner_pm_ids
        )
    return unknown


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
) -> list:
    """Assign elements (CAs or FBs) to their parent responsibility by ID prefix.

    For each element, extracts the numeric prefix from its ``id_attr``
    (e.g. ``CA-3-1`` → 3) and appends it to the matching responsibility's
    ``target_attr`` list. Returns the elements no responsibility owns.
    """
    unmatched = []
    for element in elements:
        resp = resp_by_num.get(_extract_resp_num(getattr(element, id_attr)))
        if resp is not None:
            getattr(resp, target_attr).append(element)
        else:
            unmatched.append(element)
    return unmatched


def _enrich_responsibilities(
    responsibility_set: ResponsibilitySet,
    control_element_set: ControlElementSet,
) -> list[Responsibility]:
    """Deep-copy responsibilities and assign Call 2b CAs/FBs onto them by ID prefix.

    Returns a deep-copied list of the Call 2a responsibilities with the
    Call 2b ``control_actions`` and ``feedback_channels`` appended to the
    matching responsibility by ID prefix (CA-X-Y → RESP-X, FB-X-Y → RESP-X).
    An element no responsibility owns is rejected instead of being
    distributed by response-array order.
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
    )
    unmatched_fbs = _assign_elements_to_responsibilities(
        control_element_set.feedback_channels,
        "fb_id",
        resp_by_num,
        "feedback_channels",
    )
    if unmatched_cas or unmatched_fbs:
        unmatched_labels = [
            *[f"CA {item.ca_id}" for item in unmatched_cas],
            *[f"FB {item.fb_id}" for item in unmatched_fbs],
        ]
        raise ValueError(
            "unmatched control-element ownership; cannot distribute by response "
            f"order: {', '.join(unmatched_labels)}"
        )
    return enriched


def _assemble_control_structure(
    responsibility_set: ResponsibilitySet,
    control_element_set: ControlElementSet,
) -> ControlStructure:
    """Merge Call 2a (responsibilities + RCs + PMs) and Call 2b (CAs + FBs + CPs).

    Matches CAs and FBs to responsibilities by ID prefix (CA-X-Y → RESP-X,
    FB-X-Y → RESP-X). Produces the final ControlStructure with canonical IDs
    and validates it.
    """
    responsibilities = _enrich_responsibilities(responsibility_set, control_element_set)
    controlled_processes = copy.deepcopy(control_element_set.controlled_processes)

    return _build_control_structure(responsibilities, controlled_processes)


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
) -> ControlStructure:
    """Construct a control structure with canonical IDs and validate it."""
    return validate_normalized_control_structure(
        _control_structure_payload(responsibilities, controlled_processes)
    )


# ---------------------------------------------------------------------------
# Checked assembly — deterministic, no LLM dependency
# ---------------------------------------------------------------------------


def _dict_items(value: Any) -> list[dict[str, Any]]:
    """Return the dictionary members of a decoded list, ignoring other shapes."""
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _unresolved_element_ref(
    label: str, ref: Any, resp_ids: set[Any], cp_ids: set[Any]
) -> list[str]:
    """Name a typed reference that resolves to no responsibility or process."""
    if ref is None:
        return []
    if not isinstance(ref, dict):
        return [f"{label} {ref!r}"]
    ref_type = getattr(ref.get("type"), "value", ref.get("type"))
    ref_id = ref.get("id")
    known = {"responsibility": resp_ids, "controlled_process": cp_ids}.get(
        ref_type, set()
    )
    if isinstance(ref_id, str) and ref_id in known:
        return []
    return [f"{label} {ref_type} {ref_id!r}"]


def _unknown_ids(label: str, refs: list[Any], known_ids: set[Any]) -> list[str]:
    """Name each ID reference that is not one of the known IDs."""
    return [
        f"{label} {ref!r}"
        for ref in refs
        if not (isinstance(ref, str) and ref in known_ids)
    ]


def _unresolved_responsibility_refs(
    resp: dict[str, Any], resp_ids: set[Any], cp_ids: set[Any]
) -> list[str]:
    """Name the unresolved references inside one responsibility."""
    pm_parts = _dict_items(resp.get("process_model_parts"))
    local_pm_ids = {
        pm.get("pm_id") for pm in pm_parts if isinstance(pm.get("pm_id"), str)
    }
    found: list[str] = []
    for pm in pm_parts:
        found += _unresolved_element_ref(
            f"ProcessModelPart {pm.get('pm_id')} feedback_source",
            pm.get("feedback_source"),
            resp_ids,
            cp_ids,
        )
    for ca in _dict_items(resp.get("control_actions")):
        label = f"ControlAction {ca.get('ca_id')}"
        found += _unresolved_element_ref(
            f"{label} target", ca.get("target"), resp_ids, cp_ids
        )
        found += _unknown_ids(
            f"{label} process_model_refs",
            ca.get("process_model_refs") or [],
            local_pm_ids,
        )
    for fb in _dict_items(resp.get("feedback_channels")):
        label = f"FeedbackChannel {fb.get('fb_id')}"
        found += _unresolved_element_ref(
            f"{label} source", fb.get("source"), resp_ids, cp_ids
        )
        found += _unknown_ids(f"{label} updates", [fb.get("updates")], local_pm_ids)
    return found


def _unresolved_references(payload: dict[str, Any]) -> list[str]:
    """Name every reference in a control-structure payload that resolves nowhere.

    The payload is normalized first, so the names match the identifiers the
    failed validation saw.  The checks mirror the reference rules of
    :class:`ControlStructure`; duplicate IDs and other non-reference failures
    produce no entry.
    """
    normalized = normalize_control_structure_payload(payload).payload
    responsibilities = _dict_items(normalized.get("responsibilities"))
    resp_ids = {resp.get("resp_id") for resp in responsibilities}
    cp_ids = {
        cp.get("cp_id") for cp in _dict_items(normalized.get("controlled_processes"))
    }
    all_pm_ids = {
        pm.get("pm_id")
        for resp in responsibilities
        for pm in _dict_items(resp.get("process_model_parts"))
    }
    found: list[str] = []
    for resp in responsibilities:
        found += _unresolved_responsibility_refs(resp, resp_ids, cp_ids)
    for link in _dict_items(normalized.get("coordination_links")):
        found += _unresolved_link_refs(link, resp_ids, all_pm_ids)
    return found


def _unresolved_link_refs(
    link: dict[str, Any], resp_ids: set[Any], all_pm_ids: set[Any]
) -> list[str]:
    """Name the unresolved endpoints and shared state of one coordination link."""
    label = f"CoordinationLink {link.get('link_id')}"
    return [
        *_unknown_ids(f"{label} source responsibility", [link.get("source")], resp_ids),
        *_unknown_ids(f"{label} target responsibility", [link.get("target")], resp_ids),
        *_unknown_ids(f"{label} shared_pm", [link.get("shared_pm")], all_pm_ids),
    ]


def _validation_failure(
    exc: Exception,
    payload: dict[str, Any] | None,
    *,
    step: str,
    run_dir: Path,
    model: str,
    call_log: CallLog | None,
) -> StageError:
    """Log a failed deterministic step and describe it as a ``StageError``."""
    log_llm_call_failure(
        model,
        run_dir,
        STAGE,
        step,
        f"{type(exc).__name__}: {exc}",
        call_log=call_log,
    )
    unresolved = _unresolved_references(payload) if payload is not None else []
    if unresolved:
        message = (
            "control structure failed validation; unresolved references: "
            + "; ".join(unresolved)
        )
    else:
        message = f"control structure failed validation: {type(exc).__name__}: {exc}"
    return StageError(stage=STAGE, step=step, message=message)


def _assemble_stage2_structure(
    responsibility_set: ResponsibilitySet,
    control_element_set: ControlElementSet,
    run_dir: Path,
    model: str,
    *,
    call_log: CallLog | None = None,
) -> ControlStructure:
    """Assemble the ControlStructure from Call 2a + Call 2b or stop Stage 2.

    On failure the step is logged to ``calls.jsonl`` and a ``StageError``
    names every unresolved reference, so the SP1 runner records a fatal
    stage diagnostic and no degraded structure is written.

    Args:
        responsibility_set: Responsibilities with RCs and PMs from Call 2a.
        control_element_set: CAs, FBs, and CPs from Call 2b.
        run_dir: Directory for failure logging.
        model: LLM model name (used in the call-log entry).
    """
    try:
        return _assemble_control_structure(responsibility_set, control_element_set)
    except Exception as exc:
        try:
            payload = _control_structure_payload(
                _enrich_responsibilities(responsibility_set, control_element_set),
                control_element_set.controlled_processes,
            )
        except Exception:
            payload = None
        raise _validation_failure(
            exc,
            payload,
            step="assemble_control_structure",
            run_dir=run_dir,
            model=model,
            call_log=call_log,
        ) from exc


# ---------------------------------------------------------------------------
# Coordination link addition — deterministic, no LLM dependency
# ---------------------------------------------------------------------------


def _add_coordination_links(
    control_structure: ControlStructure,
    coordination_analysis: CoordinationAnalysis,
    run_dir: Path,
    model: str,
    source_id_mappings: dict[str, dict[str, str]] | None = None,
    call_log: CallLog | None = None,
) -> ControlStructure:
    """Add coordination links from Call 3 to the ControlStructure or stop Stage 2.

    On failure the step is logged to ``calls.jsonl`` and a ``StageError``
    names every unresolved link reference.

    Args:
        control_structure: The assembled ControlStructure (without links).
        coordination_analysis: Coordination links and integrity findings from Call 3.
        run_dir: Directory for failure logging.
        model: LLM model name (used in the call-log entry).
    """
    if not coordination_analysis.coordination_links:
        return control_structure

    payload: dict[str, Any] | None = None
    try:
        links = [
            link.model_dump(mode="python", exclude_none=False)
            for link in coordination_analysis.coordination_links
        ]
        if source_id_mappings is not None:
            _rewrite_coordination_link_source_ids(links, source_id_mappings)
        payload = {
            **control_structure.model_dump(mode="python", exclude_none=False),
            "coordination_links": links,
        }
        return validate_normalized_control_structure(payload)
    except Exception as exc:
        raise _validation_failure(
            exc,
            payload,
            step="add_coordination_links",
            run_dir=run_dir,
            model=model,
            call_log=call_log,
        ) from exc


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
    post_review_density_check: (
        Callable[
            [
                LossAnalysis,
                Callable[..., LossAnalysis],
                Callable[[], tuple[frozenset[str], frozenset[str]]],
            ],
            object,
        ]
        | None
    ) = None,
    target_evidence: TargetEvidence | None = None,
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
            canonical artifact.  It receives the reviewed graph, a
            correction callable that re-runs Call 3 once for the scoped
            records named by failing checks, and a callable returning the
            hazard and constraint IDs the review in force marks unresolved.
            Raising here fails the derivation closed instead of persisting a
            regressed graph.
        target_evidence: Optional discovered target evidence rendered into
            every Stage 2 call.  Control actions may then name the observed
            operation they invoke; unknown names are dropped with a warning.

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
        target_evidence=target_evidence,
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
        target_evidence=target_evidence,
    )

    # Call 2b — CAs + FBs + CPs
    control_element_set = _call_2b_control_elements(
        llm_client=llm_client,
        use_case_text=use_case_text,
        responsibility_set=responsibility_set,
        run_dir=run_dir,
        loader=loader,
        temperature=temperature,
        target_evidence=target_evidence,
    )

    # Assembly: merge Call 2a + Call 2b → ControlStructure
    assembly_source_id_maps = _assembly_source_id_maps(
        responsibility_set, control_element_set
    )
    control_structure = _assemble_stage2_structure(
        responsibility_set,
        control_element_set,
        run_dir,
        llm_client.model,
        call_log=call_log_of(llm_client),
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
        target_evidence=target_evidence,
    )

    write_yaml(coordination_analysis, run_dir / "control-structure-review.yaml")
    assembled_structure = control_structure
    semantic_result = apply_control_structure_semantic_review(
        control_structure,
        loss_analysis,
        coordination_analysis.semantic_review,
        use_case_text=use_case_text,
    )
    reviewed_loss_analysis = semantic_result.loss_analysis
    control_structure = semantic_result.control_structure

    # The reviewed graph is the graph in force: it is what Stage 2 uses and
    # what replaces the canonical ``loss-analysis.yaml``.  Persist it under its
    # own name before the offline re-check so the evidence is always the exact
    # graph the gate evaluated.  The pre-review merged graph stays available as
    # ``loss-analysis-draft.yaml``.  The canonical name is written once, after
    # the re-check, with whichever graph is in force.  Failing closed leaves an
    # internally consistent run: the gates artifact names the still-failing
    # checks and the canonical artifact holds that same graph, instead of a
    # stale pre-review graph that silently keeps an edge the gate rejected.
    write_yaml(reviewed_loss_analysis, run_dir / "loss-analysis-reviewed.yaml")

    # Fail closed before completing the stage: the semantic review may reword
    # hazards or constraints, or replace constraint hazard edges, and could
    # silently undo the Phase 1 density gates that the Stage 1a artifact
    # recorded as passed.  The offline re-check records its second report in
    # the gates artifact and raises when the reviewed graph regresses.
    try:
        if post_review_density_check is not None:
            review_in_force = coordination_analysis.semantic_review

            def correct_review(
                failing_checks: tuple[str, ...],
                hazard_ids: tuple[str, ...],
                constraint_ids: tuple[str, ...],
            ) -> LossAnalysis:
                # One more Call 3 with the exact failing checks.  Only the review
                # rows of the scoped records are taken from the new response;
                # every other decision and the coordination links stay as first
                # reviewed, and the merged review passes the same application
                # validators as the first one.
                nonlocal semantic_result, review_in_force
                corrected = _call_3_coordination(
                    llm_client=llm_client,
                    use_case_text=use_case_text,
                    control_structure=assembled_structure,
                    loss_analysis=loss_analysis,
                    run_dir=run_dir,
                    loader=loader,
                    temperature=temperature,
                    correction_feedback=_density_correction_feedback(
                        failing_checks, hazard_ids, constraint_ids
                    ),
                    step="call_3_density_correction",
                    target_evidence=target_evidence,
                )
                merged_review = _merge_scoped_review_rows(
                    coordination_analysis.semantic_review,
                    corrected.semantic_review,
                    hazard_ids=set(hazard_ids),
                    constraint_ids=set(constraint_ids),
                )
                try:
                    result = apply_control_structure_semantic_review(
                        assembled_structure,
                        loss_analysis,
                        merged_review,
                        use_case_text=use_case_text,
                    )
                except ValueError as exc:
                    raise StageError(
                        stage=STAGE,
                        step="call_3_density_correction",
                        message=f"corrected review failed application: {exc}",
                    ) from exc
                write_yaml(
                    coordination_analysis.model_copy(
                        update={"semantic_review": merged_review}
                    ),
                    run_dir / "control-structure-review-corrected.yaml",
                )
                write_yaml(
                    result.loss_analysis,
                    run_dir / "loss-analysis-reviewed-corrected.yaml",
                )
                semantic_result = result
                review_in_force = merged_review
                return result.loss_analysis

            post_review_density_check(
                reviewed_loss_analysis,
                correct_review,
                lambda: review_in_force.unresolved_ids(),
            )
            reviewed_loss_analysis = semantic_result.loss_analysis
            control_structure = semantic_result.control_structure
    finally:
        write_yaml(semantic_result.loss_analysis, run_dir / "loss-analysis.yaml")

    # Add coordination links to the ControlStructure
    control_structure = _add_coordination_links(
        control_structure,
        coordination_analysis,
        run_dir,
        llm_client.model,
        assembly_source_id_maps,
        call_log=call_log_of(llm_client),
    )

    write_yaml(control_structure, run_dir / "control-structure-reviewed.yaml")
    write_yaml(control_structure, run_dir / "control-structure.yaml")
    return ControlStructureDerivationResult(
        loss_analysis=reviewed_loss_analysis,
        control_structure=control_structure,
        warnings=repair_warnings,
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
    response_parser: (
        Callable[[Any, list[dict[str, Any]]], _Stage2ModelT] | None
    ) = None,
    user_prompt_suffix: str = "",
    recover: (
        Callable[[CallOutcome[_Stage2ModelT], str, str], _Stage2ModelT | None] | None
    ) = None,
) -> _Stage2ModelT:
    """Render prompts, call the LLM, validate, and raise StageError on failure.

    Shared backbone for the four Stage 2 LLM calls (Call 1, 2a, 2b, 3).
    Each call renders a system + user prompt, invokes the LLM via
    ``call_with_policy``, and raises ``StageError`` if the call or validation
    fails.  ``recover`` receives a failed outcome with the system and user
    prompts and may return a model from a follow-up request instead.
    """
    system_prompt = loader.render_prompt(system_template)
    user_prompt = (
        loader.render_prompt(user_template, **user_prompt_kwargs) + user_prompt_suffix
    )

    outcome = call_with_policy(
        llm_client=llm_client,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        response_format=response_format,
        run_dir=run_dir,
        stage=STAGE,
        step=step,
        policy=CorrectionPolicy(
            json_retries=JSON_DECODE_RETRIES,
            validation_retries=1,
            feedback=_INTERMEDIATE_VALIDATION_RETRY_FEEDBACK,
            include_schema=False,
            include_response=True,
        ),
        temperature=temperature,
        allow_unvalidated=allow_unvalidated,
        raw_result_validator=raw_result_validator,
        response_parser=response_parser,
        result_validator=result_validator,
    )
    if outcome.error is not None and recover is not None:
        recovered = recover(outcome, system_prompt, user_prompt)
        if recovered is not None:
            return recovered
    if outcome.error is not None:
        raise StageError(stage=STAGE, step=step, message=outcome.error)
    return outcome.value  # type: ignore[return-value]


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
    target_evidence: TargetEvidence | None = None,
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
            "target_evidence": target_evidence,
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
    target_evidence: TargetEvidence | None = None,
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
            "target_evidence": target_evidence,
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
        raw_result_validator=_validate_responsibility_wire,
        result_parser_with_cleanup=_parse_responsibility_result,
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
    target_evidence: TargetEvidence | None = None,
) -> ControlElementSet:
    """Run Call 2b: derive control actions, feedback channels, and controlled processes.

    Raises:
        StageError: If the LLM call fails or the response fails validation.
    """

    def parse(result: LLMResult) -> ControlElementSet:
        return parse_control_element_set_response(
            result.content, responsibilities=responsibility_set.responsibilities
        )

    def correct_references(
        outcome: CallOutcome[ControlElementSet], system_prompt: str, user_prompt: str
    ) -> ControlElementSet | None:
        return _correct_call_2b_references(
            outcome,
            llm_client=llm_client,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            responsibilities=responsibility_set.responsibilities,
            parse=parse,
            run_dir=run_dir,
            loader=loader,
            temperature=temperature,
        )

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
            "target_evidence": target_evidence,
        },
        response_format=_ControlElementProviderSet,
        step="call_2b_control_elements",
        # Call 2b is semantic output.  Its stage-local parser rejects unknown
        # carriers and missing meaning before canonical IDs are repaired.
        response_parser=parse,
        recover=correct_references,
    )


def _correct_call_2b_references(
    outcome: CallOutcome[ControlElementSet],
    *,
    llm_client: LLMClient,
    system_prompt: str,
    user_prompt: str,
    responsibilities: Sequence[Responsibility],
    parse: Callable[[LLMResult], ControlElementSet],
    run_dir: Path,
    loader: TemplateLoader,
    temperature: float,
) -> ControlElementSet | None:
    """Send the one reference correction for a Call 2b response, or decline.

    It runs only when the generic correction is spent and the last response
    still names unknown targets, sources or process model parts.  The request
    names each unknown reference, offers the valid IDs with their
    descriptions, and continues the step's attempt numbering.  Every other
    failure is declined so the caller stops as before.
    """
    failure = outcome.failure
    if not isinstance(failure, UnknownReferenceError) or outcome.result is None:
        return None
    owners = {item.owner for item in failure.references if item.owner is not None}
    feedback = "\n\n" + loader.render_prompt(
        "stage2_call2b_reference_correction.j2",
        unknown_references=failure.references,
        responsibilities=responsibilities,
        controlled_processes=failure.controlled_processes,
        process_model_owners=[
            responsibility
            for responsibility in responsibilities
            if responsibility.resp_id in owners
        ],
    )
    corrected = call_with_policy(
        llm_client=llm_client,
        system_prompt=system_prompt,
        user_prompt=correction_prompt(
            original_prompt=user_prompt,
            feedback=feedback,
            error=failure,
            response_format=_ControlElementProviderSet,
            include_schema=False,
            prior_result=outcome.result,
            include_prior_response=True,
        ),
        response_format=_ControlElementProviderSet,
        run_dir=run_dir,
        stage=STAGE,
        step="call_2b_control_elements",
        policy=CorrectionPolicy(),
        temperature=temperature,
        result_parser=parse,
        first_attempt_number=outcome.attempt_number + 1,
    )
    if corrected.error is not None:
        raise StageError(
            stage=STAGE, step="call_2b_control_elements", message=corrected.error
        )
    return corrected.value


# ---------------------------------------------------------------------------
# Call 3 — Coordination + integrity
# ---------------------------------------------------------------------------


def _deterministic_integrity_findings(
    control_structure: ControlStructure,
    loss_analysis: LossAnalysis,
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
    loss_analysis: LossAnalysis,
    run_dir: Path,
    loader: TemplateLoader,
    temperature: float,
    correction_feedback: str = "",
    step: str = "call_3_coordination",
    target_evidence: TargetEvidence | None = None,
) -> CoordinationAnalysis:
    """Run Call 3: identify coordination links using deterministic diagnostics.

    Returns a CoordinationAnalysis containing coordination links and the
    deterministic structural findings supplied to the prompt. The provider
    reviews coordination and semantic adequacy; it does not recompute or
    author the integrity list.  ``correction_feedback`` is appended to the
    rendered user prompt for the post-review density correction round.

    Raises:
        StageError: If the LLM call fails or the response fails validation.
    """
    source_excerpts = _build_call3_source_excerpts(use_case_text, loss_analysis)
    integrity_findings = _deterministic_integrity_findings(
        control_structure, loss_analysis
    )
    source_ref_by_canonical = {
        excerpt.canonical_ref: excerpt.local_ref for excerpt in source_excerpts
    }
    response_format = _coordination_provider_schema(
        control_structure,
        loss_analysis,
        use_case_text=use_case_text,
        source_excerpts=source_excerpts,
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
            "target_evidence": target_evidence,
        },
        response_format=response_format,
        step=step,
        user_prompt_suffix=correction_feedback,
        result_validator=lambda value: _validate_semantic_review_response(
            value,
            control_structure,
            loss_analysis,
            use_case_text=use_case_text,
        ),
        response_parser=lambda result, _cleanup: _parse_call3_source_selection(
            result,
            source_excerpts,
            structure=control_structure,
            loss_analysis=loss_analysis,
        ),
    )
    # The durable record receives the structural check actually performed
    # above; the current provider wire cannot supply integrity findings.
    return analysis.model_copy(update={"integrity_findings": list(integrity_findings)})


_DENSITY_CORRECTION_INSTRUCTIONS = """

## Correction Request

Your previous semantic review was applied, and the deterministic hazard-graph
density gate then failed these checks:

{checks}

Every hazard you `preserve` or `revise` needs at least one security
constraint, and every constraint you `preserve` or `revise` needs at least
one hazard. A constraint may not reference a hazard you mark `unresolved`, so
a kept constraint whose only hazard is unresolved fails the gate. A record
you mark `unresolved` is recorded with its missing fact and does not fail
the gate.

Review again only these records: {records}. For each one, decide again from
the supplied sources:

- `preserve` or `revise` it with exact source evidence, and select its hazard
  edges among hazards you do not mark `unresolved`; or
- mark it `unresolved` when the sources genuinely lack the fact. Do not
  resolve a record only to satisfy the gate.

Return the complete review object in the same format. Deterministic code
keeps your earlier decisions for every record not listed above and your
earlier coordination links.
"""


def _density_correction_feedback(
    failing_checks: tuple[str, ...],
    hazard_ids: tuple[str, ...],
    constraint_ids: tuple[str, ...],
) -> str:
    """Render the post-review density correction request."""
    return _DENSITY_CORRECTION_INSTRUCTIONS.format(
        checks="\n".join(f"- {check}" for check in failing_checks),
        records=", ".join((*hazard_ids, *constraint_ids)),
    )


def _merge_scoped_review_rows(
    original: ControlStructureSemanticReview,
    corrected: ControlStructureSemanticReview,
    *,
    hazard_ids: set[str],
    constraint_ids: set[str],
) -> ControlStructureSemanticReview:
    """Take only the scoped hazard and constraint rows from ``corrected``."""
    corrected_hazards = {row.hazard_id: row for row in corrected.hazards}
    corrected_constraints = {row.constraint_id: row for row in corrected.constraints}
    return original.model_copy(
        update={
            "hazards": tuple(
                corrected_hazards.get(row.hazard_id, row)
                if row.hazard_id in hazard_ids
                else row
                for row in original.hazards
            ),
            "constraints": tuple(
                corrected_constraints.get(row.constraint_id, row)
                if row.constraint_id in constraint_ids
                else row
                for row in original.constraints
            ),
        }
    )


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
    analysis = CoordinationAnalysis.model_validate(value)
    errors = _coordination_ownership_errors(structure, analysis.coordination_links)
    if errors:
        raise ValueError("; ".join(errors))


def _coordination_ownership_errors(
    structure: ControlStructure, links: Sequence[CoordinationLink]
) -> list[str]:
    """Describe every link whose shared PM is not owned by one endpoint.

    The retry prompt only sees this message, so each entry names the actual
    owner and the endpoint PM identifiers the link may use instead.
    """
    from asago_scenario_generator.stpa.models.control_structure import (
        coordination_process_model_owner,
    )

    owner_by_pm = {
        pm.pm_id: resp.resp_id
        for resp in structure.responsibilities
        for pm in resp.process_model_parts
    }
    pms_by_resp = {
        resp.resp_id: [pm.pm_id for pm in resp.process_model_parts]
        for resp in structure.responsibilities
    }
    errors: list[str] = []
    for link in links:
        try:
            coordination_process_model_owner(structure, link)
        except ValueError as exc:
            errors.append(
                _ownership_error_message(
                    exc, link, owner_by_pm.get(link.shared_pm), pms_by_resp
                )
            )
    return errors


def _ownership_error_message(
    exc: ValueError,
    link: CoordinationLink,
    owner: str | None,
    pms_by_resp: dict[str, list[str]],
) -> str:
    """Name the shared PM's actual owner and the endpoint PMs the link may use."""
    location = (
        f"belongs to {owner}"
        if owner is not None
        else "is not a process-model part of any responsibility"
    )
    choices = [
        pm_id
        for resp_id in dict.fromkeys((link.source, link.target))
        for pm_id in pms_by_resp.get(resp_id, [])
    ]
    remedy = (
        f"use a PM listed under {link.source} or {link.target} "
        f"({', '.join(choices) if choices else 'none listed'})"
    )
    if owner is not None:
        remedy += f", or make {owner} an endpoint of the link"
    return (
        f"{exc}: '{link.shared_pm}' {location} "
        f"(link {link.source} -> {link.target}); {remedy}"
    )
