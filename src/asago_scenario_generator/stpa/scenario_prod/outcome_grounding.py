"""Keep literal provenance distinct from the model's interpretation of a rule.

Exact quotation checks establish source presence, not that a comparison faithfully
interprets a policy. The interpretation remains an explicit model-authored claim.
"""

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictStr

from asago_scenario_generator.stpa.models.semantic_conditions import (
    ActionValueCondition,
    SemanticBindingPlaceholder,
    SemanticCondition,
    StateValueCondition,
)

from .target_observations import TargetObservationSnapshot


class ComparisonEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    source_ref: StrictStr = Field(min_length=1)
    quote: StrictStr = Field(min_length=1, max_length=600)
    rationale: StrictStr = Field(min_length=1, max_length=600)


GroundingOrigin = Literal[
    "provider_evidence",
    "deterministic_observed_json_presence",
    "typed_placeholder",
    "model_output_predicate",
    "unresolved",
    "not_applicable",
]
GroundingStatus = Literal["grounded", "parameterized", "not_applicable"]


@dataclass(frozen=True)
class OutcomeGroundingResolution:
    """One deterministic outcome resolution plus its audit provenance."""

    condition: SemanticCondition
    origin: GroundingOrigin
    status: GroundingStatus
    source_text: str | None = None
    matched_observation_refs: tuple[str, ...] = ()
    matched_json_paths: tuple[str, ...] = ()

    @property
    def matched_observation_count(self) -> int:
        """Return the number of distinct observations with exact matches."""
        return len(self.matched_observation_refs)


class OutcomeGroundingRecord(BaseModel):
    """Audit evidence, separate from execution decisions and observed results."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    scenario_id: str
    context_digest: str
    target_observation_digest: str | None = None
    proposed_condition: SemanticCondition
    compiled_condition: SemanticCondition
    evidence: ComparisonEvidence | None
    source_text: str | None
    grounding_origin: GroundingOrigin
    grounding_status: GroundingStatus
    matched_observation_refs: tuple[str, ...] = ()
    matched_json_paths: tuple[str, ...] = ()
    interpretation_independently_verified: bool = False


def _literal_is_quoted(value: object, quote: str) -> bool:
    # Strings must actually be quoted, not merely a substring of another value.
    literal = json.dumps(value, ensure_ascii=False, allow_nan=False)
    if isinstance(value, str):
        return literal in quote
    return (
        re.search(r'(?<!["\w.+-])' + re.escape(literal) + r'(?!["\w]|\.\d)', quote)
        is not None
    )


def _has_source(
    value: object, evidence: ComparisonEvidence | None, sources: Mapping[str, str]
) -> bool:
    if evidence is None:
        return False
    source = sources.get(evidence.source_ref)
    if source is None or evidence.quote not in source:
        return False
    if _literal_is_quoted(value, evidence.quote):
        return True
    return (
        isinstance(value, str)
        and evidence.quote == value
        and _json_source_contains_string(value, source)
    )


def _json_source_contains_string(expected: str, source: str) -> bool:
    """Check one bare citation against exact JSON string values or object keys."""
    try:
        parsed = json.loads(source)
    except (TypeError, ValueError):
        return False
    return _json_value_contains_string(expected, parsed)


def _json_value_contains_string(expected: str, value: object) -> bool:
    return bool(_json_match_paths(expected, value))


def _json_match_paths(
    expected: object, value: object, path: str = ""
) -> tuple[str, ...]:
    """Return exact JSON scalar/key paths for one expected typed value.

    Paths use RFC 6901 JSON Pointer escaping.  ``value:`` and ``key:`` keep
    an object-key match distinct from a value at the same pointer.
    """
    paths: list[str] = []
    if _json_scalar_matches(expected, value):
        paths.append(f"value:{path}")
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}/{_escape_json_pointer_part(key)}"
            if isinstance(expected, str) and key == expected:
                paths.append(f"key:{child_path}")
            paths.extend(_json_match_paths(expected, child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            paths.extend(_json_match_paths(expected, child, f"{path}/{index}"))
    return tuple(paths)


def _escape_json_pointer_part(value: str) -> str:
    """Escape one object key according to RFC 6901."""
    return value.replace("~", "~0").replace("/", "~1")


def _json_scalar_matches(expected: object, actual: object) -> bool:
    """Compare JSON scalars without bool/int coercion or string conversion."""
    if type(expected) is not type(actual):
        return False
    return isinstance(expected, (str, bool, int, float)) and expected == actual


def _observed_json_matches(
    expected: object,
    target_observations: TargetObservationSnapshot | None,
) -> tuple[tuple[str, ...], tuple[str, ...], dict[str, str]]:
    """Collect exact matches from JSON observations, preserving every path."""
    refs: list[str] = []
    paths: list[str] = []
    source_texts: dict[str, str] = {}
    if target_observations is None:
        return (), (), {}
    for observation in target_observations.observations:
        if observation.content_format != "json":
            continue
        reference = observation.observation_ref
        content = observation.content
        try:
            parsed = json.loads(content)
        except (TypeError, ValueError):
            continue
        found = _json_match_paths(expected, parsed)
        if not found:
            continue
        refs.append(reference)
        paths.extend(f"{reference}:{path}" for path in found)
        source_texts[reference] = content
    return tuple(refs), tuple(paths), source_texts


def resolve_outcome_grounding(
    condition: SemanticCondition,
    evidence: ComparisonEvidence | None,
    sources: Mapping[str, str],
    *,
    model_output: bool,
    proposition: str | None,
    target_observations: TargetObservationSnapshot | None = None,
) -> OutcomeGroundingResolution:
    """Resolve one outcome and retain the exact evidence provenance."""
    if not isinstance(condition, (ActionValueCondition, StateValueCondition)):
        return OutcomeGroundingResolution(
            condition=condition,
            origin="not_applicable",
            status="not_applicable",
        )
    if isinstance(condition.expected, SemanticBindingPlaceholder):
        return OutcomeGroundingResolution(
            condition=condition,
            origin="typed_placeholder",
            status="parameterized",
            source_text=(sources.get(evidence.source_ref) if evidence else None),
        )
    if _is_output_predicate(condition, model_output):
        return OutcomeGroundingResolution(
            condition=condition,
            origin="model_output_predicate",
            status="grounded",
            source_text=(sources.get(evidence.source_ref) if evidence else None),
        )
    if evidence is not None:
        if _has_source(condition.expected, evidence, sources):
            return OutcomeGroundingResolution(
                condition=condition,
                origin="provider_evidence",
                status="grounded",
                source_text=sources.get(evidence.source_ref),
            )
        return OutcomeGroundingResolution(
            condition=_unknown_reference(condition, proposition),
            origin="provider_evidence",
            status="parameterized",
            source_text=sources.get(evidence.source_ref),
        )
    refs, paths, source_texts = _observed_json_matches(
        condition.expected,
        target_observations,
    )
    if refs:
        # Preserve every matching witness.  When several observations carry
        # the same exact value, the pinned snapshot is the complete source;
        # the single-text audit field cannot represent multiple source bodies.
        source_text = source_texts[refs[0]] if len(refs) == 1 else None
        return OutcomeGroundingResolution(
            condition=condition,
            origin="deterministic_observed_json_presence",
            status="grounded",
            source_text=source_text,
            matched_observation_refs=refs,
            matched_json_paths=paths,
        )
    return OutcomeGroundingResolution(
        condition=_unknown_reference(condition, proposition),
        origin=("deterministic_observed_json_presence" if refs else "unresolved"),
        status="parameterized",
        matched_observation_refs=refs,
        matched_json_paths=paths,
    )


def _is_output_predicate(condition, model_output: bool) -> bool:
    return (
        model_output
        and isinstance(condition, ActionValueCondition)
        and condition.property == "semantic_proposition"
        and condition.operator == "equals"
        and condition.expected is True
    )


def _unknown_reference(condition, proposition: str | None) -> SemanticCondition:
    value_type = {str: "string", int: "integer", float: "number", bool: "boolean"}[
        type(condition.expected)
    ]
    unknown = SemanticBindingPlaceholder(
        binding_ref="SEM-OUTCOME-VALUE",
        value_type=value_type,
        description=(
            f"Source-backed reference value for {condition.property}; "
            f"criterion: {proposition or 'the supplied unsafe outcome'}. "
            "No matching literal was established in the supplied source evidence."
        ),
    )
    return type(condition).model_validate(
        {**condition.model_dump(), "expected": unknown}
    )


def scope_temporal_placeholder(
    value: object,
    scope: str,
    field_name: str,
) -> object:
    """Scope one temporal placeholder without changing its typed metadata."""
    if not isinstance(value, SemanticBindingPlaceholder):
        return value
    binding_ref = value.binding_ref
    # Stage 5 uses exact occurrence
    # namespaces (``factor-1`` … ``factor-N`` and ``outcome``).  Only the
    # matching field namespace is idempotent; a provider may have copied an
    # outcome reference into a factor, and that occurrence must still be
    # independently bindable.
    expected_prefix = f"SEM-{scope}-{field_name}-"
    if binding_ref.startswith(expected_prefix):
        return value
    base = binding_ref.removeprefix("SEM-")
    return value.model_copy(update={"binding_ref": f"SEM-{scope}-{field_name}-{base}"})
