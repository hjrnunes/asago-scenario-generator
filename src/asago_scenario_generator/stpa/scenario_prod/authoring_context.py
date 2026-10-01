"""Request-local context and admissible-choice index for current authoring.

This module is deliberately independent of the historical provider wire.  It
turns the supplied target state and observations into bounded, explained
handles.  A provider selects handles; it never writes paths, source bytes, or
obligation references into the current answer.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal

from asago_scenario_generator.models.canonical import canonical_json_bytes
from asago_scenario_generator.stpa.models.execution_classification import (
    ExecutionTargetProfile,
)
from asago_scenario_generator.stpa.models.target_subject_model import (
    SessionSubject,
    TargetSubjectModel,
)
from asago_scenario_generator.stpa.scenario_prod.authoring_types import (
    render_oracle_text,
)

MAX_STATE_FACT_HANDLES = 512
MAX_OBSERVATION_HANDLES = 256
OMISSION_PROPOSITION_LIMIT = 600


class AuthoringContextError(ValueError):
    """The supplied run inputs cannot form a closed current authoring context."""


@dataclass(frozen=True)
class SourceHandle:
    """One explained, request-local source selection.

    ``kind`` is ``state_fact`` for a target-state path and ``observation`` for
    a leaf selected from one supplied observation.  Observation handles retain
    the root observation reference and exact content so the adapter can copy
    the source bytes without asking the provider to quote them.
    """

    handle: str
    kind: Literal["state_fact", "observation"]
    path: tuple[str, ...]
    value: Any
    explanation: str
    observation_ref: str | None = None
    observation_content: str | None = None

    @property
    def numeric(self) -> bool:
        return isinstance(self.value, (int, float)) and not isinstance(self.value, bool)

    @property
    def canonical_value(self) -> str:
        """Return the exact canonical source representation used by the adapter."""
        if isinstance(self.value, str):
            return self.value
        return canonical_json_bytes(self.value).decode("utf-8")

    @property
    def display_value(self) -> str:
        """Return a typed JSON rendering for the provider-facing prompt."""
        return canonical_json_bytes(self.value).decode("utf-8")


@dataclass(frozen=True)
class ReferenceToolChoice:
    """One closed reference-tool choice for a ``tool_order`` check."""

    handle: str
    tool: str
    shared_arguments: tuple[str, ...]


@dataclass(frozen=True)
class AdmissibleCheck:
    """A complete model-visible choice for one oracle kind.

    The choice combines the obligation entry, oracle kind, fixed action, and
    operand restrictions.  The provider sees this exact set, so changing a
    reviewed obligation-to-action binding changes the prompt and the valid
    handle universe together.
    """

    handle: str
    kind: str
    obligation_ref: str | None
    action_name: str
    basis: str
    operators: tuple[str, ...] = ()
    operand_sources: tuple[str, ...] = ()
    reference_tools: tuple[ReferenceToolChoice, ...] = ()


@dataclass(frozen=True)
class AuthoringContentBudget:
    """The fixed compiler allowance exposed to the current provider."""

    total_characters: int
    fixed_compiler_characters: int
    model_content_characters: int


@dataclass(frozen=True)
class AuthoringContext:
    """Immutable current authoring inputs and their closed index."""

    candidate: Any
    state: dict[str, Any]
    observation_records: tuple[dict[str, str], ...]
    source_handles: tuple[SourceHandle, ...]
    checks: tuple[AdmissibleCheck, ...]
    unavailable_checks: tuple[tuple[str, str, str], ...]
    reference_tools: tuple[ReferenceToolChoice, ...]
    session: SessionSubject
    profile: ExecutionTargetProfile
    subject_model: TargetSubjectModel | None
    omission_budget: AuthoringContentBudget

    @property
    def state_handles(self) -> tuple[SourceHandle, ...]:
        return tuple(item for item in self.source_handles if item.kind == "state_fact")

    @property
    def observation_handles(self) -> tuple[SourceHandle, ...]:
        return tuple(item for item in self.source_handles if item.kind == "observation")

    @property
    def conversation_allowed(self) -> bool:
        """Whether this action has an accepted subject role for conversation tests.

        Conversation context is useful only when the target action has a
        declared subject argument whose interpretation can carry the earlier
        identity or record premise.  Keep this request-local admission beside
        the indexed action and subject model so the provider schema and prompt
        use the same rule.
        """
        if self.candidate.action_binding.kind != "tool_call":
            return False
        if self.subject_model is None:
            return False
        action_name = self.candidate.action_name
        return any(
            self.subject_model.role_for(action_name, argument) is not None
            for argument in self.candidate.action_binding.argument_names
        )

    @property
    def checks_by_kind(self) -> dict[str, tuple[AdmissibleCheck, ...]]:
        grouped: dict[str, list[AdmissibleCheck]] = {}
        for check in self.checks:
            grouped.setdefault(check.kind, []).append(check)
        return {kind: tuple(rows) for kind, rows in grouped.items()}

    def source(self, handle: str, *, kind: str | None = None) -> SourceHandle:
        """Resolve one provider-selected handle, optionally by source kind."""
        matches = [item for item in self.source_handles if item.handle == handle]
        if kind is not None:
            matches = [item for item in matches if item.kind == kind]
        if len(matches) != 1:
            qualifier = f" of kind {kind!r}" if kind else ""
            raise AuthoringContextError(
                f"unknown or ambiguous authoring source handle {handle!r}{qualifier}"
            )
        return matches[0]

    def check(self, handle: str, *, kind: str | None = None) -> AdmissibleCheck:
        """Resolve one provider-selected admissible check handle."""
        matches = [item for item in self.checks if item.handle == handle]
        if kind is not None:
            matches = [item for item in matches if item.kind == kind]
        if len(matches) != 1:
            qualifier = f" of kind {kind!r}" if kind else ""
            raise AuthoringContextError(
                f"unknown or ambiguous authoring choice handle {handle!r}{qualifier}"
            )
        return matches[0]

    def reference_tool(self, handle: str) -> ReferenceToolChoice:
        matches = [item for item in self.reference_tools if item.handle == handle]
        if len(matches) != 1:
            raise AuthoringContextError(
                f"unknown or ambiguous reference-tool handle {handle!r}"
            )
        return matches[0]


def _walk_leaves(
    value: Any, path: tuple[str, ...] = ()
) -> list[tuple[tuple[str, ...], Any]]:
    """Enumerate every supplied value with mapping keys and list indexes."""
    if isinstance(value, Mapping):
        if not value:
            return [(path, {})]
        leaves: list[tuple[tuple[str, ...], Any]] = []
        for key in sorted(value, key=str):
            leaves.extend(_walk_leaves(value[key], path + (str(key),)))
        return leaves
    if isinstance(value, list):
        if not value:
            return [(path, [])]
        leaves = []
        for index, item in enumerate(value):
            leaves.extend(_walk_leaves(item, path + (str(index),)))
        return leaves
    return [(path, value)]


def _source_explanation(kind: str, path: tuple[str, ...], value: Any) -> str:
    encoded = canonical_json_bytes(value).decode("utf-8")
    label = "TARGET-STATE" if kind == "state_fact" else "policy observation"
    return f"{label} value at path {list(path)!r}: {encoded}"


def _state_handles(state: dict[str, Any]) -> tuple[SourceHandle, ...]:
    # The historical state-path contract requires at least one segment.  An
    # empty root object/list therefore has no usable state-fact handle, while
    # an empty container at a named path (for example ``{"items": {}}``)
    # remains a legitimate source at ``("items",)``.
    leaves = [item for item in _walk_leaves(state) if item[0]]
    if len(leaves) > MAX_STATE_FACT_HANDLES:
        raise AuthoringContextError(
            f"target state exposes {len(leaves)} fact handles; the bounded "
            f"authoring context allows {MAX_STATE_FACT_HANDLES}"
        )
    return tuple(
        SourceHandle(
            handle=f"fact:{index}",
            kind="state_fact",
            path=path,
            value=value,
            explanation=_source_explanation("state_fact", path, value),
        )
        for index, (path, value) in enumerate(leaves, start=1)
    )


def _observation_handles(
    records: tuple[dict[str, str], ...],
) -> tuple[SourceHandle, ...]:
    handles: list[SourceHandle] = []
    for record_index, record in enumerate(records, start=1):
        reference = str(record.get("observation_ref") or "")
        content = record.get("content") or ""
        if not reference or not content:
            continue
        try:
            parsed = json.loads(content)
        except (TypeError, json.JSONDecodeError):
            parsed = content
        leaves = _walk_leaves(parsed)
        for leaf_index, (path, value) in enumerate(leaves, start=1):
            handles.append(
                SourceHandle(
                    # Keep provider handles opaque and collision-free;
                    # arbitrary JSON keys may contain slashes or equal
                    # ``root`` while the exact path remains explanatory.
                    handle=f"observation:{record_index}:{leaf_index}",
                    kind="observation",
                    path=path,
                    value=value,
                    explanation=(
                        f"observation {reference!r} value at path {list(path)!r}: "
                        f"{canonical_json_bytes(value).decode('utf-8')}"
                    ),
                    observation_ref=reference,
                    observation_content=content,
                )
            )
    if len(handles) > MAX_OBSERVATION_HANDLES:
        raise AuthoringContextError(
            f"policy observations expose {len(handles)} fact handles; the bounded "
            f"authoring context allows {MAX_OBSERVATION_HANDLES}"
        )
    return tuple(handles)


def _reference_tools(
    profile: ExecutionTargetProfile, candidate: Any
) -> tuple[ReferenceToolChoice, ...]:
    if candidate.action_binding.kind != "tool_call":
        return ()
    action_arguments = set(candidate.action_binding.argument_names)
    choices: list[ReferenceToolChoice] = []
    for resource in profile.resources:
        if resource.tool_name is None or resource.tool_name == candidate.action_name:
            continue
        shared = tuple(
            name for name in resource.argument_names if name in action_arguments
        )
        if shared:
            choices.append(
                ReferenceToolChoice(
                    handle=f"reference:{resource.tool_name}",
                    tool=resource.tool_name,
                    shared_arguments=shared,
                )
            )
    return tuple(sorted(choices, key=lambda item: item.tool))


def choice_handle(index: int) -> str:
    """Return an opaque request-local handle for one admissible choice."""
    return f"choice:{index}"


def operand_sources_for_choice(
    kind: str,
    operators: tuple[str, ...],
    available_sources: frozenset[str],
) -> tuple[str, ...]:
    if kind not in {"tool_argument", "tool_order"}:
        return ()
    if "owner_differs_from_session" in operators and len(operators) == 1:
        # The operand is the record address (for example ``LOAN-201``), not
        # an arbitrary leaf from that record.  RecordIndex and the accepted
        # subject model own the relation from that address to its owner.  A
        # generic state leaf such as ``member_id`` would instead pass the
        # owner value where the tool expects the record id.
        return ("literal",)
    return tuple(
        source
        for source in ("literal", "state_fact", "observation")
        if source == "literal" or source in available_sources
    )


def omission_budget(action_name: str) -> AuthoringContentBudget:
    """Compute the usable model allowance after fixed omission rendering."""
    fixed = len(
        render_oracle_text(
            "tool_absent_with_evidence", tool=action_name, trigger="", evidence=""
        )
    )
    return AuthoringContentBudget(
        total_characters=OMISSION_PROPOSITION_LIMIT,
        fixed_compiler_characters=fixed,
        model_content_characters=max(0, OMISSION_PROPOSITION_LIMIT - fixed),
    )


def build_authoring_context(
    candidate: Any,
    *,
    state: dict[str, Any],
    observation_records: tuple[dict[str, str], ...],
    session: SessionSubject,
    profile: ExecutionTargetProfile,
    subject_model: TargetSubjectModel | None = None,
    reviewed_bindings: frozenset[tuple[str, str, str]] = frozenset(),
    checks: tuple[AdmissibleCheck, ...] = (),
    unavailable_checks: tuple[tuple[str, str, str], ...] = (),
) -> AuthoringContext:
    """Build the low-level source index from exactly the supplied run inputs.

    Admission is intentionally resolved by the orchestration layer.  Callers
    that need a provider-ready context should pass the resulting ``checks``
    and ``unavailable_checks``; the retained ``reviewed_bindings`` keyword is
    accepted for compatibility with older direct callers but is not consulted
    by this source-index layer.
    """
    state_handles = _state_handles(state)
    observation_handles = _observation_handles(observation_records)
    references = _reference_tools(profile, candidate)
    return AuthoringContext(
        candidate=candidate,
        state=dict(state),
        observation_records=tuple(dict(record) for record in observation_records),
        source_handles=state_handles + observation_handles,
        checks=checks,
        unavailable_checks=unavailable_checks,
        reference_tools=references,
        session=session,
        profile=profile,
        subject_model=subject_model,
        omission_budget=omission_budget(candidate.action_name),
    )


__all__ = [
    "AdmissibleCheck",
    "AuthoringContentBudget",
    "AuthoringContext",
    "AuthoringContextError",
    "MAX_OBSERVATION_HANDLES",
    "MAX_STATE_FACT_HANDLES",
    "OMISSION_PROPOSITION_LIMIT",
    "ReferenceToolChoice",
    "SourceHandle",
    "build_authoring_context",
    "choice_handle",
    "omission_budget",
    "operand_sources_for_choice",
]
