"""ControlStructure boundary schema (Section 4.2 of the STPA-Sec foundation spec).

SP1 output, consumed by SP2 and SP3.

Cross-reference validation is done in Pydantic validators. Structural
heuristics are **separate** deterministic post-checks (``check_structural_heuristics``)
because the Gherkin distinguishes "the control structure is validated"
vs "the control structure structural heuristics are checked".
"""

from __future__ import annotations

import itertools
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import TYPE_CHECKING, Annotated

from pydantic import (
    AfterValidator,
    BaseModel,
    Field,
    StrictStr,
    ValidationError,
    ValidationInfo,
    ValidatorFunctionWrapHandler,
    field_validator,
    model_validator,
)

from asago_scenario_generator.stpa.models._validation import check_duplicate_ids

if TYPE_CHECKING:
    from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis


ASSEMBLY_DEFERRED: Mapping[str, bool] = MappingProxyType({"defer_to_assembly": True})
"""Validation context for Stage 2 model output.

Stage 2 parses model output before ``id_normalization`` renumbers its IDs by
structural position, and the assembled ``ControlStructure`` validates the
result. Passing this context keeps each ID as written instead of rejecting its
format; every other field rule still applies.
"""


def _assembly_deferred(info: ValidationInfo | None) -> bool:
    """Return whether *info* carries the :data:`ASSEMBLY_DEFERRED` context."""
    context = info.context if info is not None else None
    return bool(context and context.get("defer_to_assembly"))


def _non_blank(value: str) -> str:
    """Require a visible character while keeping the string exactly."""
    if not value.strip():
        raise ValueError("must be a non-empty string")
    return value


NonBlankStr = Annotated[StrictStr, AfterValidator(_non_blank)]
"""Model-written text that must show a character; the string is kept as written."""


def _keep_when_deferred(
    value: object, handler: ValidatorFunctionWrapHandler, info: ValidationInfo
) -> object:
    """Validate *value*, or keep an invalid string under ASSEMBLY_DEFERRED."""
    try:
        return handler(value)
    except ValidationError:
        if _assembly_deferred(info) and isinstance(value, str):
            return value
        raise


def _validate_id_format(
    value: str,
    field_name: str,
    format_spec: str,
    example: str,
    pattern: str,
    info: ValidationInfo | None = None,
) -> str:
    """Validate that *value* matches the expected ID format.

    All control-structure ID fields share the same validation logic:
    regex-check the value and raise a descriptive ValueError on mismatch.
    This helper eliminates the per-field boilerplate while keeping each
    field's error message specific.

    Args:
        value: The ID string to validate.
        field_name: Human-readable field name for the error message.
        format_spec: Format placeholder (e.g. ``"RC-X-Y"``).
        example: Concrete example for the error message (e.g. ``"RC-1-1"``).
        pattern: Anchored regex pattern the value must match.
        info: Validation info; under :data:`ASSEMBLY_DEFERRED` the format
            check is skipped.

    Returns:
        The validated value (unchanged).

    Raises:
        ValueError: If *value* does not match *pattern*.
    """
    if _assembly_deferred(info):
        return value
    if not re.match(pattern, value):
        raise ValueError(
            f"{field_name} must match format '{format_spec}' "
            f"(e.g. '{example}'), got '{value}'"
        )
    return value


class ReferenceType(str, Enum):
    """Type of element referenced by an ElementRef."""

    responsibility = "responsibility"
    controlled_process = "controlled_process"


class ControlActionEffectKind(str, Enum):
    """Typed observable effect produced by a control action.

    The effect is intentionally independent of the action's prose description.
    Consumers can therefore select an execution observation without guessing
    from verbs such as ``send`` or ``update``.  ``None`` on a legacy action is
    retained as an analytical/legacy value; new Stage 2 output should provide
    one of these values explicitly.  The closed wire values mean:

    - ``model_output``: text or structured output returned to the caller;
    - ``tool_call``: a structured operation invocation emitted by the agent;
    - ``state_change``: a session or persistent state update;
    - ``agent_message``: an internal message to another controller;
    - ``environment_action``: an external side effect beyond output, invocation,
      or state mutation.
    """

    model_output = "model_output"
    tool_call = "tool_call"
    state_change = "state_change"
    agent_message = "agent_message"
    environment_action = "environment_action"


class ControlActionTemporality(str, Enum):
    """Typed temporal shape of a control action.

    ``continuous`` and ``bounded_duration`` actions have an observable
    duration.  ``instantaneous`` and ``discrete`` actions are point events;
    ``unknown`` is explicit uncertainty rather than an inferred duration.
    """

    instantaneous = "instantaneous"
    discrete = "discrete"
    continuous = "continuous"
    bounded_duration = "bounded_duration"
    unknown = "unknown"


class FeedbackSourceKind(str, Enum):
    """Where a feedback channel's information comes from (STPA-Sec inputs).

    The kind fixes the channel's trust: information the user or retrieved
    content supplies is untrusted, because an adversary can author it, and
    conversation history is an input path that carries earlier user turns.

    - ``operation_result``: record or state data returned by an operation;
    - ``session_context``: fields the runtime sets for the conversation;
    - ``user_message``: the current user message;
    - ``conversation_history``: earlier turns of the conversation;
    - ``retrieved_content``: free text retrieved from documents or sources;
    - ``other``: any other source named by the channel description.
    """

    operation_result = "operation_result"
    session_context = "session_context"
    user_message = "user_message"
    conversation_history = "conversation_history"
    retrieved_content = "retrieved_content"
    other = "other"


UNTRUSTED_FEEDBACK_SOURCES = frozenset(
    {
        FeedbackSourceKind.user_message,
        FeedbackSourceKind.conversation_history,
        FeedbackSourceKind.retrieved_content,
    }
)


def _empty(value: object) -> bool:
    return not value


class ElementRef(BaseModel):
    """A reference to a responsibility or controlled process."""

    type: ReferenceType
    id: str  # RESP-* or CP-*

    @field_validator("type", mode="wrap")
    @classmethod
    def keep_deferred_type(
        cls, value: object, handler: ValidatorFunctionWrapHandler, info: ValidationInfo
    ) -> object:
        """Under ASSEMBLY_DEFERRED, leave an unknown type for assembly to reject."""
        return _keep_when_deferred(value, handler, info)


class ResponsibilityConstraint(BaseModel):
    """A constraint on a responsibility."""

    rc_id: str  # RC-X-Y
    description: str = Field(min_length=1)

    @field_validator("rc_id")
    @classmethod
    def validate_rc_id_format(cls, v: str, info: ValidationInfo) -> str:
        return _validate_id_format(
            v, "rc_id", "RC-X-Y", "RC-1-1", r"^RC-\d+-\d+$", info
        )


class ProcessModelPart(BaseModel):
    """A part of a controller's process model."""

    pm_id: str  # PM-X-Y
    description: str = Field(min_length=1)
    feedback_source: ElementRef | None = None
    values: list[str] = Field(
        default_factory=list,
        exclude_if=_empty,
        description=(
            "Distinct values of this process-model variable that change a "
            "control decision; they span the variable's context-table rows."
        ),
    )
    evidence_refs: list[str] = Field(
        default_factory=list,
        exclude_if=_empty,
        description=(
            "Exact discovered-evidence references (state:, session:, "
            "argument:, policy:) the variable is read from."
        ),
    )

    @field_validator("pm_id")
    @classmethod
    def validate_pm_id_format(cls, v: str, info: ValidationInfo) -> str:
        return _validate_id_format(
            v, "pm_id", "PM-X-Y", "PM-1-1", r"^PM-\d+-\d+$", info
        )


def normalize_control_action_effect_kind(
    target: ElementRef | None,
    effect_kind: ControlActionEffectKind | None,
) -> ControlActionEffectKind | None:
    """Apply the deterministic responsibility-target effect rule.

    This helper is also used by tolerant Stage 2 parsing, whose recovery path
    intentionally uses ``model_construct`` and therefore bypasses Pydantic's
    model validators.  It accepts legacy missing values but never silently
    changes an explicitly conflicting effect.
    """
    if effect_kind is not None:
        try:
            effect_kind = ControlActionEffectKind(effect_kind)
        except ValueError as exc:
            raise ValueError(
                "effect_kind must be one of: "
                + ", ".join(item.value for item in ControlActionEffectKind)
            ) from exc
    if target is None or target.type is not ReferenceType.responsibility:
        return effect_kind
    if (
        effect_kind is not None
        and effect_kind is not ControlActionEffectKind.agent_message
    ):
        raise ValueError(
            "control actions targeting a responsibility must use "
            "effect_kind='agent_message'"
        )
    return ControlActionEffectKind.agent_message


class ControlAction(BaseModel):
    """A control action a controller can execute."""

    ca_id: str  # CA-X-Y
    description: str = Field(min_length=1)
    target: ElementRef | None = None
    effect_kind: ControlActionEffectKind | None = Field(
        default=None,
        description=(
            "Typed observable action effect. Omitted values are retained for "
            "legacy analytical artifacts."
        ),
    )
    temporality: ControlActionTemporality | None = Field(
        default=None,
        description=(
            "Typed temporal shape of the action; continuous or bounded_duration "
            "supports duration analysis."
        ),
    )
    operation: str | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
        description="Exact name of the observed operation this action invokes.",
    )
    process_model_refs: list[str] = Field(
        default_factory=list,
        exclude_if=_empty,
        description=(
            "PM-X-Y variables of the same responsibility the controller needs "
            "to issue this action safely."
        ),
    )

    @field_validator("ca_id")
    @classmethod
    def validate_ca_id_format(cls, v: str, info: ValidationInfo) -> str:
        return _validate_id_format(
            v, "ca_id", "CA-X-Y", "CA-1-1", r"^CA-\d+-\d+$", info
        )

    @field_validator("effect_kind", "temporality", mode="wrap")
    @classmethod
    def keep_deferred_kind(
        cls, value: object, handler: ValidatorFunctionWrapHandler, info: ValidationInfo
    ) -> object:
        """Under ASSEMBLY_DEFERRED, leave an unknown kind for assembly to reject."""
        return _keep_when_deferred(value, handler, info)

    @model_validator(mode="before")
    @classmethod
    def infer_responsibility_message_effect(
        cls, value: object, info: ValidationInfo
    ) -> object:
        """Derive the only valid effect for a responsibility target.

        Responsibility-to-responsibility actions are messages between
        controllers.  The inference is deterministic and does not inspect the
        action description.  A conflicting explicit value is rejected so a
        downstream execution planner never has to choose between contradictory
        typed facts.  A ``before`` validator keeps the model immutable during
        post-validation; tolerant Stage 2 parsing calls the shared helper
        explicitly because it uses ``model_construct``.  Under
        ASSEMBLY_DEFERRED an invalid or conflicting effect is left for the
        assembled structure to reject.
        """
        if not isinstance(value, dict):
            return value
        target = value.get("target")
        target_type = getattr(target, "type", None)
        if isinstance(target, dict):
            target_type = target.get("type")
        if target_type not in {
            ReferenceType.responsibility,
            ReferenceType.responsibility.value,
        }:
            return value
        effect_kind = value.get("effect_kind")
        if effect_kind is not None:
            try:
                normalized = ControlActionEffectKind(effect_kind)
            except (TypeError, ValueError) as exc:
                if _assembly_deferred(info):
                    return value
                raise ValueError("invalid effect_kind") from exc
            if normalized is not ControlActionEffectKind.agent_message:
                if _assembly_deferred(info):
                    return value
                raise ValueError(
                    "control actions targeting a responsibility must use "
                    "effect_kind='agent_message'"
                )
        updated = dict(value)
        updated["effect_kind"] = ControlActionEffectKind.agent_message
        return updated


class FeedbackChannel(BaseModel):
    """A feedback channel providing information to a controller."""

    fb_id: str  # FB-X-Y
    description: str = Field(min_length=1)
    updates: str  # pm_id ref
    source: ElementRef | None = None
    source_kind: FeedbackSourceKind | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
        description="Origin of the information; fixes the channel's trust.",
    )

    @property
    def untrusted(self) -> bool:
        """Whether an adversary can author this channel's information."""
        return self.source_kind in UNTRUSTED_FEEDBACK_SOURCES

    @field_validator("fb_id")
    @classmethod
    def validate_fb_id_format(cls, v: str, info: ValidationInfo) -> str:
        return _validate_id_format(
            v, "fb_id", "FB-X-Y", "FB-1-1", r"^FB-\d+-\d+$", info
        )


class Responsibility(BaseModel):
    """A controller's responsibility in the control structure."""

    resp_id: str  # RESP-1, RESP-2, ...
    description: str = Field(min_length=1)
    responsibility_constraints: list[ResponsibilityConstraint] = Field(
        default_factory=list
    )
    security_constraint_refs: list[str] = Field(
        default_factory=list,
        description="SC-N IDs from LossAnalysis that this responsibility implements.",
    )
    process_model_parts: list[ProcessModelPart] = Field(default_factory=list)
    control_actions: list[ControlAction] = Field(default_factory=list)
    feedback_channels: list[FeedbackChannel] = Field(default_factory=list)

    @field_validator("resp_id")
    @classmethod
    def validate_resp_id_format(cls, v: str, info: ValidationInfo) -> str:
        return _validate_id_format(
            v, "resp_id", "RESP-N", "RESP-1", r"^RESP-\d+$", info
        )


class ControlledProcess(BaseModel):
    """A controlled process in the control structure."""

    cp_id: str  # CP-1, CP-2, ...
    description: str = Field(min_length=1)

    @field_validator("cp_id")
    @classmethod
    def validate_cp_id_format(cls, v: str, info: ValidationInfo) -> str:
        return _validate_id_format(v, "cp_id", "CP-N", "CP-1", r"^CP-\d+$", info)


class CoordinationMechanism(BaseModel):
    """A mechanism for coordinating between controllers."""

    cm_id: str  # CM-X
    description: str = Field(min_length=1)
    payload: str

    @field_validator("cm_id")
    @classmethod
    def validate_cm_id_format(cls, v: str, info: ValidationInfo) -> str:
        return _validate_id_format(v, "cm_id", "CM-N", "CM-1", r"^CM-\d+$", info)


class CoordinationLink(BaseModel):
    """A coordination link between two controllers."""

    link_id: str  # CL-1, CL-2, ...
    source: str  # resp_id
    target: str  # resp_id
    shared_pm: str  # pm_id ref
    coordination_mechanism: CoordinationMechanism
    description: str = Field(min_length=1)

    @field_validator("link_id")
    @classmethod
    def validate_link_id_format(cls, v: str, info: ValidationInfo) -> str:
        return _validate_id_format(v, "link_id", "CL-N", "CL-1", r"^CL-\d+$", info)


class ControlStructure(BaseModel):
    """The hierarchical control structure of the system."""

    responsibilities: list[Responsibility] = Field(min_length=1)
    controlled_processes: list[ControlledProcess] = Field(default_factory=list)
    coordination_links: list[CoordinationLink] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_references_and_duplicates(self) -> ControlStructure:
        resp_ids = {r.resp_id for r in self.responsibilities}
        cp_ids = {cp.cp_id for cp in self.controlled_processes}

        all_rc_ids, all_pm_ids, all_ca_ids, all_fb_ids, pm_by_resp = _collect_child_ids(
            self.responsibilities
        )

        _check_all_duplicate_ids(
            self.responsibilities,
            self.controlled_processes,
            self.coordination_links,
            all_rc_ids,
            all_pm_ids,
            all_ca_ids,
            all_fb_ids,
        )

        _check_cross_namespace_collision(
            self.responsibilities, self.controlled_processes
        )

        _normalize_control_action_semantics(self.responsibilities)
        _validate_element_refs(self.responsibilities, resp_ids, cp_ids)
        _validate_feedback_updates(self.responsibilities, pm_by_resp)
        _validate_action_process_model_refs(self.responsibilities, pm_by_resp)
        _validate_coordination_links(self.coordination_links, resp_ids, all_pm_ids)

        return self


def coordination_process_model_owner(
    structure: ControlStructure, link: CoordinationLink
) -> Responsibility:
    """Resolve a coordination link's shared state to exactly one endpoint.

    Stage 2 checks this before accepting its provider response; later scenario
    assembly uses the same rule rather than discovering a different contract.
    """
    owners = [
        resp
        for resp in structure.responsibilities
        if resp.resp_id in (link.source, link.target)
        and any(pm.pm_id == link.shared_pm for pm in resp.process_model_parts)
    ]
    if len(owners) != 1:
        raise ValueError(
            f"coordination link '{link.link_id}' shared PM '{link.shared_pm}' "
            "is not owned by exactly one endpoint responsibility"
        )
    return owners[0]


def _check_all_duplicate_ids(
    responsibilities: list[Responsibility],
    controlled_processes: list[ControlledProcess],
    coordination_links: list[CoordinationLink],
    all_rc_ids: list[str],
    all_pm_ids: list[str],
    all_ca_ids: list[str],
    all_fb_ids: list[str],
) -> None:
    """Check every ID type for duplicates at the control-structure level."""
    check_duplicate_ids([r.resp_id for r in responsibilities], "resp_id")
    check_duplicate_ids([cp.cp_id for cp in controlled_processes], "cp_id")
    check_duplicate_ids(all_rc_ids, "rc_id")
    check_duplicate_ids(all_pm_ids, "pm_id")
    check_duplicate_ids(all_ca_ids, "ca_id")
    check_duplicate_ids(all_fb_ids, "fb_id")
    check_duplicate_ids([cl.link_id for cl in coordination_links], "link_id")
    check_duplicate_ids(
        [cl.coordination_mechanism.cm_id for cl in coordination_links], "cm_id"
    )


def _is_valid_element_ref(
    ref: ElementRef,
    resp_ids: set[str],
    cp_ids: set[str],
) -> bool:
    """Check if an ElementRef points to a valid responsibility or controlled process."""
    if ref.type == ReferenceType.responsibility:
        return ref.id in resp_ids
    if ref.type == ReferenceType.controlled_process:
        return ref.id in cp_ids
    return False


def _collect_child_ids(
    responsibilities: list[Responsibility],
) -> tuple[list[str], list[str], list[str], list[str], dict[str, set[str]]]:
    """Collect all RC/PM/CA/FB IDs and check for per-responsibility duplicates.

    Returns:
        A tuple of (all_rc_ids, all_pm_ids, all_ca_ids, all_fb_ids, pm_ids_by_resp).
    """
    all_rc_ids: list[str] = []
    all_pm_ids: list[str] = []
    all_ca_ids: list[str] = []
    all_fb_ids: list[str] = []
    pm_by_resp: dict[str, set[str]] = {}

    for resp in responsibilities:
        rc_list = [rc.rc_id for rc in resp.responsibility_constraints]
        pm_list = [pm.pm_id for pm in resp.process_model_parts]
        ca_list = [ca.ca_id for ca in resp.control_actions]
        fb_list = [fb.fb_id for fb in resp.feedback_channels]

        pm_by_resp[resp.resp_id] = set(pm_list)
        all_rc_ids.extend(rc_list)
        all_pm_ids.extend(pm_list)
        all_ca_ids.extend(ca_list)
        all_fb_ids.extend(fb_list)

        check_duplicate_ids(rc_list, "rc_id")
        check_duplicate_ids(pm_list, "pm_id")
        check_duplicate_ids(ca_list, "ca_id")
        check_duplicate_ids(fb_list, "fb_id")

    return all_rc_ids, all_pm_ids, all_ca_ids, all_fb_ids, pm_by_resp


def _collect_all_id_sets(
    responsibilities: list[Responsibility],
) -> tuple[set[str], set[str], set[str], set[str], set[str]]:
    """Collect all RC/PM/CA/FB/RESP ID sets across responsibilities.

    Returns:
        A tuple of (rc_ids, pm_ids, ca_ids, fb_ids, resp_ids).
    """
    rc_ids: set[str] = set()
    pm_ids: set[str] = set()
    ca_ids: set[str] = set()
    fb_ids: set[str] = set()
    resp_ids: set[str] = set()
    for resp in responsibilities:
        resp_ids.add(resp.resp_id)
        rc_ids.update(rc.rc_id for rc in resp.responsibility_constraints)
        pm_ids.update(pm.pm_id for pm in resp.process_model_parts)
        ca_ids.update(ca.ca_id for ca in resp.control_actions)
        fb_ids.update(fb.fb_id for fb in resp.feedback_channels)
    return rc_ids, pm_ids, ca_ids, fb_ids, resp_ids


def _collect_namespace_buckets(
    responsibilities: list[Responsibility],
    controlled_processes: list[ControlledProcess],
) -> list[tuple[str, set[str]]]:
    """Collect ID sets grouped by namespace name.

    Returns a list of (namespace_name, id_set) pairs for every ID type
    in the control structure.
    """
    rc_ids, pm_ids, ca_ids, fb_ids, resp_ids = _collect_all_id_sets(responsibilities)
    cp_ids = {cp.cp_id for cp in controlled_processes}
    return [
        ("rc_id", rc_ids),
        ("pm_id", pm_ids),
        ("ca_id", ca_ids),
        ("fb_id", fb_ids),
        ("resp_id", resp_ids),
        ("cp_id", cp_ids),
    ]


def _check_cross_namespace_collision(
    responsibilities: list[Responsibility],
    controlled_processes: list[ControlledProcess],
) -> None:
    """Detect IDs that appear in more than one ID namespace.

    Collects every ID from each element type into a separate namespace
    bucket, then checks whether any ID value appears in more than one
    bucket.  This catches cross-namespace collisions that field
    validators alone cannot detect when validators are bypassed (e.g.
    an RC-1-1 value used as both rc_id and pm_id).
    """
    namespace_buckets = _collect_namespace_buckets(
        responsibilities, controlled_processes
    )
    for i, (name_a, bucket_a) in enumerate(namespace_buckets):
        for name_b, bucket_b in namespace_buckets[i + 1 :]:
            shared = bucket_a & bucket_b
            if shared:
                raise ValueError(
                    f"Cross-namespace collision: ID(s) {sorted(shared)} "
                    f"appear in both {name_a} and {name_b} namespaces. "
                    f"Each ID value must belong to exactly one namespace."
                )


def _validate_element_refs(
    responsibilities: list[Responsibility],
    resp_ids: set[str],
    cp_ids: set[str],
) -> None:
    """Validate ElementRef targets in PMs, CAs, and FBs."""
    for resp in responsibilities:
        _validate_pm_refs(resp, resp_ids, cp_ids)
        _validate_ca_refs(resp, resp_ids, cp_ids)
        _validate_fb_source_refs(resp, resp_ids, cp_ids)


def _normalize_control_action_semantics(
    responsibilities: list[Responsibility],
) -> None:
    """Fill derived action semantics after tolerant nested construction."""
    for responsibility in responsibilities:
        for index, action in enumerate(responsibility.control_actions):
            effect_kind = normalize_control_action_effect_kind(
                action.target, action.effect_kind
            )
            if effect_kind != action.effect_kind:
                responsibility.control_actions[index] = action.model_copy(
                    update={"effect_kind": effect_kind}
                )


def _validate_pm_refs(
    resp: Responsibility, resp_ids: set[str], cp_ids: set[str]
) -> None:
    """Validate feedback_source references in process model parts."""
    for pm in resp.process_model_parts:
        if pm.feedback_source is not None:
            if not _is_valid_element_ref(pm.feedback_source, resp_ids, cp_ids):
                raise ValueError(
                    f"ProcessModelPart {pm.pm_id} feedback_source "
                    f"references non-existent element "
                    f"{pm.feedback_source.type.value} '{pm.feedback_source.id}'."
                )


def _validate_ca_refs(
    resp: Responsibility, resp_ids: set[str], cp_ids: set[str]
) -> None:
    """Validate target references in control actions."""
    for ca in resp.control_actions:
        if ca.target is not None:
            if not _is_valid_element_ref(ca.target, resp_ids, cp_ids):
                raise ValueError(
                    f"ControlAction {ca.ca_id} target references "
                    f"non-existent element "
                    f"{ca.target.type.value} '{ca.target.id}'."
                )


def _validate_fb_source_refs(
    resp: Responsibility, resp_ids: set[str], cp_ids: set[str]
) -> None:
    """Validate source references in feedback channels."""
    for fb in resp.feedback_channels:
        if fb.source is None:
            continue
        if not _is_valid_element_ref(fb.source, resp_ids, cp_ids):
            raise ValueError(
                f"FeedbackChannel {fb.fb_id} source references "
                f"non-existent element "
                f"{fb.source.type.value} '{fb.source.id}'."
            )


def _validate_feedback_updates(
    responsibilities: list[Responsibility],
    pm_by_resp: dict[str, set[str]],
) -> None:
    """Validate that feedback channel updates reference a PM in the same responsibility."""
    all_pm_ids = {pm for s in pm_by_resp.values() for pm in s}
    for resp in responsibilities:
        local_pm_ids = pm_by_resp[resp.resp_id]
        for fb in resp.feedback_channels:
            _validate_fb_update_target(fb, resp.resp_id, local_pm_ids, all_pm_ids)


def _validate_action_process_model_refs(
    responsibilities: list[Responsibility],
    pm_by_resp: dict[str, set[str]],
) -> None:
    """Require every action's process-model refs to name its own PM parts."""
    for resp in responsibilities:
        local_pm_ids = pm_by_resp[resp.resp_id]
        for ca in resp.control_actions:
            unknown = [ref for ref in ca.process_model_refs if ref not in local_pm_ids]
            if unknown:
                raise ValueError(
                    f"ControlAction {ca.ca_id} process_model_refs {unknown} are not "
                    f"process model parts of {resp.resp_id}."
                )


def _validate_fb_update_target(
    fb: FeedbackChannel,
    resp_id: str,
    local_pm_ids: set[str],
    all_pm_ids: set[str],
) -> None:
    """Validate a single feedback channel's updates reference."""
    if fb.updates in local_pm_ids:
        return
    if fb.updates in all_pm_ids:
        raise ValueError(
            f"FeedbackChannel {fb.fb_id} updates references "
            f"PM '{fb.updates}' which belongs to a different "
            f"responsibility (not {resp_id})."
        )
    raise ValueError(
        f"FeedbackChannel {fb.fb_id} updates references non-existent PM '{fb.updates}'."
    )


def _validate_coordination_links(
    links: list[CoordinationLink],
    resp_ids: set[str],
    all_pm_ids: list[str],
) -> None:
    """Validate coordination link source/target/shared_pm references."""
    pm_id_set = set(all_pm_ids)
    for cl in links:
        if cl.source not in resp_ids:
            raise ValueError(
                f"CoordinationLink {cl.link_id} source references "
                f"non-existent responsibility '{cl.source}'."
            )
        if cl.target not in resp_ids:
            raise ValueError(
                f"CoordinationLink {cl.link_id} target references "
                f"non-existent responsibility '{cl.target}'."
            )
        if cl.shared_pm not in pm_id_set:
            raise ValueError(
                f"CoordinationLink {cl.link_id} shared_pm references "
                f"non-existent PM '{cl.shared_pm}'."
            )


# ---------------------------------------------------------------------------
# Structural heuristics (deterministic post-checks, separate from validation)
# ---------------------------------------------------------------------------


@dataclass
class HeuristicResult:
    """Result of structural heuristic checks."""

    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return len(self.errors) == 0


def check_structural_heuristics(
    cs: ControlStructure,
    loss_analysis: LossAnalysis | None = None,
) -> HeuristicResult:
    """Run deterministic structural heuristic post-checks on a control structure.

    These are separate from Pydantic field validation. They check:

    - Every responsibility has >=1 process model part, >=1 control action,
      >=1 feedback channel.
    - Every controlled process is referenced by >=1 feedback channel source
      OR >=1 control action target.
    - Every hazard (from LossAnalysis) traces to >=1 responsibility
      (via security constraints -> responsibilities).
    - Orphan PM parts (not updated by any feedback channel) are flagged as
      warnings.

    Args:
        cs: The control structure to check.
        loss_analysis: Optional loss analysis for hazard tracing.

    Returns:
        A HeuristicResult with errors and warnings.
    """
    result = HeuristicResult()

    _check_responsibility_completeness(cs, result)
    _check_controlled_process_references(cs, result)
    _check_orphan_pms(cs, result)
    if loss_analysis is not None:
        _check_hazard_tracing(cs, loss_analysis, result)

    return result


def _check_responsibility_completeness(
    cs: ControlStructure, result: HeuristicResult
) -> None:
    """Every responsibility has >=1 PM, >=1 CA, >=1 FB."""
    for resp in cs.responsibilities:
        if not resp.process_model_parts:
            result.errors.append(
                f"Responsibility {resp.resp_id} has no process model part."
            )
        if not resp.control_actions:
            result.errors.append(
                f"Responsibility {resp.resp_id} has no control action."
            )
        if not resp.feedback_channels:
            result.errors.append(
                f"Responsibility {resp.resp_id} has no feedback channel."
            )


def _check_controlled_process_references(
    cs: ControlStructure, result: HeuristicResult
) -> None:
    """Every controlled process is referenced by >=1 feedback source or CA target."""
    referenced_cps = _collect_referenced_cps(cs.responsibilities)
    for cp in cs.controlled_processes:
        if cp.cp_id not in referenced_cps:
            result.errors.append(
                f"Controlled process {cp.cp_id} is not referenced by any "
                f"feedback channel source or control action target."
            )


def _collect_referenced_cps(responsibilities: list[Responsibility]) -> set[str]:
    """Collect CP IDs referenced by feedback sources or CA targets."""
    referenced: set[str] = set()
    for resp in responsibilities:
        _add_cps_from_feedback(referenced, resp.feedback_channels)
        _add_cps_from_control_actions(referenced, resp.control_actions)
    return referenced


def _add_cps_from_feedback(
    referenced: set[str], channels: list[FeedbackChannel]
) -> None:
    """Add CP IDs referenced by feedback channel sources."""
    for fb in channels:
        if fb.source is not None and fb.source.type == ReferenceType.controlled_process:
            referenced.add(fb.source.id)


def _add_cps_from_control_actions(
    referenced: set[str], actions: list[ControlAction]
) -> None:
    """Add CP IDs referenced by control action targets."""
    for ca in actions:
        if ca.target is not None and ca.target.type == ReferenceType.controlled_process:
            referenced.add(ca.target.id)


def _check_orphan_pms(cs: ControlStructure, result: HeuristicResult) -> None:
    """Orphan PM parts (not updated by any feedback channel) produce warnings."""
    for resp in cs.responsibilities:
        updated_pms = {fb.updates for fb in resp.feedback_channels}
        for pm in resp.process_model_parts:
            if pm.pm_id not in updated_pms:
                result.warnings.append(
                    f"Orphan PM {pm.pm_id} in responsibility {resp.resp_id} "
                    f"is not updated by any feedback channel."
                )


def _check_hazard_tracing(
    cs: ControlStructure,
    loss_analysis: LossAnalysis,
    result: HeuristicResult,
) -> None:
    """Every hazard traces to >=1 responsibility via security constraints."""
    constraints_by_resp = _build_constraints_by_resp(cs.responsibilities)
    hazard_to_constraints = _build_hazard_to_constraints(
        loss_analysis.security_constraints
    )

    for hazard in loss_analysis.hazards:
        covering = hazard_to_constraints.get(hazard.hazard_id, set())
        traced_resps = _trace_responsibilities(covering, constraints_by_resp)
        if not traced_resps:
            result.errors.append(
                f"Hazard {hazard.hazard_id} is not traced to any "
                f"responsibility (no responsibility references a constraint "
                f"that covers this hazard)."
            )


def _build_constraints_by_resp(
    responsibilities: list[Responsibility],
) -> dict[str, set[str]]:
    """Map security_constraint_id -> set of resp_ids that reference it."""
    mapping: dict[str, set[str]] = {}
    for resp in responsibilities:
        for sc_id in resp.security_constraint_refs:
            mapping.setdefault(sc_id, set()).add(resp.resp_id)
    return mapping


def _build_hazard_to_constraints(
    security_constraints: list,
) -> dict[str, set[str]]:
    """Map hazard_id -> set of constraint_ids that cover it."""
    mapping: dict[str, set[str]] = {}
    for sc in security_constraints:
        for h_id in sc.related_hazards:
            mapping.setdefault(h_id, set()).add(sc.constraint_id)
    return mapping


def _trace_responsibilities(
    covering_constraints: set[str],
    constraints_by_resp: dict[str, set[str]],
) -> set[str]:
    """Find all responsibilities referenced by the covering constraints."""
    traced: set[str] = set()
    for c_id in covering_constraints:
        traced.update(constraints_by_resp.get(c_id, set()))
    return traced


MAX_CONTEXT_ROWS_PER_ACTION = 12


@dataclass(frozen=True)
class ContextRow:
    """One row of a control action's context table.

    A row assigns one value to each process-model variable the action names
    in ``process_model_refs``; Stage 3 findings cite a row to state the exact
    context in which the action is unsafe.
    """

    row_id: str
    control_action: str
    assignments: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class ContextTable:
    """A control action's context table and what its row budget left out.

    ``combinations`` counts the full Cartesian product.  ``hidden_values``
    lists each ``(pm_id, value)`` that no shown row holds; it is non-empty
    only when a variable has more values than the budget has rows.
    """

    control_action: str
    combinations: int
    rows: tuple[ContextRow, ...]
    hidden_values: tuple[tuple[str, str], ...]


def control_action_context_rows(
    structure: ControlStructure, ca_id: str
) -> tuple[ContextRow, ...]:
    """Return the rows of one control action's context table."""
    table = control_action_context_table(structure, ca_id)
    return () if table is None else table.rows


def control_action_context_table(
    structure: ControlStructure, ca_id: str
) -> ContextTable | None:
    """Return the deterministic context table of one control action.

    Each row assigns one value to every referenced process-model variable
    that has values; an action with no valued variable has no table.  A
    product within :data:`MAX_CONTEXT_ROWS_PER_ACTION` is shown whole, in
    reference and value order.  A larger product is sampled: every value
    appears in some row whenever the budget allows, and the remaining rows
    cover value pairs that no earlier row holds.  A row's ID is its 1-based
    position in the full product, so an ID names one combination whichever
    rows the budget keeps.
    """
    columns = _context_columns(structure, ca_id)
    if not columns:
        return None
    sizes = [len(values) for _, values in columns]
    rows = tuple(
        _context_row(ca_id, columns, pick) for pick in _context_picks(columns, sizes)
    )
    return ContextTable(
        control_action=ca_id,
        combinations=math.prod(sizes),
        rows=rows,
        hidden_values=_hidden_values(columns, rows),
    )


def _context_columns(
    structure: ControlStructure, ca_id: str
) -> list[tuple[str, tuple[str, ...]]]:
    """Return the action's referenced variables that have values, with them."""
    located = _locate_control_action(structure, ca_id)
    if located is None:
        return []
    resp, action = located
    parts = {pm.pm_id: pm for pm in resp.process_model_parts}
    return [
        (ref, tuple(parts[ref].values))
        for ref in action.process_model_refs
        if ref in parts and parts[ref].values
    ]


def _context_picks(
    columns: list[tuple[str, tuple[str, ...]]], sizes: list[int]
) -> list[tuple[int, ...]]:
    """Return the value-index rows to show, in full-product order."""
    if math.prod(sizes) <= MAX_CONTEXT_ROWS_PER_ACTION:
        return list(itertools.product(*(range(size) for size in sizes)))
    # Visit columns by size and ID, not reference order, so the order in
    # which a model listed the references cannot decide what is shown.
    # One-valued columns go first: the last column visited keeps a row
    # distinct, which a column with one value cannot do.
    order = sorted(
        range(len(columns)),
        key=lambda c: (sizes[c] > 1, -sizes[c], columns[c][0]),
    )
    return sorted(_covering_picks(sizes, order, MAX_CONTEXT_ROWS_PER_ACTION))


def _hidden_values(
    columns: list[tuple[str, tuple[str, ...]]], rows: tuple[ContextRow, ...]
) -> tuple[tuple[str, str], ...]:
    """Return each ``(pm_id, value)`` no row shows, in column then value order."""
    shown = {pair for row in rows for pair in row.assignments}
    return tuple(
        (pm_id, value)
        for pm_id, values in columns
        for value in values
        if (pm_id, value) not in shown
    )


def control_structure_context_tables(
    structure: ControlStructure,
) -> tuple[ContextTable, ...]:
    """Return the context table of every action that has one, in model order."""
    tables = (
        control_action_context_table(structure, action.ca_id)
        for resp in structure.responsibilities
        for action in resp.control_actions
    )
    return tuple(table for table in tables if table is not None)


def _locate_control_action(
    structure: ControlStructure, ca_id: str
) -> tuple[Responsibility, ControlAction] | None:
    """Return the first responsibility declaring *ca_id* and that action."""
    for resp in structure.responsibilities:
        action = next((ca for ca in resp.control_actions if ca.ca_id == ca_id), None)
        if action is not None:
            return resp, action
    return None


def _context_row(
    ca_id: str, columns: list[tuple[str, tuple[str, ...]]], pick: tuple[int, ...]
) -> ContextRow:
    """Build the row holding value index ``pick[c]`` of each column ``c``."""
    position = 0
    for (_, values), index in zip(columns, pick, strict=True):
        position = position * len(values) + index
    return ContextRow(
        row_id=f"{ca_id}:ctx-{position + 1}",
        control_action=ca_id,
        assignments=tuple(
            (pm_id, values[index])
            for (pm_id, values), index in zip(columns, pick, strict=True)
        ),
    )


def _covering_picks(
    sizes: list[int], order: list[int], budget: int
) -> list[tuple[int, ...]]:
    """Choose ``budget`` distinct value-index rows from a larger product."""
    coverage = _PairCoverage(sizes)
    while len(coverage.picks) < budget:
        coverage.add(coverage.next_pick(order))
    return coverage.picks


class _PairCoverage:
    """Greedy row selection over value indices, without enumerating the product.

    A row is built one column at a time.  While a column has a value no row
    shows, the row takes one of those, so every value appears once the
    budget reaches the largest column.  Among the candidates the row prefers
    the value completing the most uncovered value pairs with the columns
    already chosen, then the value with the most uncovered pairs left, then
    the least used value, then the earliest value.
    """

    def __init__(self, sizes: list[int]) -> None:
        self.sizes = sizes
        self.picks: list[tuple[int, ...]] = []
        self._unseen = [set(range(size)) for size in sizes]
        self._open = [[sum(sizes) - size] * size for size in sizes]
        self._uses = [[0] * size for size in sizes]
        self._covered: set[tuple[int, int, int, int]] = set()

    def next_pick(self, order: list[int]) -> tuple[int, ...]:
        row: dict[int, int] = {}
        for column in order:
            candidates = sorted(self._unseen[column]) or list(range(self.sizes[column]))
            if len(row) == len(self.sizes) - 1:
                candidates = [
                    value
                    for value in candidates
                    if self._complete(row, column, value) not in self.picks
                ]
            if not candidates:
                return self._first_unpicked()
            row[column] = max(
                candidates, key=lambda value: self._score(row, column, value)
            )
        return tuple(row[column] for column in range(len(self.sizes)))

    def add(self, pick: tuple[int, ...]) -> None:
        self.picks.append(pick)
        for column, value in enumerate(pick):
            self._unseen[column].discard(value)
            self._uses[column][value] += 1
        for left, right in itertools.combinations(range(len(pick)), 2):
            pair = (left, pick[left], right, pick[right])
            if pair not in self._covered:
                self._covered.add(pair)
                self._open[left][pick[left]] -= 1
                self._open[right][pick[right]] -= 1

    def _score(
        self, row: dict[int, int], column: int, value: int
    ) -> tuple[int, int, int, int]:
        completed = sum(
            _ordered_pair(other, chosen, column, value) not in self._covered
            for other, chosen in row.items()
        )
        return (
            completed,
            self._open[column][value],
            -self._uses[column][value],
            -value,
        )

    def _complete(
        self, row: dict[int, int], column: int, value: int
    ) -> tuple[int, ...]:
        full = {**row, column: value}
        return tuple(full[c] for c in range(len(self.sizes)))

    def _first_unpicked(self) -> tuple[int, ...]:
        # Every completion of the row so far is already picked.  Fewer rows
        # than the budget are picked, so the scan stops within budget + 1.
        return next(
            pick
            for pick in itertools.product(*(range(size) for size in self.sizes))
            if pick not in self.picks
        )


def _ordered_pair(left: int, a: int, right: int, b: int) -> tuple[int, int, int, int]:
    return (left, a, right, b) if left < right else (right, b, left, a)
