"""Pure provider-prompt contract auditing and model-aware budget helpers.

The STPA providers keep complete durable artifacts out of the prompt.  This
module supplies the small, IO-free seam that checks a rendered prompt before a
provider adapter is allowed to dispatch it.  It deliberately knows nothing
about a provider client, filesystem, workflow controller, or particular STPA
stage.

``PromptBudget`` accepts a caller-supplied tokenizer when one is available and
otherwise uses the documented conservative four-characters-per-token estimate.
``audit_prompt_contract`` returns a digest-bearing audit on success and raises
a typed diagnostic on contract or budget failure.  Callers that need to retain
diagnostics without raising can pass ``raise_on_error=False``.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, TypeVar

try:  # Pydantic is a project dependency, but keeping this leaf optional helps tooling.
    from pydantic import BaseModel
except ImportError:  # pragma: no cover - only static tooling can take this branch
    BaseModel = None  # type: ignore[assignment,misc]


_T = TypeVar("_T")
TokenCounter = Callable[[str], int]

_DEFAULT_PROHIBITED_FIELD_MARKERS = (
    "digest",
    "pin",
    "path",
    "score",
    "mapping",
    "mitigation",
    "provider_call",
    "schema_name",
)
_LOCAL_PATH_RE = re.compile(
    r"(?:^|[\s\"'=(:])(?:/Users/|/home/|/private/|/var/|/tmp/|"
    r"[A-Za-z]:[\\/]|\\\\)[^\s\"'<>]+"
)
_RELATIVE_PATH_RE = re.compile(
    r"(?:^|[\s\"'=(:])(?:\.{1,2}/|(?:build|artifact|artifacts|run|runs|"
    r"workspace)/)[^\s\"'<>]+"
)
_REFERENCE_TOKEN_RE = re.compile(
    r"\b(?:RESP|CA|FB|CP|PM|RC|SC|H|L|REQ|CL|CM)-[A-Za-z0-9][A-Za-z0-9_.:-]*\b"
)


def _profile_value(
    profile: Mapping[str, Any] | object, name: str, fallback: Any = None
) -> Any:
    """Read one profile value from either a mapping or an object."""
    if isinstance(profile, Mapping):
        return profile.get(name, fallback)
    return getattr(profile, name, fallback)


def estimate_prompt_tokens(text: str) -> int:
    """Estimate prompt tokens conservatively from UTF-8 text length.

    Four characters per token is intentionally conservative for ordinary
    English prompts and is used only when the configured model tokenizer is
    unavailable.  At least one token is returned for non-empty text.
    """
    if not text:
        return 0
    return max(1, math.ceil(len(text.encode("utf-8")) / 4))


@dataclass(frozen=True)
class PromptBudget:
    """Resolved model context budget for one provider call."""

    context_window: int
    maximum_completion_tokens: int
    safety_margin: int | None = None
    token_counter: TokenCounter | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.context_window <= 0:
            raise ValueError("context_window must be positive")
        if self.maximum_completion_tokens <= 0:
            raise ValueError("maximum_completion_tokens must be positive")
        margin = self.safety_margin
        if margin is None:
            margin = max(1_024, math.ceil(self.context_window * 0.10))
            object.__setattr__(self, "safety_margin", margin)
        if margin < 0:
            raise ValueError("safety_margin must be non-negative")

    @property
    def usable_input_tokens(self) -> int:
        """Return context left after completion reservation and safety margin."""
        return max(
            0,
            self.context_window
            - self.maximum_completion_tokens
            - (self.safety_margin or 0),
        )

    def count(self, text: str) -> int:
        """Count *text* with the configured tokenizer or conservative estimator."""
        if self.token_counter is None:
            return estimate_prompt_tokens(text)
        counted = self.token_counter(text)
        if not isinstance(counted, int) or counted < 0:
            raise ValueError("token_counter must return a non-negative integer")
        return counted

    @classmethod
    def from_profile(
        cls,
        profile: Mapping[str, Any] | object,
        *,
        token_counter: TokenCounter | None = None,
    ) -> "PromptBudget":
        """Resolve a budget from a mapping or model-profile-like object.

        Both normative names (``maximum_completion_tokens``) and the existing
        project profile spelling (``max_completion_tokens``) are accepted.
        Missing context information fails closed instead of inventing a model
        window.
        """

        context_window = _profile_value(profile, "context_window")
        if context_window is None:
            context_window = _profile_value(profile, "model_context_window")
        completion = _profile_value(profile, "maximum_completion_tokens")
        if completion is None:
            completion = _profile_value(profile, "max_completion_tokens")
        if context_window is None:
            raise ValueError("model profile must declare context_window")
        if completion is None:
            raise ValueError(
                "model profile must declare maximum_completion_tokens or "
                "max_completion_tokens"
            )
        return cls(
            context_window=int(context_window),
            maximum_completion_tokens=int(completion),
            safety_margin=_profile_value(profile, "safety_margin"),
            token_counter=token_counter,
        )


class PromptContractError(ValueError):
    """Typed deterministic failure that prevents provider dispatch."""

    code = "prompt_contract_invalid"
    provider_call_allowed = False

    def __init__(self, *errors: str) -> None:
        self.errors = tuple(errors)
        detail = "; ".join(self.errors) or "prompt contract is invalid"
        super().__init__(detail)


class PromptBudgetExceeded(PromptContractError):
    """Prompt does not fit the resolved model input budget."""

    code = "prompt_budget_exceeded"

    def __init__(
        self,
        *,
        input_tokens: int,
        usable_input_tokens: int,
        context_window: int,
        maximum_completion_tokens: int,
        safety_margin: int,
    ) -> None:
        self.input_tokens = input_tokens
        self.usable_input_tokens = usable_input_tokens
        self.context_window = context_window
        self.maximum_completion_tokens = maximum_completion_tokens
        self.safety_margin = safety_margin
        super().__init__(
            f"{self.code}: rendered prompt uses {input_tokens} input tokens, "
            f"budget allows {usable_input_tokens} "
            f"(context_window={context_window}, "
            f"maximum_completion_tokens={maximum_completion_tokens}, "
            f"safety_margin={safety_margin})"
        )


@dataclass(frozen=True)
class PromptAudit:
    """Deterministic evidence recorded for one rendered prompt."""

    stage: str
    rendered_prompt_digest: str
    input_tokens: int
    input_tokens_estimated: bool
    context_window: int | None
    maximum_completion_tokens: int | None
    safety_margin: int | None
    usable_input_tokens: int | None
    errors: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        """Whether the provider call is allowed by this audit."""
        return not self.errors and (
            self.usable_input_tokens is None
            or self.input_tokens <= self.usable_input_tokens
        )

    @property
    def prompt_digest(self) -> str:
        """Compatibility alias for the rendered prompt digest."""
        return self.rendered_prompt_digest

    @property
    def provider_call_allowed(self) -> bool:
        """Compatibility alias for :attr:`ok`."""
        return self.ok


def _view_items(value: Any, path: str = "") -> Iterable[tuple[str, Any]]:
    """Yield recursively reachable view field names and values."""
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="python")
    elif hasattr(value, "__dataclass_fields__"):
        value = {
            name: getattr(value, name)
            for name in value.__dataclass_fields__  # type: ignore[attr-defined]
        }
    if isinstance(value, Mapping):
        for key, item in value.items():
            key_text = str(key)
            child_path = f"{path}.{key_text}" if path else key_text
            yield child_path, item
            yield from _view_items(item, child_path)
    elif isinstance(value, (list, tuple, set, frozenset)):
        for index, item in enumerate(value):
            yield from _view_items(item, f"{path}[{index}]")


def _optional_text(value: Any) -> str:
    """Render an optional description as text, with ``None`` as empty."""
    return "" if value is None else str(value)


def _reference_pair(item: Any, message: str) -> tuple[str, Any]:
    """Split one bare ID or ``(id, description)`` pair; bare IDs have no description."""
    if isinstance(item, str):
        return item, None
    try:
        identifier, description = item
    except (TypeError, ValueError) as exc:
        raise ValueError(message) from exc
    return str(identifier), description


def _selectable_pairs(value: Any) -> list[tuple[str, str]]:
    """Normalize selectable ID/description input for deterministic checking."""
    if value is None:
        return []
    if isinstance(value, Mapping):
        return [(str(key), _optional_text(item)) for key, item in value.items()]
    message = "selectable_references must contain (id, description) pairs"
    return [
        (identifier, _optional_text(description))
        for identifier, description in (
            _reference_pair(item, message) for item in value
        )
    ]


def _reference_ids(value: Any) -> set[str]:
    """Normalize an authoritative reference collection to its exact IDs."""
    if value is None:
        return set()
    if isinstance(value, str):
        return {value}
    if isinstance(value, Mapping):
        return {str(identifier) for identifier in value}
    message = "authoritative_references must contain IDs or (id, description) pairs"
    return {_reference_pair(item, message)[0] for item in value}


def _schema_field_names(output_schema: Any) -> tuple[str, ...]:
    """Extract field names from a schema class, mapping, or field sequence."""
    if output_schema is None:
        return ()
    if isinstance(output_schema, Mapping):
        return tuple(str(name) for name in output_schema)
    if isinstance(output_schema, str):
        return (output_schema,)
    if isinstance(output_schema, type) and BaseModel is not None:
        return _model_schema_field_names(output_schema)
    if isinstance(output_schema, Iterable):
        return tuple(str(name) for name in output_schema)
    return ()


def _model_schema_field_names(output_schema: type[Any]) -> tuple[str, ...]:
    """Extract field names from a Pydantic model without leaking introspection errors."""
    try:
        fields = output_schema.model_fields
    except AttributeError:
        return ()
    return tuple(str(name) for name in fields)


def _serialized_example(value: Any) -> str:
    """Serialize a valid example only for contract-presence checks."""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    except (TypeError, ValueError):
        return str(value)


def _handle_contract_errors(
    input_handles: Iterable[str] | None,
    accounted_handles: Iterable[str] | None,
) -> tuple[list[str], tuple[str, ...]]:
    """Validate that every supplied opaque input handle is accounted for."""
    if input_handles is None:
        if accounted_handles is None:
            return [], ()
        return ["accounted handles cannot be supplied without input handles"], ()
    handles = tuple(str(item) for item in input_handles)
    errors: list[str] = []
    if len(handles) != len(set(handles)):
        errors.append("input handles must be unique")
    if accounted_handles is None:
        errors.append("input handles must be fully accounted for")
    else:
        errors.extend(_accounting_errors(handles, accounted_handles))
    return errors, handles


def _accounting_errors(
    handles: tuple[str, ...], accounted_handles: Iterable[str]
) -> list[str]:
    """Compare supplied input handles with the handles a caller accounted for."""
    accounted = tuple(str(item) for item in accounted_handles)
    errors: list[str] = []
    if len(accounted) != len(set(accounted)):
        errors.append("accounted handles must be unique")
    gaps = (
        ("missing", sorted(set(handles) - set(accounted))),
        ("unexpected", sorted(set(accounted) - set(handles))),
    )
    detail = [f"{label} {', '.join(ids)}" for label, ids in gaps if ids]
    if detail:
        errors.append("input handles are not fully accounted for: " + "; ".join(detail))
    return errors


def _selectable_contract_errors(value: Any) -> list[str]:
    """Validate selectable IDs and their explanations."""
    try:
        selectable = _selectable_pairs(value)
    except ValueError as exc:
        return [str(exc)]
    errors = [
        f"selectable ID {identifier!r} requires a description"
        for identifier, description in selectable
        if not description.strip()
    ]
    selectable_ids = [identifier for identifier, _description in selectable]
    if len(selectable_ids) != len(set(selectable_ids)):
        errors.append("selectable references must have unique IDs")
    return errors


def _view_contract_errors(
    prompt_view: Any,
    combined_prompt: str,
    prohibited_fields: Iterable[str] | None,
) -> list[str]:
    """Detect metadata, raw mapping, and path leakage in a typed prompt view."""
    marker_source = (
        _DEFAULT_PROHIBITED_FIELD_MARKERS
        if prohibited_fields is None
        else prohibited_fields
    )
    markers = tuple(marker.lower() for marker in marker_source)
    errors: list[str] = []
    for field_path, value in _view_items(prompt_view):
        errors.extend(_view_item_errors(field_path, value, markers, combined_prompt))
    errors.extend(
        message
        for pattern, message in _PROMPT_PATH_CHECKS
        if pattern.search(combined_prompt)
    )
    return errors


_PROMPT_PATH_CHECKS = (
    (_LOCAL_PATH_RE, "absolute local path appears in rendered prompt"),
    (_RELATIVE_PATH_RE, "workspace-relative source path appears in rendered prompt"),
)


def _view_item_errors(
    field_path: str, value: Any, markers: tuple[str, ...], combined_prompt: str
) -> list[str]:
    """Detect a prohibited field or raw mapping JSON at one prompt-view path."""
    lower_path = field_path.lower()
    errors: list[str] = []
    if any(_field_path_has_marker(lower_path, marker) for marker in markers):
        errors.append(f"prohibited prompt-view field leaked: {field_path}")
        if isinstance(value, str) and value and value in combined_prompt:
            errors.append(f"prohibited prompt-view value leaked: {field_path}")
    if _is_raw_mapping_text(lower_path, value):
        errors.append(f"raw mapping JSON is not allowed in prompt view: {field_path}")
    return errors


def _is_raw_mapping_text(lower_path: str, value: Any) -> bool:
    """Whether a mapping-named field carries text that looks like JSON."""
    return (
        isinstance(value, str)
        and any(marker in lower_path for marker in ("mapping", "raw_json"))
        and value.strip().startswith(("{", "["))
    )


def _field_path_has_marker(field_path: str, marker: str) -> bool:
    """Match field-name markers without treating words such as mapping as pins."""
    segments = tuple(item for item in re.split(r"[.\[\]]+", field_path) if item)
    return any(_segment_has_marker(segment, marker) for segment in segments)


def _segment_has_marker(segment: str, marker: str) -> bool:
    """Match one snake-case field segment against a prohibited marker."""
    words = tuple(item for item in segment.split("_") if item)
    return marker in words or f"{marker}s" in words


def _reference_contract_errors(
    prompt_view: Any,
    authoritative_references: Any,
    handles: tuple[str, ...],
) -> tuple[list[str], set[str]]:
    """Validate that view references stay inside the supplied authority slice."""
    try:
        authoritative_ids = _reference_ids(authoritative_references)
    except ValueError as exc:
        return [str(exc)], set()
    known_ids = authoritative_ids | set(handles)
    errors: list[str] = []
    for field_path, value in _view_items(prompt_view):
        if isinstance(value, str):
            errors.extend(_reference_item_errors(field_path, value, known_ids))
    return errors, authoritative_ids


def _reference_item_errors(
    field_path: str, value: str, known_ids: set[str]
) -> list[str]:
    """Report unknown reference tokens and serialized payloads in one view text."""
    errors = [
        f"prompt-view reference {identifier!r} is not in the "
        f"authoritative slice ({field_path})"
        for identifier in _REFERENCE_TOKEN_RE.findall(value)
        if identifier not in known_ids
    ]
    stripped = value.strip()
    if stripped.startswith(("{", "[")) and _parses_as_json(stripped):
        errors.append(f"raw serialized mapping payload is not allowed: {field_path}")
    return errors


def _parses_as_json(text: str) -> bool:
    """Return whether *text* is a complete JSON document."""
    try:
        json.loads(text)
    except (TypeError, ValueError):
        return False
    return True


def _missing_field_errors(
    prefix: str, names: Iterable[str], combined_prompt: str
) -> list[str]:
    """Return one diagnostic listing the *names* absent from the prompt, if any."""
    missing = [name for name in names if name not in combined_prompt]
    return [prefix + ", ".join(missing)] if missing else []


def _output_contract_errors(
    combined_prompt: str,
    output_schema: Any,
    valid_example: Any,
) -> list[str]:
    """Ensure the prompt teaches the requested output shape with an example."""
    errors = _missing_field_errors(
        "requested output schema is missing field(s): ",
        _schema_field_names(output_schema),
        combined_prompt,
    )
    if valid_example is not None:
        errors.extend(_example_contract_errors(combined_prompt, valid_example))
    return errors


def _example_contract_errors(combined_prompt: str, valid_example: Any) -> list[str]:
    """Ensure the prompt carries the valid output example and names it."""
    example_text = _serialized_example(valid_example)
    errors: list[str] = []
    if isinstance(valid_example, Mapping):
        errors = _missing_field_errors(
            "valid output example is missing field(s): ",
            [str(name) for name in valid_example],
            combined_prompt,
        )
    elif example_text and example_text not in combined_prompt:
        errors.append("valid output example is not present in rendered prompt")
    if "example" not in combined_prompt.lower():
        errors.append("requested output schema must include one valid example")
    return errors


def _contract_errors(
    *,
    prompt_view: Any,
    combined_prompt: str,
    expected_view_type: type[Any] | None,
    input_handles: Iterable[str] | None,
    accounted_handles: Iterable[str] | None,
    selectable_references: Any,
    authoritative_references: Any,
    prohibited_fields: Iterable[str] | None,
    output_schema: Any,
    valid_example: Any,
) -> list[str]:
    """Collect non-budget prompt contract diagnostics."""
    errors: list[str] = []
    if expected_view_type is not None and type(prompt_view) is not expected_view_type:
        errors.append(
            "prompt view must be the exact closed type "
            f"{expected_view_type.__name__}, got {type(prompt_view).__name__}"
        )

    handle_errors, handles = _handle_contract_errors(input_handles, accounted_handles)
    errors.extend(handle_errors)
    errors.extend(_selectable_contract_errors(selectable_references))
    errors.extend(
        _view_contract_errors(prompt_view, combined_prompt, prohibited_fields)
    )
    if authoritative_references is not None:
        reference_errors, _authoritative_ids = _reference_contract_errors(
            prompt_view, authoritative_references, handles
        )
        errors.extend(reference_errors)
    errors.extend(
        _output_contract_errors(combined_prompt, output_schema, valid_example)
    )
    return errors


def _resolve_prompt_budget(
    *,
    budget: PromptBudget | None,
    model_profile: Mapping[str, Any] | object | None,
    token_counter: TokenCounter | None,
    context_window: int | None,
    maximum_completion_tokens: int | None,
    safety_margin: int | None,
) -> PromptBudget | None:
    """Resolve the optional budget using the same precedence as the public seam."""
    if budget is not None:
        return budget
    if model_profile is not None:
        return PromptBudget.from_profile(model_profile, token_counter=token_counter)
    if context_window is None:
        return None
    if maximum_completion_tokens is None:
        raise ValueError("maximum_completion_tokens is required with context_window")
    return PromptBudget(
        context_window=context_window,
        maximum_completion_tokens=maximum_completion_tokens,
        safety_margin=safety_margin,
        token_counter=token_counter,
    )


def _budget_error(
    budget: PromptBudget | None,
    input_tokens: int,
) -> PromptBudgetExceeded | None:
    """Create a typed budget diagnostic when the rendered prompt is too large."""
    if budget is None or input_tokens <= budget.usable_input_tokens:
        return None
    return PromptBudgetExceeded(
        input_tokens=input_tokens,
        usable_input_tokens=budget.usable_input_tokens,
        context_window=budget.context_window,
        maximum_completion_tokens=budget.maximum_completion_tokens,
        safety_margin=budget.safety_margin or 0,
    )


def _controlled_budget_value(controls: Any, configured: Any, name: str) -> Any:
    """Read a budget value from stage controls, then from a configured budget."""
    value = getattr(controls, name, None)
    if value is None and isinstance(configured, PromptBudget):
        value = getattr(configured, name)
    return value


def _client_budget_value(client: Any, value: Any, *names: str) -> Any:
    """Fall back to the first client attribute among *names* while *value* is unset."""
    for name in names:
        if value is not None or client is None:
            break
        value = getattr(client, name, None)
    return value


def resolve_adapter_prompt_budget(
    adapter: Any,
    controls: Any,
    *,
    maximum_completion_tokens: int,
) -> PromptBudget | None:
    """Resolve one adapter's context budget from controls, client, or settings.

    Routing and slot filling use the same provider-budget rules.  Keeping the
    resolution here prevents the two stages from drifting in how they inspect
    an adapter or cap completion reservation, while accepting ``Any`` keeps
    this infrastructure leaf independent of stage-specific control models.
    """
    configured = getattr(adapter, "prompt_budget", None)
    context_window = _controlled_budget_value(controls, configured, "context_window")
    client = getattr(adapter, "llm_client", None)
    context_window = _client_budget_value(
        client, context_window, "context_window", "model_context_window"
    )
    if context_window is None:
        return None
    safety_margin = _client_budget_value(
        client,
        _controlled_budget_value(controls, configured, "safety_margin"),
        "safety_margin",
    )
    configured_completion = getattr(controls, "maximum_completion_tokens", None)
    return PromptBudget(
        context_window=int(context_window),
        maximum_completion_tokens=min(
            maximum_completion_tokens,
            configured_completion or maximum_completion_tokens,
        ),
        safety_margin=safety_margin,
    )


def audit_prompt_contract(
    *,
    stage: str,
    prompt_view: Any,
    system_prompt: str,
    user_prompt: str,
    expected_view_type: type[Any] | None = None,
    input_handles: Iterable[str] | None = None,
    accounted_handles: Iterable[str] | None = None,
    selectable_references: Any = None,
    authoritative_references: Any = None,
    prohibited_fields: Iterable[str] | None = None,
    output_schema: Any = None,
    valid_example: Any = None,
    budget: PromptBudget | None = None,
    model_profile: Mapping[str, Any] | object | None = None,
    token_counter: TokenCounter | None = None,
    context_window: int | None = None,
    maximum_completion_tokens: int | None = None,
    safety_margin: int | None = None,
    raise_on_error: bool = True,
) -> PromptAudit:
    """Audit one fully rendered provider prompt before dispatch.

    The digest covers the exact system/user pair with one newline separator.
    Prompt budget accounting covers both messages.  A model profile or an
    explicit ``PromptBudget`` is required when budget enforcement is desired;
    callers may omit both for a contract-only audit.
    """
    if not isinstance(system_prompt, str) or not isinstance(user_prompt, str):
        raise TypeError("system_prompt and user_prompt must be strings")
    combined_prompt = f"{system_prompt}\n{user_prompt}"
    digest = hashlib.sha256(combined_prompt.encode("utf-8")).hexdigest()
    resolved_budget = _resolve_prompt_budget(
        budget=budget,
        model_profile=model_profile,
        token_counter=token_counter,
        context_window=context_window,
        maximum_completion_tokens=maximum_completion_tokens,
        safety_margin=safety_margin,
    )

    errors = _contract_errors(
        prompt_view=prompt_view,
        combined_prompt=combined_prompt,
        expected_view_type=expected_view_type,
        input_handles=input_handles,
        accounted_handles=accounted_handles,
        selectable_references=selectable_references,
        authoritative_references=authoritative_references,
        prohibited_fields=prohibited_fields,
        output_schema=output_schema,
        valid_example=valid_example,
    )
    if resolved_budget is None:
        input_tokens = estimate_prompt_tokens(combined_prompt)
    else:
        input_tokens = resolved_budget.count(combined_prompt)
    budget_error = _budget_error(resolved_budget, input_tokens)
    if budget_error is not None:
        errors.append(str(budget_error))

    audit = PromptAudit(
        stage=stage,
        rendered_prompt_digest=digest,
        input_tokens=input_tokens,
        errors=tuple(errors),
        **_budget_audit_fields(resolved_budget),
    )
    if raise_on_error and errors:
        raise budget_error or PromptContractError(*errors)
    return audit


def _budget_audit_fields(budget: PromptBudget | None) -> dict[str, Any]:
    """Return the audit fields that describe the resolved budget, if any."""
    if budget is None:
        return {
            "input_tokens_estimated": True,
            "context_window": None,
            "maximum_completion_tokens": None,
            "safety_margin": None,
            "usable_input_tokens": None,
        }
    return {
        "input_tokens_estimated": budget.token_counter is None,
        "context_window": budget.context_window,
        "maximum_completion_tokens": budget.maximum_completion_tokens,
        "safety_margin": budget.safety_margin,
        "usable_input_tokens": budget.usable_input_tokens,
    }


__all__ = [
    "PromptAudit",
    "PromptBudget",
    "PromptBudgetExceeded",
    "PromptContractError",
    "audit_prompt_contract",
    "estimate_prompt_tokens",
    "resolve_adapter_prompt_budget",
]
