"""Provider-authored behavior drafts compiled to canonical Gherkin artifacts."""

from __future__ import annotations

import json
from collections import Counter
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from asago_scenario_generator.models.attack_tree import AttackTree
from asago_scenario_generator.models.capability_profile import CapabilityProfile
from asago_scenario_generator.models.scenario import (
    BehaviorAction,
    BehaviorAssertion,
    BehaviorScenario,
    BehaviorSpec,
)
from asago_scenario_generator.pipeline.generate.tree_semantics import (
    CanonicalCompilationError,
    DraftValidation,
    InvalidSemanticDraft,
    ProjectionInfeasible,
    SemanticDraftViolation,
    _handle_membership_violations,
)

ExampleValue = str | int | float | bool


class BehaviorParameterSpec(BaseModel):
    """Compiler-owned parameter contract for one executable interaction."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z][A-Za-z0-9_]*$")
    value_type: Literal["string", "integer", "number", "boolean"]
    required: bool = True


class ActionHandle(BaseModel):
    """A short provider handle backed by one canonical behavior action."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    handle: str = Field(pattern=r"^a\d+$")
    action: BehaviorAction
    parameters: tuple[BehaviorParameterSpec, ...] = ()
    zone: str | None = None


class AssertionHandle(BaseModel):
    """A short provider handle backed by one canonical postcondition."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    handle: str = Field(pattern=r"^p\d+$")
    assertion_id: str = Field(min_length=1)
    source_step_id: str = Field(min_length=1)
    postcondition_id: str = Field(min_length=1)
    description: str = Field(min_length=1, max_length=500)


class BehaviorCompilationContext(BaseModel):
    """Immutable inventory exposed at the behavior draft/compiler seam."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action_handles: tuple[ActionHandle, ...] = Field(min_length=1)
    assertion_handles: tuple[AssertionHandle, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def _handles_are_unique(self) -> "BehaviorCompilationContext":
        handles = [item.handle for item in self.action_handles] + [
            item.handle for item in self.assertion_handles
        ]
        if len(set(handles)) != len(handles):
            raise ValueError("behavior context handles must be unique")
        return self


class BehaviorDraftStep(BaseModel):
    """One provider-authored interaction or assertion placement."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["action", "assertion"]
    handle: str = Field(min_length=1, max_length=16)
    text: str = Field(min_length=1, max_length=500)
    examples: dict[str, ExampleValue] = Field(default_factory=dict, max_length=8)


class BehaviorScenarioDraft(BaseModel):
    """Provider-authored scenario grouping and concrete step order."""

    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=1, max_length=160)
    steps: tuple[BehaviorDraftStep, ...] = Field(min_length=1, max_length=64)


class BehaviorDraftV2(BaseModel):
    """Bounded semantic behavior response; never raw Gherkin syntax."""

    model_config = ConfigDict(extra="forbid")

    scenarios: tuple[BehaviorScenarioDraft, ...] = Field(min_length=1, max_length=8)


class CompactBehaviorDraftV2(BehaviorDraftV2):
    """Length-retry schema name; semantic fields remain unchanged."""


def build_behavior_draft_response_model(
    handles: tuple[str, ...] | list[str],
    *,
    compact: bool = False,
    examples_allowed: bool = True,
) -> type[BehaviorDraftV2]:
    """Return a request-local schema advertising only supplied handles."""

    allowed = tuple(handles)
    if not allowed:
        raise ValueError("behavior response schema requires handles")
    base = CompactBehaviorDraftV2 if compact else BehaviorDraftV2

    def model_json_schema(
        cls: type[BaseModel], *args: object, **kwargs: object
    ) -> dict[str, object]:
        del cls
        schema = base.model_json_schema(*args, **kwargs)

        def constrain(value: object) -> None:
            if isinstance(value, dict):
                properties = value.get("properties")
                if isinstance(properties, dict) and "handle" in properties:
                    properties["handle"] = {
                        "enum": list(allowed),
                        "maxLength": 16,
                        "minLength": 1,
                        "title": "Handle",
                        "type": "string",
                    }
                if (
                    not examples_allowed
                    and isinstance(properties, dict)
                    and "examples" in properties
                ):
                    properties["examples"] = {
                        "additionalProperties": False,
                        "default": {},
                        "maxProperties": 0,
                        "title": "Examples",
                        "type": "object",
                    }
                for child in value.values():
                    constrain(child)
            elif isinstance(value, list):
                for child in value:
                    constrain(child)

        constrain(schema)
        return schema

    prefix = "Compact" if compact else ""
    return type(
        f"{prefix}BehaviorDraftV2For{len(allowed)}Handles",
        (base,),
        {"model_json_schema": classmethod(model_json_schema)},
    )


def derive_behavior_handles(
    attack_tree: AttackTree,
    profile: CapabilityProfile,
    projection_context: dict[str, object],
    *,
    parameter_specs_by_action_id: dict[str, tuple[BehaviorParameterSpec, ...]]
    | None = None,
) -> BehaviorCompilationContext:
    """Build compact action/assertion handles from accepted canonical artifacts."""

    from asago_scenario_generator.pipeline.generate.gherkin import (
        _collect_leaf_nodes_dfs,
        _derive_behavior_actions,
    )

    actions = _derive_behavior_actions(attack_tree, profile, projection_context)
    zones_by_action_id = {
        f"ba-{leaf.id}": leaf.zone for leaf in _collect_leaf_nodes_dfs(attack_tree.root)
    }
    parameter_specs_by_action_id = parameter_specs_by_action_id or {}
    action_handles = tuple(
        ActionHandle(
            handle=f"a{index}",
            action=action,
            parameters=parameter_specs_by_action_id.get(action.action_id, ()),
            zone=zones_by_action_id.get(action.action_id),
        )
        for index, action in enumerate(actions)
    )

    selected_steps = projection_context.get("selected_steps", [])
    assertions: list[AssertionHandle] = []
    for step in selected_steps if isinstance(selected_steps, list) else []:
        if not isinstance(step, dict) or not step.get("step_id"):
            continue
        step_id = str(step["step_id"])
        for pc in step.get("observable_postconditions", []):
            if not isinstance(pc, dict) or not pc.get("security_relevant"):
                continue
            pc_id = str(pc["postcondition_id"])
            assertions.append(
                AssertionHandle(
                    handle=f"p{len(assertions)}",
                    assertion_id=f"assert-{step_id}-{pc_id}",
                    source_step_id=step_id,
                    postcondition_id=pc_id,
                    description=str(pc.get("description") or "observable outcome"),
                )
            )
    if not assertions:
        raise ProjectionInfeasible(
            "behavior compilation requires a security-relevant postcondition"
        )
    return BehaviorCompilationContext(
        action_handles=action_handles,
        assertion_handles=tuple(assertions),
    )


def _example_matches(value: ExampleValue, expected: str) -> bool:
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    return isinstance(value, str)


def _behavior_handle_violations(
    expected_actions: tuple[str, ...],
    expected_assertions: tuple[str, ...],
    actual: tuple[str, ...],
) -> tuple[list[SemanticDraftViolation], tuple[str, ...], tuple[str, ...]]:
    """Collect unknown, duplicate, and split missing behavior violations."""
    violations, unknown, duplicates = _handle_membership_violations(
        expected_actions + expected_assertions, actual, "behavior"
    )
    counts = Counter(actual)
    missing_actions = tuple(
        handle for handle in expected_actions if handle not in counts
    )
    missing_assertions = tuple(
        handle for handle in expected_assertions if handle not in counts
    )
    if missing_actions:
        violations.append(
            SemanticDraftViolation(
                code="missing_handle",
                handles=missing_actions,
                message=f"missing action handles: {list(missing_actions)}",
            )
        )
    if missing_assertions:
        violations.append(
            SemanticDraftViolation(
                code="missing_handle",
                handles=missing_assertions,
                message=f"missing assertion handles: {list(missing_assertions)}",
            )
        )
    return violations, unknown, duplicates


def _step_kind_violations(
    step: BehaviorDraftStep,
    action_by_handle: dict[str, ActionHandle],
    assertion_by_handle: dict[str, AssertionHandle],
) -> list[SemanticDraftViolation]:
    """Collect handle/kind mismatches for one authored step."""
    if step.kind == "action" and step.handle in assertion_by_handle:
        return [
            SemanticDraftViolation(
                code="handle_kind_mismatch",
                handles=(step.handle,),
                message=f"assertion handle '{step.handle}' used as an action",
            )
        ]
    if step.kind == "assertion" and step.handle in action_by_handle:
        return [
            SemanticDraftViolation(
                code="handle_kind_mismatch",
                handles=(step.handle,),
                message=f"action handle '{step.handle}' used as an assertion",
            )
        ]
    return []


def _unknown_parameter_violation(
    step: BehaviorDraftStep,
    parameter_by_name: dict[str, BehaviorParameterSpec],
) -> SemanticDraftViolation | None:
    """Return the unknown-example-parameter violation, when present."""
    unknown_parameters = tuple(sorted(set(step.examples) - set(parameter_by_name)))
    if not unknown_parameters:
        return None
    return SemanticDraftViolation(
        code="unknown_example_parameter",
        handles=(step.handle,),
        message=(
            f"action '{step.handle}' uses unknown example parameters "
            f"{list(unknown_parameters)}"
        ),
    )


def _missing_parameter_violation(
    step: BehaviorDraftStep,
    parameter_by_name: dict[str, BehaviorParameterSpec],
) -> SemanticDraftViolation | None:
    """Return the missing-required-parameter violation, when present."""
    missing_parameters = tuple(
        name
        for name, item in parameter_by_name.items()
        if item.required and name not in step.examples
    )
    if not missing_parameters:
        return None
    return SemanticDraftViolation(
        code="missing_example_parameter",
        handles=(step.handle,),
        message=(
            f"action '{step.handle}' omits required example parameters "
            f"{list(missing_parameters)}"
        ),
    )


def _invalid_parameter_type_violation(
    step: BehaviorDraftStep,
    parameter_by_name: dict[str, BehaviorParameterSpec],
) -> SemanticDraftViolation | None:
    """Return the invalid-example-type violation, when present."""
    invalid = tuple(
        name
        for name, value in step.examples.items()
        if name in parameter_by_name
        and not _example_matches(value, parameter_by_name[name].value_type)
    )
    if not invalid:
        return None
    return SemanticDraftViolation(
        code="invalid_example_type",
        handles=(step.handle,),
        message=f"action '{step.handle}' has invalid example types for {list(invalid)}",
    )


def _step_parameter_violations(
    step: BehaviorDraftStep, action: ActionHandle
) -> list[SemanticDraftViolation]:
    """Collect example-parameter contract violations for one action step."""
    parameter_by_name = {item.name: item for item in action.parameters}
    violations: list[SemanticDraftViolation] = []
    for violation in (
        _unknown_parameter_violation(step, parameter_by_name),
        _missing_parameter_violation(step, parameter_by_name),
        _invalid_parameter_type_violation(step, parameter_by_name),
    ):
        if violation is not None:
            violations.append(violation)
    return violations


def _assertion_owner_violations(
    step: BehaviorDraftStep,
    assertion: AssertionHandle,
    context: BehaviorCompilationContext,
) -> list[SemanticDraftViolation]:
    """Collect ownership violations for one assertion placement."""
    owners = [
        action.handle
        for action in context.action_handles
        if assertion.source_step_id in action.action.projected_step_ids
    ]
    if len(owners) != 1:
        return [
            SemanticDraftViolation(
                code="invalid_assertion_owner",
                handles=(step.handle,),
                message=(
                    f"assertion '{step.handle}' must have exactly one "
                    f"canonical owning action; found {owners}"
                ),
            )
        ]
    return []


def _action_order_violation(
    expected_actions: tuple[str, ...],
    actual_action_order: tuple[str, ...],
    duplicates: tuple[str, ...],
    unknown: tuple[str, ...],
) -> SemanticDraftViolation | None:
    """Return the ordering violation when coverage is exact but order is not."""
    if duplicates or unknown or actual_action_order == expected_actions:
        return None
    return SemanticDraftViolation(
        code="illegal_order",
        handles=actual_action_order,
        message="action handles do not preserve canonical projected-step order",
    )


def _step_validation_violations(
    step: BehaviorDraftStep,
    action_by_handle: dict[str, ActionHandle],
    assertion_by_handle: dict[str, AssertionHandle],
    context: BehaviorCompilationContext,
) -> list[SemanticDraftViolation]:
    """Collect kind, parameter, and ownership violations for one authored step."""
    violations = _step_kind_violations(step, action_by_handle, assertion_by_handle)
    if step.handle in action_by_handle:
        violations.extend(
            _step_parameter_violations(step, action_by_handle[step.handle])
        )
    if step.handle in assertion_by_handle:
        violations.extend(
            _assertion_owner_violations(step, assertion_by_handle[step.handle], context)
        )
    return violations


def _flatten_scenario_steps(draft: BehaviorDraftV2) -> list[BehaviorDraftStep]:
    """Return every authored step across scenarios in draft order."""
    return [step for scenario in draft.scenarios for step in scenario.steps]


def _expected_handle_tuples(
    context: BehaviorCompilationContext,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Return the canonical action and assertion handle tuples."""
    return (
        tuple(item.handle for item in context.action_handles),
        tuple(item.handle for item in context.assertion_handles),
    )


def _handle_lookup_maps(
    context: BehaviorCompilationContext,
) -> tuple[dict[str, ActionHandle], dict[str, AssertionHandle]]:
    """Return handle lookup maps for canonical actions and assertions."""
    return (
        {item.handle: item for item in context.action_handles},
        {item.handle: item for item in context.assertion_handles},
    )


def _actual_handle_sequence(all_steps: list[BehaviorDraftStep]) -> tuple[str, ...]:
    """Return the authored handle sequence in exact draft order."""
    return tuple(step.handle for step in all_steps)


def _authored_action_order(
    all_steps: list[BehaviorDraftStep],
    action_by_handle: dict[str, ActionHandle],
) -> tuple[str, ...]:
    """Return the authored action-handle sequence, skipping assertion handles."""
    return tuple(step.handle for step in all_steps if step.handle in action_by_handle)


def validate_behavior_draft(
    draft: BehaviorDraftV2,
    context: BehaviorCompilationContext,
) -> DraftValidation:
    """Validate exact coverage, ordering, parameters, and assertion placement."""

    all_steps = _flatten_scenario_steps(draft)
    expected_actions, expected_assertions = _expected_handle_tuples(context)
    violations, unknown, duplicates = _behavior_handle_violations(
        expected_actions,
        expected_assertions,
        _actual_handle_sequence(all_steps),
    )

    action_by_handle, assertion_by_handle = _handle_lookup_maps(context)
    order_violation = _action_order_violation(
        expected_actions,
        _authored_action_order(all_steps, action_by_handle),
        duplicates,
        unknown,
    )
    if order_violation is not None:
        violations.append(order_violation)

    for scenario in draft.scenarios:
        for step in scenario.steps:
            violations.extend(
                _step_validation_violations(
                    step, action_by_handle, assertion_by_handle, context
                )
            )
    return DraftValidation(accepted=not violations, violations=tuple(violations))


def _one_line(text: str) -> str:
    return " ".join(text.split())


def strip_compiler_owned_zone_suffix(text: str, zone: str | None) -> str:
    """Remove provider-echoed zone metadata before canonical rendering."""

    normalized = _one_line(text)
    if zone is None:
        return normalized
    suffix = f" ({zone})"
    while normalized.endswith(suffix):
        normalized = normalized[: -len(suffix)].rstrip()
    return normalized


def _render_example(value: ExampleValue) -> str:
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _compile_behavior_draft(
    draft: BehaviorDraftV2,
    context: BehaviorCompilationContext,
) -> BehaviorSpec:
    """Attach canonical identity and render accepted semantic interactions."""

    validation = validate_behavior_draft(draft, context)
    if not validation.accepted:
        raise InvalidSemanticDraft(validation)
    action_by_handle = {item.handle: item for item in context.action_handles}
    compiled_actions: list[BehaviorAction] = []
    compiled_assertions: list[BehaviorAssertion] = []
    scenarios: list[BehaviorScenario] = []
    zone_map: dict[str, str] = {}

    authored_steps = {
        step.handle: step for scenario in draft.scenarios for step in scenario.steps
    }
    assertions_by_action: dict[str, list[AssertionHandle]] = {
        item.handle: [] for item in context.action_handles
    }
    for assertion in context.assertion_handles:
        owner = next(
            action.handle
            for action in context.action_handles
            if assertion.source_step_id in action.action.projected_step_ids
        )
        assertions_by_action[owner].append(assertion)

    scenario_index = 0
    for authored_scenario in draft.scenarios:
        authored_actions = [
            step for step in authored_scenario.steps if step.handle in action_by_handle
        ]
        if not authored_actions:
            continue
        scenario_index += 1
        step_ids: list[str] = []
        for step in authored_actions:
            handle = action_by_handle[step.handle]
            text = strip_compiler_owned_zone_suffix(step.text, handle.zone)
            if step.examples:
                rendered = ", ".join(
                    f"{name}={_render_example(step.examples[name])}"
                    for name in sorted(step.examples)
                )
                text = f"{text} [{rendered}]"
            action = handle.action.model_copy(update={"text": text}, deep=True)
            compiled_actions.append(action)
            step_ids.append(action.action_id)
            if handle.zone is not None:
                zone_map[action.action_id] = handle.zone
            for owned_assertion in assertions_by_action[step.handle]:
                assertion_step = authored_steps[owned_assertion.handle]
                assertion = BehaviorAssertion(
                    assertion_id=owned_assertion.assertion_id,
                    source_step_ids=(owned_assertion.source_step_id,),
                    projected_postcondition_ids=(owned_assertion.postcondition_id,),
                    gherkin_keyword="Then",
                    text=_one_line(assertion_step.text),
                )
                compiled_assertions.append(assertion)
                step_ids.append(assertion.assertion_id)
        scenarios.append(
            BehaviorScenario(
                scenario_id=f"bs-{scenario_index}",
                title=_one_line(authored_scenario.title),
                step_ids=tuple(step_ids),
            )
        )

    from asago_scenario_generator.pipeline.generate.behavior_compiler import (
        render_gherkin_from_behavior_spec,
    )

    gherkin = render_gherkin_from_behavior_spec(
        compiled_actions,
        compiled_assertions,
        zone_map=zone_map,
        scenarios=scenarios,
    )
    return BehaviorSpec(
        actions=tuple(compiled_actions),
        assertions=tuple(compiled_assertions),
        scenarios=tuple(scenarios),
        gherkin_text=gherkin,
    )


def compile_behavior_draft(
    draft: BehaviorDraftV2,
    context: BehaviorCompilationContext,
) -> BehaviorSpec:
    """Compile one accepted behavior draft, classifying compiler defects."""

    try:
        return _compile_behavior_draft(draft, context)
    except InvalidSemanticDraft:
        raise
    except CanonicalCompilationError:
        raise
    except Exception as exc:
        raise CanonicalCompilationError(
            f"accepted behavior draft failed canonical compilation: {exc}"
        ) from exc
