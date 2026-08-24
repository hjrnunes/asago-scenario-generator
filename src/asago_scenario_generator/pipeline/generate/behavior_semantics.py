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


def _constrain_behavior_handle_schema(
    properties: dict[str, object], allowed: tuple[str, ...]
) -> None:
    """Pin a schema's handle property to the supplied finite enum."""
    properties["handle"] = {
        "enum": list(allowed),
        "maxLength": 16,
        "minLength": 1,
        "title": "Handle",
        "type": "string",
    }


def _constrain_examples_schema(properties: dict[str, object]) -> None:
    """Replace a schema's examples property with the empty-object contract."""
    properties["examples"] = {
        "additionalProperties": False,
        "default": {},
        "maxProperties": 0,
        "title": "Examples",
        "type": "object",
    }


def _examples_schema_is_banned(properties: object, examples_allowed: bool) -> bool:
    """Return True when the examples property must be pinned to empty."""
    return (
        not examples_allowed
        and isinstance(properties, dict)
        and "examples" in properties
    )


def _schema_child_values(value: object) -> tuple[object, ...]:
    """Return the child nodes of a schema value, if any."""
    if isinstance(value, dict):
        return tuple(value.values())
    return tuple(value) if isinstance(value, list) else ()


def _constrain_behavior_schema_node(
    value: dict[str, object],
    allowed: tuple[str, ...],
    examples_allowed: bool,
) -> None:
    """Pin handle and examples contracts on one schema node."""
    properties = value.get("properties")
    if isinstance(properties, dict) and "handle" in properties:
        _constrain_behavior_handle_schema(properties, allowed)
    if _examples_schema_is_banned(properties, examples_allowed):
        _constrain_examples_schema(properties)


def _constrain_behavior_schema_tree(
    value: object, allowed: tuple[str, ...], examples_allowed: bool
) -> None:
    """Recursively pin behavior-handle contracts across the schema tree."""
    if isinstance(value, dict):
        _constrain_behavior_schema_node(value, allowed, examples_allowed)
    for child in _schema_child_values(value):
        _constrain_behavior_schema_tree(child, allowed, examples_allowed)


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
        _constrain_behavior_schema_tree(schema, allowed, examples_allowed)
        return schema

    prefix = "Compact" if compact else ""
    return type(
        f"{prefix}BehaviorDraftV2For{len(allowed)}Handles",
        (base,),
        {"model_json_schema": classmethod(model_json_schema)},
    )


def _action_handles_from_derived(
    actions: list[BehaviorAction],
    zones_by_action_id: dict[str, str | None],
    parameter_specs_by_action_id: dict[str, tuple[BehaviorParameterSpec, ...]],
) -> tuple[ActionHandle, ...]:
    """Allocate one compact action handle per derived canonical action."""
    return tuple(
        ActionHandle(
            handle=f"a{index}",
            action=action,
            parameters=parameter_specs_by_action_id.get(action.action_id, ()),
            zone=zones_by_action_id.get(action.action_id),
        )
        for index, action in enumerate(actions)
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
    action_handles = _action_handles_from_derived(
        actions,
        zones_by_action_id,
        parameter_specs_by_action_id or {},
    )

    assertions = _assertion_handles_from_selected_steps(
        projection_context.get("selected_steps", [])
    )
    if not assertions:
        raise ProjectionInfeasible(
            "behavior compilation requires a security-relevant postcondition"
        )
    return BehaviorCompilationContext(
        action_handles=action_handles,
        assertion_handles=tuple(assertions),
    )


def _step_id_or_none(step: object) -> str | None:
    """Return the step id of a dict-shaped selected step, if present."""
    if not isinstance(step, dict) or not step.get("step_id"):
        return None
    return str(step["step_id"])


def _is_security_relevant(postcondition: object) -> bool:
    """Return True when a postcondition is dict-shaped and security-relevant."""
    return isinstance(postcondition, dict) and bool(
        postcondition.get("security_relevant")
    )


def _security_relevant_pairs(
    step: dict[str, object], step_id: str
) -> list[tuple[str, dict[str, object]]]:
    """Collect the security-relevant postconditions of one selected step."""
    pairs: list[tuple[str, dict[str, object]]] = []
    for postcondition in step.get("observable_postconditions", []):
        if _is_security_relevant(postcondition):
            pairs.append((step_id, postcondition))
    return pairs


def _security_relevant_postconditions(
    steps: object,
) -> list[tuple[str, dict[str, object]]]:
    """Collect (step_id, postcondition) pairs from selected projected steps."""
    pairs: list[tuple[str, dict[str, object]]] = []
    for step in steps if isinstance(steps, list) else []:
        step_id = _step_id_or_none(step)
        if step_id is None:
            continue
        pairs.extend(_security_relevant_pairs(step, step_id))
    return pairs


def _assertion_handles_from_selected_steps(
    selected_steps: object,
) -> list[AssertionHandle]:
    """Derive one assertion handle per security-relevant postcondition."""
    assertions: list[AssertionHandle] = []
    for step_id, postcondition in _security_relevant_postconditions(selected_steps):
        pc_id = str(postcondition["postcondition_id"])
        assertions.append(
            AssertionHandle(
                handle=f"p{len(assertions)}",
                assertion_id=f"assert-{step_id}-{pc_id}",
                source_step_id=step_id,
                postcondition_id=pc_id,
                description=str(
                    postcondition.get("description") or "observable outcome"
                ),
            )
        )
    return assertions


def _example_matches(value: ExampleValue, expected: str) -> bool:
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    return isinstance(value, str)


def _missing_handles(expected: tuple[str, ...], counts: Counter) -> tuple[str, ...]:
    """Return the expected handles absent from the authored counts."""
    return tuple(handle for handle in expected if handle not in counts)


def _missing_behavior_handle_violations(
    expected_actions: tuple[str, ...],
    expected_assertions: tuple[str, ...],
    counts: Counter,
) -> list[SemanticDraftViolation]:
    """Collect split missing-action and missing-assertion violations."""
    violations: list[SemanticDraftViolation] = []
    missing_actions = _missing_handles(expected_actions, counts)
    missing_assertions = _missing_handles(expected_assertions, counts)
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
    return violations


def _behavior_handle_violations(
    expected_actions: tuple[str, ...],
    expected_assertions: tuple[str, ...],
    actual: tuple[str, ...],
) -> tuple[list[SemanticDraftViolation], tuple[str, ...], tuple[str, ...]]:
    """Collect unknown, duplicate, and split missing behavior violations."""
    violations, unknown, duplicates = _handle_membership_violations(
        expected_actions + expected_assertions, actual, "behavior"
    )
    violations.extend(
        _missing_behavior_handle_violations(
            expected_actions, expected_assertions, Counter(actual)
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


def _authored_steps_by_handle(draft: BehaviorDraftV2) -> dict[str, BehaviorDraftStep]:
    """Return every authored step keyed by its handle."""
    return {
        step.handle: step for scenario in draft.scenarios for step in scenario.steps
    }


def _assertions_by_owner(
    context: BehaviorCompilationContext,
    action_by_handle: dict[str, ActionHandle],
) -> dict[str, list[AssertionHandle]]:
    """Group canonical assertion handles under their owning action handle."""
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
    return assertions_by_action


def _compile_step_text(step: BehaviorDraftStep, handle: ActionHandle) -> str:
    """Render one authored action step to canonical interaction text."""
    text = strip_compiler_owned_zone_suffix(step.text, handle.zone)
    if step.examples:
        rendered = ", ".join(
            f"{name}={_render_example(step.examples[name])}"
            for name in sorted(step.examples)
        )
        text = f"{text} [{rendered}]"
    return text


def _compile_assertion_for_owner(
    owned_assertion: AssertionHandle,
    authored_steps: dict[str, BehaviorDraftStep],
) -> BehaviorAssertion:
    """Render one owned assertion placement to a canonical assertion."""
    assertion_step = authored_steps[owned_assertion.handle]
    return BehaviorAssertion(
        assertion_id=owned_assertion.assertion_id,
        source_step_ids=(owned_assertion.source_step_id,),
        projected_postcondition_ids=(owned_assertion.postcondition_id,),
        gherkin_keyword="Then",
        text=_one_line(assertion_step.text),
    )


def _compile_owned_assertions(
    handle: str,
    assertions_by_action: dict[str, list[AssertionHandle]],
    authored_steps: dict[str, BehaviorDraftStep],
) -> tuple[list[BehaviorAssertion], list[str]]:
    """Compile the assertions owned by one authored action step."""
    compiled: list[BehaviorAssertion] = []
    step_ids: list[str] = []
    for owned_assertion in assertions_by_action[handle]:
        assertion = _compile_assertion_for_owner(owned_assertion, authored_steps)
        compiled.append(assertion)
        step_ids.append(assertion.assertion_id)
    return compiled, step_ids


def _authored_actions_in_scenario(
    authored_scenario: BehaviorScenarioDraft,
    action_by_handle: dict[str, ActionHandle],
) -> list[BehaviorDraftStep]:
    """Return the authored action steps of one scenario, in draft order."""
    return [step for step in authored_scenario.steps if step.handle in action_by_handle]


def _compilable_authored_scenarios(
    draft: BehaviorDraftV2, action_by_handle: dict[str, ActionHandle]
) -> list[BehaviorScenarioDraft]:
    """Return the authored scenarios containing at least one action step."""
    return [
        scenario
        for scenario in draft.scenarios
        if _authored_actions_in_scenario(scenario, action_by_handle)
    ]


def _compile_authored_scenario(
    authored_scenario: BehaviorScenarioDraft,
    action_by_handle: dict[str, ActionHandle],
    assertions_by_action: dict[str, list[AssertionHandle]],
    authored_steps: dict[str, BehaviorDraftStep],
    scenario_index: int,
) -> tuple[
    BehaviorScenario, list[BehaviorAction], list[BehaviorAssertion], dict[str, str]
]:
    """Compile one authored scenario holding at least one action step."""
    compiled_actions: list[BehaviorAction] = []
    compiled_assertions: list[BehaviorAssertion] = []
    zone_map: dict[str, str] = {}
    step_ids: list[str] = []
    for step in _authored_actions_in_scenario(authored_scenario, action_by_handle):
        handle = action_by_handle[step.handle]
        action = handle.action.model_copy(
            update={"text": _compile_step_text(step, handle)}, deep=True
        )
        compiled_actions.append(action)
        step_ids.append(action.action_id)
        if handle.zone is not None:
            zone_map[action.action_id] = handle.zone
        assertions, assertion_ids = _compile_owned_assertions(
            step.handle, assertions_by_action, authored_steps
        )
        compiled_assertions.extend(assertions)
        step_ids.extend(assertion_ids)
    scenario = BehaviorScenario(
        scenario_id=f"bs-{scenario_index}",
        title=_one_line(authored_scenario.title),
        step_ids=tuple(step_ids),
    )
    return scenario, compiled_actions, compiled_assertions, zone_map


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

    authored_steps = _authored_steps_by_handle(draft)
    assertions_by_action = _assertions_by_owner(context, action_by_handle)

    for scenario_index, authored_scenario in enumerate(
        _compilable_authored_scenarios(draft, action_by_handle), start=1
    ):
        scenario, scenario_actions, scenario_assertions, scenario_zones = (
            _compile_authored_scenario(
                authored_scenario,
                action_by_handle,
                assertions_by_action,
                authored_steps,
                scenario_index,
            )
        )
        scenarios.append(scenario)
        compiled_actions.extend(scenario_actions)
        compiled_assertions.extend(scenario_assertions)
        zone_map.update(scenario_zones)

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


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-24T01:20:30Z","module_hash":"2e423b381ad3e4236d3bb00508362b63fee5121c0bf6146be55c17a53cd64434","source_sha256":"f81965337ece93ebdc221422b47f49a8779f43201da61b8a58c40feb1c183225","functions":[{"id":"func/BehaviorCompilationContext._handles_are_unique","name":"_handles_are_unique","line":73,"end_line":79,"hash":"3a0e6087d388eb57f045a121e5d890f6586a5d1004ff70f365c15490ebfdd9d3"},{"id":"func/_constrain_behavior_handle_schema","name":"_constrain_behavior_handle_schema","line":114,"end_line":124,"hash":"c55542573f50c41b121d6dbe0751f29ecdba9f4b2e09f3eeb7d85d372a4a77d9"},{"id":"func/_constrain_examples_schema","name":"_constrain_examples_schema","line":127,"end_line":135,"hash":"ff41a2ba9828254451f23eb7f06330cc4aab60a704d953e0d4b4e8d80bbaaf31"},{"id":"func/_examples_schema_is_banned","name":"_examples_schema_is_banned","line":138,"end_line":144,"hash":"743761c0b0715f5e7d9ff7722316937b065911f67856a18963866f00f803e70d"},{"id":"func/_schema_child_values","name":"_schema_child_values","line":147,"end_line":151,"hash":"5f4165d8e8afb7798330ee70cd34f476fca204d615b0044d3f64c9ffacc55653"},{"id":"func/_constrain_behavior_schema_node","name":"_constrain_behavior_schema_node","line":154,"end_line":164,"hash":"63699ce8c81137e1d162394f34fa390a592a223ff0a791544d455ec3eda8853b"},{"id":"func/_constrain_behavior_schema_tree","name":"_constrain_behavior_schema_tree","line":167,"end_line":174,"hash":"ee4560a62984b4d1b018c01df37a642c53975b64e3ddc5c81d88cb75cbed5d9e"},{"id":"func/build_behavior_draft_response_model","name":"build_behavior_draft_response_model","line":177,"end_line":203,"hash":"f70d2066e1c94b8a58ac4603a6c86c188773c37c4b16f029f3b766358de43a35"},{"id":"func/_action_handles_from_derived","name":"_action_handles_from_derived","line":206,"end_line":220,"hash":"a5b9ec6014271e83897ebed74f084621d5f8bb6417da17e46414c76d889ed4d7"},{"id":"func/derive_behavior_handles","name":"derive_behavior_handles","line":223,"end_line":258,"hash":"c70cdc611caeab680a9adcb8b53b622a73d8898cec3010a6c9e7e74d41fdebda"},{"id":"func/_step_id_or_none","name":"_step_id_or_none","line":261,"end_line":265,"hash":"7c8065a536ff3ab003a87da0e5ad6db188f96dc890bc88c3e8d71e71e4052b47"},{"id":"func/_is_security_relevant","name":"_is_security_relevant","line":268,"end_line":272,"hash":"f8eaa99f362cbe05673886d479c4be3b29217c32c33cfb73f154a38cb74709b9"},{"id":"func/_security_relevant_pairs","name":"_security_relevant_pairs","line":275,"end_line":283,"hash":"8dab05c0b27fe7a31e2567a6d414ff46b663af208cc43efa7105f0ca46b6bead"},{"id":"func/_security_relevant_postconditions","name":"_security_relevant_postconditions","line":286,"end_line":296,"hash":"d0ed5f67f7464beb97b9c161be01967fa524e965748a32d1784484921c3fb837"},{"id":"func/_assertion_handles_from_selected_steps","name":"_assertion_handles_from_selected_steps","line":299,"end_line":317,"hash":"85bde08932ce590006f3344defef1473c9439c87f69fd7b1acd55a7b761f1dd9"},{"id":"func/_example_matches","name":"_example_matches","line":320,"end_line":327,"hash":"fddfb18aaac5cdcbed0d7efbfd016d87520d904bca7f1655de982dd5bf3e7534"},{"id":"func/_missing_handles","name":"_missing_handles","line":330,"end_line":332,"hash":"c56dca3cb21b61082f7809c3694c81ae56bd216cf774e1dad3feb3308010d508"},{"id":"func/_missing_behavior_handle_violations","name":"_missing_behavior_handle_violations","line":335,"end_line":360,"hash":"b90e9a1ecbb6680e20304ad623d11370add270067bb9d4fd5fb60e2615d07dbc"},{"id":"func/_behavior_handle_violations","name":"_behavior_handle_violations","line":363,"end_line":377,"hash":"e61cd99b5eadbf1b7e6618324b001b0d6a98950bee2fbf5a647804c174a26568"},{"id":"func/_step_kind_violations","name":"_step_kind_violations","line":380,"end_line":402,"hash":"09b62154bb4fbdfda6763f020bba12fe12db01ee0c3626139798ee569cb06b83"},{"id":"func/_unknown_parameter_violation","name":"_unknown_parameter_violation","line":405,"end_line":420,"hash":"70b5a52f67322f9d052fefcd5d03b426d4df8cbc1496a80ef464986bf44b8410"},{"id":"func/_missing_parameter_violation","name":"_missing_parameter_violation","line":423,"end_line":442,"hash":"ff7f3c3c4993936cd657bbfeed85dc710e47ca10f95798bd12e6c6a0bf5ecd04"},{"id":"func/_invalid_parameter_type_violation","name":"_invalid_parameter_type_violation","line":445,"end_line":462,"hash":"1175d00f029d9cd27ee865a9676d438978898a8848501fd929c19eab0284beff"},{"id":"func/_step_parameter_violations","name":"_step_parameter_violations","line":465,"end_line":478,"hash":"9bdd33606180966b34d964d2a09e9e629f68fd88814cb5ee143916bc8b90aced"},{"id":"func/_assertion_owner_violations","name":"_assertion_owner_violations","line":481,"end_line":503,"hash":"0f122c641530bffba07df0d6fd885ae5f9f87f6059d7589122ed29e9aeded036"},{"id":"func/_action_order_violation","name":"_action_order_violation","line":506,"end_line":519,"hash":"a1fc5cbef6b147b40c678585c2b2f28bc0585a9b0813b5a6f4c721cac64ee69a"},{"id":"func/_step_validation_violations","name":"_step_validation_violations","line":522,"end_line":538,"hash":"b8d3f620f77004e10f689a2d6964134479b9676963f2d5481079728bb877eb8d"},{"id":"func/_flatten_scenario_steps","name":"_flatten_scenario_steps","line":541,"end_line":543,"hash":"d203468a0e5254872864d0cbb083d1236c67fd85c1468b950b476f8de087d446"},{"id":"func/_expected_handle_tuples","name":"_expected_handle_tuples","line":546,"end_line":553,"hash":"9180c2311a97fff2d59385e75bf12ab51a638f5098a5433cefc3806f36cfee0d"},{"id":"func/_handle_lookup_maps","name":"_handle_lookup_maps","line":556,"end_line":563,"hash":"6a58420c8e153184c04948db360b61f32b5e2a36bc54596ddee10e063f88865c"},{"id":"func/_actual_handle_sequence","name":"_actual_handle_sequence","line":566,"end_line":568,"hash":"508688e4d6f2bf16e1987ddaf9266f4fa3433c56570e75782fe75aebd549c616"},{"id":"func/_authored_action_order","name":"_authored_action_order","line":571,"end_line":576,"hash":"b225723001c51d2c2e29ae00371ea47e0fa771e7a08cb1896903c1f5e61b67c1"},{"id":"func/validate_behavior_draft","name":"validate_behavior_draft","line":579,"end_line":610,"hash":"d96a0efe6fef88751ec513dc81227c7e70ddefbaf2f579bee751e5eb6490bfb9"},{"id":"func/_one_line","name":"_one_line","line":613,"end_line":614,"hash":"1ada406571bbe28c8a0575eef4f30130354fcfa100b348cb27e1ef3d306a8bbd"},{"id":"func/strip_compiler_owned_zone_suffix","name":"strip_compiler_owned_zone_suffix","line":617,"end_line":626,"hash":"90b2b2a131d2509c39458ab40b03817a1e5b8117aa74f93ab2423a8b383ad8ee"},{"id":"func/_render_example","name":"_render_example","line":629,"end_line":634,"hash":"54b7e03a1bfdce77884931c54bfa7923d64de0a929240552476d56e510269336"},{"id":"func/_authored_steps_by_handle","name":"_authored_steps_by_handle","line":637,"end_line":641,"hash":"2ba41ad33d17a6334a08be77a4a931fac8baa162864ed111246843d9e33be978"},{"id":"func/_assertions_by_owner","name":"_assertions_by_owner","line":644,"end_line":659,"hash":"57374c9000d8571239be79573cc5cf435632c541bd62759b91cfa5a2eed4c30c"},{"id":"func/_compile_step_text","name":"_compile_step_text","line":662,"end_line":671,"hash":"6b05b025e703ac7befed938d19a779c0bea1e1b9228189dc70544fc56f286dac"},{"id":"func/_compile_assertion_for_owner","name":"_compile_assertion_for_owner","line":674,"end_line":686,"hash":"a4e610f84cb9979841666679963c9b84246f36982d454b976d235d7bb456297d"},{"id":"func/_compile_owned_assertions","name":"_compile_owned_assertions","line":689,"end_line":701,"hash":"26690ca6046d02eef5bb6ab0f95d953fcd81fd6aa7cddaf322fcbe3c01c666af"},{"id":"func/_authored_actions_in_scenario","name":"_authored_actions_in_scenario","line":704,"end_line":709,"hash":"9e94ff4f7e90ce8ff5bfb09937313f9988c81e3184a8092373e16a58b170ad17"},{"id":"func/_compilable_authored_scenarios","name":"_compilable_authored_scenarios","line":712,"end_line":720,"hash":"2f178734ec04e0c4f81cefbc2299156c3cc00792255bdc4eb9b4dcca1ec45123"},{"id":"func/_compile_authored_scenario","name":"_compile_authored_scenario","line":723,"end_line":756,"hash":"54cb1a5fdc04ef071322bb6583348849c95103dd6cb5ad73dd0a1077483028b3"},{"id":"func/_compile_behavior_draft","name":"_compile_behavior_draft","line":759,"end_line":809,"hash":"ba3b249610ad09fbc5656283f7bfe4a889f822ba1d6902d3abaf4098ecfa609f"},{"id":"func/compile_behavior_draft","name":"compile_behavior_draft","line":812,"end_line":827,"hash":"6da96511c9732b58b64e54bf4a98561efb9b5973c60daa948b73dc5092caf992"}]}
# mutate4py-manifest-end
