"""Acceptance step handlers for the STPA execution projection feature.

Implements ``features/stpa_execution_envelope.feature`` (STPA-EXEC-01
through STPA-EXEC-06): candidate execution envelope assembly, canonical
traceability, temporal assertions, sensor/actuator anomaly steps, and
the empty (no-invented-behavior) contract.  Step handlers use
regex-based parameter extraction and keep the scenario state on the
per-example world.
"""

from __future__ import annotations

import re

from runtime_shared import World

from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlStructure,
    ControlledProcess,
    ElementRef,
    FeedbackChannel,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
)
from asago_scenario_generator.stpa.models.execution_envelope import (
    CandidateExecutionEnvelope,
    CausalFactor,
    CausalFactorKind,
    ScenarioStepKind,
    TemporalActionVector,
    TemporalPredicate,
    candidate_id_for,
    step_kind_for,
    uca_ref_for,
)
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.scenario_prod.assembly import (
    assemble_candidate_envelope,
)
from asago_scenario_generator.stpa.scenario_prod.narrative import (
    derive_temporal_action_vector,
)

_KIND_BY_LABEL = {
    "process-model flaw": CausalFactorKind.process_model_flaw,
    "feedback delay": CausalFactorKind.feedback_delay,
    "sensor anomaly": CausalFactorKind.sensor_anomaly,
    "actuator anomaly": CausalFactorKind.actuator_anomaly,
}

_KIND_BY_ID_PREFIX = {
    "PM": CausalFactorKind.process_model_flaw,
    "FB": CausalFactorKind.feedback_delay,
    "CA": CausalFactorKind.actuator_anomaly,
}

_RE_LABELED_ITEM = re.compile(
    r"^(?:a |an )?(process-model flaw|feedback delay|sensor anomaly|"
    r"actuator anomaly) for ([A-Z0-9-]+)$"
)


def _iteration_ids(spec: str) -> list[str]:
    """Parse a comma-free "X and Y" identifier list into stable ids."""
    return [part.strip() for part in spec.split(" and ") if part.strip()]


def _make_building_blocks_control_structure() -> ControlStructure:
    """Build the deterministic control structure named in the background."""
    return ControlStructure(
        controlled_processes=[
            ControlledProcess(cp_id="CP-1", description="Controlled process"),
        ],
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="Controller",
                process_model_parts=[
                    ProcessModelPart(
                        pm_id="PM-1-1", description="Depicted system state"
                    ),
                ],
                control_actions=[
                    ControlAction(
                        ca_id="CA-1-1",
                        description="Adjust the controlled process",
                        target=ElementRef(
                            type=ReferenceType.controlled_process, id="CP-1"
                        ),
                    ),
                ],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-1-1",
                        description="State feedback",
                        updates="PM-1-1",
                        source=ElementRef(
                            type=ReferenceType.controlled_process, id="CP-1"
                        ),
                    ),
                ],
            )
        ],
    )


def _find_control_action(
    control_structure: ControlStructure, control_action_id: str
) -> tuple[str, str] | None:
    """Return the (owner, description) of a control action, if any."""
    for responsibility in control_structure.responsibilities:
        for control_action in responsibility.control_actions:
            if control_action.ca_id == control_action_id:
                return responsibility.resp_id, control_action.description
    return None


def _h_models_importable(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Given: the STPA execution projection models are importable."""
    world.stpa_models_importable = all(
        callable(obj) or isinstance(obj, type)
        for obj in (
            assemble_candidate_envelope,
            derive_temporal_action_vector,
            CandidateExecutionEnvelope,
            CausalFactor,
            TemporalActionVector,
        )
    )
    if not world.stpa_models_importable:
        return False, "STPA execution projection models are not importable"
    return True, ""


def _h_control_structure_available(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Given: a control structure with RESP-1, PM-1-1, FB-1-1, and CA-1-1 is available."""
    match = re.match(
        r"a control structure with (RESP-\d+), (PM-\d+-\d+), "
        r"(FB-\d+-\d+), and (CA-\d+-\d+) is available",
        text,
    )
    if not match:
        return False, f"Could not parse control structure step: {text}"
    controller_id, pm_id, fb_id, ca_id = match.groups()
    control_structure = _make_building_blocks_control_structure()
    if control_structure.responsibilities[0].resp_id != controller_id:
        return False, f"Missing responsibility {controller_id}"
    responsibility = control_structure.responsibilities[0]
    if not any(pm.pm_id == pm_id for pm in responsibility.process_model_parts):
        return False, f"Missing process model part {pm_id}"
    if not any(fb.fb_id == fb_id for fb in responsibility.feedback_channels):
        return False, f"Missing feedback channel {fb_id}"
    if not any(ca.ca_id == ca_id for ca in responsibility.control_actions):
        return False, f"Missing control action {ca_id}"
    world.stpa_control_structure = control_structure
    world.stpa_controller = controller_id
    return True, ""


def _h_uca_targets(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Given: a WRONG_TIMING unsafe control action targets CA-1-1."""
    match = re.match(
        r"a (NOT_PROVIDED|INCORRECT|WRONG_TIMING|WRONG_DURATION) "
        r"unsafe control action targets (CA-\d+-\d+)",
        text,
    )
    if not match:
        return False, f"Could not parse UCA step: {text}"
    uca_value, control_action_id = match.groups()
    control_structure = getattr(world, "stpa_control_structure", None)
    if control_structure is None:
        return False, "No control structure is available yet"
    owner = _find_control_action(control_structure, control_action_id)
    if owner is None:
        return False, f"Control action {control_action_id} has no owning responsibility"
    controller_id = owner[0]
    world.stpa_uca_type = UCAType(uca_value)
    world.stpa_control_action = control_action_id
    world.stpa_controller = controller_id
    return True, ""


def _h_causal_factors_explain(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Given: causal factors PM-1-1 and FB-1-1 explain the unsafe control action."""
    match = re.match(
        r"causal factors? (.+) (?:explain|explains) the unsafe control action",
        text,
    )
    if not match:
        return False, f"Could not parse causal factors step: {text}"
    factors = []
    for source_id in _iteration_ids(match.group(1)):
        kind = _KIND_BY_ID_PREFIX.get(source_id.split("-")[0])
        if kind is None:
            return False, f"Unsupported causal factor source: {source_id}"
        factors.append(
            CausalFactor(kind=kind, source_id=source_id, description=source_id)
        )
    world.stpa_causal_factors = factors
    return True, ""


def _h_causal_factors_include(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Given: causal factors include a process-model flaw for PM-1-1 and ..."""
    match = re.match(r"causal factors include (.+)", text)
    if not match:
        return False, f"Could not parse causal factors step: {text}"
    factors = []
    for item in _iteration_ids(match.group(1)):
        item_match = _RE_LABELED_ITEM.match(item)
        if not item_match:
            return False, f"Could not parse causal factor item: {item}"
        label, source_id = item_match.groups()
        factors.append(
            CausalFactor(
                kind=_KIND_BY_LABEL[label],
                source_id=source_id,
                description=source_id,
            )
        )
    world.stpa_causal_factors = factors
    return True, ""


def _h_no_causal_factors(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Given: no causal factors explain the unsafe control action."""
    world.stpa_causal_factors = []
    return True, ""


def _context(world: World) -> tuple[str, str, UCAType] | None:
    """Return the (controller, control action, UCA type) context, if set."""
    controller_id = getattr(world, "stpa_controller", None)
    control_action_id = getattr(world, "stpa_control_action", None)
    uca_type = getattr(world, "stpa_uca_type", None)
    if controller_id is None or control_action_id is None or uca_type is None:
        return None
    return controller_id, control_action_id, uca_type


def _h_assemble_envelope(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """When: the candidate execution envelope is assembled (with temporal assertions)."""
    match = re.match(
        r"the candidate execution envelope is assembled( with temporal assertions)?",
        text,
    )
    if not match:
        return False, f"Could not parse assembly step: {text}"
    context = _context(world)
    control_structure = getattr(world, "stpa_control_structure", None)
    if context is None or control_structure is None:
        return False, "Missing envelope assembly context"
    controller_id, control_action_id, uca_type = context
    world.stpa_envelope = assemble_candidate_envelope(
        control_structure,
        controller_id=controller_id,
        control_action_id=control_action_id,
        uca_type=uca_type,
        causal_factors=getattr(world, "stpa_causal_factors", []),
        derive_temporal_vector=bool(match.group(1)),
    )
    return True, ""


def _h_derive_vector(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """When: the temporal action vector is derived."""
    context = _context(world)
    if context is None:
        return False, "Missing temporal vector derivation context"
    controller_id, control_action_id, uca_type = context
    world.stpa_temporal_vector = derive_temporal_action_vector(
        getattr(world, "stpa_causal_factors", []),
        controller_id=controller_id,
        control_action_id=control_action_id,
        uca_type=uca_type,
    )
    return True, ""


def _h_envelope_identifies(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Then: the envelope identifies controller RESP-1 and control action CA-1-1."""
    match = re.match(
        r"the envelope identifies controller (\S+) and control action (\S+)", text
    )
    if not match:
        return False, f"Could not parse envelope identity step: {text}"
    controller_id, control_action_id = match.groups()
    envelope = getattr(world, "stpa_envelope", None)
    if envelope is None:
        return False, "No candidate execution envelope assembled"
    if envelope.controller_id != controller_id:
        return (
            False,
            f"Envelope controller is {envelope.controller_id}, not {controller_id}",
        )
    if envelope.control_action_id != control_action_id:
        return (
            False,
            f"Envelope control action is {envelope.control_action_id}, "
            f"not {control_action_id}",
        )
    return True, ""


def _h_envelope_retains_uca_type(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: the envelope retains UCA type WRONG_TIMING."""
    match = re.match(r"the envelope retains UCA type (\S+)", text)
    if not match:
        return False, f"Could not parse UCA type step: {text}"
    envelope = getattr(world, "stpa_envelope", None)
    if envelope is None:
        return False, "No candidate execution envelope assembled"
    if envelope.uca_type.value != match.group(1):
        return (
            False,
            f"Envelope UCA type is {envelope.uca_type.value}, not {match.group(1)}",
        )
    return True, ""


def _h_envelope_maps_factors(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: the envelope maps causal factors PM-1-1 and FB-1-1."""
    match = re.match(r"the envelope maps causal factors (.+)", text)
    if not match:
        return False, f"Could not parse causal factor mapping step: {text}"
    envelope = getattr(world, "stpa_envelope", None)
    if envelope is None:
        return False, "No candidate execution envelope assembled"
    expected = _iteration_ids(match.group(1))
    actual = [factor.source_id for factor in envelope.causal_factors]
    if actual != expected:
        return False, f"Envelope maps factors {actual}, expected {expected}"
    return True, ""


def _h_envelope_platform_neutral(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: the envelope is platform-neutral."""
    envelope = getattr(world, "stpa_envelope", None)
    if envelope is None:
        return False, "No candidate execution envelope assembled"
    if envelope.platform_neutral is not True:
        return False, "Envelope is not platform-neutral"
    return True, ""


def _h_envelope_canonical_id(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: the envelope has a canonical candidate identifier."""
    envelope = getattr(world, "stpa_envelope", None)
    if envelope is None:
        return False, "No candidate execution envelope assembled"
    expected = candidate_id_for(
        envelope.controller_id, envelope.control_action_id, envelope.uca_type
    )
    if envelope.candidate_id != expected:
        return False, f"Envelope candidate id {envelope.candidate_id} is not canonical"
    return True, ""


def _h_every_factor_has_source(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: every mapped causal factor has a source identifier."""
    envelope = getattr(world, "stpa_envelope", None)
    if envelope is None:
        return False, "No candidate execution envelope assembled"
    if not all(factor.source_id for factor in envelope.causal_factors):
        return False, "A mapped causal factor lacks a source identifier"
    return True, ""


def _h_envelope_links_uca(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Then: the envelope links the UCA to its control action."""
    envelope = getattr(world, "stpa_envelope", None)
    if envelope is None:
        return False, "No candidate execution envelope assembled"
    expected = uca_ref_for(
        envelope.controller_id, envelope.control_action_id, envelope.uca_type
    )
    if envelope.uca_ref != expected:
        return False, f"Envelope uca_ref {envelope.uca_ref} does not link the UCA"
    if envelope.control_action_id not in envelope.uca_ref:
        return False, "Envelope uca_ref does not reference the control action"
    return True, ""


def _h_assertion_count(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Then: it contains 2 temporal assertions."""
    match = re.match(r"it contains (\d+) temporal assertions", text)
    if not match:
        return False, f"Could not parse assertion count step: {text}"
    vector = getattr(world, "stpa_temporal_vector", None)
    if vector is None:
        return False, "No temporal action vector derived"
    expected = int(match.group(1))
    if len(vector.assertions) != expected:
        return (
            False,
            f"Vector contains {len(vector.assertions)} temporal assertions, "
            f"expected {expected}",
        )
    return True, ""


def _h_assertions_executable(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: the temporal assertions are executable."""
    vector = getattr(world, "stpa_temporal_vector", None)
    if vector is None:
        return False, "No temporal action vector derived"
    for index, assertion in enumerate(vector.assertions):
        if assertion.predicate not in TemporalPredicate:
            return (
                False,
                f"Assertion {assertion.assertion_id} has no executable predicate",
            )
        if assertion.order_index != index:
            return (
                False,
                f"Assertion {assertion.assertion_id} has no deterministic order",
            )
    return True, ""


def _h_steps_in_factor_order(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: the vector contains scenario steps in causal-factor order."""
    vector = getattr(world, "stpa_temporal_vector", None)
    if vector is None:
        return False, "No temporal action vector derived"
    factors = getattr(world, "stpa_causal_factors", [])
    factor_steps = [
        step
        for step in vector.steps
        if step.kind != ScenarioStepKind.unsafe_control_action
    ]
    if len(factor_steps) != len(factors):
        return False, "Scenario step count does not match the causal factor count"
    for index, factor in enumerate(factors):
        step = factor_steps[index]
        if step.source_id != factor.source_id:
            return (
                False,
                f"Step {index} references {step.source_id}, expected {factor.source_id}",
            )
        if step.kind != step_kind_for(factor.kind):
            return (
                False,
                f"Step {index} kind {step.kind.value} does not match the factor",
            )
    return True, ""


def _h_step_before(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Then: a scenario step references PM-1-1 before CA-1-1."""
    match = re.match(r"a scenario step references (\S+) before (\S+)", text)
    if not match:
        return False, f"Could not parse step ordering assertion: {text}"
    earlier_id, later_id = match.groups()
    vector = getattr(world, "stpa_temporal_vector", None)
    if vector is None:
        return False, "No temporal action vector derived"
    sources = [step.source_id for step in vector.steps]
    if earlier_id not in sources:
        return False, f"No scenario step references {earlier_id}"
    if later_id not in sources:
        return False, f"No scenario step references {later_id}"
    if sources.index(earlier_id) >= sources.index(later_id):
        return False, f"Step referencing {earlier_id} does not precede {later_id}"
    return True, ""


def _h_anomaly_step(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Then: the vector contains a sensor anomaly step for FB-1-1."""
    match = re.match(
        r"the vector contains (?:a |an )?(process-model flaw|feedback delay|"
        r"sensor anomaly|actuator anomaly) step for (\S+)",
        text,
    )
    if not match:
        return False, f"Could not parse anomaly step assertion: {text}"
    label, source_id = match.groups()
    vector = getattr(world, "stpa_temporal_vector", None)
    if vector is None:
        return False, "No temporal action vector derived"
    expected_kind = step_kind_for(_KIND_BY_LABEL[label])
    if not any(
        step.kind == expected_kind and step.source_id == source_id
        for step in vector.steps
    ):
        return False, f"Missing {label} step for {source_id}"
    return True, ""


def _h_deterministic_order(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Then: every scenario step has a deterministic order."""
    vector = getattr(world, "stpa_temporal_vector", None)
    if vector is None:
        return False, "No temporal action vector derived"
    for index, step in enumerate(vector.steps):
        if step.order_index != index:
            return (
                False,
                f"Step {step.step_id} has order {step.order_index}, expected {index}",
            )
    return True, ""


def _h_envelope_has_vector(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Then: the envelope contains a temporal action vector."""
    envelope = getattr(world, "stpa_envelope", None)
    if envelope is None:
        return False, "No candidate execution envelope assembled"
    if envelope.temporal_vector is None:
        return False, "Envelope does not contain a temporal action vector"
    return True, ""


def _h_vector_linked(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Then: the temporal vector is linked to the envelope candidate identifier."""
    envelope = getattr(world, "stpa_envelope", None)
    if envelope is None or envelope.temporal_vector is None:
        return False, "Envelope lacks a linked temporal action vector"
    if envelope.temporal_vector.candidate_id != envelope.candidate_id:
        return (
            False,
            f"Vector candidate {envelope.temporal_vector.candidate_id} is not "
            f"{envelope.candidate_id}",
        )
    return True, ""


def _h_description_retained(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: the envelope retains the canonical control action description."""
    envelope = getattr(world, "stpa_envelope", None)
    control_structure = getattr(world, "stpa_control_structure", None)
    if envelope is None or control_structure is None:
        return False, "Envelope or control structure missing"
    found = _find_control_action(control_structure, envelope.control_action_id)
    if found is None:
        return False, f"No control action {envelope.control_action_id} in the structure"
    expected = found[1]
    if envelope.control_action_description != expected:
        return (
            False,
            "Envelope does not retain the canonical control action description",
        )
    return True, ""


def _h_no_assertions(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Then: it contains no temporal assertions."""
    vector = getattr(world, "stpa_temporal_vector", None)
    if vector is None:
        return False, "No temporal action vector derived"
    if vector.assertions:
        return False, "Vector contains invented temporal assertions"
    return True, ""


def _h_no_steps(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Then: it contains no scenario steps."""
    vector = getattr(world, "stpa_temporal_vector", None)
    if vector is None:
        return False, "No temporal action vector derived"
    if vector.steps:
        return False, "Vector contains invented scenario steps"
    return True, ""


FEATURE_ID = "stpa"


def register(api: object) -> None:
    """Register the STPA execution projection handlers globally."""
    api.set_feature(None)
    api.register(
        r"the STPA execution projection models are importable", _h_models_importable
    )
    api.register(
        r"a control structure with (RESP-\d+), (PM-\d+-\d+), (FB-\d+-\d+), "
        r"and (CA-\d+-\d+) is available",
        _h_control_structure_available,
    )
    api.register(
        r"a (NOT_PROVIDED|INCORRECT|WRONG_TIMING|WRONG_DURATION) unsafe "
        r"control action targets (CA-\d+-\d+)",
        _h_uca_targets,
    )
    api.register(
        r"causal factors? (.+) (?:explain|explains) the unsafe control action",
        _h_causal_factors_explain,
    )
    api.register(r"causal factors include (.+)", _h_causal_factors_include)
    api.register(
        r"no causal factors explain the unsafe control action", _h_no_causal_factors
    )
    api.register(
        r"the candidate execution envelope is assembled( with temporal assertions)?",
        _h_assemble_envelope,
    )
    api.register(r"the temporal action vector is derived", _h_derive_vector)
    api.register(
        r"the envelope identifies controller (\S+) and control action (\S+)",
        _h_envelope_identifies,
    )
    api.register(r"the envelope retains UCA type (\S+)", _h_envelope_retains_uca_type)
    api.register(r"the envelope maps causal factors (.+)", _h_envelope_maps_factors)
    api.register(r"the envelope is platform-neutral", _h_envelope_platform_neutral)
    api.register(
        r"the envelope has a canonical candidate identifier", _h_envelope_canonical_id
    )
    api.register(
        r"every mapped causal factor has a source identifier",
        _h_every_factor_has_source,
    )
    api.register(
        r"the envelope links the UCA to its control action", _h_envelope_links_uca
    )
    api.register(r"it contains (\d+) temporal assertions", _h_assertion_count)
    api.register(r"the temporal assertions are executable", _h_assertions_executable)
    api.register(
        r"the vector contains scenario steps in causal-factor order",
        _h_steps_in_factor_order,
    )
    api.register(r"a scenario step references (\S+) before (\S+)", _h_step_before)
    api.register(
        r"the vector contains (?:a |an )?(process-model flaw|feedback delay|"
        r"sensor anomaly|actuator anomaly) step for (\S+)",
        _h_anomaly_step,
    )
    api.register(
        r"every scenario step has a deterministic order", _h_deterministic_order
    )
    api.register(
        r"the envelope contains a temporal action vector", _h_envelope_has_vector
    )
    api.register(
        r"the temporal vector is linked to the envelope candidate identifier",
        _h_vector_linked,
    )
    api.register(
        r"the envelope retains the canonical control action description",
        _h_description_retained,
    )
    api.register(r"it contains no temporal assertions", _h_no_assertions)
    api.register(r"it contains no scenario steps", _h_no_steps)
