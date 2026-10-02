"""Acceptance step handlers for the STPA execution projection features.

Implements ``features/stpa_execution_envelope.feature`` (STPA-EXEC-01
through STPA-EXEC-06): candidate execution envelope assembly, canonical
traceability, temporal assertions, sensor/actuator anomaly steps, and
the empty (no-invented-behavior) contract.

Also implements ``features/stpa_execution_projection_production_wiring.feature``
(STPA-PROD-WIRING-01, -02, and -04): Stage 5 declared evidence-backed
causal factors validated against the control structure, and fail-closed
empty successful output.

Also implements ``features/stpa_execution_projection_temporal_constraints.feature``
(STPA-TEMPORAL-01 through STPA-TEMPORAL-05): typed discriminated temporal
constraints derived only from declared timing, canonical units,
namespace-bound constraint references, unknown timing requiring binding,
and the explicit UCA outcome mapping with runtime observations excluded.

Step handlers use regex-based parameter extraction and keep the scenario
state on the per-example world.
"""

from __future__ import annotations

import json
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
from asago_scenario_generator.stpa.models.enriched_threat_set import StructuralThreat
from asago_scenario_generator.stpa.models.execution_envelope import (
    CandidateExecutionEnvelope,
    CausalFactor,
    CausalFactorKind,
    ScenarioStepKind,
    TemporalActionVector,
    TemporalAssertion,
    TemporalPredicate,
    candidate_id_for,
    step_kind_for,
    uca_ref_for,
)
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.models.scenario_spec import (
    AttackerBDI,
    ScenarioSpec,
)
from asago_scenario_generator.stpa.models.temporal_constraints import (
    DelayConstraint,
    is_structural_reference,
    parse_declared_timing,
)
from pydantic import ValidationError
from asago_scenario_generator.stpa.scenario_prod.assembly import (
    assemble_candidate_envelope,
)
from asago_scenario_generator.stpa.scenario_prod.bdi_generation import (
    BDIGenerationResult,
    CausalFactorDeclaration,
    assemble_scenario_spec,
    populate_defender_bdi,
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

_KIND_BY_HYPHEN_LABEL = {
    "process-model": CausalFactorKind.process_model_flaw,
    "feedback-delay": CausalFactorKind.feedback_delay,
    "actuator-anomaly": CausalFactorKind.actuator_anomaly,
}

_RE_LABELED_ITEM = re.compile(
    r"^(?:a |an )?(process-model flaw|feedback delay|sensor anomaly|"
    r"actuator anomaly) (?:for|at) ([A-Z0-9-]+)$"
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


# ---------------------------------------------------------------------------#
# Stream B Slice 3: projection traceability validation (STPA-PROJ-03)
# ---------------------------------------------------------------------------#


# ---------------------------------------------------------------------------#
# Stream B Slice 5: canonical standalone export (STPA-PROJ-05)
# ---------------------------------------------------------------------------#


# ---------------------------------------------------------------------------#
# STPA-PROD-WIRING: Stage 5 declared factors -> Stage 6 projection -> artifacts
# ---------------------------------------------------------------------------#


def _h_projection_workflow_available(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Given: the STPA production projection workflow is available."""
    if not all(
        callable(obj)
        for obj in (
            populate_defender_bdi,
            assemble_scenario_spec,
        )
    ):
        return False, "The STPA production projection workflow is not available"
    return True, ""


def _h_control_structure_contains(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Given: a control structure contains RESP-1, PM-1-1, FB-1-1, and CA-1-1."""
    match = re.match(
        r"a control structure contains (RESP-\d+), (PM-\d+-\d+), "
        r"(FB-\d+-\d+), and (CA-\d+-\d+)",
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


def _h_structural_uca_ica_id(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Given: the structural unsafe control action has ICA ID "<id>"."""
    match = re.match(r'the structural unsafe control action has ICA ID "([^"]+)"', text)
    if not match:
        return False, f"Could not parse ICA ID step: {text}"
    world.stpa_ica_id = match.group(1)
    return True, ""


def _h_structural_uca_scenario_id(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Given: the structural unsafe control action has scenario ID "<id>"."""
    match = re.match(
        r'the structural unsafe control action has scenario ID "([^"]+)"', text
    )
    if not match:
        return False, f"Could not parse scenario ID step: {text}"
    world.stpa_scenario_id = match.group(1)
    return True, ""


def _declarations_from_labeled(
    spec: str,
) -> tuple[bool, str, list[CausalFactorDeclaration]]:
    """Parse "a <label> for <id> and ..." into Stage 5 declarations."""
    declarations: list[CausalFactorDeclaration] = []
    for item in _iteration_ids(spec):
        item_match = _RE_LABELED_ITEM.match(item)
        if not item_match:
            return False, f"Could not parse causal factor item: {item}", []
        label, source_id = item_match.groups()
        declarations.append(
            CausalFactorDeclaration(
                kind=_KIND_BY_LABEL[label],
                source_id=source_id,
                evidence=f"Stage 5 evidence for {label} at {source_id}",
            )
        )
    return True, "", declarations


def _assemble_spec_from_declarations(
    world: World, declarations: list[CausalFactorDeclaration]
) -> tuple[ScenarioSpec | None, str]:
    """Run the Stage 5 assembly seam against the world's control structure."""
    control_structure = getattr(world, "stpa_control_structure", None)
    if control_structure is None:
        return None, "No control structure is available"
    defender_bdi = populate_defender_bdi(control_structure, "RESP-1")
    threat = StructuralThreat(
        ica_slot_id="RESP-1:CA-1-1:WRONG_TIMING",
        ica_id=getattr(world, "stpa_ica_id", None),
        ica_text="Unsafe control action text",
        hazardous_context="Hazardous context",
        loss_scenario="Loss scenario",
    )
    llm_result = BDIGenerationResult(
        defender_vulnerabilities={},
        attacker_bdi=AttackerBDI(beliefs=["b"], desires=["d"], intentions=["i"]),
        causal_factors=declarations,
    )
    return (
        assemble_scenario_spec(
            defender_bdi,
            llm_result,
            threat,
            control_structure,
            scenario_index=0,
        ),
        "",
    )


def _h_stage5_ordered_evidence(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Given: Stage 5 returns ordered evidence for a flaw at PM-1-1 and ..."""
    match = re.match(r"Stage 5 returns ordered evidence for (.+)", text)
    if not match:
        return False, f"Could not parse Stage 5 evidence step: {text}"
    ok, message, declarations = _declarations_from_labeled(match.group(1))
    if not ok:
        return False, message
    world.stpa_declarations = declarations
    return True, ""


def _h_stage5_evidence_for_kind_at_unknown(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Given: Stage 5 returns evidence for a "<kind>" at unknown "<id>"."""
    match = re.match(
        r'Stage 5 returns evidence for (?:a |an )?"([^"]+)" at unknown "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse Stage 5 evidence step: {text}"
    label, source_id = match.groups()
    kind = _KIND_BY_LABEL.get(label)
    if kind is None:
        return False, f"Unsupported causal factor kind: {label}"
    world.stpa_declarations = [
        CausalFactorDeclaration(
            kind=kind,
            source_id=source_id,
            evidence=f"Stage 5 evidence for {label} at {source_id}",
        )
    ]
    return True, ""


def _h_stage5_explicit_empty(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Given: Stage 5 explicitly returns an empty causal-factor list."""
    world.stpa_declarations = []
    return True, ""


def _h_stage5_assembly(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """When: the production STPA run performs Stage 5 assembly."""
    declarations = getattr(world, "stpa_declarations", None)
    if declarations is None:
        return False, "No Stage 5 factor declarations are recorded"
    spec, message = _assemble_spec_from_declarations(world, declarations)
    if spec is None:
        return False, message
    world.stpa_scenario_spec = spec
    return True, ""


def _h_spec_contains_factors(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: the ScenarioSpec contains causal factors "<ids>" in declared order."""
    match = re.match(r'the ScenarioSpec contains causal factors "([^"]+)" in', text)
    if not match:
        return False, f"Could not parse ScenarioSpec factor step: {text}"
    spec = getattr(world, "stpa_scenario_spec", None)
    if spec is None:
        return False, "No ScenarioSpec assembled"
    expected = [part.strip() for part in match.group(1).split(",")]
    actual = [factor.source_id for factor in spec.causal_factors]
    if actual != expected:
        return False, f"ScenarioSpec causal factors are {actual}, expected {expected}"
    return True, ""


def _h_each_factor_kept(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Then: each stored factor keeps its declared kind, source, and evidence."""
    spec = getattr(world, "stpa_scenario_spec", None)
    declarations = getattr(world, "stpa_declarations", None)
    if spec is None or declarations is None:
        return False, "No ScenarioSpec or declarations recorded"
    if len(spec.causal_factors) != len(declarations):
        return False, "ScenarioSpec factor count differs from the declarations"
    for factor, declaration in zip(spec.causal_factors, declarations):
        if factor.kind != declaration.kind:
            return False, f"{factor.source_id} kind changed during Stage 5"
        if factor.source_id != declaration.source_id:
            return False, f"Factor source changed to {factor.source_id}"
        if factor.description != declaration.evidence:
            return False, f"Factor {factor.source_id} lost its evidence description"
    return True, ""


def _h_spec_validates_factors(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: the ScenarioSpec validates every causal-factor reference."""
    spec = getattr(world, "stpa_scenario_spec", None)
    control_structure = getattr(world, "stpa_control_structure", None)
    if spec is None or control_structure is None:
        return False, "No ScenarioSpec or control structure recorded"
    try:
        spec.validate_against(control_structure)
    except ValueError as error:
        return False, f"Causal-factor reference validation failed: {error}"
    return True, ""


def _h_no_factor_from_structure(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: no causal factor is selected from structural presence alone."""
    spec = getattr(world, "stpa_scenario_spec", None)
    declarations = getattr(world, "stpa_declarations", None)
    if spec is None or declarations is None:
        return False, "No ScenarioSpec or declarations recorded"
    if len(spec.causal_factors) != len(declarations):
        return False, "Stage 5 selected factors beyond the declared evidence"
    return True, ""


def _h_stage5_fails_ref_validation(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: Stage 5 fails with a causal-factor reference validation error."""
    error = getattr(world, "validation_error", None)
    if error is None:
        return False, "No Stage 5 validation error was recorded"
    message = str(error)
    if "Causal factor" not in message or "not a known" not in message:
        return (
            False,
            f"Recorded error is not a causal-factor reference error: {message}",
        )
    return True, ""


def _h_stage5_fails_empty_factors(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: an empty successful Stage 5 response fails closed."""
    error = getattr(world, "validation_error", None)
    if error is None:
        return False, "No Stage 5 validation error was recorded"
    message = str(error)
    if "causal_factors" not in message or "at least 1" not in message:
        return False, f"Recorded error is not the non-empty factor error: {message}"
    if getattr(world, "stpa_scenario_spec", None) is not None:
        return False, "Stage 5 published a ScenarioSpec with no causal factor"
    return True, ""


def _h_no_projection_artifact_invalid(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: no projection artifact is written for the invalid scenario."""
    if getattr(world, "stpa_artifact_dir", None) is not None:
        return False, "Projection artifacts were written for the invalid scenario"
    return True, ""


def _h_spec_factors_present_empty(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: the ScenarioSpec has a present empty causal_factors field."""
    spec = getattr(world, "stpa_scenario_spec", None)
    if spec is None:
        return False, "No ScenarioSpec assembled"
    if spec.causal_factors != []:
        return False, f"ScenarioSpec causal_factors is {spec.causal_factors}, not []"
    return True, ""


def _h_vector_no_assertions_no_steps(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: the temporal action vector has no assertions and no steps."""
    envelope = getattr(world, "stpa_envelope", None)
    if envelope is None:
        return False, "No projection envelope derived"
    vector = envelope.temporal_vector
    if vector.assertions:
        return False, "Temporal vector invented assertions"
    if vector.steps:
        return False, "Temporal vector invented steps"
    if vector.uca_constraint is not None:
        return False, "Temporal vector invented a UCA outcome mapping"
    return True, ""


# ---------------------------------------------------------------------------#
# STPA-TEMPORAL: typed temporal execution constraints
# ---------------------------------------------------------------------------#

_VARIANT_FIELD_SETS = {
    "OrderingConstraint": {"type", "ordering", "reference"},
    "DelayConstraint": {"type", "delay_ms", "reference"},
    "DurationConstraint": {"type", "duration_s", "reference"},
    "WindowConstraint": {"type", "window_from_ms", "window_to_ms", "reference"},
    "AbsenceConstraint": {"type", "reference"},
}


def _h_temporal_models_available(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Given: the STPA temporal projection models are available."""
    if not all(
        callable(obj) for obj in (derive_temporal_action_vector, parse_declared_timing)
    ) or not all(
        isinstance(obj, type) for obj in (TemporalAssertion, TemporalActionVector)
    ):
        return False, "The STPA temporal projection models are not available"
    return True, ""


def _h_timing_declared(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Given: "<source_id>" has declared timing "<timing>"."""
    match = re.match(r'"([^"]+)" has declared timing "([^"]*)"', text)
    if not match:
        return False, f"Could not parse declared timing step: {text}"
    source_id, timing = match.groups()
    kind = _KIND_BY_ID_PREFIX.get(source_id.split("-")[0])
    if kind is None:
        return False, f"Unsupported causal factor source: {source_id}"
    factors = getattr(world, "stpa_causal_factors", [])
    for factor in factors:
        if factor.source_id == source_id:
            factor.declared_timing = timing or None
            break
    else:
        factors.append(
            CausalFactor(
                kind=kind,
                source_id=source_id,
                description=source_id,
                declared_timing=timing or None,
            )
        )
    world.stpa_causal_factors = factors
    return True, ""


def _h_assertion_constraint_variant(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: its assertion has constraint variant "<variant>"."""
    match = re.match(r'its assertion has constraint variant "([^"]+)"', text)
    if not match:
        return False, f"Could not parse constraint variant step: {text}"
    vector = getattr(world, "stpa_temporal_vector", None)
    if vector is None:
        return False, "No temporal action vector derived"
    if not vector.assertions:
        return False, "Temporal vector has no assertions"
    constraint = vector.assertions[0].constraint
    if constraint is None:
        return False, f"Assertion constraint is None, expected {match.group(1)}"
    if type(constraint).__name__ != match.group(1):
        return (
            False,
            f"Constraint variant is {type(constraint).__name__}, not {match.group(1)}",
        )
    return True, ""


def _h_constraint_unit(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Then: the constraint uses canonical unit "<unit>"."""
    match = re.match(r'the constraint uses canonical unit "([^"]*)"', text)
    if not match:
        return False, f"Could not parse constraint unit step: {text}"
    vector = getattr(world, "stpa_temporal_vector", None)
    if vector is None or not vector.assertions:
        return False, "No temporal assertion derived"
    constraint = vector.assertions[0].constraint
    expected_unit = match.group(1)
    if constraint is None:
        units = ""
    else:
        fields = set(constraint.model_dump())
        if {"delay_ms", "window_from_ms", "window_to_ms"} & fields:
            units = "ms"
        elif "duration_s" in fields:
            units = "s"
        else:
            units = ""
    if units != expected_unit:
        return False, f"Constraint unit is {units!r}, expected {expected_unit!r}"
    return True, ""


def _h_constraint_value(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Then: the constraint contains the declared numeric value "<value>"."""
    match = re.match(
        r'the constraint contains the declared numeric value "([^"]*)"', text
    )
    if not match:
        return False, f"Could not parse constraint value step: {text}"
    expected = match.group(1)
    if not expected:
        return True, ""
    vector = getattr(world, "stpa_temporal_vector", None)
    if vector is None or not vector.assertions:
        return False, "No temporal assertion derived"
    constraint = vector.assertions[0].constraint
    if constraint is None:
        return False, f"Constraint is None, expected value {expected}"
    dump = constraint.model_dump()
    if "delay_ms" in dump:
        actual = str(dump["delay_ms"])
    elif "duration_s" in dump:
        actual = str(dump["duration_s"])
    elif "window_from_ms" in dump:
        actual = f"{dump['window_from_ms']}-{dump['window_to_ms']}"
    else:
        return False, f"Constraint has no numeric value, expected {expected}"
    if actual != expected:
        return False, f"Constraint value is {actual}, expected {expected}"
    return True, ""


def _h_constraint_reference(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: the constraint references only "<reference>"."""
    match = re.match(r'the constraint references only "([^"]+)"', text)
    if not match:
        return False, f"Could not parse constraint reference step: {text}"
    vector = getattr(world, "stpa_temporal_vector", None)
    if vector is None or not vector.assertions:
        return False, "No temporal assertion derived"
    constraint = vector.assertions[0].constraint
    if constraint is None:
        return False, "Constraint is None; it cannot carry a reference"
    if constraint.reference != match.group(1):
        return (
            False,
            f"Constraint references {constraint.reference}, not {match.group(1)}",
        )
    return True, ""


def _h_constraint_own_variant_fields(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: the constraint contains no fields of another variant."""
    vector = getattr(world, "stpa_temporal_vector", None)
    if vector is None or not vector.assertions:
        return False, "No temporal assertion derived"
    constraint = vector.assertions[0].constraint
    if constraint is None:
        return False, "Constraint is None; no variant fields to check"
    variant = type(constraint).__name__
    expected = _VARIANT_FIELD_SETS.get(variant)
    if expected is None:
        return False, f"Unknown constraint variant {variant}"
    dump = set(constraint.model_dump())
    if dump != expected:
        return (
            False,
            f"Constraint fields {sorted(dump)} do not match the "
            f"{variant} shape {sorted(expected)}",
        )
    return True, ""


def _h_timing_two_factors(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Given: declared timing uses "<a>" and "<b>" for two factors."""
    match = re.match(
        r'declared timing uses "([^"]+)" and "([^"]+)" for two factors', text
    )
    if not match:
        return False, f"Could not parse two-factor timing step: {text}"
    world.stpa_causal_factors = [
        CausalFactor(
            kind=CausalFactorKind.feedback_delay,
            source_id="FB-1-1",
            description="FB-1-1",
            declared_timing=f"delay {match.group(1)}",
        ),
        CausalFactor(
            kind=CausalFactorKind.actuator_anomaly,
            source_id="CA-1-1",
            description="CA-1-1",
            declared_timing=f"duration {match.group(2)}",
        ),
    ]
    return True, ""


def _h_canonical_units_only(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: numeric timing values use only canonical unit "ms" or "s"."""
    vector = getattr(world, "stpa_temporal_vector", None)
    if vector is None:
        return False, "No temporal action vector derived"
    for assertion in vector.assertions:
        constraint = assertion.constraint
        if constraint is None:
            return False, f"Assertion {assertion.assertion_id} lost its constraint"
        fields = set(constraint.model_dump())
        if fields & {"delay_ms", "window_from_ms", "window_to_ms"}:
            continue
        if "duration_s" in fields:
            continue
        return False, (f"Assertion {assertion.assertion_id} uses a non-canonical unit")
    return True, ""


def _h_repeated_derivation_identical(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: repeated derivation is byte-for-byte identical."""
    context = _context(world)
    if context is None:
        return False, "Missing temporal vector derivation context"
    first = getattr(world, "stpa_temporal_vector", None)
    if first is None:
        return False, "No temporal action vector derived"
    controller_id, control_action_id, uca_type = context
    second = derive_temporal_action_vector(
        getattr(world, "stpa_causal_factors", []),
        controller_id=controller_id,
        control_action_id=control_action_id,
        uca_type=uca_type,
    )
    if json.dumps(first.model_dump(mode="json"), sort_keys=True) != json.dumps(
        second.model_dump(mode="json"), sort_keys=True
    ):
        return False, "Repeated vector derivation is not byte-for-byte identical"
    return True, ""


def _h_no_freeform_timing_text(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: no free-form timing text becomes an executable constraint."""
    vector = getattr(world, "stpa_temporal_vector", None)
    if vector is None:
        return False, "No temporal action vector derived"
    dump = json.dumps(vector.model_dump(mode="json"))
    for phrase in ("milliseconds", "seconds"):
        if phrase in dump:
            return False, f"Free-form timing text {phrase!r} reached the vector"
    return True, ""


def _h_unknown_timing_factor(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Given: a <kind> factor for <id> has unknown timing."""
    match = re.match(
        r"a (process-model|feedback-delay|actuator-anomaly) factor for "
        r"([A-Z0-9-]+) has unknown timing",
        text,
    )
    if not match:
        return False, f"Could not parse unknown timing step: {text}"
    kind_label, source_id = match.groups()
    world.stpa_causal_factors = [
        CausalFactor(
            kind=_KIND_BY_HYPHEN_LABEL[kind_label],
            source_id=source_id,
            description=source_id,
            declared_timing=None,
        )
    ]
    return True, ""


def _h_assertion_constraint_null(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: its assertion has constraint null."""
    vector = getattr(world, "stpa_temporal_vector", None)
    if vector is None or not vector.assertions:
        return False, "No temporal assertion derived"
    if vector.assertions[0].constraint is not None:
        return False, "Assertion constraint is not null"
    return True, ""


def _h_assertion_requires_binding(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: its assertion has requires_binding true."""
    vector = getattr(world, "stpa_temporal_vector", None)
    if vector is None or not vector.assertions:
        return False, "No temporal assertion derived"
    if vector.assertions[0].requires_binding is not True:
        return False, "Assertion does not require binding"
    return True, ""


def _h_assertion_preserves_predicate_source(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: the assertion keeps its canonical predicate and source ID."""
    vector = getattr(world, "stpa_temporal_vector", None)
    if vector is None or not vector.assertions:
        return False, "No temporal assertion derived"
    assertion = vector.assertions[0]
    if assertion.predicate != TemporalPredicate.feedback_delayed:
        return False, f"Assertion predicate is {assertion.predicate.value}"
    if assertion.source_id != "FB-1-1":
        return False, f"Assertion source is {assertion.source_id}, not FB-1-1"
    return True, ""


def _h_no_invented_timing(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Then: the projection invents no duration, delay, window, or observation."""
    vector = getattr(world, "stpa_temporal_vector", None)
    if vector is None:
        return False, "No temporal action vector derived"
    dump = vector.model_dump(mode="json")
    if any(
        "duration" in key or "delay" in key or "window" in key or "observation" in key
        for key in _iter_keys(dump)
    ):
        return False, "Projection contains invented timing or observations"
    return True, ""


def _iter_keys(node: object) -> list[str]:
    """Yield every dict key in a plain-data tree."""
    keys: list[str] = []
    if isinstance(node, dict):
        for key, child in node.items():
            keys.append(key)
            keys.extend(_iter_keys(child))
    elif isinstance(node, list):
        for child in node:
            keys.extend(_iter_keys(child))
    return keys


def _h_candidate_constraint_reference(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Given: a candidate constraint names structural reference "<ref>"."""
    match = re.match(
        r'a candidate constraint names structural reference "([^"]+)"', text
    )
    if not match:
        return False, f"Could not parse candidate reference step: {text}"
    world.stpa_constraint_reference = match.group(1)
    return True, ""


def _h_temporal_assertion_validated(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """When: the temporal assertion is validated."""
    reference = getattr(world, "stpa_constraint_reference", None)
    if reference is None:
        return False, "No candidate constraint reference recorded"
    try:
        TemporalAssertion(
            assertion_id="TA-1",
            order_index=0,
            kind=CausalFactorKind.feedback_delay,
            source_id="FB-1-1",
            predicate=TemporalPredicate.feedback_delayed,
            constraint=DelayConstraint(delay_ms=100, reference=reference),
        )
        world.stpa_constraint_validation = "succeeds"
    except (ValueError, ValidationError):
        world.stpa_constraint_validation = "fails"
    return True, ""


def _h_constraint_validation_result(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: validation "<result>"."""
    match = re.match(r'validation "([^"]+)"', text)
    if not match:
        return False, f"Could not parse validation result step: {text}"
    actual = getattr(world, "stpa_constraint_validation", None)
    if actual != match.group(1):
        return False, f"Validation result is {actual!r}, not {match.group(1)!r}"
    return True, ""


def _h_accepted_reference_resolves(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: any accepted reference resolves to a structural ID."""
    if getattr(world, "stpa_constraint_validation", None) != "succeeds":
        return True, ""
    reference = getattr(world, "stpa_constraint_reference", None)
    if reference is None:
        return False, "No candidate constraint reference recorded"
    if not is_structural_reference(reference):
        return False, f"Accepted reference {reference} is not structural"
    return True, ""


def _h_vector_has_uca_constraint(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: the vector maps the final unsafe-control-action outcome."""
    vector = getattr(world, "stpa_temporal_vector", None)
    if vector is None:
        return False, "No temporal action vector derived"
    if vector.uca_constraint is None:
        return False, "Temporal vector lacks the UCA outcome mapping"
    return True, ""


def _h_uca_constraint_identifies(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: the uca_constraint identifies <action> and <type>."""
    match = re.match(r"the uca_constraint identifies ([A-Z0-9-]+) and ([A-Z_]+)", text)
    if not match:
        return False, f"Could not parse UCA constraint step: {text}"
    vector = getattr(world, "stpa_temporal_vector", None)
    if vector is None or vector.uca_constraint is None:
        return False, "No UCA outcome mapping derived"
    if vector.uca_constraint.control_action_id != match.group(1):
        return False, "UCA constraint names the wrong control action"
    if vector.uca_constraint.uca_type.value != match.group(2):
        return False, "UCA constraint names the wrong UCA type"
    return True, ""


def _h_final_step_remains_uca(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: the final scenario step is the UCA step for <action>."""
    match = re.match(
        r"the final scenario step remains the unsafe-control-action step for "
        r"([A-Z0-9-]+)",
        text,
    )
    if not match:
        return False, f"Could not parse final step step: {text}"
    vector = getattr(world, "stpa_temporal_vector", None)
    if vector is None or not vector.steps:
        return False, "No temporal vector steps derived"
    final_step = vector.steps[-1]
    if final_step.kind != ScenarioStepKind.unsafe_control_action:
        return False, f"Final step kind is {final_step.kind.value}"
    if final_step.source_id != match.group(1):
        return False, f"Final step references {final_step.source_id}"
    return True, ""


def _h_observations_only_evaluation(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: runtime observations are absent from the projection."""
    vector = getattr(world, "stpa_temporal_vector", None)
    if vector is None:
        return False, "No temporal action vector derived"
    dump = vector.model_dump(mode="json")
    keys = _iter_keys(dump)
    if any("observation" in key or "runtime" in key for key in keys):
        return False, "Projection contains runtime observation fields"
    return True, ""


# ---------------------------------------------------------------------------#
# STPA-TRACEABILITY: projection traceability and identity contract
# ---------------------------------------------------------------------------#


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

    # --- Stream B Slice 3: projection traceability validation ---

    # --- Stream B Slice 5: canonical standalone export ---

    # --- STPA-PROD-WIRING 01-06: production wiring ---
    api.register(
        r"the STPA production projection workflow is available",
        _h_projection_workflow_available,
    )
    api.register(
        r"a control structure contains (RESP-\d+), (PM-\d+-\d+), "
        r"(FB-\d+-\d+), and (CA-\d+-\d+)",
        _h_control_structure_contains,
    )
    api.register(
        r'the structural unsafe control action has ICA ID "([^"]+)"',
        _h_structural_uca_ica_id,
    )
    api.register(
        r'the structural unsafe control action has scenario ID "([^"]+)"',
        _h_structural_uca_scenario_id,
    )
    api.register(
        r"Stage 5 returns ordered evidence for (.+)", _h_stage5_ordered_evidence
    )
    api.register(
        r'Stage 5 returns evidence for (?:a |an )?"([^"]+)" at unknown "([^"]+)"',
        _h_stage5_evidence_for_kind_at_unknown,
    )
    api.register(
        r"Stage 5 explicitly returns an empty causal-factor list",
        _h_stage5_explicit_empty,
    )
    api.register(
        r"the production STPA run performs Stage 5 assembly", _h_stage5_assembly
    )
    api.register(
        r'the ScenarioSpec contains causal factors "([^"]+)" in declared order',
        _h_spec_contains_factors,
    )
    api.register(
        r"each stored causal factor has its declared kind, source ID, "
        r"and evidence description",
        _h_each_factor_kept,
    )
    api.register(
        r"the ScenarioSpec validates every causal-factor reference against "
        r"the control structure",
        _h_spec_validates_factors,
    )
    api.register(
        r"no causal factor is selected from structural presence alone",
        _h_no_factor_from_structure,
    )
    api.register(
        r"Stage 5 fails with a causal-factor reference validation error",
        _h_stage5_fails_ref_validation,
    )
    api.register(
        r"Stage 5 fails with a non-empty causal_factors validation error",
        _h_stage5_fails_empty_factors,
    )
    api.register(
        r"no projection artifact is written for the invalid scenario",
        _h_no_projection_artifact_invalid,
    )
    api.register(
        r"the ScenarioSpec has a present causal_factors field containing "
        r"an empty list",
        _h_spec_factors_present_empty,
    )
    api.register(
        r"the temporal action vector has no assertions and no steps",
        _h_vector_no_assertions_no_steps,
    )

    # --- STPA-TEMPORAL 01-05: typed temporal execution constraints ---
    api.register(
        r"the STPA temporal projection models are available",
        _h_temporal_models_available,
    )
    api.register(r'"([^"]+)" has declared timing "([^"]*)"', _h_timing_declared)
    api.register(
        r'its assertion has constraint variant "([^"]+)"',
        _h_assertion_constraint_variant,
    )
    api.register(r'the constraint uses canonical unit "([^"]*)"', _h_constraint_unit)
    api.register(
        r'the constraint contains the declared numeric value "([^"]*)"',
        _h_constraint_value,
    )
    api.register(r'the constraint references only "([^"]+)"', _h_constraint_reference)
    api.register(
        r"the constraint contains no fields belonging to another variant",
        _h_constraint_own_variant_fields,
    )
    api.register(
        r'declared timing uses "([^"]+)" and "([^"]+)" for two factors',
        _h_timing_two_factors,
    )
    api.register(
        r'each numeric timing value uses only canonical unit "ms" or "s"',
        _h_canonical_units_only,
    )
    api.register(
        r"repeated derivation preserves the numeric values, units, and "
        r"constraint discriminators byte-for-byte",
        _h_repeated_derivation_identical,
    )
    api.register(
        r"no free-form timing text is used as an executable constraint",
        _h_no_freeform_timing_text,
    )
    api.register(
        r"a (process-model|feedback-delay|actuator-anomaly) factor for "
        r"([A-Z0-9-]+) has unknown timing",
        _h_unknown_timing_factor,
    )
    api.register(r"its assertion has constraint null", _h_assertion_constraint_null)
    api.register(
        r"its assertion has requires_binding true", _h_assertion_requires_binding
    )
    api.register(
        r"the assertion still preserves the canonical feedback-delay predicate "
        r"and source ID",
        _h_assertion_preserves_predicate_source,
    )
    api.register(
        r"the projection does not invent a duration, delay, window, or "
        r"runtime observation",
        _h_no_invented_timing,
    )
    api.register(
        r'a candidate constraint names structural reference "([^"]+)"',
        _h_candidate_constraint_reference,
    )
    api.register(
        r"the temporal assertion is validated", _h_temporal_assertion_validated
    )
    api.register(r'validation "([^"]+)"', _h_constraint_validation_result)
    api.register(
        r"any accepted reference resolves to a PM-, FB-, CA-, or S-\* "
        r"structural ID",
        _h_accepted_reference_resolves,
    )
    api.register(
        r"the vector has a uca_constraint for the final unsafe-control-action outcome",
        _h_vector_has_uca_constraint,
    )
    api.register(
        r"the uca_constraint identifies ([A-Z0-9-]+) and ([A-Z_]+)",
        _h_uca_constraint_identifies,
    )
    api.register(
        r"the final scenario step remains the unsafe-control-action step for "
        r"([A-Z0-9-]+)",
        _h_final_step_remains_uca,
    )
    api.register(
        r"runtime observations are absent from the projection and available "
        r"only to evaluation",
        _h_observations_only_evaluation,
    )

    # --- STPA-TRACEABILITY 01-05: traceability and identity contract ---
