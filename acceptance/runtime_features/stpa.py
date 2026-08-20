"""Acceptance step handlers for the STPA execution projection features.

Implements ``features/stpa_execution_envelope.feature`` (STPA-EXEC-01
through STPA-EXEC-06): candidate execution envelope assembly, canonical
traceability, temporal assertions, sensor/actuator anomaly steps, and
the empty (no-invented-behavior) contract.

Also implements ``features/stpa_execution_projection_slices_3_5.feature``
(STPA-PROJ-03-01 through STPA-PROJ-05-04): deterministic projection
traceability validation with typed violation codes, validator-derived
Stage 6 prompt alignment tables, and canonical standalone JSON/YAML
export with round-trip forgery rejection.

Also implements ``features/stpa_execution_projection_production_wiring.feature``
(STPA-PROD-WIRING-01 through STPA-PROD-WIRING-06): Stage 5 declared
evidence-backed causal factors validated against the control structure,
inference-free deterministic ``project_execution``, explicit present-
empty factors, one shared Stage 6 alignment table, and canonical
projection artifacts written beside the legacy scenario YAML and Gherkin
feature.

Also implements ``features/stpa_execution_projection_temporal_constraints.feature``
(STPA-TEMPORAL-01 through STPA-TEMPORAL-05): typed discriminated temporal
constraints derived only from declared timing, canonical units,
namespace-bound constraint references, unknown timing requiring binding,
and the explicit UCA outcome mapping with runtime observations excluded.

Also implements ``features/stpa_execution_projection_traceability_contract.feature``
(STPA-TRACEABILITY-01 through STPA-TRACEABILITY-05): fail-closed missing
vector validation, present-empty validity, forged-link rejection with
typed violation codes, distinct candidate/ICA/scenario identities, and
plain-data round-trip without project objects.

Step handlers use regex-based parameter extraction and keep the scenario
state on the per-example world.
"""

from __future__ import annotations

import json
import re
import tempfile
from copy import deepcopy
from pathlib import Path

import yaml
from runtime_shared import World

from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.infra.yaml_io import write_yaml
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
    predicate_for,
    step_kind_for,
    uca_ref_for,
)
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossAnalysis,
    LossProvenance,
    SecurityConstraint,
)
from asago_scenario_generator.stpa.models.scenario_spec import (
    AttackerBDI,
    DefenderBDI,
    DefenderBelief,
    DefenderDesire,
    DefenderIntention,
    ScenarioSpec,
    ThreatSource,
)
from asago_scenario_generator.stpa.models.temporal_constraints import (
    DelayConstraint,
    is_structural_reference,
    parse_declared_timing,
)
from pydantic import ValidationError
from asago_scenario_generator.stpa.scenario_prod._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.scenario_prod.assembly import (
    assemble_candidate_envelope,
)
from asago_scenario_generator.stpa.scenario_prod.attack_tree import (
    build_attack_tree_prompts,
)
from asago_scenario_generator.stpa.scenario_prod.bdi_generation import (
    BDIGenerationResult,
    CausalFactorDeclaration,
    assemble_scenario_spec,
    populate_defender_bdi,
)
from asago_scenario_generator.stpa.scenario_prod.gherkin import build_gherkin_prompts
from asago_scenario_generator.stpa.scenario_prod.narrative import (
    build_narrative_prompts,
    derive_temporal_action_vector,
)
from asago_scenario_generator.stpa.scenario_prod.projection import (
    canonical_projection_data,
    canonical_violations_json,
    export_projection_json,
    export_projection_yaml,
    project_execution,
    validate_exported_projection,
    validate_projection_traceability,
)
from asago_scenario_generator.stpa.scenario_prod.prompt_alignment import (
    derive_projection_alignment_rows,
    render_projection_alignment_table,
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
            validate_projection_traceability,
            export_projection_json,
            export_projection_yaml,
            derive_projection_alignment_rows,
            render_projection_alignment_table,
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


def _envelope_doc(world: World) -> dict | None:
    """Return the canonical projection document, creating it when needed."""
    if getattr(world, "stpa_projection_doc", None) is None:
        envelope = getattr(world, "stpa_envelope", None)
        if envelope is None:
            return None
        world.stpa_projection_doc = canonical_projection_data(envelope)
    return world.stpa_projection_doc


def _h_traceability_validated(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """When: STPA projection traceability is validated (twice)."""
    match = re.match(r"STPA projection traceability is validated( twice)?$", text)
    if not match:
        return False, f"Could not parse traceability step: {text}"
    doc = _envelope_doc(world)
    if doc is None:
        return False, "No candidate execution envelope assembled"
    world.stpa_traceability = validate_projection_traceability(doc)
    if match.group(1):
        world.stpa_traceability_second = validate_projection_traceability(doc)
    return True, ""


def _h_traceability_validity(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: STPA projection traceability is valid|invalid."""
    match = re.match(r"STPA projection traceability is (valid|invalid)$", text)
    if not match:
        return False, f"Could not parse traceability validity: {text}"
    result = getattr(world, "stpa_traceability", None)
    if result is None:
        return False, "No traceability result recorded"
    expected_valid = match.group(1) == "valid"
    if result.valid != expected_valid:
        return (
            False,
            f"Traceability result is {'valid' if result.valid else 'invalid'}, "
            f"expected {match.group(1)}",
        )
    return True, ""


def _h_traceability_no_violations(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: the traceability result has no violations."""
    result = getattr(world, "stpa_traceability", None)
    if result is None:
        return False, "No traceability result recorded"
    if result.violations:
        codes = [violation.code.value for violation in result.violations]
        return False, f"Traceability result has violations: {codes}"
    return True, ""


def _h_traceability_violation_code(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: the traceability result contains violation code "<code>"."""
    match = re.match(
        r'the traceability result contains violation code "([^"]+)"$', text
    )
    if not match:
        return False, f"Could not parse violation code step: {text}"
    result = getattr(world, "stpa_traceability", None)
    if result is None:
        return False, "No traceability result recorded"
    matched = next(
        (
            violation
            for violation in result.violations
            if violation.code.value == match.group(1)
        ),
        None,
    )
    world.stpa_matched_violation = matched
    if matched is None:
        codes = [violation.code.value for violation in result.violations]
        return False, f"No violation with code {match.group(1)}; found {codes}"
    return True, ""


def _h_violation_identifies(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: the violation identifies the earliest affected projection element."""
    violation = getattr(world, "stpa_matched_violation", None)
    expected = getattr(world, "stpa_expected_element", None)
    if violation is None:
        return False, "No matched violation recorded"
    if expected is None:
        return False, "No expected projection element recorded"
    if violation.element_id != expected:
        return (
            False,
            f"Violation identifies '{violation.element_id}', expected '{expected}'",
        )
    return True, ""


def _h_projection_candidate_id(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: the projection candidate identifier is "<candidate>"."""
    match = re.match(r'the projection candidate identifier is "([^"]+)"$', text)
    if not match:
        return False, f"Could not parse candidate identifier step: {text}"
    doc = _envelope_doc(world)
    if doc is None:
        return False, "No projection document recorded"
    if doc["candidate_id"] != match.group(1):
        return (
            False,
            f"Projection candidate identifier is {doc['candidate_id']}, "
            f"expected {match.group(1)}",
        )
    return True, ""


def _h_assertion_sources_ordered(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: assertion sources are ordered "<id,id>\"."""
    match = re.match(r'assertion sources are ordered "([^"]+)"$', text)
    if not match:
        return False, f"Could not parse assertion order step: {text}"
    doc = _envelope_doc(world)
    if doc is None:
        return False, "No projection document recorded"
    expected = [part.strip() for part in match.group(1).split(",")]
    actual = [assertion["source_id"] for assertion in doc["assertions"]]
    if actual != expected:
        return False, f"Assertion sources are {actual}, expected {expected}"
    return True, ""


def _h_factor_steps_ordered(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: factor scenario steps are ordered "<id,id>\"."""
    match = re.match(r'factor scenario steps are ordered "([^"]+)"$', text)
    if not match:
        return False, f"Could not parse factor step order step: {text}"
    doc = _envelope_doc(world)
    if doc is None:
        return False, "No projection document recorded"
    expected = [part.strip() for part in match.group(1).split(",")]
    factor_steps = [
        step for step in doc["steps"] if step["source_kind"] == "causal_factor"
    ]
    actual = [step["source_id"] for step in factor_steps]
    if actual != expected:
        return False, f"Factor scenario steps are {actual}, expected {expected}"
    return True, ""


def _h_final_step_references(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: the final scenario step references control action "<id>"."""
    match = re.match(
        r'the final scenario step references control action "([^"]+)"$', text
    )
    if not match:
        return False, f"Could not parse final step step: {text}"
    doc = _envelope_doc(world)
    if doc is None:
        return False, "No projection document recorded"
    if not doc["steps"] or doc["steps"][-1]["source_id"] != match.group(1):
        return False, f"Final scenario step does not reference {match.group(1)}"
    return True, ""


def _h_assertions_canonical(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: every temporal assertion has its canonical predicate and provenance."""
    doc = _envelope_doc(world)
    if doc is None:
        return False, "No projection document recorded"
    factors = doc.get("causal_factors", [])
    assertions = doc.get("assertions", [])
    if len(assertions) != len(factors):
        return False, "Assertion count does not match the causal factor count"
    for index, assertion in enumerate(assertions):
        kind = CausalFactorKind(assertion["kind"])
        if assertion["predicate"] != predicate_for(kind).value:
            return (
                False,
                f"Assertion {assertion['assertion_id']} predicate is not canonical",
            )
        if assertion["source_id"] != factors[index]["source_id"]:
            return (
                False,
                f"Assertion {assertion['assertion_id']} source does not match "
                f"factor {factors[index]['source_id']}",
            )
        if assertion["source_kind"] != "causal_factor":
            return (
                False,
                f"Assertion {assertion['assertion_id']} lacks causal-factor provenance",
            )
    return True, ""


def _apply_temporal_projection_mutation(
    doc: dict, mutation: str
) -> tuple[bool, str | None]:
    """Apply one named temporal-projection mutation.

    Returns a (applied, expected_element_id) pair; the expected element is
    the earliest projection element the mutation affects.
    """
    if mutation == "omitting the PM-1-1 assertion":
        doc["assertions"] = [
            assertion
            for assertion in doc["assertions"]
            if assertion["source_id"] != "PM-1-1"
        ]
        return True, "TA-1"
    if mutation == "reordering the PM-1-1 and FB-1-1 assertions":
        if len(doc["assertions"]) < 2:
            return False, None
        doc["assertions"][0], doc["assertions"][1] = (
            doc["assertions"][1],
            doc["assertions"][0],
        )
        return True, "TA-1"
    for element_id, source_id, label in (
        ("TA-2", "PM-1-1", "assertions"),
        ("S-2", "PM-1-1", "steps"),
    ):
        if mutation == f"changing {element_id} source to {source_id}":
            for item in doc[label]:
                if (
                    item.get("assertion_id") == element_id
                    or item.get("step_id") == element_id
                ):
                    item["source_id"] = source_id
                    return True, element_id
            return False, None
    if mutation == "changing TA-1 predicate to FEEDBACK_DELAYED":
        for assertion in doc["assertions"]:
            if assertion["assertion_id"] == "TA-1":
                assertion["predicate"] = "FEEDBACK_DELAYED"
                return True, "TA-1"
        return False, None
    if mutation == "changing the final step source to CA-9-9":
        if not doc["steps"]:
            return False, None
        doc["steps"][-1]["source_id"] = "CA-9-9"
        return True, "S-3"
    return False, None


def _h_mutate_temporal_projection(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """When: the temporal projection is mutated by "<mutation>"."""
    match = re.match(r'the temporal projection is mutated by "([^"]+)"$', text)
    if not match:
        return False, f"Could not parse mutation step: {text}"
    doc = _envelope_doc(world)
    if doc is None:
        return False, "No projection document recorded"
    applied, expected = _apply_temporal_projection_mutation(doc, match.group(1))
    if not applied:
        return False, f"Unknown temporal projection mutation: {match.group(1)}"
    world.stpa_expected_element = expected
    return True, ""


def _h_change_candidate_id(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """When: the temporal vector candidate identifier is changed to "<id>"."""
    match = re.match(
        r'the temporal vector candidate identifier is changed to "([^"]+)"$', text
    )
    if not match:
        return False, f"Could not parse candidate change step: {text}"
    doc = _envelope_doc(world)
    if doc is None:
        return False, "No projection document recorded"
    doc["candidate_id"] = match.group(1)
    world.stpa_expected_element = match.group(1)
    return True, ""


def _h_vector_no_assertions(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: the temporal vector contains no assertions."""
    doc = _envelope_doc(world)
    if doc is None:
        return False, "No projection document recorded"
    if doc["assertions"]:
        return False, "Temporal vector contains invented assertions"
    return True, ""


def _h_vector_no_steps(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Then: the temporal vector contains no scenario steps."""
    doc = _envelope_doc(world)
    if doc is None:
        return False, "No projection document recorded"
    if doc["steps"]:
        return False, "Temporal vector contains invented scenario steps"
    return True, ""


def _h_no_invented_provenance(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: the traceability result has no invented causal-factor provenance."""
    result = getattr(world, "stpa_traceability", None)
    if result is None:
        return False, "No traceability result recorded"
    if result.violations:
        codes = [violation.code.value for violation in result.violations]
        return False, f"Traceability result invented provenance: {codes}"
    return True, ""


def _h_same_validity(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Then: both traceability results have the same validity."""
    first = getattr(world, "stpa_traceability", None)
    second = getattr(world, "stpa_traceability_second", None)
    if first is None or second is None:
        return False, "Traceability was not validated twice"
    if first.valid != second.valid:
        return False, "Traceability results disagree on validity"
    return True, ""


def _h_byte_identical_violations(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: both traceability results have byte-identical canonical violations."""
    first = getattr(world, "stpa_traceability", None)
    second = getattr(world, "stpa_traceability_second", None)
    if first is None or second is None:
        return False, "Traceability was not validated twice"
    if canonical_violations_json(first) != canonical_violations_json(second):
        return False, "Canonical violations differ between the two results"
    return True, ""


# ---------------------------------------------------------------------------#
# Stream B Slice 4: Stage 6 prompt alignment tables (STPA-PROJ-04)
# ---------------------------------------------------------------------------#


def _make_scenario_spec(envelope: CandidateExecutionEnvelope) -> ScenarioSpec:
    """Build the minimal scenario spec matching an assembled envelope."""
    return ScenarioSpec(
        scenario_id="SCN-001",
        threat_source=ThreatSource(
            ica_slot_id=envelope.uca_ref, provenance="structural"
        ),
        target_controller=envelope.controller_id,
        target_control_action=envelope.control_action_id,
        ica_type=envelope.uca_type,
        defender_bdi=DefenderBDI(
            beliefs=[DefenderBelief(pm_id="PM-1-1", content="b", vulnerability="v")],
            desires=[DefenderDesire(resp_id=envelope.controller_id, content="d")],
            intentions=[
                DefenderIntention(ca_id=envelope.control_action_id, content="i")
            ],
        ),
        attacker_bdi=AttackerBDI(beliefs=["b"], desires=["d"], intentions=["i"]),
        loss_scenario="loss",
    )


def _make_loss_analysis() -> LossAnalysis:
    """Build the minimal loss analysis used by the Gherkin prompt."""
    return LossAnalysis(
        risk_card_losses=[],
        use_case_losses=[
            Loss(
                loss_id="L-1",
                description="Loss",
                provenance=LossProvenance.use_case,
            )
        ],
        hazards=[Hazard(hazard_id="H-1", description="Hazard", related_losses=["L-1"])],
        security_constraints=[
            SecurityConstraint(
                constraint_id="SC-1",
                description="Constraint",
                related_hazards=["H-1"],
            )
        ],
    )


def _render_call_prompts(
    world: World,
    call: str,
    loader: TemplateLoader,
    spec: ScenarioSpec,
    table: str,
) -> tuple[str, str] | None:
    """Render both prompts of one Stage 6 call with the alignment table."""
    if call == "narrative":
        return build_narrative_prompts(spec, loader, projection_alignment=table)
    if call == "tree":
        control_structure = getattr(world, "stpa_control_structure", None)
        if control_structure is None:
            return None
        return build_attack_tree_prompts(
            spec, control_structure, loader, projection_alignment=table
        )
    if call == "gherkin":
        loss_analysis = _make_loss_analysis()
        return build_gherkin_prompts(
            spec,
            loss_analysis.security_constraints[0],
            loss_analysis,
            loader,
            projection_alignment=table,
        )
    return None


def _validate_and_render(world: World, calls: tuple[str, ...]) -> tuple[bool, str]:
    """Validate the projection, then render the requested Stage 6 prompts."""
    doc = _envelope_doc(world)
    if doc is None:
        return False, "No candidate execution envelope assembled"
    result = validate_projection_traceability(doc)
    if not result.valid:
        codes = [violation.code.value for violation in result.violations]
        return False, f"Projection is not valid; violations: {codes}"
    table = render_projection_alignment_table(doc)
    if not table:
        return False, "Projection alignment table is empty"
    envelope = getattr(world, "stpa_envelope", None)
    if envelope is None:
        return False, "No candidate execution envelope assembled"
    spec = _make_scenario_spec(envelope)
    loader = TemplateLoader(PROMPTS_DIR)
    world.stpa_alignment_table = table
    rendered = {}
    for call in calls:
        prompts = _render_call_prompts(world, call, loader, spec, table)
        if prompts is None:
            return False, f"Could not render {call} prompts"
        rendered[call] = prompts
    world.stpa_stage6 = rendered
    return True, ""


def _h_render_stage6_prompts(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """When: the STPA Stage 6 prompts are rendered from the validated projection."""
    return _validate_and_render(world, ("narrative", "tree", "gherkin"))


def _h_render_stage6_call(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """When: the STPA <narrative|attack-tree|Gherkin> prompts are rendered."""
    match = re.match(
        r"the STPA (narrative|attack-tree|Gherkin) prompts are rendered "
        r"from the validated projection$",
        text,
    )
    if not match:
        return False, f"Could not parse Stage 6 render step: {text}"
    call = {"narrative": "narrative", "attack-tree": "tree", "Gherkin": "gherkin"}[
        match.group(1)
    ]
    return _validate_and_render(world, (call,))


def _table_rows(table_text: str) -> list[list[str]]:
    """Parse the markdown table rows (header excluded)."""
    rows: list[list[str]] = []
    for line in table_text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("|"):
            continue
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if all(cell == "---" for cell in cells):
            continue
        rows.append(cells)
    return rows[1:] if rows else []


def _row_contains(cells: list[str], tokens: list[str]) -> bool:
    """True if the cells contain the tokens in order (subsequence)."""
    iterator = iter(cells)
    return all(any(token == cell for cell in iterator) for token in tokens)


def _alignment_rows_in_prompts(prompts: tuple[str, str]) -> list[list[str]] | None:
    """Parse the alignment table from the first prompt that carries it."""
    for prompt in prompts:
        marker = "## Projection Alignment"
        index = prompt.find(marker)
        if index >= 0:
            return _table_rows(prompt[index:])
    return None


def _stage6_text(world: World, call: str) -> str | None:
    """Join both prompts of one rendered call into one text."""
    prompts = getattr(world, "stpa_stage6", {}).get(call)
    if prompts is None:
        return None
    return "\n".join(prompts)


def _h_every_prompt_has_table(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: every narrative, tree, and Gherkin Stage 6 prompt has the table."""
    table = getattr(world, "stpa_alignment_table", None)
    stage6 = getattr(world, "stpa_stage6", None)
    if table is None or stage6 is None:
        return False, "No Stage 6 prompts rendered"
    for call in ("narrative", "tree", "gherkin"):
        prompts = stage6.get(call)
        if prompts is None:
            return False, f"{call} prompts were not rendered"
        for prompt in prompts:
            if "Projection Alignment" not in prompt:
                return False, f"{call} prompt lacks the alignment heading"
            if table not in prompt:
                return False, f"{call} prompt lacks the projection alignment table"
    return True, ""


def _h_table_columns(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Then: the table has columns "<column,column,...>"."""
    match = re.match(r'the table has columns "([^"]+)"$', text)
    if not match:
        return False, f"Could not parse table columns step: {text}"
    table = getattr(world, "stpa_alignment_table", None)
    if table is None:
        return False, "No projection alignment table recorded"
    expected = [part.strip() for part in match.group(1).split(",")]
    lines = [
        stripped
        for stripped in (line.strip() for line in table.splitlines())
        if stripped.startswith("|")
    ]
    header = [cell.strip() for cell in lines[0].strip("|").split("|")]
    if header != expected:
        return False, f"Table columns are {header}, expected {expected}"
    return True, ""


def _h_table_row_count(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Then: the table has exactly one row per assertion and final UCA step."""
    table = getattr(world, "stpa_alignment_table", None)
    doc = _envelope_doc(world)
    if table is None or doc is None:
        return False, "No projection alignment table recorded"
    rows = _table_rows(table)
    expected = len(doc.get("assertions", [])) + 1
    if len(rows) != expected:
        return (
            False,
            f"Alignment table has {len(rows)} rows, expected {expected}",
        )
    return True, ""


def _h_table_rows_ordered(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Then: the table rows preserve causal-factor order, UCA row last."""
    table = getattr(world, "stpa_alignment_table", None)
    doc = _envelope_doc(world)
    if table is None or doc is None:
        return False, "No projection alignment table recorded"
    rows = _table_rows(table)
    if not rows:
        return False, "Alignment table has no rows"
    factor_sources = [factor["source_id"] for factor in doc["causal_factors"]]
    if [row[0] for row in rows[:-1]] != factor_sources:
        return False, "Alignment rows do not preserve causal-factor order"
    if rows[-1][6] != "UNSAFE_CONTROL_ACTION":
        return False, "The UCA row is not last in the alignment table"
    orders = [row[7] for row in rows]
    if orders != [str(index) for index in range(1, len(rows) + 1)]:
        return False, f"Alignment row orders are not consecutive: {orders}"
    return True, ""


def _h_table_contains(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Then: the table contains "<value,value,...>" in one row."""
    match = re.match(r'the table contains "([^"]+)"$', text)
    if not match:
        return False, f"Could not parse table content step: {text}"
    table = getattr(world, "stpa_alignment_table", None)
    if table is None:
        return False, "No projection alignment table recorded"
    tokens = [part.strip() for part in match.group(1).split(",")]
    for row in _table_rows(table):
        if _row_contains(row, tokens):
            return True, ""
    return False, f"No alignment row contains {tokens}"


def _h_table_contains_candidate(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: the table contains candidate identifier "<candidate>"."""
    match = re.match(r'the table contains candidate identifier "([^"]+)"$', text)
    if not match:
        return False, f"Could not parse candidate step: {text}"
    table = getattr(world, "stpa_alignment_table", None)
    if table is None:
        return False, "No projection alignment table recorded"
    if match.group(1) not in table:
        return False, f"Alignment table lacks candidate {match.group(1)}"
    return True, ""


def _h_semantic_ids_not_positional(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: projection IDs are semantic structural IDs, not positional labels."""
    table = getattr(world, "stpa_alignment_table", None)
    if table is None:
        return False, "No projection alignment table recorded"
    if "semantic structural IDs" not in table:
        return False, "Alignment table does not identify semantic structural IDs"
    if "positional labels" not in table:
        return False, "Alignment table does not reject positional labels"
    for row in _table_rows(table):
        if not re.match(r"^(PM|FB|CA|RESP)-", row[0]):
            return False, f"Projection ID {row[0]!r} is not a structural ID"
    return True, ""


def _h_narrative_order(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Then: the narrative prompt requires <a> before <b> before <c>."""
    match = re.match(
        r"the narrative prompt requires (\S+) before (\S+) before (\S+)$", text
    )
    if not match:
        return False, f"Could not parse narrative order step: {text}"
    narrative_text = _stage6_text(world, "narrative")
    if narrative_text is None:
        return False, "Narrative prompts were not rendered"
    if "strictly in table order" not in narrative_text:
        return False, "Narrative prompt lacks the table-order instruction"
    rows = _alignment_rows_in_prompts(getattr(world, "stpa_stage6")["narrative"])
    if rows is None:
        return False, "Narrative prompt lacks the alignment table"
    order_by_id = {row[0]: int(row[7]) for row in rows if row[7].isdigit()}
    first, second, third = match.groups()
    for identifier in (first, second, third):
        if identifier not in order_by_id:
            return False, f"Narrative alignment table lacks {identifier}"
    if not (order_by_id[first] < order_by_id[second] < order_by_id[third]):
        return (
            False,
            f"Narrative order is not {first} < {second} < {third}: {order_by_id}",
        )
    return True, ""


def _h_narrative_exact_uca(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Then: the narrative prompt requires the exact UCA type "<type>"."""
    match = re.match(
        r'the narrative prompt requires the exact UCA type "([^"]+)"$', text
    )
    if not match:
        return False, f"Could not parse UCA type step: {text}"
    narrative_text = _stage6_text(world, "narrative")
    if narrative_text is None:
        return False, "Narrative prompts were not rendered"
    if "exact ICA type" not in narrative_text:
        return False, "Narrative prompt lacks the exact-ICA-type instruction"
    if match.group(1) not in narrative_text:
        return False, f"Narrative prompt lacks UCA type {match.group(1)}"
    return True, ""


def _h_narrative_forbids_inventing(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: the narrative prompt forbids inventing projection elements."""
    narrative_text = _stage6_text(world, "narrative")
    if narrative_text is None:
        return False, "Narrative prompts were not rendered"
    phrase = "Do not invent any causal factor, temporal assertion, or scenario step"
    if phrase not in narrative_text:
        return False, "Narrative prompt does not forbid inventing elements"
    return True, ""


def _h_narrative_fb_distinction(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: the narrative prompt keeps FB-* logical vs. inferred transport."""
    match = re.match(
        r"the narrative prompt preserves the distinction between (\S+) as a "
        r"logical feedback dependency and an inferred transport$",
        text,
    )
    if not match:
        return False, f"Could not parse feedback distinction step: {text}"
    narrative_text = _stage6_text(world, "narrative")
    if narrative_text is None:
        return False, "Narrative prompts were not rendered"
    if match.group(1) not in narrative_text:
        return False, f"Narrative prompt lacks {match.group(1)}"
    if "logical information dependency" not in narrative_text:
        return False, "Narrative prompt loses the logical dependency distinction"
    if "Never infer" not in narrative_text:
        return False, "Narrative prompt loses the transport-inference prohibition"
    return True, ""


def _h_tree_root(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Then: the attack-tree prompt requires root "<root>"."""
    match = re.match(r'the attack-tree prompt requires root "([^"]+)"$', text)
    if not match:
        return False, f"Could not parse tree root step: {text}"
    tree_text = _stage6_text(world, "tree")
    if tree_text is None:
        return False, "Attack-tree prompts were not rendered"
    if match.group(1) not in tree_text:
        return False, f"Attack-tree prompt lacks root {match.group(1)!r}"
    return True, ""


def _h_tree_structural_refs(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: the attack-tree prompt requires known structural references <ids>."""
    match = re.match(
        r"the attack-tree prompt requires known structural references (.+)$", text
    )
    if not match:
        return False, f"Could not parse tree references step: {text}"
    identifiers = [
        part.strip() for part in match.group(1).split(" and ") if part.strip()
    ]
    rows = _alignment_rows_in_prompts(getattr(world, "stpa_stage6", {}).get("tree"))
    if rows is None:
        return False, "Attack-tree prompt lacks the alignment table"
    row_ids = {row[0] for row in rows}
    missing = [identifier for identifier in identifiers if identifier not in row_ids]
    if missing:
        return False, f"Attack-tree alignment table lacks {missing}"
    return True, ""


def _h_tree_leaf_order(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Then: the attack-tree prompt preserves temporal-factor leaf order."""
    tree_text = _stage6_text(world, "tree")
    if tree_text is None:
        return False, "Attack-tree prompts were not rendered"
    if "preserve the projection order" not in tree_text:
        return False, "Attack-tree prompt lacks the projection-order instruction"
    rows = _alignment_rows_in_prompts(getattr(world, "stpa_stage6")["tree"])
    if rows is None:
        return False, "Attack-tree prompt lacks the alignment table"
    factor_orders = [int(row[7]) for row in rows[:-1] if row[7].isdigit()]
    if factor_orders != sorted(factor_orders) or len(set(factor_orders)) < 2:
        return False, "Attack-tree alignment rows have no preserved factor order"
    return True, ""


def _h_tree_infra_evidence(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Then: the attack-tree prompt forbids unproven infrastructure mechanisms."""
    tree_text = _stage6_text(world, "tree")
    if tree_text is None:
        return False, "Attack-tree prompts were not rendered"
    if "explicitly attacker-accessible" not in tree_text:
        return False, "Attack-tree prompt lacks the attacker-evidence requirement"
    return True, ""


def _h_gherkin_given_pm(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Then: the Gherkin prompt requires a Given reference to <id>."""
    match = re.match(r"the Gherkin prompt requires a Given reference to (\S+)$", text)
    if not match:
        return False, f"Could not parse Gherkin Given step: {text}"
    gherkin_text = _stage6_text(world, "gherkin")
    if gherkin_text is None:
        return False, "Gherkin prompts were not rendered"
    if "process model state IDs (PM-*)" not in gherkin_text:
        return False, "Gherkin prompt lacks the Given PM reference instruction"
    rows = _alignment_rows_in_prompts(getattr(world, "stpa_stage6")["gherkin"])
    if rows is None:
        return False, "Gherkin prompt lacks the alignment table"
    row_ids = {row[0] for row in rows}
    if match.group(1) not in row_ids:
        return False, f"Gherkin alignment table lacks {match.group(1)}"
    return True, ""


def _h_gherkin_actual_outcome(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: the Gherkin prompt requires <type> on <action> in the outcome."""
    match = re.match(
        r'the Gherkin prompt requires the exact ICA type "([^"]+)" and '
        r'control action "([^"]+)" in the actual outcome$',
        text,
    )
    if not match:
        return False, f"Could not parse Gherkin outcome step: {text}"
    gherkin_text = _stage6_text(world, "gherkin")
    if gherkin_text is None:
        return False, "Gherkin prompts were not rendered"
    if "actual outcome" not in gherkin_text:
        return False, "Gherkin prompt lacks the actual-outcome instruction"
    for value in match.groups():
        if value not in gherkin_text:
            return False, f"Gherkin prompt lacks {value}"
    return True, ""


def _h_gherkin_forbids_ids(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Then: the Gherkin prompt forbids unknown structural IDs."""
    gherkin_text = _stage6_text(world, "gherkin")
    if gherkin_text is None:
        return False, "Gherkin prompts were not rendered"
    phrase = "outside the projection alignment table or the control structure"
    if phrase not in gherkin_text:
        return False, "Gherkin prompt lacks the structural-ID boundary instruction"
    return True, ""


def _h_gherkin_loss_ids(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Then: the Gherkin prompt retains independent valid Loss ID validation."""
    gherkin_text = _stage6_text(world, "gherkin")
    if gherkin_text is None:
        return False, "Gherkin prompts were not rendered"
    if "valid Loss IDs" not in gherkin_text:
        return False, "Gherkin prompt loses the valid Loss ID instruction"
    if "L-1" not in gherkin_text:
        return False, "Gherkin prompt does not render the valid Loss IDs"
    return True, ""


def _h_derive_alignment_twice(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """When: the STPA alignment table is derived twice."""
    doc = _envelope_doc(world)
    if doc is None:
        return False, "No projection document recorded"
    world.stpa_alignment_a = render_projection_alignment_table(doc)
    world.stpa_alignment_b = render_projection_alignment_table(doc)
    world.stpa_alignment_rows = derive_projection_alignment_rows(doc)
    return True, ""


def _h_alignment_byte_identical(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: both alignment tables are byte-identical."""
    first = getattr(world, "stpa_alignment_a", None)
    second = getattr(world, "stpa_alignment_b", None)
    if first is None or second is None:
        return False, "Alignment table was not derived twice"
    if first.encode() != second.encode():
        return False, "Alignment tables are not byte-identical"
    return True, ""


def _h_assertion_rows_match_mapping(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: each assertion row equals the causal-factor validator mapping."""
    rows = getattr(world, "stpa_alignment_rows", None)
    envelope = getattr(world, "stpa_envelope", None)
    if rows is None or envelope is None:
        return False, "No alignment rows derived"
    for index, row in enumerate(rows[:-1]):
        factor = envelope.causal_factors[index]
        expected_predicate = predicate_for(factor.kind).value
        if row["source_id"] != factor.source_id:
            return False, f"Row {index} source does not match factor {factor.source_id}"
        if row["assertion_predicate"] != expected_predicate:
            return (
                False,
                f"Row {index} predicate {row['assertion_predicate']} is not the "
                f"validator mapping {expected_predicate}",
            )
        if row["assertion_id"] != f"TA-{index + 1}":
            return False, f"Row {index} assertion id is not canonical"
    return True, ""


def _h_step_rows_match_mapping(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: each factor step row equals the causal-factor validator mapping."""
    rows = getattr(world, "stpa_alignment_rows", None)
    envelope = getattr(world, "stpa_envelope", None)
    if rows is None or envelope is None:
        return False, "No alignment rows derived"
    for index, row in enumerate(rows[:-1]):
        factor = envelope.causal_factors[index]
        expected_kind = step_kind_for(factor.kind).value
        if row["source_id"] != factor.source_id:
            return False, f"Row {index} source does not match factor {factor.source_id}"
        if row["step_kind"] != expected_kind:
            return (
                False,
                f"Row {index} step kind {row['step_kind']} is not the "
                f"validator mapping {expected_kind}",
            )
        if row["step_id"] != f"S-{index + 1}":
            return False, f"Row {index} step id is not canonical"
    return True, ""


def _h_final_row_uca(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Then: the final row is the unsafe-control-action step for "<id>"."""
    match = re.match(
        r'the final row is the unsafe-control-action step for "([^"]+)"$', text
    )
    if not match:
        return False, f"Could not parse final row step: {text}"
    rows = getattr(world, "stpa_alignment_rows", None)
    if rows is None:
        return False, "No alignment rows derived"
    if not rows:
        return False, "Alignment table has no rows"
    final_row = rows[-1]
    if final_row["source_id"] != match.group(1):
        return (
            False,
            f"Final row references {final_row['source_id']}, not {match.group(1)}",
        )
    if final_row["step_kind"] != "UNSAFE_CONTROL_ACTION":
        return False, "Final row is not the unsafe control action step"
    return True, ""


def _h_no_hand_authored_rows(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: no alignment row is hand-authored independently by a Stage 6 prompt."""
    rows = getattr(world, "stpa_alignment_rows", None)
    if rows is None:
        return False, "No alignment rows derived"
    row_literals = {
        cell
        for row in rows
        for cell in (
            row["assertion_id"],
            row["assertion_predicate"],
            row["step_id"],
        )
        if cell != "-"
    }
    templates = sorted(PROMPTS_DIR.glob("stage6*.j2")) + [
        PROMPTS_DIR / "_stage6_projection_alignment.j2"
    ]
    for template in templates:
        text = template.read_text()
        for literal in row_literals:
            if literal in text:
                return (
                    False,
                    f"{template.name} hand-authors row literal {literal!r}",
                )
    return True, ""


# ---------------------------------------------------------------------------#
# Stream B Slice 5: canonical standalone export (STPA-PROJ-05)
# ---------------------------------------------------------------------------#


def _h_export_json(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """When: the STPA execution projection is exported as canonical JSON."""
    envelope = getattr(world, "stpa_envelope", None)
    if envelope is None:
        return False, "No candidate execution envelope assembled"
    world.stpa_json_export = export_projection_json(envelope)
    return True, ""


def _h_export_both(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """When: the STPA execution projection is exported as JSON and YAML."""
    envelope = getattr(world, "stpa_envelope", None)
    if envelope is None:
        return False, "No candidate execution envelope assembled"
    world.stpa_json_export = export_projection_json(envelope)
    world.stpa_yaml_export = export_projection_yaml(envelope)
    return True, ""


def _h_export_schema_version(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: both exports declare schema version "<version>"."""
    match = re.match(r'both exports declare schema version "([^"]+)"$', text)
    if not match:
        return False, f"Could not parse schema version step: {text}"
    json_doc = json.loads(getattr(world, "stpa_json_export", "{}"))
    yaml_doc = yaml.safe_load(getattr(world, "stpa_yaml_export", "")) or {}
    if json_doc.get("schema_version") != match.group(1):
        return False, "JSON export schema version does not match"
    if yaml_doc.get("schema_version") != match.group(1):
        return False, "YAML export schema version does not match"
    return True, ""


def _h_export_identifies(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Then: both exports identify candidate|UCA reference "<value>"."""
    match = re.match(
        r'both exports identify (candidate|UCA reference) "([^"]+)"$', text
    )
    if not match:
        return False, f"Could not parse export identity step: {text}"
    json_doc = json.loads(getattr(world, "stpa_json_export", "{}"))
    yaml_doc = yaml.safe_load(getattr(world, "stpa_yaml_export", "")) or {}
    key = "candidate_id" if match.group(1) == "candidate" else "uca_ref"
    expected = match.group(2)
    if json_doc.get(key) != expected:
        return False, f"JSON export {key} does not match"
    if yaml_doc.get(key) != expected:
        return False, f"YAML export {key} does not match"
    return True, ""


def _h_export_equivalent(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Then: standard readers parse both exports to equivalent data."""
    json_doc = json.loads(getattr(world, "stpa_json_export", "{}"))
    yaml_doc = yaml.safe_load(getattr(world, "stpa_yaml_export", ""))
    if json_doc != yaml_doc:
        return False, "JSON and YAML exports are not equivalent"
    return True, ""


_PLAIN_TYPES = (str, int, float, bool, type(None))


def _is_plain_data(value: object) -> bool:
    """True when the value is plain JSON/YAML data (no project objects)."""
    if isinstance(value, dict):
        return all(
            key.__class__ is str and _is_plain_data(child)
            for key, child in value.items()
        )
    if isinstance(value, list):
        return all(_is_plain_data(child) for child in value)
    return value.__class__ in _PLAIN_TYPES


def _h_export_no_imports(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Then: parsing either export does not require project imports."""
    json_doc = json.loads(getattr(world, "stpa_json_export", "{}"))
    yaml_doc = yaml.safe_load(getattr(world, "stpa_yaml_export", ""))
    if not _is_plain_data(json_doc) or not _is_plain_data(yaml_doc):
        return False, "Exports contain non-standard data shapes"
    return True, ""


def _h_export_ids_in_order(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Then: the export contains assertion|step IDs "<ids>" in order."""
    match = re.match(
        r'the export contains (assertion|step) IDs "([^"]+)" in order$', text
    )
    if not match:
        return False, f"Could not parse export IDs step: {text}"
    json_doc = json.loads(getattr(world, "stpa_json_export", "{}"))
    key = "assertions" if match.group(1) == "assertion" else "steps"
    id_field = "assertion_id" if key == "assertions" else "step_id"
    expected = [part.strip() for part in match.group(2).split(",")]
    actual = [item[id_field] for item in json_doc.get(key, [])]
    if actual != expected:
        return False, f"Export {key} ids are {actual}, expected {expected}"
    return True, ""


def _h_export_typed_provenance(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: assertion|step "<id>" has typed provenance "<kind>"/"<source>"."""
    match = re.match(
        r'(assertion|step) "([^"]+)" has typed provenance source kind '
        r'"([^"]+)" and source ID "([^"]+)"$',
        text,
    )
    if not match:
        return False, f"Could not parse provenance step: {text}"
    json_doc = json.loads(getattr(world, "stpa_json_export", "{}"))
    key = "assertions" if match.group(1) == "assertion" else "steps"
    id_field = "assertion_id" if key == "assertions" else "step_id"
    item = next(
        (entry for entry in json_doc.get(key, []) if entry[id_field] == match.group(2)),
        None,
    )
    if item is None:
        return False, f"Export lacks {match.group(1)} {match.group(2)}"
    if item["source_kind"] != match.group(3) or item["source_id"] != match.group(4):
        return (
            False,
            f"{match.group(1)} {match.group(2)} provenance is "
            f"{item['source_kind']}/{item['source_id']}",
        )
    return True, ""


_STRUCTURAL_ID = re.compile(r"\b(RESP|PM|FB|CA)-\d+(?:-\d+)?")


def _structural_references(value: object) -> set[str]:
    """Collect all structural IDs referenced by string values in the data."""
    found: set[str] = set()
    if isinstance(value, dict):
        for child in value.values():
            found.update(_structural_references(child))
    elif isinstance(value, list):
        for child in value:
            found.update(_structural_references(child))
    elif isinstance(value, str):
        found.update(match.group(0) for match in _STRUCTURAL_ID.finditer(value))
    return found


def _h_export_structural_refs(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: every exported structural reference is one of "<ids>"."""
    match = re.match(r'every exported structural reference is one of "([^"]+)"$', text)
    if not match:
        return False, f"Could not parse structural reference step: {text}"
    allowed = {part.strip() for part in match.group(1).split(",")}
    json_doc = json.loads(getattr(world, "stpa_json_export", "{}"))
    found = _structural_references(json_doc)
    unknown = found - allowed
    if unknown:
        return False, f"Export references unknown structural IDs: {unknown}"
    return True, ""


def _h_export_twice(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """When: canonical JSON and YAML exports are produced twice."""
    envelope = getattr(world, "stpa_envelope", None)
    if envelope is None:
        return False, "No candidate execution envelope assembled"
    world.stpa_json_export = export_projection_json(envelope)
    world.stpa_json_export_second = export_projection_json(envelope)
    world.stpa_yaml_export = export_projection_yaml(envelope)
    world.stpa_yaml_export_second = export_projection_yaml(envelope)
    return True, ""


def _h_json_byte_identical(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Then: the two JSON exports are byte-identical."""
    first = getattr(world, "stpa_json_export", None)
    second = getattr(world, "stpa_json_export_second", None)
    if first is None or second is None:
        return False, "JSON exports were not produced twice"
    if first.encode() != second.encode():
        return False, "JSON exports are not byte-identical"
    return True, ""


def _h_yaml_byte_identical(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Then: the two YAML exports are byte-identical."""
    first = getattr(world, "stpa_yaml_export", None)
    second = getattr(world, "stpa_yaml_export_second", None)
    if first is None or second is None:
        return False, "YAML exports were not produced twice"
    if first.encode() != second.encode():
        return False, "YAML exports are not byte-identical"
    return True, ""


def _h_json_keys_canonical(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Then: JSON object keys use canonical ordering."""
    json_doc = json.loads(getattr(world, "stpa_json_export", "{}"))
    stack = [json_doc]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            if list(node.keys()) != sorted(node.keys()):
                return False, f"JSON object keys are not canonical: {list(node.keys())}"
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    return True, ""


def _h_yaml_list_order(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Then: YAML list ordering is preserved, never sorted by source text."""
    yaml_doc = yaml.safe_load(getattr(world, "stpa_yaml_export", "")) or {}
    assertion_sources = [a["source_id"] for a in yaml_doc.get("assertions", [])]
    step_sources = [s["source_id"] for s in yaml_doc.get("steps", [])]
    if assertion_sources == sorted(assertion_sources):
        return False, "YAML assertions appear sorted by source text"
    if step_sources == sorted(step_sources):
        return False, "YAML steps appear sorted by source text"
    return True, ""


def _apply_export_mutation(doc: dict, mutation: str) -> bool:
    """Apply one named export mutation; True when the mutation is known."""
    if mutation == "changing candidate_id to another EXEC ID":
        doc["candidate_id"] = "EXEC:RESP-2:CA-1-1:WRONG_TIMING"
        return True
    if mutation == "changing assertion TA-1 source_id":
        for assertion in doc.get("assertions", []):
            if assertion["assertion_id"] == "TA-1":
                assertion["source_id"] = "FB-1-1"
                return True
        return False
    if mutation == "changing step S-3 source_id":
        for step in doc.get("steps", []):
            if step["step_id"] == "S-3":
                step["source_id"] = "CA-9-9"
                return True
        return False
    if mutation == "changing provenance source_kind":
        for assertion in doc.get("assertions", []):
            if assertion["assertion_id"] == "TA-1":
                assertion["source_kind"] = "unsafe_control_action"
                return True
        return False
    if mutation == "removing schema_version":
        doc.pop("schema_version", None)
        return True
    return False


def _h_mutate_json_export(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """When: the canonical JSON export is mutated by "<mutation>"."""
    match = re.match(r'the canonical JSON export is mutated by "([^"]+)"$', text)
    if not match:
        return False, f"Could not parse export mutation step: {text}"
    export = getattr(world, "stpa_json_export", None)
    if export is None:
        envelope = getattr(world, "stpa_envelope", None)
        if envelope is None:
            return False, "No candidate execution envelope assembled"
        export = export_projection_json(envelope)
        world.stpa_json_export = export
    doc = json.loads(export)
    if not _apply_export_mutation(doc, match.group(1)):
        return False, f"Unknown export mutation: {match.group(1)}"
    world.stpa_json_export_mutated = doc
    return True, ""


def _h_export_loaded_validated(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """When: the exported projection is loaded and validated."""
    doc = getattr(world, "stpa_json_export_mutated", None)
    if doc is None:
        return False, "No mutated JSON export recorded"
    loaded = json.loads(json.dumps(doc))
    world.stpa_export_validation = validate_exported_projection(loaded)
    return True, ""


def _h_export_fails(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Then: exported projection validation fails with "<error>"."""
    match = re.match(r'exported projection validation fails with "([^"]+)"$', text)
    if not match:
        return False, f"Could not parse export failure step: {text}"
    result = getattr(world, "stpa_export_validation", None)
    if result is None:
        return False, "No exported projection validation recorded"
    if result.valid:
        return False, "Exported projection validation unexpectedly passed"
    codes = {violation.code.value for violation in result.violations}
    if match.group(1) not in codes:
        return False, f"Exported projection errors are {codes}, not {match.group(1)}"
    return True, ""


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
            project_execution,
            canonical_projection_data,
            validate_projection_traceability,
            render_projection_alignment_table,
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


def _h_stage5_evidence_declares_factors(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Given: the Stage 5 evidence declares causal factors "<factors>"."""
    match = re.match(r'the Stage 5 evidence declares causal factors "([^"]+)"', text)
    if not match:
        return False, f"Could not parse declared factors step: {text}"
    ok, message, declarations = _declarations_from_labeled(match.group(1))
    if not ok:
        return False, message
    world.stpa_declarations = declarations
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


def _h_no_stage6_calls_for_invalid(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: no Stage 6 call is made for the invalid ScenarioSpec."""
    if getattr(world, "stpa_stage6", None) is not None:
        return False, "Stage 6 prompts were rendered for the invalid ScenarioSpec"
    if getattr(world, "stpa_alignment_table", None) is not None:
        return False, "An alignment table was derived for the invalid ScenarioSpec"
    if getattr(world, "stpa_projection_doc", None) is not None:
        return False, "A projection document was derived for the invalid ScenarioSpec"
    return True, ""


def _h_no_projection_artifact_invalid(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: no projection artifact is written for the invalid scenario."""
    if getattr(world, "stpa_artifact_dir", None) is not None:
        return False, "Projection artifacts were written for the invalid scenario"
    return True, ""


def _h_project_execution_twice(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """When: project_execution is applied to the ScenarioSpec twice."""
    declarations = getattr(world, "stpa_declarations", None)
    control_structure = getattr(world, "stpa_control_structure", None)
    if declarations is None or control_structure is None:
        return False, "No Stage 5 declarations or control structure recorded"
    spec, message = _assemble_spec_from_declarations(world, declarations)
    if spec is None:
        return False, message
    world.stpa_scenario_spec = spec
    world.stpa_envelope_a = project_execution(spec, control_structure)
    world.stpa_envelope_b = project_execution(spec, control_structure)
    return True, ""


def _h_envelopes_byte_equivalent(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: both candidate execution envelopes are byte-equivalent."""
    first = getattr(world, "stpa_envelope_a", None)
    second = getattr(world, "stpa_envelope_b", None)
    if first is None or second is None:
        return False, "project_execution was not applied twice"
    if json.dumps(first.model_dump(mode="json")) != json.dumps(
        second.model_dump(mode="json")
    ):
        return False, "Repeated project_execution envelopes are not byte-equivalent"
    return True, ""


def _h_envelope_candidate_identifier(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: the envelope candidate identifier is "<id>"."""
    match = re.match(r'the envelope candidate identifier is "([^"]+)"', text)
    if not match:
        return False, f"Could not parse envelope candidate step: {text}"
    envelope = getattr(world, "stpa_envelope_a", None)
    if envelope is None:
        return False, "No projection envelope derived"
    if envelope.candidate_id != match.group(1):
        return (
            False,
            f"Envelope candidate is {envelope.candidate_id}, not {match.group(1)}",
        )
    return True, ""


def _h_envelope_factor_ids(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Then: the envelope causal factors are "<ids>" in declared order."""
    match = re.match(
        r'the envelope causal factors are "([^"]+)" in declared order', text
    )
    if not match:
        return False, f"Could not parse envelope factor step: {text}"
    expected = [part.strip() for part in match.group(1).split(",")]
    envelope = getattr(world, "stpa_envelope_a", None)
    if envelope is None:
        return False, "No projection envelope derived"
    actual = [factor.source_id for factor in envelope.causal_factors]
    if actual != expected:
        return False, f"Envelope causal factors are {actual}, expected {expected}"
    return True, ""


def _h_envelope_no_undeclared_behavior(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: the envelope invents no factor or temporal behavior."""
    declarations = getattr(world, "stpa_declarations", None)
    envelope = getattr(world, "stpa_envelope_a", None)
    if declarations is None or envelope is None:
        return False, "No declarations or projection envelope recorded"
    if len(envelope.causal_factors) != len(declarations):
        return False, "Envelope factor count exceeds the declared factors"
    vector = envelope.temporal_vector
    if len(vector.assertions) != len(declarations):
        return False, "Envelope assertions exceed the declared factors"
    for factor, assertion in zip(envelope.causal_factors, vector.assertions):
        expected = parse_declared_timing(factor.declared_timing, factor.source_id)
        if assertion.source_id != factor.source_id:
            return False, f"Assertion {assertion.assertion_id} source is not declared"
        if (assertion.constraint is None) != (expected is None):
            return False, f"Assertion {assertion.assertion_id} timing is invented"
    expected_steps = len(declarations) + 1
    if len(vector.steps) != expected_steps:
        return False, "Envelope has invented scenario steps"
    if vector.steps[-1].kind != ScenarioStepKind.unsafe_control_action:
        return False, "Envelope final step is not the unsafe control action"
    if not declarations and vector.uca_constraint is not None:
        return False, "Envelope invents a UCA outcome without declared factors"
    return True, ""


def _h_derive_projection_and_write(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """When: the production STPA run derives the projection and writes artifacts."""
    spec = getattr(world, "stpa_scenario_spec", None)
    control_structure = getattr(world, "stpa_control_structure", None)
    if spec is None or control_structure is None:
        return False, "No ScenarioSpec or control structure recorded"
    _write_scenario_artifacts(world, project_execution(spec, control_structure))
    return True, ""


def _write_scenario_artifacts(
    world: World, envelope: CandidateExecutionEnvelope
) -> None:
    """Write legacy and canonical scenario artifacts into a fresh run dir."""
    run_dir = Path(tempfile.mkdtemp(prefix="stpa_wiring_"))
    scenarios_dir = run_dir / "scenarios"
    scenarios_dir.mkdir(parents=True, exist_ok=True)
    write_yaml(envelope, scenarios_dir / f"{envelope.scenario_id}.yaml")
    (scenarios_dir / f"{envelope.scenario_id}.feature").write_text(
        "Feature: Attack scenario\n"
        "  Scenario: Attack scenario\n"
        "    When the attacker acts\n",
        encoding="utf-8",
    )
    canonical_dir = scenarios_dir / "canonical"
    canonical_dir.mkdir(parents=True, exist_ok=True)
    (canonical_dir / f"{envelope.scenario_id}.projection.json").write_text(
        export_projection_json(envelope), encoding="utf-8"
    )
    (canonical_dir / f"{envelope.scenario_id}.projection.yaml").write_text(
        export_projection_yaml(envelope), encoding="utf-8"
    )
    world.stpa_envelope = envelope
    world.stpa_projection_doc = canonical_projection_data(envelope)
    world.stpa_artifact_dir = scenarios_dir
    world.stpa_scenario_id = envelope.scenario_id


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


def _h_projection_vectors_present_empty(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: the projection has present empty causal_factors/assertions/steps."""
    doc = _envelope_doc(world)
    if doc is None:
        return False, "No projection document recorded"
    for key in ("causal_factors", "assertions", "steps"):
        if key not in doc:
            return False, f"Projection lacks the present '{key}' field"
        if doc[key] != []:
            return False, f"Projection '{key}' is {doc[key]}, not []"
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


def _h_no_behavior_invented(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: no behavior is invented from structural presence alone."""
    doc = _envelope_doc(world)
    if doc is None:
        return False, "No projection document recorded"
    if doc["causal_factors"] or doc["assertions"] or doc["steps"]:
        return False, "Structural presence invented projection behavior"
    return True, ""


def _h_validated_factor_set_follows(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Given: the validated Stage 5 factor set contains X followed by Y."""
    match = re.match(r"the validated Stage 5 factor set contains (.+)", text)
    if not match:
        return False, f"Could not parse validated factor set step: {text}"
    items = [part.strip() for part in match.group(1).split(" followed by ")]
    declarations = []
    for source_id in items:
        kind = _KIND_BY_ID_PREFIX.get(source_id.split("-")[0])
        if kind is None:
            return False, f"Unsupported causal factor source: {source_id}"
        declarations.append(
            CausalFactorDeclaration(
                kind=kind,
                source_id=source_id,
                evidence=f"Stage 5 evidence for {source_id}",
            )
        )
    world.stpa_declarations = declarations
    return True, ""


def _h_stage6_derives_one_alignment(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """When: Stage 6 derives one projection alignment from the projection."""
    declarations = getattr(world, "stpa_declarations", None)
    control_structure = getattr(world, "stpa_control_structure", None)
    if declarations is None or control_structure is None:
        return False, "No Stage 5 factor set or control structure recorded"
    spec, message = _assemble_spec_from_declarations(world, declarations)
    if spec is None:
        return False, message
    envelope = project_execution(spec, control_structure)
    world.stpa_envelope = envelope
    doc = canonical_projection_data(envelope)
    result = validate_projection_traceability(doc)
    if not result.valid:
        return False, "Validated projection failed traceability validation"
    table = render_projection_alignment_table(doc)
    if not table:
        return False, "Projection alignment table is empty"
    world.stpa_alignment_table = table
    world.stpa_projection_doc = doc
    loader = TemplateLoader(PROMPTS_DIR)
    rendered = {}
    for call in ("narrative", "tree", "gherkin"):
        prompts = _render_call_prompts(world, call, loader, spec, table)
        if prompts is None:
            return False, f"Could not render {call} prompts"
        rendered[call] = prompts
    world.stpa_stage6 = rendered
    return True, ""


def _h_calls_receive_same_table(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: every Stage 6 call receives the same alignment table."""
    table = getattr(world, "stpa_alignment_table", None)
    stage6 = getattr(world, "stpa_stage6", None)
    if table is None or stage6 is None:
        return False, "No Stage 6 alignment derived"
    for call in ("narrative", "tree", "gherkin"):
        prompts = stage6.get(call)
        if prompts is None:
            return False, f"{call} prompts were not rendered"
        for prompt in prompts:
            if table not in prompt:
                return False, f"{call} prompt lacks the shared alignment table"
    return True, ""


def _h_table_rows_specific(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Then: the table has one row per named factor and one final UCA row."""
    match = re.match(
        r"the table has one row for ([A-Z0-9-]+), one row for ([A-Z0-9-]+), "
        r"and one final row for ([A-Z0-9-]+)",
        text,
    )
    if not match:
        return False, f"Could not parse table row step: {text}"
    expected = list(match.groups())
    table = getattr(world, "stpa_alignment_table", None)
    if table is None:
        return False, "No projection alignment table derived"
    rows = _table_rows(table)
    actual = [row[0] for row in rows]
    if actual != expected:
        return False, f"Alignment rows are {actual}, expected {expected}"
    return True, ""


def _h_rows_preserve_order_uca_last(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: the rows preserve declared order with the UCA row last."""
    table = getattr(world, "stpa_alignment_table", None)
    declarations = getattr(world, "stpa_declarations", None)
    if table is None or declarations is None:
        return False, "No alignment table or declared factor set recorded"
    rows = _table_rows(table)
    if not rows:
        return False, "Alignment table has no rows"
    declared = [declaration.source_id for declaration in declarations]
    if [row[0] for row in rows[:-1]] != declared:
        return False, "Alignment rows do not preserve declared factor order"
    if rows[-1][6] != "UNSAFE_CONTROL_ACTION":
        return False, "The unsafe-control-action row is not last"
    return True, ""


def _h_every_stage6_prompt_forbids_inventing(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: every Stage 6 prompt forbids inventing factors, assertions, steps."""
    stage6 = getattr(world, "stpa_stage6", None)
    if stage6 is None:
        return False, "No Stage 6 prompts rendered"
    phrase = "Do not invent any causal factor, temporal assertion, or scenario step"
    for call in ("narrative", "tree", "gherkin"):
        prompts = stage6.get(call)
        if prompts is None:
            return False, f"{call} prompts were not rendered"
        for prompt in prompts:
            if phrase not in prompt:
                return False, f"{call} prompt does not forbid inventing behavior"
    return True, ""


def _h_prompt_semantic_ids(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Then: the prompt references semantic structural IDs, not labels."""
    stage6 = getattr(world, "stpa_stage6", None)
    if stage6 is None:
        return False, "No Stage 6 prompts rendered"
    phrases = ("semantic structural IDs", "not positional labels")
    for call in ("narrative", "tree", "gherkin"):
        prompts = stage6.get(call)
        if prompts is None:
            return False, f"{call} prompts were not rendered"
        for prompt in prompts:
            for phrase in phrases:
                if phrase not in prompt:
                    return (
                        False,
                        f"{call} prompt reduces IDs to positional labels",
                    )
    return True, ""


def _h_stage5_one_evidence_factor(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Given: Stage 5 returns one evidence-backed <kind> factor at <id>."""
    match = re.match(
        r"Stage 5 returns one evidence-backed (process-model|feedback-delay|"
        r"actuator-anomaly) factor at ([A-Z0-9-]+)",
        text,
    )
    if not match:
        return False, f"Could not parse Stage 5 evidence step: {text}"
    kind_label, source_id = match.groups()
    world.stpa_declarations = [
        CausalFactorDeclaration(
            kind=_KIND_BY_HYPHEN_LABEL[kind_label],
            source_id=source_id,
            evidence=f"Stage 5 evidence for {kind_label} at {source_id}",
        )
    ]
    return True, ""


def _h_run_completes_scenario(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """When: the production STPA run completes the scenario."""
    control_structure = getattr(world, "stpa_control_structure", None)
    if control_structure is None:
        return False, "No control structure recorded"
    spec = getattr(world, "stpa_scenario_spec", None)
    if spec is None:
        declarations = getattr(world, "stpa_declarations", None)
        if declarations is None:
            return False, "No Stage 5 factor declarations recorded"
        spec, message = _assemble_spec_from_declarations(world, declarations)
        if spec is None:
            return False, message
        world.stpa_scenario_spec = spec
    _write_scenario_artifacts(world, project_execution(spec, control_structure))
    return True, ""


def _h_dir_contains_legacy(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Then: the scenario directory contains legacy YAML and Gherkin."""
    artifact_dir = getattr(world, "stpa_artifact_dir", None)
    if artifact_dir is None:
        return False, "No scenario artifact directory recorded"
    scenario_id = getattr(world, "stpa_scenario_id", None)
    if scenario_id is None:
        return False, "No scenario ID recorded"
    if not (artifact_dir / f"{scenario_id}.yaml").is_file():
        return False, "Legacy scenario YAML is missing"
    if not (artifact_dir / f"{scenario_id}.feature").is_file():
        return False, "Gherkin feature is missing"
    return True, ""


def _h_dir_contains_canonical(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: the scenario directory contains canonical JSON and YAML artifacts."""
    artifact_dir = getattr(world, "stpa_artifact_dir", None)
    if artifact_dir is None:
        return False, "No scenario artifact directory recorded"
    canonical_dir = artifact_dir / "canonical"
    if not (canonical_dir / "SCN-001.projection.json").is_file():
        return False, "Canonical JSON projection artifact is missing"
    if not (canonical_dir / "SCN-001.projection.yaml").is_file():
        return False, "Canonical YAML projection artifact is missing"
    return True, ""


def _read_canonical_artifacts(
    world: World,
) -> tuple[dict | None, dict | None] | None:
    """Parse the canonical projection artifacts of the run dir.

    Returns the (json_doc, yaml_doc) pair read with standard JSON and
    YAML readers, or ``None`` when no artifact directory is recorded.
    """
    artifact_dir = getattr(world, "stpa_artifact_dir", None)
    if artifact_dir is None:
        return None
    canonical_dir = artifact_dir / "canonical"
    json_doc = json.loads(
        (canonical_dir / "SCN-001.projection.json").read_text(encoding="utf-8")
    )
    yaml_doc = yaml.safe_load(
        (canonical_dir / "SCN-001.projection.yaml").read_text(encoding="utf-8")
    )
    return json_doc, yaml_doc


def _h_canonical_schema_version(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: each canonical artifact declares schema version "<version>"."""
    match = re.match(
        r'each canonical projection artifact declares schema version "([^"]+)"', text
    )
    if not match:
        return False, f"Could not parse schema version step: {text}"
    artifacts = _read_canonical_artifacts(world)
    if artifacts is None:
        return False, "No scenario artifact directory recorded"
    json_doc, yaml_doc = artifacts
    if json_doc.get("schema_version") != match.group(1):
        return False, "Canonical JSON schema version does not match"
    if yaml_doc.get("schema_version") != match.group(1):
        return False, "Canonical YAML schema version does not match"
    return True, ""


def _h_canonical_identifies_ica_scenario(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: the artifacts identify ICA and scenario separately."""
    match = re.match(
        r'the canonical projection artifacts identify ICA "([^"]+)" and '
        r'scenario "([^"]+)" separately',
        text,
    )
    if not match:
        return False, f"Could not parse artifact identity step: {text}"
    artifacts = _read_canonical_artifacts(world)
    if artifacts is None:
        return False, "No scenario artifact directory recorded"
    json_doc, yaml_doc = artifacts
    ica_id, scenario_id = match.groups()
    for export in (json_doc, yaml_doc):
        if export.get("ica_id") != ica_id:
            return False, f"Export ICA ID is {export.get('ica_id')}, not {ica_id}"
        if export.get("scenario_id") != scenario_id:
            return False, (
                f"Export scenario ID is {export.get('scenario_id')}, not {scenario_id}"
            )
    return True, ""


def _h_canonical_standard_reader(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: standard readers parse the artifacts without project imports."""
    artifacts = _read_canonical_artifacts(world)
    if artifacts is None:
        return False, "No scenario artifact directory recorded"
    json_doc, yaml_doc = artifacts
    if not _is_plain_data(json_doc) or not _is_plain_data(yaml_doc):
        return False, "Canonical artifacts require project imports to parse"
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


def _h_valid_canonical_projection(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Given: a valid canonical STPA projection with candidate "<id>"."""
    match = re.match(
        r'a valid canonical STPA projection with candidate "([^"]+)"', text
    )
    if not match:
        return False, f"Could not parse canonical projection step: {text}"
    if getattr(world, "stpa_control_structure", None) is None:
        control_structure = _make_building_blocks_control_structure()
        world.stpa_control_structure = control_structure
        world.stpa_controller = "RESP-1"
    if getattr(world, "stpa_ica_id", None) is None:
        world.stpa_ica_id = "RESP-1:CA-1-1:WRONG_TIMING:1"
    declarations = [
        CausalFactorDeclaration(
            kind=CausalFactorKind.process_model_flaw,
            source_id="PM-1-1",
            evidence="Evidence for PM-1-1",
        ),
        CausalFactorDeclaration(
            kind=CausalFactorKind.feedback_delay,
            source_id="FB-1-1",
            evidence="Evidence for FB-1-1",
        ),
    ]
    spec, message = _assemble_spec_from_declarations(world, declarations)
    if spec is None:
        return False, message
    control_structure = getattr(world, "stpa_control_structure", None)
    envelope = project_execution(spec, control_structure)
    if envelope.candidate_id != match.group(1):
        return False, f"Projection candidate is {envelope.candidate_id}"
    world.stpa_envelope = envelope
    world.stpa_projection_doc = canonical_projection_data(envelope)
    result = validate_projection_traceability(world.stpa_projection_doc)
    if not result.valid:
        codes = [v.code.value for v in result.violations]
        return False, f"Canonical projection is not valid: {codes}"
    return True, ""


def _h_its_uca_reference(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Then: its UCA reference is "<ref>"."""
    match = re.match(r'its UCA reference is "([^"]+)"', text)
    if not match:
        return False, f"Could not parse UCA reference step: {text}"
    doc = _envelope_doc(world)
    if doc is None:
        return False, "No canonical projection recorded"
    if doc["uca_ref"] != match.group(1):
        return False, f"UCA reference is {doc['uca_ref']}, not {match.group(1)}"
    return True, ""


def _h_projection_missing_key(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Given: the canonical projection is missing the "<key>" key."""
    match = re.match(r'the canonical projection is missing the "([^"]+)" key', text)
    if not match:
        return False, f"Could not parse missing key step: {text}"
    doc = _envelope_doc(world)
    if doc is None:
        return False, "No canonical projection recorded"
    if match.group(1) not in doc:
        return False, f"Key {match.group(1)} is already absent"
    del doc[match.group(1)]
    return True, ""


def _h_traceability_plain_validity(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: traceability is valid|invalid."""
    match = re.match(r"traceability is (valid|invalid)$", text)
    if not match:
        return False, f"Could not parse traceability validity: {text}"
    result = getattr(world, "stpa_traceability", None)
    if result is None:
        return False, "No traceability result recorded"
    expected_valid = match.group(1) == "valid"
    if result.valid != expected_valid:
        return (
            False,
            f"Traceability is {'valid' if result.valid else 'invalid'}, "
            f"expected {match.group(1)}",
        )
    return True, ""


def _h_typed_violation_code(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: the result contains typed violation code "<code>"."""
    match = re.match(r'the result contains typed violation code "([^"]+)"', text)
    if not match:
        return False, f"Could not parse typed violation code step: {text}"
    result = getattr(world, "stpa_traceability", None)
    if result is None:
        return False, "No traceability result recorded"
    matched = next(
        (
            violation
            for violation in result.violations
            if violation.code.value == match.group(1)
        ),
        None,
    )
    world.stpa_matched_violation = matched
    if matched is None:
        codes = [violation.code.value for violation in result.violations]
        return False, f"No violation with code {match.group(1)}; found {codes}"
    return True, ""


def _h_violation_identifies_element(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: the violation identifies projection element "<key>"."""
    match = re.match(r'the violation identifies projection element "([^"]+)"', text)
    if not match:
        return False, f"Could not parse violation element step: {text}"
    violation = getattr(world, "stpa_matched_violation", None)
    if violation is None:
        return False, "No matched violation recorded"
    if violation.element_id != match.group(1):
        return (
            False,
            f"Violation identifies '{violation.element_id}', "
            f"expected '{match.group(1)}'",
        )
    return True, ""


def _h_projection_explicit_empty_vectors(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Given: the projection explicitly contains empty list vectors."""
    doc = _envelope_doc(world)
    if doc is None:
        return False, "No canonical projection recorded"
    for key in ("causal_factors", "assertions", "steps"):
        doc[key] = []
    return True, ""


def _h_result_contains_no_violations(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: the result contains no violations."""
    result = getattr(world, "stpa_traceability", None)
    if result is None:
        return False, "No traceability result recorded"
    if result.violations:
        codes = [violation.code.value for violation in result.violations]
        return False, f"Traceability result has violations: {codes}"
    return True, ""


def _h_no_provenance_invented(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: no causal-factor, assertion, or step provenance is invented."""
    doc = _envelope_doc(world)
    if doc is None:
        return False, "No canonical projection recorded"
    if doc["causal_factors"] or doc["assertions"] or doc["steps"]:
        return False, "Present-empty projection invented provenance entries"
    return True, ""


def _apply_contract_mutation(doc: dict, field: str, value: str) -> tuple[bool, str]:
    """Apply one contract mutation; return (applied, expected element)."""
    if field == "candidate_id":
        doc["candidate_id"] = value
        return True, value
    if field == "assertion source_id":
        for assertion in doc.get("assertions", []):
            assertion["source_id"] = value
            return True, str(assertion.get("assertion_id", "TA-1"))
        return False, "no assertions to mutate"
    if field == "step source_id":
        if not doc.get("steps"):
            return False, "no steps to mutate"
        doc["steps"][-1]["source_id"] = value
        return True, str(doc["steps"][-1].get("step_id", "S-3"))
    if field == "assertion source_kind":
        for assertion in doc.get("assertions", []):
            assertion["source_kind"] = value
            return True, str(assertion.get("assertion_id", "TA-1"))
        return False, "no assertions to mutate"
    if field == "schema_version":
        if value == "absent":
            doc.pop("schema_version", None)
        else:
            doc["schema_version"] = value
        return True, "schema_version"
    return False, "unknown field"


def _h_valid_projection_mutated(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Given: the valid canonical projection is mutated by changing <field>."""
    match = re.match(
        r'the valid canonical projection is mutated by changing "([^"]+)" to "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse mutation step: {text}"
    doc = _envelope_doc(world)
    if doc is None:
        return False, "No canonical projection recorded"
    applied, expected = _apply_contract_mutation(doc, match.group(1), match.group(2))
    if not applied:
        return False, f"Unknown contract mutation: {match.group(1)}"
    world.stpa_expected_element = expected
    return True, ""


def _h_validation_earliest_element(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: validation identifies the earliest affected projection element."""
    result = getattr(world, "stpa_traceability", None)
    expected = getattr(world, "stpa_expected_element", None)
    if result is None:
        return False, "No traceability result recorded"
    if expected is None:
        return False, "No expected projection element recorded"
    if not result.violations:
        return False, "Traceability has no violations to identify"
    first = result.violations[0]
    if first.element_id != expected:
        return (
            False,
            f"Earliest affected element is '{first.element_id}', expected '{expected}'",
        )
    return True, ""


def _h_projection_carries_identities(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Given: the projection carries ICA ID and scenario ID."""
    match = re.match(
        r'the projection carries ICA ID "([^"]+)" and scenario ID "([^"]+)"', text
    )
    if not match:
        return False, f"Could not parse projection identities step: {text}"
    doc = _envelope_doc(world)
    if doc is None:
        return False, "No canonical projection recorded"
    ica_id, scenario_id = match.groups()
    if doc.get("ica_id") != ica_id:
        return False, f"Projection ICA ID is {doc.get('ica_id')}, not {ica_id}"
    if doc.get("scenario_id") != scenario_id:
        return False, (
            f"Projection scenario ID is {doc.get('scenario_id')}, not {scenario_id}"
        )
    return True, ""


def _h_projection_exported_both(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """When: the projection is exported as canonical JSON and YAML."""
    envelope = getattr(world, "stpa_envelope", None)
    if envelope is None:
        return False, "No candidate execution envelope recorded"
    world.stpa_json_export = export_projection_json(envelope)
    world.stpa_yaml_export = export_projection_yaml(envelope)
    return True, ""


def _h_exports_parsed_standard(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """When: both exports are parsed with standard readers."""
    json_doc = json.loads(getattr(world, "stpa_json_export", "{}"))
    yaml_doc = yaml.safe_load(getattr(world, "stpa_yaml_export", ""))
    if json_doc is None or yaml_doc is None:
        return False, "Exports are empty"
    if not _is_plain_data(json_doc) or not _is_plain_data(yaml_doc):
        return False, "Exports require project imports to parse"
    world.stpa_parsed_json = json_doc
    world.stpa_parsed_yaml = yaml_doc
    return True, ""


def _h_exports_retain_candidate(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: both exports retain candidate "<id>"."""
    match = re.match(r'both exports retain candidate "([^"]+)"', text)
    if not match:
        return False, f"Could not parse retained candidate step: {text}"
    json_doc = getattr(world, "stpa_parsed_json", None)
    yaml_doc = getattr(world, "stpa_parsed_yaml", None)
    if json_doc is None or yaml_doc is None:
        return False, "Exports were not parsed"
    if json_doc.get("candidate_id") != match.group(1):
        return False, "JSON export lost the candidate identifier"
    if yaml_doc.get("candidate_id") != match.group(1):
        return False, "YAML export lost the candidate identifier"
    return True, ""


def _h_exports_contain_ica_id(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: both exports contain ICA ID "<id>" in its own field."""
    match = re.match(r'both exports contain ICA ID "([^"]+)" in its own field', text)
    if not match:
        return False, f"Could not parse ICA field step: {text}"
    json_doc = getattr(world, "stpa_parsed_json", None)
    yaml_doc = getattr(world, "stpa_parsed_yaml", None)
    if json_doc is None or yaml_doc is None:
        return False, "Exports were not parsed"
    if json_doc.get("ica_id") != match.group(1):
        return False, "JSON export lost the ICA ID field"
    if yaml_doc.get("ica_id") != match.group(1):
        return False, "YAML export lost the ICA ID field"
    return True, ""


def _h_exports_contain_scenario_id(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: both exports contain scenario ID "<id>" in its own field."""
    match = re.match(
        r'both exports contain scenario ID "([^"]+)" in its own field', text
    )
    if not match:
        return False, f"Could not parse scenario field step: {text}"
    json_doc = getattr(world, "stpa_parsed_json", None)
    yaml_doc = getattr(world, "stpa_parsed_yaml", None)
    if json_doc is None or yaml_doc is None:
        return False, "Exports were not parsed"
    if json_doc.get("scenario_id") != match.group(1):
        return False, "JSON export lost the scenario ID field"
    if yaml_doc.get("scenario_id") != match.group(1):
        return False, "YAML export lost the scenario ID field"
    return True, ""


def _h_identity_change_keeps_candidate(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: changing <identity> does not change structural candidate ID."""
    match = re.match(
        r'changing "([^"]+)" does not change structural candidate ID', text
    )
    if not match:
        return False, f"Could not parse identity independence step: {text}"
    json_doc = getattr(world, "stpa_parsed_json", None)
    if json_doc is None:
        return False, "Exports were not parsed"
    candidate_id = json_doc.get("candidate_id")
    if not candidate_id:
        return False, "Export lacks a candidate identifier"
    changed = deepcopy(json_doc)
    if match.group(1) == "scenario ID":
        changed["scenario_id"] = "SCN-999"
    elif match.group(1) == "ICA ID":
        changed["ica_id"] = "RESP-1:CA-1-1:WRONG_TIMING:9"
    else:
        return False, f"Unknown identity field: {match.group(1)}"
    if changed["candidate_id"] != candidate_id:
        return False, "Changing the identity rewrote the candidate identifier"
    if candidate_id == changed["scenario_id"] or candidate_id == changed["ica_id"]:
        return False, "Candidate identifier embeds the mutable identity"
    return True, ""


def _h_projection_two_factors_ordered(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Given: the projection contains two causal factors in declared order."""
    doc = _envelope_doc(world)
    if doc is None:
        return False, "No canonical projection recorded"
    actual = [factor["source_id"] for factor in doc["causal_factors"]]
    if actual != ["PM-1-1", "FB-1-1"]:
        return False, f"Projection causal factors are {actual}"
    return True, ""


def _h_canonical_produced_twice(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """When: canonical JSON and YAML are produced twice."""
    envelope = getattr(world, "stpa_envelope", None)
    if envelope is None:
        return False, "No candidate execution envelope recorded"
    world.stpa_json_export = export_projection_json(envelope)
    world.stpa_json_export_second = export_projection_json(envelope)
    world.stpa_yaml_export = export_projection_yaml(envelope)
    world.stpa_yaml_export_second = export_projection_yaml(envelope)
    return True, ""


def _h_repeated_outputs_byte_identical(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: the repeated JSON and YAML outputs are each byte-identical."""
    json_first = getattr(world, "stpa_json_export", None)
    json_second = getattr(world, "stpa_json_export_second", None)
    yaml_first = getattr(world, "stpa_yaml_export", None)
    yaml_second = getattr(world, "stpa_yaml_export_second", None)
    if None in (json_first, json_second, yaml_first, yaml_second):
        return False, "Canonical exports were not produced twice"
    if json_first.encode() != json_second.encode():
        return False, "Repeated JSON exports are not byte-identical"
    if yaml_first.encode() != yaml_second.encode():
        return False, "Repeated YAML exports are not byte-identical"
    return True, ""


def _h_exports_preserve_order(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: JSON and YAML preserve factor, assertion, and step order."""
    json_doc = getattr(world, "stpa_parsed_json", None)
    yaml_doc = getattr(world, "stpa_parsed_yaml", None)
    if json_doc is None or yaml_doc is None:
        json_doc = json.loads(getattr(world, "stpa_json_export", "{}"))
        yaml_doc = yaml.safe_load(getattr(world, "stpa_yaml_export", "")) or {}
    for key, id_field in (
        ("causal_factors", "source_id"),
        ("assertions", "assertion_id"),
        ("steps", "step_id"),
    ):
        json_order = [item[id_field] for item in json_doc.get(key, [])]
        yaml_order = [item[id_field] for item in yaml_doc.get(key, [])]
        if json_order != yaml_order:
            return False, f"{key} order differs between JSON and YAML"
    return True, ""


def _parsed_exports(world: World) -> tuple[dict | None, dict | None]:
    """Return (json_doc, yaml_doc), parsing the raw exports when needed."""
    json_doc = getattr(world, "stpa_parsed_json", None)
    yaml_doc = getattr(world, "stpa_parsed_yaml", None)
    if json_doc is None or yaml_doc is None:
        json_doc = json.loads(getattr(world, "stpa_json_export", "null"))
        yaml_doc = yaml.safe_load(getattr(world, "stpa_yaml_export", ""))
    return json_doc, yaml_doc


def _h_parsing_standard_reader_only(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: parsing either export needs only a standard reader."""
    json_doc, yaml_doc = _parsed_exports(world)
    if json_doc is None or yaml_doc is None:
        return False, "Exports were not produced"
    if not _is_plain_data(json_doc) or not _is_plain_data(yaml_doc):
        return False, "Exports contain non-standard data shapes"
    return True, ""


def _h_parsed_exports_same_rules(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Then: validating either parsed export applies the same typed rules."""
    json_doc, yaml_doc = _parsed_exports(world)
    if json_doc is None or yaml_doc is None:
        return False, "Exports were not produced"
    json_result = validate_projection_traceability(json_doc)
    yaml_result = validate_projection_traceability(yaml_doc)
    if json_result.valid != yaml_result.valid:
        return False, "Parsed exports disagree on traceability validity"
    if not json_result.valid:
        return False, "Parsed exports fail traceability validation"
    if canonical_violations_json(json_result) != canonical_violations_json(yaml_result):
        return False, "Parsed exports apply different typed traceability rules"
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

    # --- Stream B Slice 3: projection traceability validation ---
    api.register_first(
        r"STPA projection traceability is validated( twice)?$",
        _h_traceability_validated,
    )
    api.register(
        r"STPA projection traceability is (valid|invalid)$", _h_traceability_validity
    )
    api.register(
        r"the traceability result has no violations", _h_traceability_no_violations
    )
    api.register(
        r'the traceability result contains violation code "([^"]+)"$',
        _h_traceability_violation_code,
    )
    api.register_first(
        r"the violation identifies the (earliest affected projection element|"
        r"temporal vector candidate identifier)$",
        _h_violation_identifies,
    )
    api.register(
        r'the projection candidate identifier is "([^"]+)"$', _h_projection_candidate_id
    )
    api.register(
        r'assertion sources are ordered "([^"]+)"$', _h_assertion_sources_ordered
    )
    api.register(
        r'factor scenario steps are ordered "([^"]+)"$', _h_factor_steps_ordered
    )
    api.register(
        r'the final scenario step references control action "([^"]+)"$',
        _h_final_step_references,
    )
    api.register(
        r"every temporal assertion has its canonical predicate and source provenance",
        _h_assertions_canonical,
    )
    api.register(
        r'the temporal projection is mutated by "([^"]+)"$',
        _h_mutate_temporal_projection,
    )
    api.register(
        r'the temporal vector candidate identifier is changed to "([^"]+)"$',
        _h_change_candidate_id,
    )
    api.register(r"the temporal vector contains no assertions", _h_vector_no_assertions)
    api.register(r"the temporal vector contains no scenario steps", _h_vector_no_steps)
    api.register(
        r"the traceability result has no invented causal-factor provenance",
        _h_no_invented_provenance,
    )
    api.register(r"both traceability results have the same validity", _h_same_validity)
    api.register(
        r"both traceability results have byte-identical canonical violations",
        _h_byte_identical_violations,
    )

    # --- Stream B Slice 4: Stage 6 prompt alignment tables ---
    api.register(
        r"the STPA Stage 6 prompts are rendered from the validated projection",
        _h_render_stage6_prompts,
    )
    api.register(
        r"the STPA (narrative|attack-tree|Gherkin) prompts are rendered "
        r"from the validated projection$",
        _h_render_stage6_call,
    )
    api.register(
        r"every narrative, tree, and Gherkin Stage 6 prompt contains a "
        r"projection alignment table",
        _h_every_prompt_has_table,
    )
    api.register(r'the table has columns "([^"]+)"$', _h_table_columns)
    api.register(
        r"the table has exactly one row for each temporal assertion and "
        r"final UCA step",
        _h_table_row_count,
    )
    api.register(
        r"the table rows preserve causal-factor order and place the UCA row last",
        _h_table_rows_ordered,
    )
    api.register(r'the table contains "([^"]+)"$', _h_table_contains)
    api.register_first(
        r'the table contains candidate identifier "([^"]+)"$',
        _h_table_contains_candidate,
    )
    api.register(
        r"the prompts identify projection IDs as semantic structural IDs "
        r"rather than positional labels",
        _h_semantic_ids_not_positional,
    )
    api.register(
        r"the narrative prompt requires (\S+) before (\S+) before (\S+)$",
        _h_narrative_order,
    )
    api.register(
        r'the narrative prompt requires the exact UCA type "([^"]+)"$',
        _h_narrative_exact_uca,
    )
    api.register(
        r"the narrative prompt forbids inventing a causal factor, assertion, "
        r"or scenario step",
        _h_narrative_forbids_inventing,
    )
    api.register(
        r"the narrative prompt preserves the distinction between (\S+) as a "
        r"logical feedback dependency and an inferred transport$",
        _h_narrative_fb_distinction,
    )
    api.register(r'the attack-tree prompt requires root "([^"]+)"$', _h_tree_root)
    api.register(
        r"the attack-tree prompt requires known structural references (.+)$",
        _h_tree_structural_refs,
    )
    api.register(
        r"the attack-tree prompt requires any temporal-factor leaf references "
        r"to preserve projection order",
        _h_tree_leaf_order,
    )
    api.register(
        r"the attack-tree prompt forbids an infrastructure or session mechanism "
        r"without explicit attacker-accessible evidence",
        _h_tree_infra_evidence,
    )
    api.register(
        r"the Gherkin prompt requires a Given reference to (\S+)$", _h_gherkin_given_pm
    )
    api.register(
        r'the Gherkin prompt requires the exact ICA type "([^"]+)" and '
        r'control action "([^"]+)" in the actual outcome$',
        _h_gherkin_actual_outcome,
    )
    api.register(
        r"the Gherkin prompt forbids structural IDs not present in the "
        r"validated projection or control structure",
        _h_gherkin_forbids_ids,
    )
    api.register(
        r"the Gherkin prompt retains independent valid Loss ID validation",
        _h_gherkin_loss_ids,
    )
    api.register(
        r"the STPA alignment table is derived twice", _h_derive_alignment_twice
    )
    api.register(
        r"both alignment tables are byte-identical", _h_alignment_byte_identical
    )
    api.register_first(
        r"each assertion row source and predicate equals the causal-factor "
        r"validator mapping",
        _h_assertion_rows_match_mapping,
    )
    api.register_first(
        r"each factor step row source and step kind equals the causal-factor "
        r"validator mapping",
        _h_step_rows_match_mapping,
    )
    api.register(
        r'the final row is the unsafe-control-action step for "([^"]+)"$',
        _h_final_row_uca,
    )
    api.register(
        r"no alignment row is hand-authored independently by a Stage 6 prompt",
        _h_no_hand_authored_rows,
    )

    # --- Stream B Slice 5: canonical standalone export ---
    api.register_first(
        r"the STPA execution projection is exported as canonical JSON$",
        _h_export_json,
    )
    api.register(
        r"the STPA execution projection is exported as canonical JSON and YAML",
        _h_export_both,
    )
    api.register(
        r'both exports declare schema version "([^"]+)"$', _h_export_schema_version
    )
    api.register(
        r'both exports identify (?:candidate|UCA reference) "([^"]+)"$',
        _h_export_identifies,
    )
    api.register(
        r"parsing both exports with only standard JSON and YAML readers "
        r"yields equivalent data",
        _h_export_equivalent,
    )
    api.register(
        r"parsing either export does not require project imports",
        _h_export_no_imports,
    )
    api.register(
        r'the export contains (assertion|step) IDs "([^"]+)" in order$',
        _h_export_ids_in_order,
    )
    api.register(
        r'(assertion|step) "([^"]+)" has typed provenance source kind '
        r'"([^"]+)" and source ID "([^"]+)"$',
        _h_export_typed_provenance,
    )
    api.register(
        r'every exported structural reference is one of "([^"]+)"$',
        _h_export_structural_refs,
    )
    api.register(r"canonical JSON and YAML exports are produced twice", _h_export_twice)
    api.register(r"the two JSON exports are byte-identical", _h_json_byte_identical)
    api.register(r"the two YAML exports are byte-identical", _h_yaml_byte_identical)
    api.register(r"JSON object keys use canonical ordering", _h_json_keys_canonical)
    api.register(
        r"YAML list ordering preserves assertions and steps without sorting "
        r"by source text",
        _h_yaml_list_order,
    )
    api.register(
        r'the canonical JSON export is mutated by "([^"]+)"$', _h_mutate_json_export
    )
    api.register(
        r"the exported projection is loaded and validated without project imports",
        _h_export_loaded_validated,
    )
    api.register(
        r'exported projection validation fails with "([^"]+)"$', _h_export_fails
    )

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
        r'the Stage 5 evidence declares causal factors "([^"]+)"',
        _h_stage5_evidence_declares_factors,
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
        r"no Stage 6 narrative, attack-tree, or Gherkin call is made for "
        r"the invalid ScenarioSpec",
        _h_no_stage6_calls_for_invalid,
    )
    api.register(
        r"no projection artifact is written for the invalid scenario",
        _h_no_projection_artifact_invalid,
    )
    api.register(
        r"project_execution is applied to the ScenarioSpec and control "
        r"structure twice",
        _h_project_execution_twice,
    )
    api.register(
        r"both candidate execution envelopes are byte-equivalent",
        _h_envelopes_byte_equivalent,
    )
    api.register(
        r'the envelope candidate identifier is "([^"]+)"',
        _h_envelope_candidate_identifier,
    )
    api.register(
        r'the envelope causal factors are "([^"]+)" in declared order',
        _h_envelope_factor_ids,
    )
    api.register(
        r"the envelope contains no causal factor or temporal behavior not "
        r"declared by Stage 5",
        _h_envelope_no_undeclared_behavior,
    )
    api.register(
        r"the production STPA run derives the projection and writes artifacts",
        _h_derive_projection_and_write,
    )
    api.register(
        r"the ScenarioSpec has a present causal_factors field containing "
        r"an empty list",
        _h_spec_factors_present_empty,
    )
    api.register(
        r"the projection has present causal_factors, assertions, and steps "
        r"fields containing empty lists",
        _h_projection_vectors_present_empty,
    )
    api.register(
        r"the temporal action vector has no assertions and no steps",
        _h_vector_no_assertions_no_steps,
    )
    api.register(
        r"no behavior is invented from .+ being present in the control structure",
        _h_no_behavior_invented,
    )
    api.register(
        r"the validated Stage 5 factor set contains (.+)",
        _h_validated_factor_set_follows,
    )
    api.register(
        r"Stage 6 derives one projection alignment from that validated projection",
        _h_stage6_derives_one_alignment,
    )
    api.register(
        r"the narrative, attack-tree, and Gherkin calls each receive the "
        r"same alignment table",
        _h_calls_receive_same_table,
    )
    api.register(
        r"the table has one row for ([A-Z0-9-]+), one row for "
        r"([A-Z0-9-]+), and one final row for ([A-Z0-9-]+)",
        _h_table_rows_specific,
    )
    api.register(
        r"the rows preserve declared factor order and place the "
        r"unsafe-control-action row last",
        _h_rows_preserve_order_uca_last,
    )
    api.register(
        r"every Stage 6 prompt forbids inventing causal factors, assertions, "
        r"or steps",
        _h_every_stage6_prompt_forbids_inventing,
    )
    api.register(
        r"the prompt references semantic structural IDs rather than positional labels",
        _h_prompt_semantic_ids,
    )
    api.register(
        r"Stage 5 returns one evidence-backed (process-model|feedback-delay|"
        r"actuator-anomaly) factor at ([A-Z0-9-]+)",
        _h_stage5_one_evidence_factor,
    )
    api.register(
        r"the production STPA run completes the scenario", _h_run_completes_scenario
    )
    api.register(
        r"the scenario directory contains the legacy scenario YAML and "
        r"Gherkin feature",
        _h_dir_contains_legacy,
    )
    api.register(
        r"the scenario directory contains canonical JSON and YAML projection "
        r"artifacts",
        _h_dir_contains_canonical,
    )
    api.register(
        r'each canonical projection artifact declares schema version "([^"]+)"',
        _h_canonical_schema_version,
    )
    api.register(
        r'the canonical projection artifacts identify ICA "([^"]+)" and '
        r'scenario "([^"]+)" separately',
        _h_canonical_identifies_ica_scenario,
    )
    api.register(
        r"parsing either canonical projection artifact with a standard reader "
        r"does not require project imports",
        _h_canonical_standard_reader,
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
    api.register(
        r'a valid canonical STPA projection with candidate "([^"]+)"',
        _h_valid_canonical_projection,
    )
    api.register(r'its UCA reference is "([^"]+)"', _h_its_uca_reference)
    api.register(
        r'the canonical projection is missing the "([^"]+)" key',
        _h_projection_missing_key,
    )
    api.register(r"traceability is (valid|invalid)$", _h_traceability_plain_validity)
    api.register(
        r'the result contains typed violation code "([^"]+)"', _h_typed_violation_code
    )
    api.register(
        r'the violation identifies projection element "([^"]+)"',
        _h_violation_identifies_element,
    )
    api.register(
        r"the canonical projection explicitly contains causal_factors, "
        r"assertions, and steps as empty lists",
        _h_projection_explicit_empty_vectors,
    )
    api.register(r"the result contains no violations", _h_result_contains_no_violations)
    api.register(
        r"no causal-factor, assertion, or step provenance is invented",
        _h_no_provenance_invented,
    )
    api.register(
        r'the valid canonical projection is mutated by changing "([^"]+)" to "([^"]+)"',
        _h_valid_projection_mutated,
    )
    api.register(
        r"validation identifies the earliest affected projection element",
        _h_validation_earliest_element,
    )
    api.register(
        r'the projection carries ICA ID "([^"]+)" and scenario ID "([^"]+)"',
        _h_projection_carries_identities,
    )
    api.register(
        r"the projection is exported as canonical JSON and YAML",
        _h_projection_exported_both,
    )
    api.register(
        r"both exports are parsed with standard readers", _h_exports_parsed_standard
    )
    api.register(
        r'both exports retain candidate "([^"]+)"', _h_exports_retain_candidate
    )
    api.register(
        r'both exports contain ICA ID "([^"]+)" in its own field',
        _h_exports_contain_ica_id,
    )
    api.register(
        r'both exports contain scenario ID "([^"]+)" in its own field',
        _h_exports_contain_scenario_id,
    )
    api.register(
        r'changing "([^"]+)" does not change structural candidate ID',
        _h_identity_change_keeps_candidate,
    )
    api.register(
        r"the projection contains two causal factors in declared order",
        _h_projection_two_factors_ordered,
    )
    api.register(
        r"canonical JSON and YAML are produced twice", _h_canonical_produced_twice
    )
    api.register(
        r"the repeated JSON and YAML outputs are each byte-identical",
        _h_repeated_outputs_byte_identical,
    )
    api.register(
        r"JSON and YAML preserve causal-factor, assertion, and step order",
        _h_exports_preserve_order,
    )
    api.register(
        r"parsing either export requires only a standard JSON or YAML reader",
        _h_parsing_standard_reader_only,
    )
    api.register(
        r"validating either parsed export applies the same typed traceability rules",
        _h_parsed_exports_same_rules,
    )
