"""Acceptance step handlers for the STPA execution projection features.

Implements ``features/stpa_execution_projection_production_wiring.feature``
(STPA-PROD-WIRING-01, -02, and -04): Stage 5 declared evidence-backed
causal factors validated against the control structure, and fail-closed
empty successful output.

Step handlers use regex-based parameter extraction and keep the scenario
state on the per-example world.
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
from asago_scenario_generator.stpa.models.causal_factor import CausalFactorKind
from asago_scenario_generator.stpa.models.enriched_threat_set import StructuralThreat
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.models.scenario_spec import (
    AttackerBDI,
    ScenarioSpec,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.wire import (
    BDIGenerationResult,
    CausalFactorDeclaration,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.assemble import (
    assemble_scenario_spec,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.defender import (
    populate_defender_bdi,
)

_KIND_BY_LABEL = {
    "process-model flaw": CausalFactorKind.process_model_flaw,
    "feedback delay": CausalFactorKind.feedback_delay,
    "sensor anomaly": CausalFactorKind.sensor_anomaly,
    "actuator anomaly": CausalFactorKind.actuator_anomaly,
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


def _context(world: World) -> tuple[str, str, UCAType] | None:
    """Return the (controller, control action, UCA type) context, if set."""
    controller_id = getattr(world, "stpa_controller", None)
    control_action_id = getattr(world, "stpa_control_action", None)
    uca_type = getattr(world, "stpa_uca_type", None)
    if controller_id is None or control_action_id is None or uca_type is None:
        return None
    return controller_id, control_action_id, uca_type


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


# ---------------------------------------------------------------------------#
# STPA-TRACEABILITY: projection traceability and identity contract
# ---------------------------------------------------------------------------#


FEATURE_ID = "stpa"


def register(api: object) -> None:
    """Register the STPA execution projection handlers globally."""
    api.set_feature(None)

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

    # --- STPA-TRACEABILITY 01-05: traceability and identity contract ---
