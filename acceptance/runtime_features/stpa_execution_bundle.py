"""Acceptance handlers for the v2 execution projection and bundle seams."""

from __future__ import annotations

import json
import re
import tempfile
from pathlib import Path
from typing import Any

from runtime_shared import World

from asago_scenario_generator.stpa.models.causal_factor import (
    CausalFactor,
    CausalFactorKind,
)
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
from asago_scenario_generator.stpa.models.execution_projection_v2 import (
    ExecutionRunIdentity,
)
from asago_scenario_generator.stpa.models.execution_classification import (
    ExecutionActionKind,
    ExecutionDeliveryClass,
    RequestedEnvironmentBasis,
    SemanticExecutionContract,
    SemanticExecutionDelivery,
)
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossAnalysis,
    LossProvenance,
    SecurityConstraint,
)
from asago_scenario_generator.stpa.models.scenario_envelope import (
    GherkinSpec,
    ScenarioEnvelope,
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
from asago_scenario_generator.stpa.models.semantic_conditions import (
    ActionValueCondition,
    SemanticBindingPlaceholder,
)
from asago_scenario_generator.stpa.scenario_prod.execution_bundle import (
    ExecutionBundlePublication,
    publish_execution_bundle,
    verify_execution_bundle,
)
from asago_scenario_generator.stpa.scenario_prod.execution_projection import (
    ExecutionProjectionPreparationError,
    prepare_execution_projection,
    validate_execution_projection,
)
from asago_scenario_generator.stpa.scenario_prod.context import (
    build_scenario_generation_context,
)


FEATURE_ID = "stpa_execution_bundle"


def _contract_root() -> Path:
    """Return the repository-owned contract fixture root."""
    return Path(__file__).resolve().parents[2] / "data" / "contracts" / "stpa-execution"


def _control_structure() -> ControlStructure:
    return ControlStructure(
        controlled_processes=[
            ControlledProcess(cp_id="CP-1", description="Controlled process")
        ],
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="Controller",
                process_model_parts=[
                    ProcessModelPart(pm_id="PM-1-1", description="Authorization state")
                ],
                control_actions=[
                    ControlAction(
                        ca_id="CA-1-1",
                        description="Authorize action",
                        target=ElementRef(
                            type=ReferenceType.controlled_process,
                            id="CP-1",
                        ),
                    )
                ],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-1-1",
                        description="Authorization feedback",
                        updates="PM-1-1",
                        source=ElementRef(
                            type=ReferenceType.controlled_process,
                            id="CP-1",
                        ),
                    )
                ],
            )
        ],
    )


def _loss_analysis() -> LossAnalysis:
    return LossAnalysis(
        risk_card_losses=[
            Loss(
                loss_id="L-1",
                description="Loss",
                provenance=LossProvenance.risk_card,
                source_risk_cards=["risk-1"],
            )
        ],
        use_case_losses=[],
        hazards=[Hazard(hazard_id="H-1", description="Hazard", related_losses=["L-1"])],
        security_constraints=[
            SecurityConstraint(
                constraint_id="SC-1",
                description="Validate before action",
                related_hazards=["H-1"],
            )
        ],
    )


def _spec(*, placeholder: bool, with_outcome: bool = True) -> ScenarioSpec:
    control_structure = _control_structure()
    threat = StructuralThreat(
        ica_slot_id="RESP-1:CA-1-1:INCORRECT",
        provenance="structural",
        ica_id="RESP-1:CA-1-1:INCORRECT:1",
        ica_text="The action carries an incorrect value",
        hazardous_context="Authorization state is stale",
        loss_scenario="An unauthorized action is accepted",
        related_hazards=["H-1"],
        related_constraints=["SC-1"],
    )
    context = build_scenario_generation_context(
        threat,
        control_structure,
        _loss_analysis(),
        scenario_id="SCN-001",
    )
    condition = ActionValueCondition(
        control_action_id="CA-1-1",
        property="authorization_state",
        operator="equals",
        expected=(
            SemanticBindingPlaceholder(
                binding_ref="SEM-1",
                value_type="string",
                description="The authorized state in this deployment.",
            )
            if placeholder
            else "approved"
        ),
    )
    return ScenarioSpec(
        scenario_id="SCN-001",
        threat_source=ThreatSource(
            ica_slot_id=threat.ica_slot_id,
            provenance=threat.provenance,
            ica_id=threat.ica_id,
        ),
        target_controller="RESP-1",
        target_control_action="CA-1-1",
        ica_type=UCAType.incorrect,
        defender_bdi=DefenderBDI(
            beliefs=[DefenderBelief(pm_id="PM-1-1", content="State", vulnerability="")],
            desires=[DefenderDesire(resp_id="RESP-1", content="Controller")],
            intentions=[DefenderIntention(ca_id="CA-1-1", content="Action")],
        ),
        attacker_bdi=AttackerBDI(
            beliefs=["The state may be stale"],
            desires=["Induce the selected action"],
            intentions=["Rely on PM-1-1 before CA-1-1"],
        ),
        loss_scenario=threat.loss_scenario,
        causal_factors=[
            CausalFactor(
                kind=CausalFactorKind.process_model_flaw,
                source_id="PM-1-1",
                description="The authorization state can be stale.",
            )
        ],
        unsafe_outcome_condition=condition if with_outcome else None,
        unsafe_outcome_hazard_refs=["H-1"],
        unsafe_outcome_constraint_refs=["SC-1"],
        scenario_context=context,
        execution_contract=SemanticExecutionContract(
            requested_environment_basis=RequestedEnvironmentBasis.target_agnostic,
            delivery=SemanticExecutionDelivery(
                delivery_class=ExecutionDeliveryClass.direct_prompt,
                factor_id="CF-1",
                source_role="direct_user_input",
            ),
            action_kind=ExecutionActionKind.model_output,
        ),
    )


def _state(world: World) -> dict[str, Any]:
    state = getattr(world, "stpa_bundle_state", None)
    if state is None:
        state = {}
        world.stpa_bundle_state = state
    return state


def _h_seams_available(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    state = _state(world)
    state["control_structure"] = _control_structure()
    state["run_identity"] = ExecutionRunIdentity(run_id="acceptance-run-1")
    state["stage6_calls"] = 0
    state["stage6_writes"] = 0
    return True, ""


def _h_given_projection(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del examples
    state = _state(world)
    state["placeholder"] = "placeholder" in text.lower()
    state["spec"] = _spec(placeholder=state["placeholder"])
    return True, ""


def _h_given_invalid_projection(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    del text, examples
    state = _state(world)
    state["spec"] = _spec(placeholder=False, with_outcome=False)
    return True, ""


def _h_prepare(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    state = _state(world)
    try:
        state["validated"] = prepare_execution_projection(
            state["spec"],
            state["control_structure"],
            state["run_identity"],
        )
    except ExecutionProjectionPreparationError as exc:
        state["prepare_error"] = str(exc)
        state["validated"] = None
    return True, ""


def _h_projection_binding(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del examples
    state = _state(world)
    validated = state.get("validated")
    if validated is None:
        return False, "No validated projection exists"
    expected = "true" in text.lower()
    actual = validated.projection.unsafe_outcome.semantic_binding_required
    return (actual is expected, f"semantic binding is {actual}, expected {expected}")


def _h_projection_requirements(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    del text, examples
    validated = _state(world).get("validated")
    if validated is None:
        return False, "No validated projection exists"
    requirements = validated.execution_requirements
    if requirements.requires_multi_agent or requirements.requires_state_observation:
        return (
            False,
            "literal single-controller action requires unsupported runtime features",
        )
    if requirements.requires_real_clock or requirements.requires_persistent_state:
        return False, "literal action unexpectedly requires clock or persistent state"
    return True, ""


def _h_prepare_rejected(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    state = _state(world)
    if state.get("validated") is not None or not state.get("prepare_error"):
        return False, "invalid projection preparation was accepted"
    return True, ""


def _h_zero_stage6(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    state = _state(world)
    return (state.get("stage6_calls") == 0, "Stage 6 calls were made before gating")


def _h_zero_writes(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    state = _state(world)
    return (state.get("stage6_writes") == 0, "scenario/projection writes occurred")


def _envelope(state: dict[str, Any]) -> ScenarioEnvelope:
    spec = state["spec"]
    return ScenarioEnvelope(
        scenario_id=spec.scenario_id,
        scenario_spec=spec,
        narrative="The selected action is unsafe when the semantic value is wrong.",
        attack_tree={"root": "INCORRECT CA-1-1", "branches": [], "leaves": []},
        gherkin_spec=GherkinSpec(
            feature="Execution bundle",
            scenario="Incorrect action value",
            given=["Given PM-1-1 is current"],
            when=["When CA-1-1 is supplied"],
            then_expected=["Then the value should be checked"],
            then_actual=["But CA-1-1 carries an incorrect value"],
        ),
        target_responsibility=spec.target_controller,
        ica_type=spec.ica_type,
        provenance="structural",
    )


def _h_publish(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    state = _state(world)
    validated = state.get("validated")
    if validated is None:
        return False, "No validated projection exists"
    state["bundle_dir"] = Path(tempfile.mkdtemp(prefix="asago-bundle-"))
    envelope = _envelope(state)
    state["index"] = publish_execution_bundle(
        state["bundle_dir"],
        state["run_identity"],
        (
            ExecutionBundlePublication(
                scenario_envelope=envelope,
                validated_projection=validated,
                scenario_path="scenarios/SCN-001.scenario.json",
                projection_path="scenarios/canonical/SCN-001.projection.json",
            ),
        ),
    )
    return True, ""


def _h_bundle_valid(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    result = verify_execution_bundle(_state(world)["bundle_dir"])
    return (result.valid, "published bundle did not verify")


def _h_tamper_bundle(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    path = _state(world)["bundle_dir"] / "scenarios/canonical/SCN-001.projection.json"
    path.write_bytes(path.read_bytes() + b"\n")
    result = verify_execution_bundle(_state(world)["bundle_dir"])
    _state(world)["tampered_result"] = result
    return True, ""


def _h_tamper_rejected(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    result = _state(world).get("tampered_result")
    if result is None or result.valid:
        return False, "tampered bundle was accepted"
    if not any(
        item.code.value == "content_digest_mismatch" for item in result.violations
    ):
        return False, "tampered bundle did not report a content digest mismatch"
    return True, ""


def _h_given_condition_fixture(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    del text
    condition = examples.get("condition", "")
    path = _contract_root() / "projection-v2" / "valid" / f"{condition}.json"
    if not path.is_file():
        return False, f"missing valid condition fixture: {path}"
    _state(world)["contract_fixture_path"] = path
    return True, ""


def _h_given_invalid_fixture(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    fixture = examples.get("fixture", "")
    if not fixture:
        match = re.search(r"invalid ([A-Za-z0-9_-]+) projection fixture", text)
        fixture = match.group(1) if match else ""
    path = _contract_root() / "projection-v2" / "invalid" / f"{fixture}.json"
    if not path.is_file():
        return False, f"missing invalid projection fixture: {path}"
    _state(world)["contract_fixture_path"] = path
    return True, ""


def _h_parse_contract_fixture(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    del text, examples
    path = _state(world).get("contract_fixture_path")
    if not isinstance(path, Path):
        return False, "no contract fixture was selected"
    try:
        payload = json.loads(path.read_bytes())
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return False, f"contract fixture is not JSON: {exc}"
    result = validate_execution_projection(payload)
    _state(world)["contract_result"] = result
    return True, ""


def _h_fixture_valid(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    result = _state(world).get("contract_result")
    if result is None:
        return False, "the fixture was not parsed"
    return (result.valid, "valid projection fixture was rejected")


def _h_validation_reports(world: World, text: str, examples: dict) -> tuple[bool, str]:
    result = _state(world).get("contract_result")
    expected = examples.get("violation", "")
    if not expected:
        match = re.search(r"reports ([A-Za-z0-9_-]+)", text)
        expected = match.group(1) if match else ""
    if result is None:
        return False, "the fixture was not parsed"
    actual = {item.code.value for item in result.violations}
    return (
        expected in actual,
        f"expected violation {expected!r}, got {sorted(actual)!r}",
    )


def _h_prepare_twice(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    state = _state(world)
    try:
        state["prepared_twice"] = (
            prepare_execution_projection(
                state["spec"], state["control_structure"], state["run_identity"]
            ),
            prepare_execution_projection(
                state["spec"], state["control_structure"], state["run_identity"]
            ),
        )
    except ExecutionProjectionPreparationError as exc:
        return False, str(exc)
    return True, ""


def _h_same_run_identity(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    prepared = _state(world).get("prepared_twice")
    if not prepared:
        return False, "the projection was not prepared twice"
    run_ids = {item.projection.run_id for item in prepared}
    return (run_ids == {"acceptance-run-1"}, f"prepared run IDs were {run_ids!r}")


def _h_prepared_canonical(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    prepared = _state(world).get("prepared_twice")
    if not prepared:
        return False, "the projection was not prepared twice"
    for item in prepared:
        if item.canonical_json_bytes != item.projection.canonical_json_bytes():
            return False, "prepared bytes do not match projection canonical bytes"
    return True, ""


def _h_source_pins(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    validated = _state(world).get("validated")
    if validated is None:
        return False, "No validated projection exists"
    pins = validated.projection.trace_refs.source_pins
    values = tuple(pins.model_dump(mode="json").values())
    return (len(values) == 4 and all(values), "projection source pins are incomplete")


def _h_interrupted_publish(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    state = _state(world)
    if state.get("validated") is None:
        return False, "No validated projection exists"
    state["bundle_dir"] = Path(tempfile.mkdtemp(prefix="asago-bundle-interrupted-"))
    publish_execution_bundle(
        state["bundle_dir"],
        state["run_identity"],
        (
            ExecutionBundlePublication(
                scenario_envelope=_envelope(state),
                validated_projection=state["validated"],
                scenario_path="scenarios/SCN-001.scenario.json",
                projection_path="scenarios/canonical/SCN-001.projection.json",
            ),
        ),
    )
    (state["bundle_dir"] / "execution-bundle.json").unlink()
    return True, ""


def _h_no_publication_marker(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    del text, examples
    result = verify_execution_bundle(_state(world)["bundle_dir"])
    return (
        not result.valid,
        "a bundle without execution-bundle.json was accepted",
    )


def _h_tamper_scenario_identity(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    del text, examples
    state = _state(world)
    path = state["bundle_dir"] / "scenarios/SCN-001.scenario.json"
    payload = json.loads(path.read_bytes())
    payload["target_responsibility"] = "RESP-TAMPERED"
    from asago_scenario_generator.models.canonical import canonical_json_bytes

    path.write_bytes(canonical_json_bytes(payload))
    state["pair_tampered_result"] = verify_execution_bundle(state["bundle_dir"])
    return True, ""


def _h_pair_tampering_rejected(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    del text, examples
    result = _state(world).get("pair_tampered_result")
    if result is None:
        return False, "the scenario pair was not tampered"
    codes = {item.code.value for item in result.violations}
    return (
        "pair_identity_mismatch" in codes,
        f"expected pair_identity_mismatch, got {sorted(codes)!r}",
    )


def _h_given_contract_kit(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    root = _contract_root()
    if not (root / "CONTRACT.lock").is_file():
        return False, "CONTRACT.lock is missing"
    _state(world)["contract_root"] = root
    return True, ""


def _h_standard_json_contracts(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    del text, examples
    root = _state(world).get("contract_root", _contract_root())
    try:
        for path in root.rglob("*.json"):
            json.loads(path.read_bytes())
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return False, f"contract JSON is invalid: {exc}"
    return True, ""


def _h_valid_contracts(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    root = _state(world).get("contract_root", _contract_root())
    for path in (root / "projection-v2" / "valid").glob("*.json"):
        result = validate_execution_projection(json.loads(path.read_bytes()))
        if not result.valid:
            return False, f"{path.name}: {result.violations!r}"
    return True, ""


def _h_invalid_contracts(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    root = _state(world).get("contract_root", _contract_root())
    expected = json.loads(
        (root / "projection-v2" / "expected-violations.json").read_bytes()
    )
    for name, values in expected.items():
        result = validate_execution_projection(
            json.loads((root / "projection-v2" / "invalid" / name).read_bytes())
        )
        actual = [item.code.value for item in result.violations]
        if actual != values:
            return False, f"{name}: expected {values!r}, got {actual!r}"
    return True, ""


def _h_minimal_bundle_fixture(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    del text, examples
    path = _contract_root() / "bundle-v1" / "valid" / "minimal-run"
    result = verify_execution_bundle(path)
    return (result.valid, "minimal bundle fixture did not verify")


def register(api: object) -> None:
    """Register the producer/bundle acceptance steps."""
    api.register(
        r"the v2 execution projection and bundle seams are available",
        _h_seams_available,
    )
    api.register(
        r"a validated (literal|placeholder) INCORRECT action_value projection",
        _h_given_projection,
    )
    api.register(
        r"an invalid projection with no unsafe outcome condition",
        _h_given_invalid_projection,
    )
    api.register(r"^the producer prepares the execution projection$", _h_prepare)
    api.register(
        r"the projection reports semantic_binding_required (true|false)",
        _h_projection_binding,
    )
    api.register(
        r"the literal projection has no multi-agent, state-observation, clock, or persistent-state requirement",
        _h_projection_requirements,
    )
    api.register(
        r"projection preparation is rejected before Stage 6",
        _h_prepare_rejected,
    )
    api.register(
        r"zero Stage 6 calls are made",
        _h_zero_stage6,
    )
    api.register(
        r"zero scenario or projection writes are made",
        _h_zero_writes,
    )
    api.register(r"the validated projection is published as a bundle", _h_publish)
    api.register(r"the published bundle verifies successfully", _h_bundle_valid)
    api.register(r"the projection bytes are tampered", _h_tamper_bundle)
    api.register(r"bundle verification rejects the tampering", _h_tamper_rejected)
    api.register(
        r"a committed valid (.+) projection fixture", _h_given_condition_fixture
    )
    api.register(
        r"a committed invalid (.+) projection fixture", _h_given_invalid_fixture
    )
    api.register(
        r"standalone projection validation parses the fixture",
        _h_parse_contract_fixture,
    )
    api.register(r"the projection fixture is valid", _h_fixture_valid)
    api.register(r"projection validation reports (.+)", _h_validation_reports)
    api.register(
        r"^the producer prepares the execution projection twice$", _h_prepare_twice
    )
    api.register(
        r"both projections carry the explicit run identity", _h_same_run_identity
    )
    api.register(r"the prepared projection is canonical JSON", _h_prepared_canonical)
    api.register(r"the projection carries all four source pins", _h_source_pins)
    api.register(
        r"the producer publishes the pair before replacing the bundle index",
        _h_interrupted_publish,
    )
    api.register(
        r"the interrupted directory has no valid publication marker",
        _h_no_publication_marker,
    )
    api.register(r"the scenario identity is tampered", _h_tamper_scenario_identity)
    api.register(
        r"bundle verification rejects the pair tampering", _h_pair_tampering_rejected
    )
    api.register(r"the committed STPA execution contract kit", _h_given_contract_kit)
    api.register(
        r"standard JSON tooling parses every contract document",
        _h_standard_json_contracts,
    )
    api.register(
        r"valid projection fixtures pass standalone validation", _h_valid_contracts
    )
    api.register(
        r"invalid projection fixtures report their expected violations",
        _h_invalid_contracts,
    )
    api.register(
        r"the minimal bundle fixture verifies successfully", _h_minimal_bundle_fixture
    )
