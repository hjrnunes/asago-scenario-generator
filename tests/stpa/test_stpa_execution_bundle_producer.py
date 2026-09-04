"""Acceptance-first tests for the v2 producer public seam."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from asago_scenario_generator.stpa.models.causal_factor import (
    CausalFactor,
    CausalFactorKind,
    CausalEvidenceStatus,
)
from asago_scenario_generator.stpa.models.enriched_threat_set import StructuralThreat
from asago_scenario_generator.stpa.models.execution_projection_v2 import (
    ExecutionCausalFactor,
    ExecutionProjectionV2,
    ExecutionRunIdentity,
)
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.models.scenario_spec import (
    AttackerBDI,
    DefenderBDI,
    DefenderBelief,
    DefenderDesire,
    DefenderIntention,
    ScenarioSpec,
    ThreatSource,
)
from asago_scenario_generator.stpa.models.scenario_envelope import (
    GherkinSpec,
    ScenarioEnvelope,
)
from asago_scenario_generator.stpa.models.control_structure import (
    ControlStructure,
    ControlledProcess,
    ElementRef,
    ReferenceType,
)
from asago_scenario_generator.stpa.scenario_prod.context import (
    build_scenario_generation_context,
)
from tests.stpa.helpers import make_minimal_loss_analysis
from asago_scenario_generator.stpa.models.semantic_conditions import (
    ActionValueCondition,
    DelayCondition,
    SemanticBindingPlaceholder,
    SemanticBindingValueType,
)
from asago_scenario_generator.stpa.models.execution_classification import (
    BindingCompleteness,
    EnvironmentBasis,
    ExecutionActionKind,
    ExecutionClassification,
    ExecutionClaimScope,
    ExecutionDeliveryClass,
    ExecutionProfileFit,
    ExecutionTargetProfile,
    InventoryCompleteness,
    ProfileAuthority,
    ProfileBasis,
    RequestedEnvironmentBasis,
    SemanticExecutionContract,
    SemanticExecutionDelivery,
)
from asago_scenario_generator.stpa.scenario_prod.execution_projection import (
    prepare_execution_projection,
    validate_execution_projection,
)
from asago_scenario_generator.stpa.scenario_prod.execution_bundle import (
    ExecutionBundlePublication,
    publish_execution_bundle,
    publish_execution_target_profile,
    verify_execution_bundle,
)
from asago_scenario_generator.stpa.scenario_prod import (
    execution_bundle as execution_bundle_module,
)
from asago_scenario_generator.stpa.scenario_prod.bdi_generation import (
    build_context_bdi_prompts,
)
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.scenario_prod._constants import PROMPTS_DIR
from tests.stpa.helpers import make_minimal_control_structure


CONTRACT_ROOT = Path(__file__).resolve().parents[2] / "data/contracts/stpa-execution"


def _control_structure() -> ControlStructure:
    base = make_minimal_control_structure()
    action = (
        base.responsibilities[0]
        .control_actions[0]
        .model_copy(
            update={
                "target": ElementRef(
                    type=ReferenceType.controlled_process,
                    id="CP-1",
                )
            }
        )
    )
    responsibility = base.responsibilities[0].model_copy(
        update={"control_actions": [action]}
    )
    return base.model_copy(
        update={
            "responsibilities": [responsibility],
            "controlled_processes": [
                ControlledProcess(cp_id="CP-1", description="Process")
            ],
        }
    )


def _spec(
    *,
    ica_type: UCAType = UCAType.wrong_timing,
    unsafe_outcome_condition=None,
) -> ScenarioSpec:
    control_structure = _control_structure()
    slot = f"RESP-1:CA-1-1:{ica_type.value}"
    threat = StructuralThreat(
        ica_slot_id=slot,
        provenance="structural",
        ica_id=f"{slot}:1",
        ica_text="Unsafe control action",
        hazardous_context="Context",
        loss_scenario="Loss scenario",
        related_hazards=["H-1"],
        related_constraints=["SC-1"],
    )
    context = build_scenario_generation_context(
        threat,
        control_structure,
        make_minimal_loss_analysis(),
        scenario_id="SCN-001",
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
        ica_type=ica_type,
        defender_bdi=DefenderBDI(
            beliefs=[DefenderBelief(pm_id="PM-1-1", content="State", vulnerability="")],
            desires=[DefenderDesire(resp_id="RESP-1", content="Controller")],
            intentions=[DefenderIntention(ca_id="CA-1-1", content="Action")],
        ),
        attacker_bdi=AttackerBDI(
            beliefs=["belief"], desires=["desire"], intentions=["intent"]
        ),
        loss_scenario="Loss scenario",
        causal_factors=[
            CausalFactor(
                kind=CausalFactorKind.feedback_delay,
                source_id="FB-1-1",
                description="Feedback is delayed.",
            )
        ],
        unsafe_outcome_condition=unsafe_outcome_condition
        or DelayCondition(
            reference_ref="FB-1-1",
            delay_ms=SemanticBindingPlaceholder(
                binding_ref="SEM-1",
                value_type="integer",
                description="Maximum supported feedback delay.",
                minimum=0,
            ),
        ),
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


def test_prepare_seam_returns_digest_bearing_projection_and_derives_binding() -> None:
    validated = prepare_execution_projection(
        _spec(),
        _control_structure(),
        ExecutionRunIdentity(run_id="run-1"),
    )

    assert validated.projection.semantic_digest == validated.semantic_digest
    assert validated.projection.unsafe_outcome.semantic_binding_required is True
    assert validated.projection.unsafe_outcome.condition.type == "delay"
    assert validated.projection.stimulus_requirements[0].factor_id == "CF-1"
    assert (
        validated.projection.stimulus_requirements[0].delivery_class.value
        == "direct_prompt"
    )
    assert validated.projection.stimulus_requirements[0].intent
    assert validated.projection.steps[-1].kind.value == "UNSAFE_CONTROL_ACTION"
    assert validate_execution_projection(
        validated.projection.model_dump(mode="json")
    ).valid


def test_projection_rejects_inconsistent_resource_free_classification() -> None:
    validated = prepare_execution_projection(
        _spec(),
        _control_structure(),
        ExecutionRunIdentity(run_id="run-classification"),
    )
    classification = ExecutionClassification(
        binding_completeness=BindingCompleteness.parameterized,
        environment_basis=EnvironmentBasis.target_agnostic,
        profile_fit=ExecutionProfileFit.needs_binding,
        claim_scope=ExecutionClaimScope.no_execution_claim,
    )
    payload = validated.projection.model_dump(mode="json", exclude={"semantic_digest"})
    payload["execution_classification"] = classification.model_dump(mode="json")

    validation = validate_execution_projection(
        payload | {"semantic_digest": validated.semantic_digest}
    )
    assert validation.valid is False
    assert validation.violations[0].code.value == "execution_classification_mismatch"

    with pytest.raises(ValueError, match="resource-free executable"):
        ExecutionProjectionV2.model_validate(payload)


def test_projection_rejects_bindings_on_analytical_classification() -> None:
    validated = prepare_execution_projection(
        _spec(),
        _control_structure(),
        ExecutionRunIdentity(run_id="run-analytical-classification"),
    )
    classification = ExecutionClassification(
        binding_completeness=BindingCompleteness.analytical_only,
        environment_basis=EnvironmentBasis.none,
        profile_fit=ExecutionProfileFit.invalid,
        claim_scope=ExecutionClaimScope.no_execution_claim,
        target_profile_digest="a" * 64,
    )
    payload = validated.projection.model_dump(mode="json", exclude={"semantic_digest"})
    payload["execution_contract"] = {
        **payload["execution_contract"],
        "disposition": "analytical_only",
        "requested_environment_basis": None,
        "delivery": None,
        "action_kind": None,
        "resource_requirements": [],
        "gaps": [
            {
                "code": "operation_missing",
                "detail": "No operation was established.",
                "evidence_refs": ["CF-1"],
            }
        ],
    }
    payload["execution_contract"].pop("semantic_digest")
    payload["execution_classification"] = classification.model_dump(mode="json")
    payload["stimulus_requirements"] = []

    with pytest.raises(ValueError, match="analytical_only classifications"):
        ExecutionProjectionV2.model_validate(payload)


def test_standalone_parser_requires_persisted_semantic_digest() -> None:
    validated = prepare_execution_projection(
        _spec(),
        _control_structure(),
        ExecutionRunIdentity(run_id="run-1"),
    )
    payload = validated.projection.model_dump(mode="json")
    del payload["semantic_digest"]

    result = validate_execution_projection(payload)

    assert result.valid is False
    assert result.violations[0].code.value == "required_field_missing"


def test_literal_incorrect_action_value_is_supported_without_runtime_requirements() -> (
    None
):
    validated = prepare_execution_projection(
        _spec(
            ica_type=UCAType.incorrect,
            unsafe_outcome_condition=ActionValueCondition(
                control_action_id="CA-1-1",
                property="authorization_state",
                operator="equals",
                expected="approved",
            ),
        ),
        _control_structure(),
        ExecutionRunIdentity(run_id="run-literal"),
    )

    requirements = validated.execution_requirements
    assert requirements.requires_multi_agent is False
    assert requirements.requires_state_observation is False
    assert requirements.requires_real_clock is False
    assert requirements.requires_persistent_state is False
    assert requirements.requires_multi_turn is False
    assert validated.projection.unsafe_outcome.semantic_binding_required is False
    assert validate_execution_projection(
        validated.projection.model_dump(mode="json")
    ).valid


def test_bundle_publication_is_canonical_index_last_and_tamper_evident(
    tmp_path,
    monkeypatch,
) -> None:
    spec = _spec(
        ica_type=UCAType.incorrect,
        unsafe_outcome_condition=ActionValueCondition(
            control_action_id="CA-1-1",
            property="authorization_state",
            operator="equals",
            expected="approved",
        ),
    )
    run_identity = ExecutionRunIdentity(run_id="run-bundle")
    validated = prepare_execution_projection(spec, _control_structure(), run_identity)
    envelope = ScenarioEnvelope(
        scenario_id=spec.scenario_id,
        scenario_spec=spec,
        narrative="The narrative retains the selected structural path.",
        attack_tree={"root": "INCORRECT CA-1-1", "branches": [], "leaves": []},
        gherkin_spec=GherkinSpec(
            feature="Execution",
            scenario="Incorrect action value",
            given=["Given authorization is known"],
            when=["When CA-1-1 is supplied"],
            then_expected=["Then the action should be checked"],
            then_actual=["But CA-1-1 uses an incorrect value"],
        ),
        target_responsibility=spec.target_controller,
        ica_type=spec.ica_type,
        provenance="structural",
    )
    publication = ExecutionBundlePublication(
        scenario_envelope=envelope,
        validated_projection=validated,
        scenario_path="scenarios/SCN-001.scenario.json",
        projection_path="scenarios/canonical/SCN-001.projection.json",
    )

    index = publish_execution_bundle(tmp_path, run_identity, (publication,))

    assert (tmp_path / "execution-bundle.json").is_file()
    assert (tmp_path / "execution-bundle.yaml").is_file()
    assert index.entries[0].validation.status == "valid"
    assert index.entries[0].validation.validator_version == (
        "stpa-execution-projection-v2"
    )
    assert verify_execution_bundle(tmp_path).valid is True

    prior_bytes = {
        path: path.read_bytes()
        for path in (
            tmp_path / "execution-bundle.json",
            tmp_path / "execution-bundle.yaml",
            tmp_path / "scenarios/SCN-001.scenario.json",
            tmp_path / "scenarios/canonical/SCN-001.projection.json",
        )
    }
    original_atomic_write = execution_bundle_module._atomic_write

    def fail_index_write(path, content):
        if path.name == "execution-bundle.json":
            for old_path in (
                tmp_path / "execution-bundle.json",
                tmp_path / "scenarios/SCN-001.scenario.json",
                tmp_path / "scenarios/canonical/SCN-001.projection.json",
            ):
                old_content = prior_bytes[old_path]
                assert old_path.read_bytes() == old_content
            raise OSError("injected completion-marker failure")
        original_atomic_write(path, content)

    monkeypatch.setattr(execution_bundle_module, "_atomic_write", fail_index_write)
    with pytest.raises(OSError, match="injected completion-marker failure"):
        publish_execution_bundle(tmp_path, run_identity, (publication,))

    assert verify_execution_bundle(tmp_path).valid is True
    for path, content in prior_bytes.items():
        assert path.read_bytes() == content

    projection_path = tmp_path / "scenarios/canonical/SCN-001.projection.json"
    projection_path.write_bytes(projection_path.read_bytes() + b"\n")
    tampered = verify_execution_bundle(tmp_path)
    assert tampered.valid is False
    assert any(
        item.code.value == "content_digest_mismatch" for item in tampered.violations
    )


def test_target_profile_publication_uses_canonical_shared_writer(tmp_path) -> None:
    profile = ExecutionTargetProfile(
        profile_id="target-profile-1",
        environment_id="target-1",
        basis=ProfileBasis.target,
        authority=ProfileAuthority.reviewed,
        inventory_completeness=InventoryCompleteness.reviewed_complete,
        evidence_refs=("review:target",),
    )

    path = publish_execution_target_profile(tmp_path, profile)

    assert path == tmp_path / "execution-target-profile.json"
    assert json.loads(path.read_text(encoding="utf-8")) == profile.model_dump(
        mode="json"
    )


def test_context_stage5_prompt_describes_constructible_typed_unsafe_condition() -> None:
    context = _spec().scenario_context
    assert context is not None
    system_prompt, user_prompt = build_context_bdi_prompts(
        context,
        TemplateLoader(PROMPTS_DIR),
    )

    assert "semantic_binding_required" not in system_prompt
    assert '"binding_ref": "SEM-outcome-value"' in system_prompt
    assert '"value_type": "integer"' in system_prompt
    assert '"minimum": 0' in system_prompt
    assert '"maximum": null' in system_prompt
    assert "must be exactly `CA-1-1`" in user_prompt


@pytest.mark.parametrize(
    "fixture",
    sorted((CONTRACT_ROOT / "projection-v2/valid").glob("*.json")),
    ids=lambda path: path.name,
)
def test_contract_valid_projection_fixtures_round_trip(fixture: Path) -> None:
    """Every producer-owned valid projection fixture passes standalone validation."""
    payload = json.loads(fixture.read_text(encoding="utf-8"))
    result = validate_execution_projection(payload)
    assert result.valid is True
    assert result.projection is not None
    digests = json.loads(
        (CONTRACT_ROOT / "projection-v2/canonical-digests.json").read_text(
            encoding="utf-8"
        )
    )
    relative = f"valid/{fixture.name}"
    assert payload["semantic_digest"] == digests["semantic_digests"][relative]


@pytest.mark.parametrize(
    "fixture",
    sorted((CONTRACT_ROOT / "projection-v2/invalid").glob("*.json")),
    ids=lambda path: path.name,
)
def test_contract_invalid_projection_fixtures_fail_with_expected_codes(
    fixture: Path,
) -> None:
    """Every invalid projection fixture retains its typed expected violation set."""
    payload = json.loads(fixture.read_text(encoding="utf-8"))
    result = validate_execution_projection(payload)
    expected = json.loads(
        (CONTRACT_ROOT / "projection-v2/expected-violations.json").read_text(
            encoding="utf-8"
        )
    )[fixture.name]
    assert result.valid is False
    assert [violation.code.value for violation in result.violations] == expected


@pytest.mark.parametrize(
    "fixture, expected_valid",
    [
        (CONTRACT_ROOT / "bundle-v1/valid/minimal-run", True),
        (CONTRACT_ROOT / "bundle-v1/invalid/hash-mismatch", False),
        (CONTRACT_ROOT / "bundle-v1/invalid/pair-mismatch", False),
    ],
    ids=["valid", "hash-mismatch", "pair-mismatch"],
)
def test_contract_bundle_fixtures_match_expected_verifier_results(
    fixture: Path,
    expected_valid: bool,
) -> None:
    """The committed bundle conformance fixtures exercise the standalone verifier."""
    result = verify_execution_bundle(fixture)
    expected = json.loads(
        (CONTRACT_ROOT / "bundle-v1/expected-violations.json").read_text(
            encoding="utf-8"
        )
    )
    key = "valid/minimal-run" if expected_valid else f"invalid/{fixture.name}"
    expected_codes = expected.get(key, [])
    assert result.valid is expected_valid
    assert [violation.code.value for violation in result.violations] == expected_codes


@pytest.mark.parametrize(
    "status, extra",
    [
        (CausalEvidenceStatus.structural_failure, {}),
        (
            CausalEvidenceStatus.reachable_capability,
            {"capability_refs": ("CAP-1",), "access_refs": ("ACCESS-1",)},
        ),
        (
            CausalEvidenceStatus.bounded_assumption,
            {"bounded_assumption": "review is pending"},
        ),
    ],
    ids=["structural", "reachable-capability", "bounded-assumption"],
)
def test_projection_factor_evidence_variants_are_typed(
    status: CausalEvidenceStatus,
    extra: dict,
) -> None:
    """Each closed causal-evidence basis can be represented without inference."""
    factor = ExecutionCausalFactor(
        factor_id="CF-1",
        order=1,
        kind=CausalFactorKind.process_model_flaw,
        structural_source_id="PM-1-1",
        description="evidence",
        evidence_status=status,
        **extra,
    )
    assert factor.evidence_status is status


@pytest.mark.parametrize(
    "value_type, minimum, maximum",
    [
        (SemanticBindingValueType.integer, 0, 10),
        (SemanticBindingValueType.number, 0, 1.5),
        (SemanticBindingValueType.string, None, None),
    ],
    ids=["integer", "number", "string"],
)
def test_placeholder_numeric_bounds_are_strict(
    value_type: SemanticBindingValueType,
    minimum: int | float | None,
    maximum: int | float | None,
) -> None:
    """Numeric placeholder bounds retain their declared type and ordering."""
    placeholder = SemanticBindingPlaceholder(
        binding_ref="SEM-BOUNDS",
        value_type=value_type,
        description="bound",
        minimum=minimum,
        maximum=maximum,
    )
    assert placeholder.minimum == minimum
    assert placeholder.maximum == maximum


@pytest.mark.parametrize(
    "value_type, minimum, maximum",
    [
        (SemanticBindingValueType.integer, 1.5, 3),
        (SemanticBindingValueType.number, -1, 3),
        (SemanticBindingValueType.string, 0, None),
        (SemanticBindingValueType.number, 5, 1),
    ],
    ids=["integer-float-bound", "negative-bound", "string-bound", "reversed"],
)
def test_placeholder_invalid_bounds_fail_closed(
    value_type: SemanticBindingValueType,
    minimum: int | float | None,
    maximum: int | float | None,
) -> None:
    """Malformed or unsafe placeholder bounds are rejected before publication."""
    with pytest.raises(ValueError):
        SemanticBindingPlaceholder(
            binding_ref="SEM-INVALID",
            value_type=value_type,
            description="bound",
            minimum=minimum,
            maximum=maximum,
        )
