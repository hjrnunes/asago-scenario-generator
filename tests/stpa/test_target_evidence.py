"""Target evidence block and evidence-binding checks."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlStructure,
    ControlledProcess,
    ElementRef,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
)
from asago_scenario_generator.stpa.models.execution_classification import (
    ExecutionTargetProfile,
    ProfileBasis,
)
from asago_scenario_generator.stpa.scenario_prod.target_observations import (
    TargetObservationSnapshot,
)
from asago_scenario_generator.stpa.system_model.target_evidence import (
    build_target_evidence,
    check_evidence_bindings,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "miniocciai-baseline-rev2"


def _profile() -> ExecutionTargetProfile:
    return ExecutionTargetProfile.model_validate(
        json.loads((FIXTURES / "execution-target-profile.json").read_text())
    )


def _snapshot() -> TargetObservationSnapshot:
    return TargetObservationSnapshot.model_validate(
        yaml.safe_load((FIXTURES / "target-observations.yaml").read_text())
    )


def _structure(*, operation: str | None, evidence_refs: list[str]) -> ControlStructure:
    return ControlStructure(
        controlled_processes=[ControlledProcess(cp_id="CP-1", description="Tools")],
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="Serve the session",
                process_model_parts=[
                    ProcessModelPart(
                        pm_id="PM-1-1",
                        description="Session principal",
                        values=["own", "other"],
                        evidence_refs=evidence_refs,
                    )
                ],
                control_actions=[
                    ControlAction(
                        ca_id="CA-1-1",
                        description="Fetch a referral",
                        target=ElementRef(
                            type=ReferenceType.controlled_process, id="CP-1"
                        ),
                        operation=operation,
                        process_model_refs=["PM-1-1"],
                    )
                ],
            )
        ],
    )


def test_evidence_projects_operations_session_and_keyed_collections() -> None:
    evidence = build_target_evidence(_profile(), _snapshot())

    assert evidence is not None
    assert "get_referral" in evidence.operation_names
    refs = evidence.refs()
    assert "operation:get_referral" in refs
    assert "argument:get_referral.patient_id" in refs
    assert "session:authenticated_patient_id" in refs
    assert "state:patients.patient_id" in refs
    resources = {item.name: item for item in evidence.resources}
    # A map of per-owner lists is a keyed collection: owner keys are record
    # addresses, never field names.
    assert "PAT-101" in resources["ehr_records"].record_keys
    assert not any(ref.startswith("state:ehr_records.PAT-") for ref in refs)


def test_simulation_profile_supplies_no_operation_evidence() -> None:
    profile = _profile().model_copy(update={"basis": ProfileBasis.simulation})

    evidence = build_target_evidence(profile, None)

    assert evidence is None


def test_bindings_keep_supported_refs_and_bind_observed_operation() -> None:
    evidence = build_target_evidence(_profile(), _snapshot())
    structure = _structure(
        operation="operation:get_referral",
        evidence_refs=["session:authenticated_patient_id"],
    )

    checked, warnings = check_evidence_bindings(structure, evidence)

    action = checked.responsibilities[0].control_actions[0]
    part = checked.responsibilities[0].process_model_parts[0]
    assert action.operation == "get_referral"
    assert part.evidence_refs == ["session:authenticated_patient_id"]
    assert len(warnings) == 1
    assert "without a control action" in warnings[0]
    assert "get_referral" not in warnings[0]


def test_bindings_drop_unsupported_refs_without_mutating_input() -> None:
    evidence = build_target_evidence(_profile(), _snapshot())
    structure = _structure(
        operation="delete_everything",
        evidence_refs=["session:authenticated_patient_id", "state:nowhere.field"],
    )

    checked, warnings = check_evidence_bindings(structure, evidence)

    action = checked.responsibilities[0].control_actions[0]
    part = checked.responsibilities[0].process_model_parts[0]
    assert action.operation is None
    assert part.evidence_refs == ["session:authenticated_patient_id"]
    assert any("state:nowhere.field" in item for item in warnings)
    assert any("delete_everything" in item for item in warnings)
    original = structure.responsibilities[0]
    assert original.control_actions[0].operation == "delete_everything"
    assert len(original.process_model_parts[0].evidence_refs) == 2


def test_bindings_without_evidence_drop_every_binding() -> None:
    structure = _structure(operation="get_referral", evidence_refs=["session:x"])

    checked, warnings = check_evidence_bindings(structure, None)

    assert checked.responsibilities[0].control_actions[0].operation is None
    assert checked.responsibilities[0].process_model_parts[0].evidence_refs == []
    assert len(warnings) == 2


def test_argument_types_come_from_the_type_or_its_alternatives() -> None:
    profile = _profile()
    tool = profile.inventory.tools[0]
    schema = {
        "properties": {
            "plain": {"type": "string"},
            "any_of": {"anyOf": [{"type": "string"}, {"type": "null"}, "bad"]},
            "one_of": {"oneOf": [{"type": "integer"}]},
            "untyped_options": {"anyOf": [{"title": "x"}]},
            "untyped": {"title": "y"},
            "not_a_schema": True,
        }
    }
    tools = [tool.model_copy(update={"input_schema": schema})]
    inventory = profile.inventory.model_copy(update={"tools": tools})
    profile = profile.model_copy(update={"inventory": inventory, "interpretations": []})

    evidence = build_target_evidence(profile, None)

    assert evidence is not None
    types = {arg.name: arg.type for arg in evidence.operations[0].arguments}
    assert types == {
        "any_of": "null|string",
        "not_a_schema": "unknown",
        "one_of": "integer",
        "plain": "string",
        "untyped": "unknown",
        "untyped_options": "unknown",
    }


def test_state_schema_separates_session_fields_and_resource_shapes() -> None:
    state = {
        "user": "PAT-1",
        "settings": {"mode": "strict", "limit": 3},
        "grouped": {"A": [{"id": 1}, "skip"], "B": [{"id": 2}]},
        "keyed": {"K-2": {"id": 2}, "K-1": {"id": 1}},
        "queue": [{"id": 1}, 2],
        "empty": {},
    }
    snapshot = _snapshot()
    observation = snapshot.observations[0].model_copy(
        update={"content": json.dumps(state)}
    )
    snapshot = snapshot.model_copy(update={"observations": [observation]})

    evidence = build_target_evidence(None, snapshot)

    assert evidence is not None
    assert [(item.name, item.value) for item in evidence.session_fields] == [
        ("user", "PAT-1")
    ]
    resources = {
        item.name: (item.record_count, item.record_keys, [f.name for f in item.fields])
        for item in evidence.resources
    }
    assert resources == {
        "empty": (1, (), []),
        "grouped": (2, ("A", "B"), ["id"]),
        "keyed": (2, ("K-1", "K-2"), ["id"]),
        "queue": (2, (), ["id"]),
        "settings": (1, (), ["limit", "mode"]),
    }
