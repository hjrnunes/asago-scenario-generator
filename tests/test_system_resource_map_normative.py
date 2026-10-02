"""Normative Phase 2 tests for the typed system-resource-map seam."""

from __future__ import annotations


import pytest


from asago_scenario_generator.models.system_resource_map import (
    CAReference,
    CLReference,
    CMReference,
    CPReference,
    FBReference,
    PMReference,
    RESPReference,
    ResourceLink,
    ResourceMapViolation,
    SystemResourceMap,
    SystemResourceMapValidation,
    compute_control_structure_digest,
    compute_resource_map_semantic_digest,
)
from asago_scenario_generator.pipeline.system_resource_map import (
    _violation_sort_key,
    validate_system_resource_map,
)
from asago_scenario_generator.pipeline.projection_contracts import (
    capture_capability_snapshot,
)
from asago_scenario_generator.models.capability_profile import CapabilityProfile
from asago_scenario_generator.stpa.models.control_structure import (
    CoordinationLink,
    CoordinationMechanism,
)
from tests.system_resource_map_support import (
    ENTRY_POINT as EP,
    TOOL,
    make_control_structure as _control_structure,
    make_link as _link,
    make_map as _map,
    make_snapshot as _snapshot,
)



def test_normative_map_is_closed_immutable_and_round_trips_yaml() -> None:
    resource_map = _map()
    assert resource_map.schema_version == "system-resource-map-v1"
    assert resource_map.links[0].control_structure_ref.kind == "CA"
    with pytest.raises(Exception):
        resource_map.links += (resource_map.links[0],)  # type: ignore[misc]
    with pytest.raises(Exception):
        SystemResourceMap.model_validate(
            {**resource_map.model_dump(), "unexpected": True}
        )
    restored = SystemResourceMap.from_yaml(resource_map.to_yaml())
    assert restored == resource_map
    assert resource_map.to_yaml() == restored.to_yaml()


def test_valid_map_uses_the_three_typed_pins_and_returns_no_violations() -> None:
    snapshot = _snapshot()
    control = _control_structure()
    result = validate_system_resource_map(_map(), snapshot, control)
    assert isinstance(result, SystemResourceMapValidation)
    assert result.is_valid
    assert result.violations == ()
    assert result.network_calls == 0
    assert result.model_calls == 0


def test_control_digest_ignores_security_constraint_reference_order() -> None:
    payload = _control_structure().model_dump(mode="python")
    payload["responsibilities"][0]["security_constraint_refs"] = ["SC-2", "SC-1"]
    forward = type(_control_structure()).model_validate(payload)
    payload["responsibilities"][0]["security_constraint_refs"].reverse()
    reverse = type(_control_structure()).model_validate(payload)

    assert compute_control_structure_digest(
        forward
    ) == compute_control_structure_digest(reverse)


@pytest.mark.parametrize(
    ("field", "expected_code"),
    [
        ("capability_snapshot_digest", "capability_snapshot_digest_mismatch"),
        ("control_structure_digest", "control_structure_digest_mismatch"),
    ],
)
def test_digest_pin_substitution_is_reported(field: str, expected_code: str) -> None:
    resource_map = _map()
    snapshot = _snapshot()
    control = _control_structure()
    changed = resource_map.model_copy(update={field: "f" * 64})
    # update bypasses after validators, as a persisted tamper/load does.
    result = validate_system_resource_map(changed, snapshot, control)
    assert not result.is_valid
    assert expected_code in {item.code for item in result.violations}


def test_unknown_capability_and_control_namespaces_are_typed_violations() -> None:
    snapshot = _snapshot()
    control = _control_structure()
    unknown_capability = _map(
        _link(
            capability_resource_ref={"kind": "tool", "tool_id": "tool:v1:" + "f" * 32}
        )
    )
    result = validate_system_resource_map(unknown_capability, snapshot, control)
    assert "unknown_capability_resource" in {item.code for item in result.violations}
    with pytest.raises(Exception):
        _link(control_structure_ref={"kind": "CA", "id": "CP-1"})
    unknown_control = _map(_link(control_structure_ref={"kind": "CA", "id": "CA-9-9"}))
    result = validate_system_resource_map(unknown_control, snapshot, control)
    assert "unknown_control_structure_reference" in {
        item.code for item in result.violations
    }


def test_relation_compatibility_and_authority_rules_fail_closed() -> None:
    snapshot = _snapshot()
    control = _control_structure()
    incompatible = _map(
        _link(
            relation_kind="coordinates_via",
            control_structure_ref={"kind": "CA", "id": "CA-1-1"},
            capability_resource_ref={"kind": "entry_point", "entry_point_id": EP},
        )
    )
    result = validate_system_resource_map(incompatible, snapshot, control)
    assert "incompatible_relation_kind" in {item.code for item in result.violations}
    model_authoritative = _map(_link(provenance="model_proposed"))
    result = validate_system_resource_map(model_authoritative, snapshot, control)
    assert "model_proposed_authoritative" in {item.code for item in result.violations}
    no_evidence = _map(_link(evidence_refs=()))
    result = validate_system_resource_map(no_evidence, snapshot, control)
    assert "authoritative_link_without_evidence" in {
        item.code for item in result.violations
    }


def test_relation_validation_rejects_one_invalid_endpoint_even_when_other_is_valid() -> (
    None
):
    resource_map = _map(
        _link(
            relation_kind="crosses",
            control_structure_ref={"kind": "CA", "id": "CA-1-1"},
            capability_resource_ref={"kind": "tool", "tool_id": TOOL},
        )
    )
    result = validate_system_resource_map(
        resource_map, _snapshot(), _control_structure()
    )
    assert "incompatible_relation_kind" in {item.code for item in result.violations}


def test_duplicate_semantic_links_and_declared_cardinality_are_rejected() -> None:
    duplicate = _map(_link(link_id="srm:v1:2"), _link(link_id="srm:v1:1"))
    result = validate_system_resource_map(duplicate, _snapshot(), _control_structure())
    codes = {item.code for item in result.violations}
    assert "duplicate_semantic_link" in codes
    conflicting = _map(
        _link(
            link_id="srm:v1:2",
            capability_resource_ref={"kind": "entry_point", "entry_point_id": EP},
            relation_kind="represents",
            control_structure_ref={"kind": "CP", "id": "CP-1"},
        ),
        _link(
            link_id="srm:v1:3",
            capability_resource_ref={"kind": "tool", "tool_id": TOOL},
            relation_kind="represents",
            control_structure_ref={"kind": "CP", "id": "CP-1"},
        ),
    )
    result = validate_system_resource_map(
        conflicting, _snapshot(), _control_structure()
    )
    assert "contradictory_authoritative_link" in {
        item.code for item in result.violations
    }


def test_one_authoritative_cardinality_target_is_valid() -> None:
    resource_map = _map(
        _link(
            relation_kind="represents",
            control_structure_ref={"kind": "CP", "id": "CP-1"},
            capability_resource_ref={"kind": "tool", "tool_id": TOOL},
        )
    )
    result = validate_system_resource_map(
        resource_map, _snapshot(), _control_structure()
    )
    assert result.is_valid


def test_model_proposed_advisory_and_incomplete_inventory_remain_observable() -> None:
    resource_map = _map(
        _link(
            provenance="model_proposed", authority_status="advisory", evidence_refs=()
        )
    )
    result = validate_system_resource_map(
        resource_map, _snapshot(), _control_structure()
    )
    assert result.is_valid
    assert result.links_by_authority["advisory"] == ("srm:v1:1",)
    assert result.unresolved == ()


def test_control_structure_reference_union_covers_all_closed_namespaces() -> None:
    references = (
        RESPReference(resp_id="RESP-1"),
        PMReference(pm_id="PM-1-1"),
        CAReference(ca_id="CA-1-1"),
        FBReference(fb_id="FB-1-1"),
        CPReference(cp_id="CP-1"),
        CLReference(link_id="CL-1"),
        CMReference(cm_id="CM-1"),
    )
    assert [(reference.kind, reference.id) for reference in references] == [
        ("RESP", "RESP-1"),
        ("PM", "PM-1-1"),
        ("CA", "CA-1-1"),
        ("FB", "FB-1-1"),
        ("CP", "CP-1"),
        ("CL", "CL-1"),
        ("CM", "CM-1"),
    ]
    assert references[2].ca_id == "CA-1-1"


def test_output_surface_and_coordination_mechanism_links_are_admitted() -> None:
    profile = CapabilityProfile.model_validate(
        {
            "zones_active": ["input", "reasoning", "tool_execution"],
            "entry_points": [
                {
                    "name": "Customer input",
                    "entry_point_type": "user_input",
                    "direction": "bidirectional",
                    "controllability": "direct",
                }
            ],
            "confidence": "high",
            "kc_subcodes": ["KC1.1", "KC5.3"],
            "tool_inventory": [
                {"name": "Payment API", "description": "Mutates payments"}
            ],
        }
    )
    snapshot = capture_capability_snapshot(profile)
    control = _control_structure()
    control.coordination_links.append(
        CoordinationLink(
            link_id="CL-1",
            source="RESP-1",
            target="RESP-1",
            shared_pm="PM-1-1",
            coordination_mechanism=CoordinationMechanism(
                cm_id="CM-1",
                description="Synchronize payment state",
                payload="payment-state",
            ),
            description="Payment coordination",
        )
    )
    output_id = profile.entry_points[0].entry_point_id
    links = (
        ResourceLink(
            link_id="srm:v1:output",
            capability_resource_ref={
                "kind": "output_surface",
                "entry_point_id": output_id,
            },
            control_structure_ref={"kind": "CP", "id": "CP-1"},
            relation_kind="emits_to",
            provenance="deterministically_derived",
            evidence_refs=("projection:output",),
            confidence=1.0,
            authority_status="authoritative",
        ),
        ResourceLink(
            link_id="srm:v1:coordination",
            capability_resource_ref={"kind": "agent_internal"},
            control_structure_ref={"kind": "CM", "id": "CM-1"},
            relation_kind="coordinates_via",
            provenance="operator_declared",
            evidence_refs=("review:coordination",),
            confidence=0.8,
            authority_status="authoritative",
        ),
    )
    digest = compute_resource_map_semantic_digest(
        schema_version="system-resource-map-v1",
        capability_snapshot_digest=snapshot.snapshot_digest,
        control_structure_digest=compute_control_structure_digest(control),
        links=links,
    )
    resource_map = SystemResourceMap(
        schema_version="system-resource-map-v1",
        semantic_digest=digest,
        capability_snapshot_digest=snapshot.snapshot_digest,
        control_structure_digest=compute_control_structure_digest(control),
        links=links,
    )
    result = validate_system_resource_map(resource_map, snapshot, control)
    assert result.is_valid


def test_canonical_order_is_independent_of_input_order() -> None:
    first = _map(
        _link(link_id="srm:v1:2", control_structure_ref={"kind": "CA", "id": "CA-1-1"}),
        _link(
            link_id="srm:v1:1", control_structure_ref={"kind": "RESP", "id": "RESP-1"}
        ),
    )
    second = _map(
        _link(
            link_id="srm:v1:1", control_structure_ref={"kind": "RESP", "id": "RESP-1"}
        ),
        _link(link_id="srm:v1:2", control_structure_ref={"kind": "CA", "id": "CA-1-1"}),
    )
    assert first == second
    assert first.to_yaml() == second.to_yaml()


def test_diagnostic_sort_key_handles_present_and_absent_optional_parts() -> None:
    present = ResourceMapViolation(
        code="z-code", message="detail", link_id="srm:v1:1", field="links"
    )
    absent = ResourceMapViolation(code="a-code", message="detail")
    assert _violation_sort_key(present) == ("srm:v1:1", "z-code", "links")
    assert _violation_sort_key(absent) == ("", "a-code", "")




