"""Model-level tests for the normative system-resource-map contract."""

from __future__ import annotations

import json

import pytest
import yaml
from pydantic import ValidationError

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
)
from tests.system_resource_map_support import (
    make_link,
    make_map,
)


def test_system_resource_map_is_closed_immutable_and_content_addressed() -> None:
    resource_map = make_map()

    assert set(resource_map.model_dump(mode="json")) == {
        "schema_version",
        "semantic_digest",
        "capability_snapshot_digest",
        "control_structure_digest",
        "links",
    }
    assert resource_map.schema_version == "system-resource-map-v1"

    with pytest.raises((TypeError, ValidationError)):
        resource_map.links += (resource_map.links[0],)  # type: ignore[misc]
    with pytest.raises(ValidationError):
        SystemResourceMap.model_validate(
            {**resource_map.model_dump(mode="json"), "unexpected": True}
        )
    with pytest.raises(ValidationError):
        ResourceMapViolation.model_validate({"code": "x", "message": "y", "extra": 1})


def test_resource_link_has_closed_typed_references_and_evidence_set() -> None:
    link = make_link(evidence_refs=("review:z", "review:a"))
    assert link.evidence_refs == ("review:a", "review:z")
    assert link.capability_resource_ref.kind == "tool"
    assert link.control_structure_ref.kind == "CA"

    with pytest.raises(ValidationError):
        ResourceLink.model_validate(
            {
                **link.model_dump(mode="json"),
                "unexpected": True,
            }
        )
    with pytest.raises(ValidationError):
        make_link(evidence_refs=("review:1", "review:1"))
    with pytest.raises(ValidationError):
        make_link(control_structure_ref={"kind": "CA", "id": "CP-1"})


def test_all_control_structure_reference_namespaces_are_closed_and_canonical() -> None:
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
    assert references[5].link_id == "CL-1"


def test_yaml_and_json_round_trips_are_byte_stable() -> None:
    resource_map = make_map()

    yaml_text = resource_map.to_yaml()
    json_text = resource_map.to_json()
    assert SystemResourceMap.from_yaml(yaml_text) == resource_map
    assert SystemResourceMap.from_json(json_text) == resource_map
    assert yaml_text == resource_map.to_yaml()
    assert json_text == resource_map.to_json()
    assert '\n- "authority_status"' in yaml_text

    parsed_json = json.loads(json_text)
    assert list(parsed_json) == sorted(parsed_json)
    assert json.dumps(
        parsed_json, indent=2, sort_keys=True, ensure_ascii=False
    ) + "\n" == (json_text)
    parsed_yaml = yaml.safe_load(yaml_text)
    assert list(parsed_yaml) == sorted(parsed_yaml)


def test_link_order_does_not_change_map_identity_or_serialization() -> None:
    first = make_link(
        link_id="srm:v1:2",
        control_structure_ref={"kind": "CA", "id": "CA-1-1"},
    )
    second = make_link(
        link_id="srm:v1:1",
        control_structure_ref={"kind": "RESP", "id": "RESP-1"},
        relation_kind="represents",
    )

    map_a = make_map(first, second)
    map_b = make_map(second, first)
    assert map_a == map_b
    assert map_a.to_yaml() == map_b.to_yaml()
    assert map_a.compute_semantic_digest() == map_b.compute_semantic_digest()


def test_digest_tampering_is_rejected_on_load() -> None:
    resource_map = make_map()
    payload = yaml.safe_load(resource_map.to_yaml())
    payload["semantic_digest"] = "f" * 64

    with pytest.raises(ValueError, match="semantic_digest|Digest mismatch"):
        SystemResourceMap.from_yaml(yaml.safe_dump(payload))
