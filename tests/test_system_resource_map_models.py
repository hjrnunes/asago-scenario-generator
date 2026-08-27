"""Focused unit tests for SystemResourceMap data contracts and serialization."""

from __future__ import annotations

from asago_scenario_generator.models.system_resource_map import (
    ActorControllerEntry,
    ControlActionEntry,
    ControlledProcessEntry,
    DataFlowEntry,
    FeedbackPathEntry,
    LossLinkEntry,
    ResourceAssertionEntry,
    SystemResourceEntry,
    SystemResourceMap,
    TrustBoundaryEntry,
    UseCaseFactEntry,
)


def _make_sample_map() -> SystemResourceMap:
    return SystemResourceMap(
        schema_version="1",
        stpa_version="stpa-v1",
        taxonomy_version="atlas-2026.05",
        system_resources=[
            SystemResourceEntry(
                element_id="SR-1",
                name="Primary Database",
                description="Database hosting user records",
                taxonomy_ref="ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
        ],
        actor_controllers=[
            ActorControllerEntry(
                element_id="RESP-1",
                name="Agent Controller",
                description="Controller handling agent decisions",
            )
        ],
        controlled_processes=[
            ControlledProcessEntry(
                element_id="CP-2",
                name="Payment Pipeline",
                description="Process executing transactions",
            )
        ],
        control_actions=[
            ControlActionEntry(
                element_id="CA-1-1",
                controller_id="RESP-1",
                process_id="CP-2",
                action_name="Authorize Payment",
            )
        ],
        feedback_paths=[
            FeedbackPathEntry(
                element_id="FB-1-1",
                controller_id="RESP-1",
                process_id="CP-2",
                feedback_name="Payment Status Confirmation",
            )
        ],
        trust_boundaries=[
            TrustBoundaryEntry(
                element_id="TB-1",
                name="Boundary 1",
                resource_ids=["SR-1"],
                taxonomy_ref="tb:v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            )
        ],
        data_flows=[
            DataFlowEntry(
                element_id="DF-1",
                name="Flow 1",
                source_resource_id="SR-1",
                target_resource_id="SR-1",
            )
        ],
        loss_links=[
            LossLinkEntry(
                element_id="LL-1",
                loss_id="L-1",
                hazard_id="H-1",
            )
        ],
        use_case_facts=[
            UseCaseFactEntry(
                element_id="UF-1",
                fact_key="auth.token_validation",
                resolution_status="unknown",
                provenance_kind="analyst",
            ),
            UseCaseFactEntry(
                element_id="UF-2",
                fact_key="storage.encryption_at_rest",
                resolution_status="absent",
                provenance_kind="imported-source",
            ),
        ],
        assertions=[
            ResourceAssertionEntry(
                element_id="A-1",
                description="Analyst assertion 1",
                provenance_kind="analyst",
            )
        ],
    )


def test_system_resource_map_construction() -> None:
    srm = _make_sample_map()
    assert srm.schema_version == "1"
    assert srm.stpa_version == "stpa-v1"
    assert srm.taxonomy_version == "atlas-2026.05"
    assert len(srm.system_resources) == 1
    assert len(srm.control_actions) == 1


def test_system_resource_map_yaml_round_trip() -> None:
    srm = _make_sample_map()
    yaml_text = srm.to_yaml()
    assert "schema_version" in yaml_text
    assert "SR-1" in yaml_text
    restored = SystemResourceMap.from_yaml(yaml_text)
    assert restored.schema_version == srm.schema_version
    assert restored.stpa_version == srm.stpa_version
    assert restored.taxonomy_version == srm.taxonomy_version
    assert len(restored.control_actions) == len(srm.control_actions)
    assert restored.control_actions[0].element_id == srm.control_actions[0].element_id
    assert restored.use_case_facts[0].resolution_status == "unknown"
    assert restored.use_case_facts[1].resolution_status == "absent"


def test_system_resource_map_json_round_trip() -> None:
    srm = _make_sample_map()
    json_text = srm.to_json()
    assert "schema_version" in json_text
    assert "SR-1" in json_text
    restored = SystemResourceMap.from_json(json_text)
    assert restored.schema_version == srm.schema_version
    assert restored.stpa_version == srm.stpa_version
    assert restored.taxonomy_version == srm.taxonomy_version
    assert len(restored.control_actions) == len(srm.control_actions)
    assert restored.control_actions[0].element_id == srm.control_actions[0].element_id


def test_system_resource_map_byte_stability() -> None:
    srm = _make_sample_map()
    y1 = srm.to_yaml()
    y2 = srm.to_yaml()
    assert y1 == y2
    j1 = srm.to_json()
    j2 = srm.to_json()
    assert j1 == j2


def test_system_resource_map_family_access() -> None:
    srm = _make_sample_map()
    ca = srm.get_family("control-action")
    assert len(ca) == 1
    assert ca[0]["element_id"] == "CA-1-1"
    tb = srm.get_family("trust-boundary")
    assert len(tb) == 1
    assert tb[0]["element_id"] == "TB-1"
