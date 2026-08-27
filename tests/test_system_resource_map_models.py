"""Focused unit tests for SystemResourceMap data contracts and serialization."""

from __future__ import annotations

import json

import yaml

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


def test_system_resource_map_json_is_sorted_and_deterministic() -> None:
    srm = _make_sample_map()
    json_text = srm.to_json()

    parsed = json.loads(json_text)
    top_keys = list(parsed)
    assert top_keys == sorted(top_keys)
    # Keys are emitted in sorted order, so re-dumping the parsed payload is
    # byte-identical: no serialization detail depends on field order.
    assert json.dumps(parsed, indent=2, sort_keys=True) + "\n" == json_text


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


def test_system_resource_map_yaml_is_block_style_with_sorted_keys() -> None:
    srm = _make_sample_map()
    text = srm.to_yaml()

    parsed = yaml.safe_load(text)
    top_keys = list(parsed)
    assert top_keys == sorted(top_keys)
    # Keys are emitted in sorted order: sorting them again is a no-op, so
    # re-serializing from a dict built in sorted order must be identical.
    assert yaml.dump(
        parsed, default_flow_style=False, sort_keys=False, allow_unicode=True,
        default_style='"',
    ) == text
    # Block sequences remain blocks, not inline flow style.
    assert "\n- " in text or text.startswith("- ")
    assert "[]" not in text


def test_system_resource_map_yaml_preserves_unicode_line_separator() -> None:
    # PyYAML's plain/single-quoted styles silently corrupt U+0085 (NEL):
    # the reader treats it as a line break, so a naive dump round trip
    # loses characters. The double-quoted dumper style escapes it.
    srm = _make_sample_map()
    srm.data_flows[0].name = "flow\x85name"

    restored = SystemResourceMap.from_yaml(srm.to_yaml())
    assert restored.data_flows[0].name == "flow\x85name"
    assert restored == srm


def test_system_resource_map_yaml_keeps_unicode_unescaped() -> None:
    # allow_unicode=True keeps non-ASCII readable instead of \\u-escaping it.
    srm = _make_sample_map()
    srm.data_flows[0].name = "café"

    text = srm.to_yaml()
    assert "café" in text
    assert SystemResourceMap.from_yaml(text) == srm


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
