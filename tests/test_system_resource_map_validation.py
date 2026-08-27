"""Focused unit tests for SystemResourceMap validation rules."""

from __future__ import annotations

from asago_scenario_generator.models.system_resource_map import (
    ActorControllerEntry,
    ControlActionEntry,
    ControlledProcessEntry,
    DataFlowEntry,
    FeedbackPathEntry,
    LossLinkEntry,
    ResourceAssertionEntry,
    ResourceMapSnapshot,
    SystemResourceEntry,
    SystemResourceMap,
    TrustBoundaryEntry,
    UseCaseFactEntry,
)
from asago_scenario_generator.pipeline.system_resource_map import validate_resource_map


def _make_snapshot() -> ResourceMapSnapshot:
    return ResourceMapSnapshot(
        schema_version="1",
        stpa_version="stpa-v1",
        taxonomy_version="atlas-2026.05",
        stpa_identifiers=["RESP-1", "CP-2", "CA-1-1", "FB-1-1", "L-1", "H-1"],
        taxonomy_identifiers=[
            "ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "tb:v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ],
    )


def _make_valid_map() -> SystemResourceMap:
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
            )
        ],
        assertions=[
            ResourceAssertionEntry(
                element_id="A-1",
                description="Analyst assertion 1",
                provenance_kind="analyst",
            )
        ],
    )


def test_representative_map_validation_succeeds() -> None:
    snap = _make_snapshot()
    srm = _make_valid_map()
    res = validate_resource_map(srm, snap)
    assert res.is_valid
    assert len(res.errors) == 0
    assert len(res.correspondence_relations) == 0
    assert res.network_calls == 0
    assert res.model_calls == 0


def test_reject_duplicate_identifier() -> None:
    snap = _make_snapshot()
    srm = _make_valid_map()
    srm.system_resources.append(
        SystemResourceEntry(
            element_id="SR-1",
            name="Duplicate DB",
            description="Duplicate identifier",
        )
    )
    res = validate_resource_map(srm, snap)
    assert not res.is_valid
    err = next((e for e in res.errors if e.code == "duplicate_identifier"), None)
    assert err is not None
    assert err.element_id == "SR-1"


def test_reject_unstable_identifier() -> None:
    snap = _make_snapshot()
    srm = _make_valid_map()
    srm.system_resources.append(
        SystemResourceEntry(
            element_id="idx-0",
            name="Unstable ID entry",
            description="Positional index identifier",
        )
    )
    res = validate_resource_map(srm, snap)
    assert not res.is_valid
    err = next((e for e in res.errors if e.code == "unstable_identifier"), None)
    assert err is not None
    assert err.element_id == "idx-0"


def test_reject_dangling_reference() -> None:
    snap = _make_snapshot()
    srm = _make_valid_map()
    srm.control_actions[0].controller_id = "RESP-99"
    res = validate_resource_map(srm, snap)
    assert not res.is_valid
    err = next((e for e in res.errors if e.code == "dangling_reference"), None)
    assert err is not None
    assert err.element_id == "RESP-99"


def test_reject_source_version_mismatch() -> None:
    snap = _make_snapshot()
    srm = _make_valid_map()
    srm.stpa_version = "stpa-v9"
    res = validate_resource_map(srm, snap)
    assert not res.is_valid
    err = next((e for e in res.errors if e.code == "source_version_mismatch"), None)
    assert err is not None


def test_reject_invalid_control_action_link() -> None:
    snap = _make_snapshot()
    srm = _make_valid_map()
    srm.control_actions[0].controller_id = ""
    res = validate_resource_map(srm, snap)
    assert not res.is_valid
    err = next((e for e in res.errors if e.code == "invalid_control_action_link"), None)
    assert err is not None
    assert err.element_id == "CA-1-1"


def test_reject_unknown_resource_link() -> None:
    snap = _make_snapshot()
    srm = _make_valid_map()
    srm.data_flows[0].source_resource_id = "SR-99"
    res = validate_resource_map(srm, snap)
    assert not res.is_valid
    err = next((e for e in res.errors if e.code == "unknown_resource_link"), None)
    assert err is not None
    assert err.element_id == "DF-1"


def test_reject_unknown_loss_link() -> None:
    snap = _make_snapshot()
    srm = _make_valid_map()
    srm.loss_links[0].loss_id = "L-99"
    res = validate_resource_map(srm, snap)
    assert not res.is_valid
    err = next((e for e in res.errors if e.code == "unknown_loss_link"), None)
    assert err is not None
    assert err.element_id == "L-99"


def test_reject_ambiguous_alias() -> None:
    snap = _make_snapshot()
    srm = _make_valid_map()
    srm.aliases["payment-backend"] = ["CP-2", "CP-4"]
    res = validate_resource_map(srm, snap)
    assert not res.is_valid
    err = next((e for e in res.errors if e.code == "ambiguous_alias"), None)
    assert err is not None
    assert err.element_id == "payment-backend"


def test_missing_optional_provenance_is_warning() -> None:
    snap = _make_snapshot()
    srm = _make_valid_map()
    srm.assertions.append(
        ResourceAssertionEntry(
            element_id="A-3",
            description="Assertion missing provenance",
            provenance_kind=None,
        )
    )
    res = validate_resource_map(srm, snap)
    assert res.is_valid
    assert len(res.errors) == 0
    warn = next((w for w in res.warnings if w.code == "missing_optional_provenance"), None)
    assert warn is not None
    assert warn.element_id == "A-3"
