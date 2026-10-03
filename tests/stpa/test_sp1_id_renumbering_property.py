"""Property tests for deterministic SP1 control-structure ID normalization.

These cover the high-level policy in ``id_normalization``:

- position-based IDs are deterministic for a given ordered structure
- unique source IDs map to those structural IDs
- typed and local references rewrite through that mapping
- a second pass is a no-op on already-canonical input
- a duplicated global source ID is omitted from rewrite maps
"""

from __future__ import annotations

from copy import deepcopy

import pytest
from hypothesis import HealthCheck, given, settings, strategies as st
from pydantic import ValidationError

from asago_scenario_generator.stpa.system_model.id_normalization import (
    normalize_control_structure_payload,
    validate_normalized_control_structure,
)

st_text = st.text(
    alphabet=st.characters(
        whitelist_categories=("Ll", "Lu", "Nd"),
        whitelist_characters=(" ", "-", "_"),
    ),
    min_size=1,
    max_size=24,
)


def _unique_ids(prefix: str, count: int) -> list[str]:
    """Return *count* distinct source IDs with a stable prefix."""
    return [f"{prefix}-{index}" for index in range(1, count + 1)]


def _responsibility(
    *,
    resp_id: str,
    description: str,
    rc_ids: list[str],
    pm_ids: list[str],
    ca_ids: list[str],
    fb_ids: list[str],
    target_id: str | None,
    source_id: str | None,
) -> dict:
    """Build one responsibility dict with local PM updates and typed refs."""
    process_model_parts = [
        {"pm_id": pm_id, "description": f"State {index}"}
        for index, pm_id in enumerate(pm_ids, start=1)
    ]
    control_actions = [
        {"ca_id": ca_id, "description": f"Action {index}"}
        for index, ca_id in enumerate(ca_ids, start=1)
    ]
    if control_actions and target_id is not None:
        control_actions[0]["target"] = {
            "type": "controlled_process",
            "id": target_id,
        }
    feedback_channels = [
        {
            "fb_id": fb_id,
            "description": f"Feedback {index}",
            "updates": pm_ids[index - 1] if index <= len(pm_ids) else "absent-pm",
        }
        for index, fb_id in enumerate(fb_ids, start=1)
    ]
    if feedback_channels and source_id is not None:
        feedback_channels[0]["source"] = {
            "type": "controlled_process",
            "id": source_id,
        }
    return {
        "resp_id": resp_id,
        "description": description,
        "responsibility_constraints": [
            {"rc_id": rc_id, "description": f"Constraint {index}"}
            for index, rc_id in enumerate(rc_ids, start=1)
        ],
        "process_model_parts": process_model_parts,
        "control_actions": control_actions,
        "feedback_channels": feedback_channels,
    }


def _payload(
    *,
    n_resps: int,
    n_children: int,
    n_cps: int,
    with_links: bool,
    id_prefix: str,
    descriptions: list[str],
) -> dict:
    """Build a well-formed payload whose source IDs are unique per namespace."""
    resp_ids = _unique_ids(f"{id_prefix}-resp", n_resps)
    cp_ids = _unique_ids(f"{id_prefix}-cp", n_cps)
    responsibilities = []
    pm_ids_by_resp: list[list[str]] = []
    for resp_index, resp_id in enumerate(resp_ids, start=1):
        pm_ids = _unique_ids(f"{id_prefix}-pm{resp_index}", n_children)
        pm_ids_by_resp.append(pm_ids)
        target_id = cp_ids[-1] if cp_ids else None
        source_id = cp_ids[0] if cp_ids else None
        responsibilities.append(
            _responsibility(
                resp_id=resp_id,
                description=descriptions[resp_index - 1],
                rc_ids=_unique_ids(f"{id_prefix}-rc{resp_index}", n_children),
                pm_ids=pm_ids,
                ca_ids=_unique_ids(f"{id_prefix}-ca{resp_index}", n_children),
                fb_ids=_unique_ids(f"{id_prefix}-fb{resp_index}", n_children),
                target_id=target_id,
                source_id=source_id,
            )
        )
    coordination_links = []
    if with_links and n_resps >= 2 and n_children >= 1:
        coordination_links.append(
            {
                "link_id": f"{id_prefix}-link-1",
                "source": resp_ids[0],
                "target": resp_ids[1],
                "shared_pm": pm_ids_by_resp[0][0],
                "coordination_mechanism": {
                    "cm_id": f"{id_prefix}-cm-1",
                    "description": "Shared state",
                    "payload": "state payload",
                },
                "description": "Coordinate controllers",
            }
        )
    return {
        "responsibilities": responsibilities,
        "controlled_processes": [
            {"cp_id": cp_id, "description": f"Process {index}"}
            for index, cp_id in enumerate(cp_ids, start=1)
        ],
        "coordination_links": coordination_links,
    }


def _canonical_ids(n_resps: int, n_children: int, n_cps: int, with_links: bool) -> dict:
    """Return the structural IDs implied by list positions."""
    return {
        "resp": [f"RESP-{index}" for index in range(1, n_resps + 1)],
        "rc": [
            f"RC-{resp}-{child}"
            for resp in range(1, n_resps + 1)
            for child in range(1, n_children + 1)
        ],
        "pm": [
            f"PM-{resp}-{child}"
            for resp in range(1, n_resps + 1)
            for child in range(1, n_children + 1)
        ],
        "ca": [
            f"CA-{resp}-{child}"
            for resp in range(1, n_resps + 1)
            for child in range(1, n_children + 1)
        ],
        "fb": [
            f"FB-{resp}-{child}"
            for resp in range(1, n_resps + 1)
            for child in range(1, n_children + 1)
        ],
        "cp": [f"CP-{index}" for index in range(1, n_cps + 1)],
        "cl": ["CL-1"] if with_links and n_resps >= 2 and n_children >= 1 else [],
        "cm": ["CM-1"] if with_links and n_resps >= 2 and n_children >= 1 else [],
    }


def _collected_ids(payload: dict) -> dict:
    """Collect published IDs from a normalized payload."""
    responsibilities = payload["responsibilities"]
    links = payload["coordination_links"]
    return {
        "resp": [resp["resp_id"] for resp in responsibilities],
        "rc": [
            rc["rc_id"]
            for resp in responsibilities
            for rc in resp["responsibility_constraints"]
        ],
        "pm": [
            pm["pm_id"]
            for resp in responsibilities
            for pm in resp["process_model_parts"]
        ],
        "ca": [
            ca["ca_id"] for resp in responsibilities for ca in resp["control_actions"]
        ],
        "fb": [
            fb["fb_id"] for resp in responsibilities for fb in resp["feedback_channels"]
        ],
        "cp": [process["cp_id"] for process in payload["controlled_processes"]],
        "cl": [link["link_id"] for link in links],
        "cm": [link["coordination_mechanism"]["cm_id"] for link in links],
    }


st_structure = st.tuples(
    st.integers(min_value=1, max_value=3),
    st.integers(min_value=1, max_value=3),
    st.integers(min_value=1, max_value=3),
    st.booleans(),
    st.lists(st_text, min_size=3, max_size=3),
)


class TestPositionBasedIdsAreDeterministic:
    """The same ordered structure always yields the same published IDs."""

    @given(st_structure)
    @settings(
        max_examples=40,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_ids_depend_only_on_position(self, structure):
        n_resps, n_children, n_cps, with_links, descriptions = structure
        first = _payload(
            n_resps=n_resps,
            n_children=n_children,
            n_cps=n_cps,
            with_links=with_links,
            id_prefix="alpha",
            descriptions=descriptions,
        )
        second = _payload(
            n_resps=n_resps,
            n_children=n_children,
            n_cps=n_cps,
            with_links=with_links,
            id_prefix="beta",
            descriptions=descriptions,
        )

        first_ids = _collected_ids(normalize_control_structure_payload(first).payload)
        second_ids = _collected_ids(normalize_control_structure_payload(second).payload)
        expected = _canonical_ids(n_resps, n_children, n_cps, with_links)

        assert first_ids == expected
        assert second_ids == expected


class TestUniqueSourceIdsMapToCanonicalIds:
    """Unique source IDs appear in the flat mapping and resolve references."""

    @given(st_structure)
    @settings(
        max_examples=40,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_mapping_and_references_follow_source_ids(self, structure):
        n_resps, n_children, n_cps, with_links, descriptions = structure
        payload = _payload(
            n_resps=n_resps,
            n_children=n_children,
            n_cps=n_cps,
            with_links=with_links,
            id_prefix="src",
            descriptions=descriptions,
        )
        original = deepcopy(payload)
        result = normalize_control_structure_payload(payload)

        first_resp = original["responsibilities"][0]
        assert result.mapping[first_resp["resp_id"]] == "RESP-1"
        assert result.mapping[first_resp["process_model_parts"][0]["pm_id"]] == "PM-1-1"
        assert result.mapping[original["controlled_processes"][0]["cp_id"]] == "CP-1"
        assert result.old_to_new == result.mapping

        normalized_first = result.payload["responsibilities"][0]
        if first_resp["control_actions"][0].get("target"):
            assert normalized_first["control_actions"][0]["target"] == {
                "type": "controlled_process",
                "id": result.mapping[original["controlled_processes"][-1]["cp_id"]],
            }
        if first_resp["feedback_channels"][0].get("source"):
            assert normalized_first["feedback_channels"][0]["source"] == {
                "type": "controlled_process",
                "id": result.mapping[original["controlled_processes"][0]["cp_id"]],
            }
        assert normalized_first["feedback_channels"][0]["updates"] == "PM-1-1"

        if original["coordination_links"]:
            link = original["coordination_links"][0]
            normalized_link = result.payload["coordination_links"][0]
            assert result.mapping[link["link_id"]] == "CL-1"
            assert result.mapping[link["coordination_mechanism"]["cm_id"]] == "CM-1"
            assert normalized_link["source"] == result.mapping[link["source"]]
            assert normalized_link["target"] == result.mapping[link["target"]]
            assert normalized_link["shared_pm"] == result.mapping[link["shared_pm"]]


class TestNormalizationIsIdempotent:
    """A second pass leaves an already-canonical payload unchanged."""

    @given(st_structure)
    @settings(
        max_examples=40,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_second_pass_is_identity(self, structure):
        n_resps, n_children, n_cps, with_links, descriptions = structure
        payload = _payload(
            n_resps=n_resps,
            n_children=n_children,
            n_cps=n_cps,
            with_links=with_links,
            id_prefix="once",
            descriptions=descriptions,
        )
        first = normalize_control_structure_payload(payload)
        second = normalize_control_structure_payload(first.payload)

        assert second.payload == first.payload
        assert _collected_ids(second.payload) == _collected_ids(first.payload)
        for old_id, new_id in second.mapping.items():
            assert old_id == new_id


class TestOrderAndNonIdFieldsArePreserved:
    """Normalization does not reorder lists or rewrite descriptions."""

    @given(st_structure)
    @settings(
        max_examples=30,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_descriptions_and_order_survive(self, structure):
        n_resps, n_children, n_cps, with_links, descriptions = structure
        payload = _payload(
            n_resps=n_resps,
            n_children=n_children,
            n_cps=n_cps,
            with_links=with_links,
            id_prefix="keep",
            descriptions=descriptions,
        )
        original_descriptions = [
            resp["description"] for resp in payload["responsibilities"]
        ]
        result = normalize_control_structure_payload(payload)

        assert [
            resp["description"] for resp in result.payload["responsibilities"]
        ] == original_descriptions
        assert payload["responsibilities"][0]["resp_id"].startswith("keep-")
        assert len(result.payload["responsibilities"]) == n_resps
        assert len(result.payload["controlled_processes"]) == n_cps


def _dup_payload(kind: str, dup: str) -> dict:
    """Return a unique-ID payload with one duplicated global source ID."""
    payload = _payload(
        n_resps=2,
        n_children=1,
        n_cps=2,
        with_links=True,
        id_prefix="src",
        descriptions=["First controller", "Second controller", "unused"],
    )
    if kind == "resp":
        for responsibility in payload["responsibilities"]:
            responsibility["resp_id"] = dup
        for link in payload["coordination_links"]:
            link["source"] = "RESP-1"
            link["target"] = "RESP-2"
        payload["responsibilities"][0]["process_model_parts"][0]["feedback_source"] = {
            "type": "responsibility",
            "id": dup,
        }
        return payload
    if kind == "cp":
        for process in payload["controlled_processes"]:
            process["cp_id"] = dup
        for responsibility in payload["responsibilities"]:
            for action in responsibility["control_actions"]:
                if action.get("target"):
                    action["target"] = {"type": "controlled_process", "id": "CP-1"}
            for channel in responsibility["feedback_channels"]:
                if channel.get("source"):
                    channel["source"] = {"type": "controlled_process", "id": "CP-1"}
        payload["responsibilities"][0]["control_actions"][0]["target"] = {
            "type": "controlled_process",
            "id": dup,
        }
        return payload
    payload["responsibilities"][0]["process_model_parts"][0]["pm_id"] = dup
    payload["responsibilities"][1]["process_model_parts"][0]["pm_id"] = dup
    for index, responsibility in enumerate(payload["responsibilities"], start=1):
        for channel in responsibility["feedback_channels"]:
            channel["updates"] = f"PM-{index}-1"
    payload["coordination_links"][0]["shared_pm"] = dup
    return payload


def _dup_probe(kind: str, payload: dict) -> tuple[str, str]:
    """Return the remaining source ID and the validation field name."""
    if kind == "resp":
        return (
            payload["responsibilities"][0]["process_model_parts"][0]["feedback_source"][
                "id"
            ],
            "feedback_source",
        )
    if kind == "cp":
        return (
            payload["responsibilities"][0]["control_actions"][0]["target"]["id"],
            "target",
        )
    return payload["coordination_links"][0]["shared_pm"], "shared_pm"


st_dup = st.text(
    alphabet=st.characters(
        whitelist_categories=("Ll", "Lu", "Nd"),
        whitelist_characters=("-", "_"),
    ),
    min_size=1,
    max_size=16,
).map(lambda text: f"dup-{text}")


class TestAmbiguousGlobalIdsAreNotRewritten:
    """A duplicated global source ID is left for validation to reject."""

    @given(st.sampled_from(("resp", "cp", "pm")), st_dup)
    @settings(
        max_examples=30,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_duplicate_global_id_stays_unmapped(self, kind, dup):
        payload = _dup_payload(kind, dup)
        result = normalize_control_structure_payload(payload)
        actual, field = _dup_probe(kind, result.payload)

        assert dup not in result.mapping
        assert actual == dup
        with pytest.raises(ValidationError) as caught:
            validate_normalized_control_structure(result.payload)
        assert field in str(caught.value)


st_shared = st.text(
    alphabet=st.characters(
        whitelist_categories=("Ll", "Lu", "Nd"),
        whitelist_characters=("-", "_"),
    ),
    min_size=1,
    max_size=16,
).map(lambda text: f"both-{text}")


class TestCrossNamespaceCollisionsAreOmitted:
    """The same source ID in two namespaces stays out of the flat map."""

    @given(st_shared)
    @settings(
        max_examples=30,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_shared_source_id_is_omitted_from_flat_map(self, shared):
        payload = _payload(
            n_resps=1,
            n_children=1,
            n_cps=1,
            with_links=False,
            id_prefix="ns",
            descriptions=["Controller", "unused", "unused"],
        )
        payload["responsibilities"][0]["resp_id"] = shared
        payload["controlled_processes"][0]["cp_id"] = shared

        result = normalize_control_structure_payload(payload)

        assert shared not in result.mapping
        assert result.mappings["responsibility"][shared] == "RESP-1"
        assert result.mappings["controlled_process"][shared] == "CP-1"
        assert result.payload["responsibilities"][0]["resp_id"] == "RESP-1"
        assert result.payload["controlled_processes"][0]["cp_id"] == "CP-1"
