"""Property tests for recoverable SP1 normalization repairs.

These cover four high-level invariants:

- ElementRef type inference fires only for invalid types whose IDs start
  with RESP- or CP-
- bare CP-/RESP- strings become ElementRef objects; dicts, None, and
  unknown-prefix strings stay as they are
- empty-string descriptions are replaced; None and non-empty stay put
- generic ``id`` fills omitted ``*_id`` fields and never other fields
"""

from __future__ import annotations

from hypothesis import HealthCheck, given, settings, strategies as st
from pydantic import BaseModel

from asago_scenario_generator.stpa.infra.unvalidated_decode import (
    construct_model_unvalidated,
)
from asago_scenario_generator.stpa.system_model.id_normalization import (
    normalize_control_structure_payload,
)

st_label = st.text(
    alphabet=st.characters(
        whitelist_categories=("Ll", "Lu", "Nd"),
        whitelist_characters=("-", "_"),
    ),
    min_size=1,
    max_size=12,
)
st_valid_type = st.sampled_from(("responsibility", "controlled_process"))
st_prefix = st.sampled_from(("RESP-", "CP-"))
st_bad_type = st_label.filter(
    lambda text: (
        text not in {"responsibility", "controlled_process"}
        and not text.startswith("RESP-")
        and not text.startswith("CP-")
    )
)
st_desc_kind = st.sampled_from(("empty", "keep", "none", "omit"))
st_slot = st.sampled_from(("target", "source", "feedback_source"))
st_unknown = st_label.filter(
    lambda text: not text.startswith("RESP-") and not text.startswith("CP-")
)


def _payload(
    *,
    source_type: str,
    source_id: str,
    description: object | None,
    include_description: bool,
) -> dict:
    """Return one controller/process pair with a typed control-action target."""
    responsibility = {
        "resp_id": "controller-alpha",
        "responsibility_constraints": [],
        "process_model_parts": [],
        "control_actions": [
            {
                "ca_id": "action-alpha",
                "description": "Action",
                "target": {"type": source_type, "id": source_id},
            }
        ],
        "feedback_channels": [],
    }
    if include_description:
        responsibility["description"] = description
    process = {"cp_id": "process-alpha", "description": "Process"}
    return {
        "responsibilities": [responsibility],
        "controlled_processes": [process],
        "coordination_links": [],
    }


def _expected_type(source_type: str, source_id: str) -> str:
    """Return the type the normalizer should publish for one ElementRef."""
    if source_type in {"responsibility", "controlled_process"}:
        return source_type
    if source_id.startswith("RESP-"):
        return "responsibility"
    if source_id.startswith("CP-"):
        return "controlled_process"
    return source_type


class TestElementRefTypeInference:
    """Type repair is prefix-driven and never overwrites a valid type."""

    @given(st_valid_type, st_prefix, st_label)
    @settings(
        max_examples=40,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_valid_types_are_preserved(self, source_type, prefix, label):
        payload = _payload(
            source_type=source_type,
            source_id=f"{prefix}{label}",
            description="Controller",
            include_description=True,
        )
        result = normalize_control_structure_payload(payload)
        target = result.payload["responsibilities"][0]["control_actions"][0]["target"]
        assert target["type"] == source_type

    @given(st_bad_type, st_prefix, st_label)
    @settings(
        max_examples=40,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_invalid_prefix_types_are_inferred(self, source_type, prefix, label):
        source_id = f"{prefix}{label}"
        payload = _payload(
            source_type=source_type,
            source_id=source_id,
            description="Controller",
            include_description=True,
        )
        result = normalize_control_structure_payload(payload)
        target = result.payload["responsibilities"][0]["control_actions"][0]["target"]
        assert target["type"] == _expected_type(source_type, source_id)

    @given(st_bad_type)
    @settings(
        max_examples=30,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_uninferable_types_stay_for_validation(self, source_type):
        payload = _payload(
            source_type=source_type,
            source_id=source_type,
            description="Controller",
            include_description=True,
        )
        result = normalize_control_structure_payload(payload)
        target = result.payload["responsibilities"][0]["control_actions"][0]["target"]
        assert target == {"type": source_type, "id": source_type}


def _slot_payload(slot: str, value: object) -> dict:
    """Return one controller/process pair with *value* in one ElementRef slot."""
    responsibility = {
        "resp_id": "controller-alpha",
        "description": "Controller",
        "responsibility_constraints": [],
        "process_model_parts": [
            {
                "pm_id": "state-alpha",
                "description": "State",
                "feedback_source": value if slot == "feedback_source" else None,
            }
        ],
        "control_actions": [
            {
                "ca_id": "action-alpha",
                "description": "Action",
                "target": value if slot == "target" else None,
            }
        ],
        "feedback_channels": [
            {
                "fb_id": "channel-alpha",
                "description": "Channel",
                "source": value if slot == "source" else None,
                "updates": "state-alpha",
            }
        ],
    }
    return {
        "responsibilities": [responsibility],
        "controlled_processes": [{"cp_id": "process-alpha", "description": "Process"}],
        "coordination_links": [],
    }


def _slot_value(payload: dict, slot: str) -> object:
    """Read one ElementRef slot from a normalized payload."""
    responsibility = payload["responsibilities"][0]
    if slot == "target":
        return responsibility["control_actions"][0]["target"]
    if slot == "source":
        return responsibility["feedback_channels"][0]["source"]
    return responsibility["process_model_parts"][0]["feedback_source"]


class TestBareStringWrap:
    """Only recognized bare CP-/RESP- strings become ElementRef objects."""

    @given(st_slot, st_prefix, st_label)
    @settings(
        max_examples=40,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_known_prefix_strings_become_objects(self, slot, prefix, label):
        source_id = f"{prefix}{label}"
        result = normalize_control_structure_payload(_slot_payload(slot, source_id))
        actual = _slot_value(result.payload, slot)
        assert isinstance(actual, dict)
        assert actual["id"] in {source_id, "CP-1", "RESP-1"}
        expected_type = "responsibility" if prefix == "RESP-" else "controlled_process"
        assert actual["type"] == expected_type

    @given(st_slot, st_unknown)
    @settings(
        max_examples=30,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_unknown_prefix_strings_stay_strings(self, slot, source_id):
        result = normalize_control_structure_payload(_slot_payload(slot, source_id))
        assert _slot_value(result.payload, slot) == source_id

    @given(st_slot)
    @settings(
        max_examples=10,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_null_slots_stay_null(self, slot):
        result = normalize_control_structure_payload(_slot_payload(slot, None))
        assert _slot_value(result.payload, slot) is None

    @given(st_slot, st_valid_type, st_label)
    @settings(
        max_examples=30,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_dicts_stay_dicts(self, slot, source_type, label):
        original = {"type": source_type, "id": f"keep-{label}"}
        result = normalize_control_structure_payload(_slot_payload(slot, original))
        actual = _slot_value(result.payload, slot)
        assert isinstance(actual, dict)
        assert actual["type"] == source_type
        assert actual["id"] == f"keep-{label}"


class TestEmptyDescriptionRepair:
    """Only the empty-string sentinel is replaced."""

    @given(st_desc_kind, st_label)
    @settings(
        max_examples=40,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_only_empty_strings_are_replaced(self, kind, label):
        include_description = kind != "omit"
        if kind == "empty":
            description: object | None = ""
        elif kind == "keep":
            description = f"keep-{label}"
        else:
            description = None
        payload = _payload(
            source_type="controlled_process",
            source_id="process-alpha",
            description=description,
            include_description=include_description,
        )
        result = normalize_control_structure_payload(payload)
        actual = result.payload["responsibilities"][0].get("description")
        if kind == "empty":
            assert actual == "Responsibility RESP-1"
        elif kind == "keep":
            assert actual == f"keep-{label}"
        elif kind == "none":
            assert actual is None
        else:
            assert "description" not in result.payload["responsibilities"][0]


class _Sample(BaseModel):
    item_id: str
    note: str
    count: int = 3


class TestGenericIdAlias:
    """Generic ``id`` fills omitted ``*_id`` fields only."""

    @given(st_label, st_label)
    @settings(
        max_examples=40,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_alias_fills_id_fields_only(self, item, note):
        decoded = construct_model_unvalidated({"id": item, "note": note}, _Sample)
        assert decoded.item_id == item
        assert decoded.note == note
        assert decoded.count == 3

        explicit = construct_model_unvalidated(
            {"id": "ignored", "item_id": item, "note": note},
            _Sample,
        )
        assert explicit.item_id == item
        assert explicit.note == note

        omitted = construct_model_unvalidated({"id": item}, _Sample)
        assert omitted.item_id == item
        assert omitted.note == ""
