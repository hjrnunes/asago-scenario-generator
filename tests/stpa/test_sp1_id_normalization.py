"""Tests for SP1 control-structure ID normalization and its recoverable repairs.

``normalize_control_structure_payload`` assigns canonical IDs from structural
position, rewrites local and global references, repairs recoverable defects
(reference types, bare references, empty descriptions), and leaves anything it
cannot repair for validation. The payloads live in
``tests/fixtures/id_normalization/``.
"""

from __future__ import annotations

import copy
import warnings
from dataclasses import FrozenInstanceError

import pytest
from pydantic import BaseModel, ValidationError

from asago_scenario_generator.stpa.infra.llm_helpers import StageError
from asago_scenario_generator.stpa.models.control_structure import (
    ControlStructure,
    ReferenceType,
)
from asago_scenario_generator.stpa.system_model.control_structure import (
    ControlElementSet,
    CoordinationAnalysis,
    RequirementSet,
    ResponsibilitySet,
    derive_control_structure,
)
from asago_scenario_generator.stpa.system_model.id_normalization import (
    ControlStructureNormalization,
    _rewrite_responsibility_references_in_payload,
    normalize_control_structure_payload,
    validate_normalized_control_structure,
)
from tests.helpers.fixtures import load_json_fixture
from tests.stpa.sp1_helpers import MockLLMClient
from tests.helpers.sp1_control_structure import _make_loss_analysis


def _raw_payload() -> dict:
    """A two-responsibility payload with intentionally arbitrary IDs."""
    return load_json_fixture("id_normalization/raw_payload.json")


def _minimal_payload() -> dict:
    """A one-controller payload with unique source IDs."""
    return load_json_fixture("id_normalization/minimal_payload.json")


def _payload_with_references() -> dict:
    """A valid structure with recoverable malformed fields."""
    return load_json_fixture("id_normalization/payload_with_references.json")


# ---------------------------------------------------------------------------
# Canonical IDs from structural position
# ---------------------------------------------------------------------------


def test_normalization_assigns_ids_from_structural_position() -> None:
    payload = _raw_payload()

    result = normalize_control_structure_payload(payload)

    normalized = result.payload
    assert [r["resp_id"] for r in normalized["responsibilities"]] == [
        "RESP-1",
        "RESP-2",
    ]
    assert [
        rc["rc_id"]
        for rc in normalized["responsibilities"][1]["responsibility_constraints"]
    ] == [
        "RC-2-1",
    ]
    assert [
        pm["pm_id"] for pm in normalized["responsibilities"][0]["process_model_parts"]
    ] == [
        "PM-1-1",
        "PM-1-2",
    ]
    assert [
        ca["ca_id"] for ca in normalized["responsibilities"][1]["control_actions"]
    ] == [
        "CA-2-1",
    ]
    assert [
        fb["fb_id"] for fb in normalized["responsibilities"][0]["feedback_channels"]
    ] == [
        "FB-1-1",
        "FB-1-2",
    ]
    assert [cp["cp_id"] for cp in normalized["controlled_processes"]] == [
        "CP-1",
        "CP-2",
    ]
    assert [link["link_id"] for link in normalized["coordination_links"]] == [
        "CL-1",
        "CL-2",
    ]
    assert [
        link["coordination_mechanism"]["cm_id"]
        for link in normalized["coordination_links"]
    ] == ["CM-1", "CM-2"]


def test_normalization_rewrites_local_and_global_references() -> None:
    payload = _raw_payload()
    payload["responsibilities"][0]["process_model_parts"][0]["feedback_source"] = {
        "type": "responsibility",
        "id": "controller-beta",
    }
    payload["responsibilities"][1]["control_actions"][0]["target"] = {
        "type": "controlled_process",
        "id": "process-beta",
    }
    payload["responsibilities"][1]["feedback_channels"][0]["source"] = {
        "type": "controlled_process",
        "id": "process-alpha",
    }

    result = normalize_control_structure_payload(payload)

    first_resp = result.payload["responsibilities"][0]
    second_resp = result.payload["responsibilities"][1]
    assert first_resp["process_model_parts"][0]["feedback_source"] == {
        "type": "responsibility",
        "id": "RESP-2",
    }
    assert second_resp["control_actions"][0]["target"] == {
        "type": "controlled_process",
        "id": "CP-2",
    }
    assert second_resp["feedback_channels"][0]["source"] == {
        "type": "controlled_process",
        "id": "CP-1",
    }
    assert result.payload["coordination_links"][0]["source"] == "RESP-1"
    assert result.payload["coordination_links"][0]["target"] == "RESP-2"
    assert result.payload["coordination_links"][0]["shared_pm"] == "PM-1-1"


def test_normalization_resolves_duplicate_pm_ids_locally() -> None:
    payload = _raw_payload()
    for responsibility in payload["responsibilities"]:
        responsibility["process_model_parts"] = [
            {"pm_id": "shared-state", "description": "Shared state"}
        ]
        responsibility["feedback_channels"] = [
            {
                "fb_id": "repeated-feedback",
                "description": "Local feedback",
                "updates": "shared-state",
            }
        ]

    result = normalize_control_structure_payload(payload)

    assert [
        responsibility["feedback_channels"][0]["updates"]
        for responsibility in result.payload["responsibilities"]
    ] == ["PM-1-1", "PM-2-1"]
    assert result.mapping.get("shared-state") is None


def test_normalization_repairs_malformed_colliding_ids_before_validation() -> None:
    payload = _raw_payload()
    payload["responsibilities"][0]["responsibility_constraints"][0]["rc_id"] = "RC-9-9"
    payload["responsibilities"][0]["process_model_parts"][0]["pm_id"] = "RC-9-9"
    payload["responsibilities"][0]["feedback_channels"][0]["updates"] = "RC-9-9"
    payload["responsibilities"][0]["process_model_parts"][1]["pm_id"] = "repeated"
    payload["responsibilities"][0]["feedback_channels"][1]["updates"] = "repeated"
    payload["coordination_links"][0]["shared_pm"] = "RC-9-9"
    payload["responsibilities"][0]["control_actions"][0]["ca_id"] = "repeated"
    payload["responsibilities"][0]["control_actions"][1]["ca_id"] = "repeated"
    payload["responsibilities"][0]["feedback_channels"][0]["fb_id"] = "FB-1"
    payload["responsibilities"][0]["feedback_channels"][1]["fb_id"] = "FB-1"
    payload["controlled_processes"][0]["cp_id"] = "CP-99-1"
    payload["coordination_links"][0]["link_id"] = "CL-20"
    payload["coordination_links"][0]["coordination_mechanism"]["cm_id"] = "CM-7-7"

    result = normalize_control_structure_payload(payload)
    control_structure = ControlStructure.model_validate(result.payload)

    assert (
        control_structure.responsibilities[0].process_model_parts[0].pm_id == "PM-1-1"
    )
    assert (
        control_structure.responsibilities[0].process_model_parts[1].pm_id == "PM-1-2"
    )
    assert (
        control_structure.responsibilities[0].responsibility_constraints[0].rc_id
        == "RC-1-1"
    )


def test_normalization_preserves_order_and_non_id_fields() -> None:
    payload = _raw_payload()
    original_descriptions = [
        responsibility["description"] for responsibility in payload["responsibilities"]
    ]
    original_payloads = [
        link["coordination_mechanism"]["payload"]
        for link in payload["coordination_links"]
    ]

    result = normalize_control_structure_payload(payload)

    assert [
        responsibility["description"]
        for responsibility in result.payload["responsibilities"]
    ] == original_descriptions
    assert [
        link["coordination_mechanism"]["payload"]
        for link in result.payload["coordination_links"]
    ] == original_payloads
    assert [link["description"] for link in result.payload["coordination_links"]] == [
        "Connection A",
        "Connection B",
    ]


def test_normalization_handles_non_mapping_children_and_links() -> None:
    payload = {
        "responsibilities": [
            {
                "resp_id": "controller",
                "description": "Controller",
                "responsibility_constraints": ["not-a-mapping"],
                "process_model_parts": "not-a-list",
                "control_actions": [None],
                "feedback_channels": [None],
            }
        ],
        "controlled_processes": [
            {"cp_id": "process", "description": "Process"},
            None,
        ],
        "coordination_links": [
            None,
            {
                "link_id": "link",
                "coordination_mechanism": None,
            },
        ],
    }

    result = normalize_control_structure_payload(payload)

    assert result.payload["responsibilities"][0]["resp_id"] == "RESP-1"
    assert result.payload["controlled_processes"][0]["cp_id"] == "CP-1"
    assert result.payload["coordination_links"][1]["link_id"] == "CL-2"
    assert payload["responsibilities"][0]["resp_id"] == "controller"


def test_stage2_rejects_unowned_ids_before_normalization(
    tmp_path,
) -> None:
    """Call 2b must not repair arbitrary IDs by response-array order."""
    client = MockLLMClient()
    responses = load_json_fixture("id_normalization/stage2_unowned_ids.json")
    for model in (
        RequirementSet,
        ResponsibilitySet,
        ControlElementSet,
        CoordinationAnalysis,
    ):
        client.set_response_for(model, responses[model.__name__])

    with pytest.raises(StageError, match="ca_id|owner|responsibility"):
        derive_control_structure(
            llm_client=client,
            use_case_text="Test",
            loss_analysis=_make_loss_analysis(),
            run_dir=tmp_path,
        )


@pytest.mark.parametrize("malformed", [None, "oops", {"ca_id": "action-a"}])
def test_normalization_leaves_non_list_control_actions_untouched(malformed) -> None:
    payload = _raw_payload()
    payload["responsibilities"][0]["control_actions"] = malformed

    normalized = normalize_control_structure_payload(payload).payload

    first = normalized["responsibilities"][0]
    assert first["control_actions"] == malformed
    assert first["feedback_channels"][0]["updates"] == "PM-1-1"


# ---------------------------------------------------------------------------
# Result type and payload guards
# ---------------------------------------------------------------------------


class _OptionalFieldPayload(BaseModel):
    """Decoded payload that still carries an explicit None field."""

    responsibilities: list
    controlled_processes: list
    coordination_links: list
    unused: str | None = None


class TestNormalizationResultIsFrozen:
    """Kill: ControlStructureNormalization frozen=True -> False."""

    def test_result_cannot_be_mutated(self) -> None:
        result = normalize_control_structure_payload(_minimal_payload())

        with pytest.raises(FrozenInstanceError):
            result.mapping = {}  # type: ignore[misc]
        with pytest.raises(FrozenInstanceError):
            result.payload = {}  # type: ignore[misc]
        assert isinstance(result, ControlStructureNormalization)
        assert result.old_to_new is result.mapping


class TestPayloadDictGuards:
    """Cover BaseModel dumping and the non-mapping TypeError."""

    def test_pydantic_none_fields_are_preserved(self) -> None:
        """Kill: exclude_none=False -> True on model_dump."""
        model = _OptionalFieldPayload(
            responsibilities=_minimal_payload()["responsibilities"],
            controlled_processes=_minimal_payload()["controlled_processes"],
            coordination_links=[],
            unused=None,
        )

        result = normalize_control_structure_payload(model)

        assert "unused" in result.payload
        assert result.payload["unused"] is None

    def test_non_mapping_payload_raises_type_error(self) -> None:
        with pytest.raises(TypeError, match="mapping or Pydantic model"):
            normalize_control_structure_payload(["not", "a", "mapping"])  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Defensive paths: the normalizer leaves what it cannot resolve
# ---------------------------------------------------------------------------

_SLOT_PATHS = {
    "target": ("control_actions", "target"),
    "feedback_source": ("process_model_parts", "feedback_source"),
    "updates": ("feedback_channels", "updates"),
}


class TestUnresolvedReferencesStayUnresolved:
    """Kill and/or mutants that would KeyError on missing source IDs."""

    @pytest.mark.parametrize(
        ("slot", "value"),
        [
            pytest.param(
                "target",
                {"type": "controlled_process", "id": "absent-process"},
                id="missing_controlled_process",
            ),
            pytest.param(
                "feedback_source",
                {"type": "responsibility", "id": "absent-controller"},
                id="missing_responsibility",
            ),
            pytest.param("updates", "absent-pm", id="missing_local_pm"),
            pytest.param(
                "target", {"type": "unknown", "id": "process-alpha"}, id="unknown_type"
            ),
            pytest.param(
                "target", {"type": 7, "id": "process-alpha"}, id="non_string_type"
            ),
        ],
    )
    def test_reference_is_left_unchanged(self, slot, value) -> None:
        payload = _minimal_payload()
        collection, key = _SLOT_PATHS[slot]
        payload["responsibilities"][0][collection][0][key] = value

        result = normalize_control_structure_payload(payload)

        assert result.payload["responsibilities"][0][collection][0][key] == value

    def test_enum_typed_reference_rewrites_like_string_type(self) -> None:
        payload = _minimal_payload()
        payload["responsibilities"][0]["control_actions"][0]["target"] = {
            "type": ReferenceType.controlled_process,
            "id": "process-alpha",
        }

        result = normalize_control_structure_payload(payload)

        assert (
            result.payload["responsibilities"][0]["control_actions"][0]["target"]["id"]
            == "CP-1"
        )


class TestFlatMappingExcludesAmbiguousSourceIds:
    """Cover _flat_unique_source_map uniqueness filtering."""

    def test_unique_ids_map_to_first_and_only_canonical_id(self) -> None:
        result = normalize_control_structure_payload(_minimal_payload())

        assert result.mapping["controller-alpha"] == "RESP-1"
        assert result.mapping["state-alpha"] == "PM-1-1"
        assert result.mapping["process-alpha"] == "CP-1"
        assert result.mapping["connection-alpha"] == "CL-1"
        assert result.mapping["mechanism-alpha"] == "CM-1"
        assert set(result.mapping) == {
            "controller-alpha",
            "constraint-a",
            "state-alpha",
            "action-a",
            "feedback-a",
            "process-alpha",
            "connection-alpha",
            "mechanism-alpha",
        }

    def test_cross_namespace_collision_is_omitted_from_flat_map(self) -> None:
        payload = _minimal_payload()
        payload["controlled_processes"][0]["cp_id"] = "controller-alpha"

        result = normalize_control_structure_payload(payload)

        assert "controller-alpha" not in result.mapping
        assert result.mappings["responsibility"]["controller-alpha"] == "RESP-1"
        assert result.mappings["controlled_process"]["controller-alpha"] == "CP-1"


class TestMalformedCollectionsAreSkipped:
    """Cover early-return and non-dict branches in collection walkers."""

    def test_non_list_top_level_collections_are_ignored(self) -> None:
        payload = {
            "responsibilities": "not-a-list",
            "controlled_processes": "not-a-list",
            "coordination_links": "not-a-list",
        }

        result = normalize_control_structure_payload(payload)

        assert result.payload["responsibilities"] == "not-a-list"
        assert result.payload["controlled_processes"] == "not-a-list"
        assert result.payload["coordination_links"] == "not-a-list"
        assert result.mapping == {}

    def test_missing_string_ids_and_non_dict_rows_are_skipped(self) -> None:
        payload = {
            "responsibilities": [
                "skip-me",
                {
                    "resp_id": 12,
                    "description": "No string IDs",
                    "responsibility_constraints": [{"rc_id": None, "description": "x"}],
                    "process_model_parts": [{"description": "no pm id"}],
                    "control_actions": "not-a-list",
                    "feedback_channels": "not-a-list",
                },
            ],
            "controlled_processes": "not-a-list",
            "coordination_links": "not-a-list",
        }

        result = normalize_control_structure_payload(payload)

        assert result.payload["responsibilities"][1]["resp_id"] == "RESP-2"
        assert result.mapping == {}

    def test_local_pm_maps_skip_non_dict_responsibilities(self) -> None:
        payload = {
            "responsibilities": [
                "skip-me",
                {
                    "resp_id": "controller",
                    "description": "Controller",
                    "process_model_parts": [{"pm_id": "state", "description": "State"}],
                    "feedback_channels": [
                        {
                            "fb_id": "fb",
                            "description": "Feedback",
                            "updates": "state",
                        }
                    ],
                },
            ],
            "controlled_processes": [],
            "coordination_links": [],
        }

        result = normalize_control_structure_payload(payload)

        assert (
            result.payload["responsibilities"][1]["feedback_channels"][0]["updates"]
            == "PM-2-1"
        )


class TestDefensiveReferenceBounds:
    """Cover the local-PM map bounds check that public input cannot miss."""

    def test_missing_local_pm_map_defaults_to_empty(self) -> None:
        payload = {
            "responsibilities": [
                {
                    "resp_id": "controller",
                    "description": "Controller",
                    "feedback_channels": [
                        {
                            "fb_id": "fb",
                            "description": "Feedback",
                            "updates": "state",
                        }
                    ],
                }
            ]
        }

        _rewrite_responsibility_references_in_payload(
            payload,
            {
                "responsibility": {},
                "controlled_process": {},
                "process_model_part": {},
            },
            [],
        )

        assert payload["responsibilities"][0]["feedback_channels"][0]["updates"] == (
            "state"
        )


class TestValidateNormalizedControlStructure:
    """Cover the public validate-after-normalize helper."""

    def test_valid_payload_returns_control_structure(self) -> None:
        control_structure = validate_normalized_control_structure(_minimal_payload())

        assert control_structure.responsibilities[0].resp_id == "RESP-1"
        assert control_structure.controlled_processes[0].cp_id == "CP-1"
        assert control_structure.coordination_links[0].link_id == "CL-1"

    @pytest.mark.parametrize(
        ("edit", "expected"),
        [
            pytest.param(
                lambda p: p["responsibilities"][0]["feedback_channels"][0].update(
                    updates="absent-reference"
                ),
                "FeedbackChannel FB-1-1 updates references non-existent PM",
                id="feedback-updates",
            ),
            pytest.param(
                lambda p: p["responsibilities"][0]["process_model_parts"][0].update(
                    feedback_source={"type": "responsibility", "id": "absent-reference"}
                ),
                "ProcessModelPart PM-1-1 feedback_source references",
                id="process-feedback-source",
            ),
            pytest.param(
                lambda p: p["responsibilities"][0]["control_actions"][0].update(
                    target={"type": "controlled_process", "id": "absent-reference"}
                ),
                "ControlAction CA-1-1 target references",
                id="control-action-target",
            ),
            pytest.param(
                lambda p: p["responsibilities"][0]["feedback_channels"][0].update(
                    source={"type": "controlled_process", "id": "absent-reference"}
                ),
                "FeedbackChannel FB-1-1 source references",
                id="feedback-source",
            ),
            pytest.param(
                lambda p: p["coordination_links"][0].update(source="absent-reference"),
                "CoordinationLink CL-1 source references",
                id="coordination-source",
            ),
            pytest.param(
                lambda p: p["coordination_links"][0].update(target="absent-reference"),
                "CoordinationLink CL-1 target references",
                id="coordination-target",
            ),
            pytest.param(
                lambda p: p["coordination_links"][0].update(
                    shared_pm="absent-reference"
                ),
                "CoordinationLink CL-1 shared_pm references non-existent PM",
                id="coordination-shared-pm",
            ),
        ],
    )
    def test_unresolved_reference_fails_validation_naming_the_field(
        self, edit, expected: str
    ) -> None:
        """SP1-ID-RENUMBERING-09: an unresolved reference is not repaired away."""
        payload = _minimal_payload()
        edit(payload)

        with pytest.raises(ValidationError) as caught:
            validate_normalized_control_structure(payload)

        message = str(caught.value)
        assert "absent-reference" in message
        assert expected in message
        assert "unhashable" not in message


# ---------------------------------------------------------------------------
# Recoverable defects
# ---------------------------------------------------------------------------


def test_normalization_infers_element_ref_types_before_rewriting_ids() -> None:
    result = normalize_control_structure_payload(_payload_with_references())

    responsibility = result.payload["responsibilities"][0]
    assert responsibility["process_model_parts"][0]["feedback_source"] == {
        "type": "responsibility",
        "id": "RESP-2",
    }
    assert responsibility["control_actions"][0]["target"] == {
        "type": "controlled_process",
        "id": "CP-2",
    }
    assert responsibility["feedback_channels"][0]["source"] == {
        "type": "controlled_process",
        "id": "CP-2",
    }
    ControlStructure.model_validate(result.payload)


def test_normalization_leaves_uninferable_element_ref_type_for_validation() -> None:
    payload = _payload_with_references()
    payload["responsibilities"][0]["control_actions"][0]["target"] = {
        "type": "process-alpha",
        "id": "process-alpha",
    }

    result = normalize_control_structure_payload(payload)

    assert result.payload["responsibilities"][0]["control_actions"][0]["target"] == {
        "type": "process-alpha",
        "id": "process-alpha",
    }
    with pytest.raises(ValueError, match="target"):
        ControlStructure.model_validate(result.payload)


def test_normalization_preserves_a_valid_reference_type() -> None:
    payload = _payload_with_references()
    payload["responsibilities"][0]["control_actions"][0]["target"] = {
        "type": "controlled_process",
        "id": "CP-9",
    }

    result = normalize_control_structure_payload(payload)

    assert result.payload["responsibilities"][0]["control_actions"][0]["target"] == {
        "type": "controlled_process",
        "id": "CP-2",
    }


@pytest.mark.parametrize(
    ("field", "source_id", "expected"),
    [
        (
            ("process_model_parts", "feedback_source"),
            "CP-9",
            {"type": "controlled_process", "id": "CP-2"},
        ),
        (
            ("control_actions", "target"),
            "RESP-10",
            {"type": "responsibility", "id": "RESP-2"},
        ),
        (
            ("feedback_channels", "source"),
            "CP-9",
            {"type": "controlled_process", "id": "CP-2"},
        ),
    ],
)
def test_normalization_wraps_bare_element_refs(
    field: tuple[str, str],
    source_id: str,
    expected: dict[str, str],
) -> None:
    payload = _payload_with_references()
    payload["responsibilities"][0][field[0]][0][field[1]] = source_id

    result = normalize_control_structure_payload(payload)

    assert result.payload["responsibilities"][0][field[0]][0][field[1]] == expected
    ControlStructure.model_validate(result.payload)


def test_normalization_leaves_unrecognized_bare_element_ref_for_validation() -> None:
    payload = _payload_with_references()
    payload["responsibilities"][0]["control_actions"][0]["target"] = "process-alpha"

    result = normalize_control_structure_payload(payload)

    assert result.payload["responsibilities"][0]["control_actions"][0]["target"] == (
        "process-alpha"
    )
    with pytest.raises(ValueError, match="target"):
        ControlStructure.model_validate(result.payload)


def test_normalization_preserves_null_element_refs() -> None:
    payload = _payload_with_references()
    payload["responsibilities"][0]["control_actions"][0]["target"] = None

    result = normalize_control_structure_payload(payload)

    assert result.payload["responsibilities"][0]["control_actions"][0]["target"] is None
    ControlStructure.model_validate(result.payload)


def test_normalization_converts_object_shaped_feedback_update_to_scalar() -> None:
    payload = _payload_with_references()
    payload["responsibilities"][0]["feedback_channels"][0]["updates"] = {
        "type": "process_model_part",
        "id": "state-alpha",
    }

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        result = normalize_control_structure_payload(payload)

    assert not caught
    feedback = result.payload["responsibilities"][0]["feedback_channels"][0]
    assert feedback["updates"] == "PM-1-1"
    ControlStructure.model_validate(result.payload)


def test_normalization_leaves_ambiguous_object_feedback_update_for_validation() -> None:
    payload = _payload_with_references()
    payload["responsibilities"][0]["process_model_parts"].append(
        {"pm_id": "state-alpha", "description": "Second state"}
    )
    payload["responsibilities"][0]["feedback_channels"][0]["updates"] = {
        "type": "process_model_part",
        "id": "state-alpha",
    }

    result = normalize_control_structure_payload(payload)

    feedback = result.payload["responsibilities"][0]["feedback_channels"][0]
    assert feedback["updates"] == {
        "type": "process_model_part",
        "id": "state-alpha",
    }
    with pytest.raises(ValueError) as exc_info:
        ControlStructure.model_validate(result.payload)
    assert "updates" in str(exc_info.value).lower()
    assert "unhashable" not in str(exc_info.value).lower()


@pytest.mark.parametrize(
    "updates",
    [
        {"type": "process_model_part", "id": "PM-UNKNOWN"},
        {"type": "control_action", "id": "CA-9-1"},
    ],
)
def test_normalization_leaves_unknown_feedback_update_shapes_for_validation(
    updates: dict[str, str],
) -> None:
    payload = _payload_with_references()
    payload["responsibilities"][0]["feedback_channels"][0]["updates"] = updates

    result = normalize_control_structure_payload(payload)

    with pytest.raises(ValueError) as exc_info:
        ControlStructure.model_validate(result.payload)
    assert "updates" in str(exc_info.value).lower()
    assert "unhashable" not in str(exc_info.value).lower()


def test_namespace_resolves_id_shaped_element_ref_type() -> None:
    payload = _payload_with_references()
    payload["controlled_processes"][1]["cp_id"] = "process-alpha"
    payload["responsibilities"][0]["control_actions"][0]["target"] = {
        "type": "process-alpha",
        "id": "process-alpha",
    }
    payload["responsibilities"][0]["feedback_channels"][0]["source"] = {
        "type": "process-alpha",
        "id": "process-alpha",
    }

    result = normalize_control_structure_payload(payload)

    target = result.payload["responsibilities"][0]["control_actions"][0]["target"]
    assert target == {"type": "controlled_process", "id": "CP-2"}
    ControlStructure.model_validate(result.payload)


def test_normalization_repairs_empty_descriptions_from_canonical_context() -> None:
    result = normalize_control_structure_payload(_payload_with_references())
    payload = result.payload
    responsibility = payload["responsibilities"][0]

    assert responsibility["description"] == "Responsibility RESP-1"
    assert (
        responsibility["responsibility_constraints"][0]["description"]
        == "Responsibility constraint RC-1-1"
    )
    assert (
        responsibility["process_model_parts"][0]["description"]
        == "Process model part PM-1-1"
    )
    assert (
        responsibility["control_actions"][0]["description"] == "Control action CA-1-1"
    )
    assert (
        responsibility["feedback_channels"][0]["description"]
        == "Feedback from controlled process CP-2 updating process model part PM-1-1"
    )
    assert payload["controlled_processes"][1]["description"] == (
        "Controlled process CP-2"
    )
    assert payload["coordination_links"][0]["description"] == ("Coordination link CL-1")
    assert payload["coordination_links"][0]["coordination_mechanism"][
        "description"
    ] == ("Coordination mechanism CM-1")
    ControlStructure.model_validate(payload)


def test_empty_description_repair_preserves_nonempty_none_and_missing_values() -> None:
    payload = _payload_with_references()
    payload["responsibilities"][1]["description"] = None
    payload["responsibilities"][1]["process_model_parts"] = [{"pm_id": "state-beta"}]

    result = normalize_control_structure_payload(payload)

    second = result.payload["responsibilities"][1]
    assert second["description"] is None
    assert "description" not in second["process_model_parts"][0]
    assert result.payload["responsibilities"][0]["description"] == (
        "Responsibility RESP-1"
    )


def test_feedback_description_uses_fallbacks_for_missing_context() -> None:
    payload = _payload_with_references()
    feedback = payload["responsibilities"][0]["feedback_channels"][0]
    feedback["source"] = None
    feedback["description"] = ""
    result = normalize_control_structure_payload(payload)
    assert (
        result.payload["responsibilities"][0]["feedback_channels"][0]["description"]
        == "Feedback updating process model part PM-1-1"
    )

    no_update_payload = copy.deepcopy(payload)
    no_update_payload["responsibilities"][0]["feedback_channels"][0]["updates"] = ""
    no_update_result = normalize_control_structure_payload(no_update_payload)
    assert (
        no_update_result.payload["responsibilities"][0]["feedback_channels"][0][
            "description"
        ]
        == "Feedback channel FB-1-1"
    )
