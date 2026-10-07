"""Mutation hardening tests for SP1 ID normalization.

These stay separate from unit and acceptance tests. They kill surviving
mutants and cover defensive branches that the happy-path suite leaves open.

The public normalizer already walks malformed collections, missing local
PM maps, and cross-namespace collisions. Remaining scan noise, if any,
comes from LCOV not attributing rewritten uniqueness filters rather than
from untested policy.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest
from pydantic import BaseModel, ValidationError

from asago_scenario_generator.stpa.models.control_structure import ReferenceType
from asago_scenario_generator.stpa.system_model.id_normalization import (
    ControlStructureNormalization,
    _rewrite_responsibility_references_in_payload,
    normalize_control_structure_payload,
    validate_normalized_control_structure,
)


def _minimal_payload() -> dict:
    """Return a one-controller payload with unique source IDs."""
    return {
        "responsibilities": [
            {
                "resp_id": "controller-alpha",
                "description": "Controller",
                "responsibility_constraints": [
                    {"rc_id": "constraint-a", "description": "Constraint A"}
                ],
                "process_model_parts": [
                    {"pm_id": "state-alpha", "description": "State A"}
                ],
                "control_actions": [
                    {
                        "ca_id": "action-a",
                        "description": "Action A",
                        "target": {
                            "type": "controlled_process",
                            "id": "process-alpha",
                        },
                    }
                ],
                "feedback_channels": [
                    {
                        "fb_id": "feedback-a",
                        "description": "Feedback A",
                        "updates": "state-alpha",
                        "source": {
                            "type": "controlled_process",
                            "id": "process-alpha",
                        },
                    }
                ],
            }
        ],
        "controlled_processes": [
            {"cp_id": "process-alpha", "description": "Process A"}
        ],
        "coordination_links": [
            {
                "link_id": "connection-alpha",
                "source": "controller-alpha",
                "target": "controller-alpha",
                "shared_pm": "state-alpha",
                "coordination_mechanism": {
                    "cm_id": "mechanism-alpha",
                    "description": "Mechanism A",
                    "payload": "payload",
                },
                "description": "Self link",
            }
        ],
    }


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


class TestUnresolvedReferencesStayUnresolved:
    """Kill and/or mutants that would KeyError on missing source IDs."""

    def test_missing_typed_reference_is_left_unchanged(self) -> None:
        payload = _minimal_payload()
        payload["responsibilities"][0]["control_actions"][0]["target"] = {
            "type": "controlled_process",
            "id": "absent-process",
        }
        payload["responsibilities"][0]["process_model_parts"][0]["feedback_source"] = {
            "type": "responsibility",
            "id": "absent-controller",
        }

        result = normalize_control_structure_payload(payload)

        assert result.payload["responsibilities"][0]["control_actions"][0][
            "target"
        ] == {
            "type": "controlled_process",
            "id": "absent-process",
        }
        assert result.payload["responsibilities"][0]["process_model_parts"][0][
            "feedback_source"
        ] == {
            "type": "responsibility",
            "id": "absent-controller",
        }

    def test_missing_local_pm_update_is_left_unchanged(self) -> None:
        payload = _minimal_payload()
        payload["responsibilities"][0]["feedback_channels"][0]["updates"] = "absent-pm"

        result = normalize_control_structure_payload(payload)

        assert (
            result.payload["responsibilities"][0]["feedback_channels"][0]["updates"]
            == "absent-pm"
        )

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

    def test_unknown_reference_type_is_ignored(self) -> None:
        payload = _minimal_payload()
        payload["responsibilities"][0]["control_actions"][0]["target"] = {
            "type": "unknown",
            "id": "process-alpha",
        }

        result = normalize_control_structure_payload(payload)

        assert result.payload["responsibilities"][0]["control_actions"][0][
            "target"
        ] == {
            "type": "unknown",
            "id": "process-alpha",
        }

    def test_non_string_reference_type_is_ignored(self) -> None:
        payload = _minimal_payload()
        payload["responsibilities"][0]["control_actions"][0]["target"] = {
            "type": 7,
            "id": "process-alpha",
        }

        result = normalize_control_structure_payload(payload)

        assert result.payload["responsibilities"][0]["control_actions"][0][
            "target"
        ] == {
            "type": 7,
            "id": "process-alpha",
        }


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
