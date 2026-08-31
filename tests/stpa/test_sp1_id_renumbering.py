"""Tests for deterministic SP1 control-structure ID normalization."""

from __future__ import annotations

from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.system_model.control_structure import (
    ControlElementSet,
    CoordinationAnalysis,
    RequirementSet,
    ResponsibilitySet,
    derive_control_structure,
)
from asago_scenario_generator.stpa.system_model.id_normalization import (
    normalize_control_structure_payload,
)
from tests.stpa.sp1_helpers import MockLLMClient
from tests.stpa.test_sp1_control_structure import _make_loss_analysis


def _raw_payload() -> dict:
    """Return a two-responsibility payload with intentionally arbitrary IDs."""
    return {
        "responsibilities": [
            {
                "resp_id": "controller-alpha",
                "description": "First controller",
                "responsibility_constraints": [
                    {"rc_id": "constraint-a", "description": "Constraint A"},
                    {"rc_id": "constraint-b", "description": "Constraint B"},
                ],
                "security_constraint_refs": ["SC-1"],
                "process_model_parts": [
                    {"pm_id": "state-a", "description": "State A"},
                    {"pm_id": "state-b", "description": "State B"},
                ],
                "control_actions": [
                    {"ca_id": "action-a", "description": "Action A"},
                    {"ca_id": "action-b", "description": "Action B"},
                ],
                "feedback_channels": [
                    {
                        "fb_id": "feedback-a",
                        "description": "Feedback A",
                        "updates": "state-a",
                    },
                    {
                        "fb_id": "feedback-b",
                        "description": "Feedback B",
                        "updates": "state-b",
                    },
                ],
            },
            {
                "resp_id": "controller-beta",
                "description": "Second controller",
                "responsibility_constraints": [
                    {"rc_id": "constraint-c", "description": "Constraint C"},
                ],
                "security_constraint_refs": ["SC-2"],
                "process_model_parts": [
                    {"pm_id": "state-c", "description": "State C"},
                ],
                "control_actions": [
                    {"ca_id": "action-c", "description": "Action C"},
                ],
                "feedback_channels": [
                    {
                        "fb_id": "feedback-c",
                        "description": "Feedback C",
                        "updates": "state-c",
                    },
                ],
            },
        ],
        "controlled_processes": [
            {"cp_id": "process-alpha", "description": "Process A"},
            {"cp_id": "process-beta", "description": "Process B"},
        ],
        "coordination_links": [
            {
                "link_id": "connection-alpha",
                "source": "controller-alpha",
                "target": "controller-beta",
                "shared_pm": "state-a",
                "coordination_mechanism": {
                    "cm_id": "mechanism-alpha",
                    "description": "Mechanism A",
                    "payload": "State payload A",
                },
                "description": "Connection A",
            },
            {
                "link_id": "connection-beta",
                "source": "controller-beta",
                "target": "controller-alpha",
                "shared_pm": "state-c",
                "coordination_mechanism": {
                    "cm_id": "mechanism-beta",
                    "description": "Mechanism B",
                    "payload": "State payload B",
                },
                "description": "Connection B",
            },
        ],
    }


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


def test_stage2_uses_tolerant_decode_then_normalizes_before_validation(
    tmp_path,
) -> None:
    client = MockLLMClient()
    client.set_response_for(
        RequirementSet,
        {
            "requirements": [
                {
                    "req_id": "REQ-1",
                    "description": "Validate input",
                    "classification": "control",
                    "source_constraint": "SC-1",
                }
            ]
        },
    )
    client.set_response_for(
        ResponsibilitySet,
        {
            "responsibilities": [
                {
                    "resp_id": "RESP-90",
                    "description": "First controller",
                    "security_constraint_refs": ["SC-1"],
                    "responsibility_constraints": [
                        {"rc_id": "RC-9-9", "description": "Constraint one"}
                    ],
                    "process_model_parts": [
                        {"pm_id": "state-one", "description": "State one"}
                    ],
                },
                {
                    "resp_id": "RESP-3",
                    "description": "Second controller",
                    "security_constraint_refs": ["SC-1"],
                    "responsibility_constraints": [
                        {"rc_id": "RC-9-9", "description": "Constraint two"}
                    ],
                    "process_model_parts": [
                        {"pm_id": "state-two", "description": "State two"}
                    ],
                },
            ]
        },
    )
    client.set_response_for(
        ControlElementSet,
        {
            "control_actions": [
                {
                    "ca_id": "first-action",
                    "description": "First action",
                    "target": {
                        "type": "controlled_process",
                        "id": "process-two",
                    },
                },
                {"ca_id": "second-action", "description": "Second action"},
            ],
            "feedback_channels": [
                {
                    "fb_id": "first-feedback",
                    "description": "First feedback",
                    "updates": "state-one",
                    "source": {
                        "type": "controlled_process",
                        "id": "process-one",
                    },
                },
                {
                    "fb_id": "second-feedback",
                    "description": "Second feedback",
                    "updates": "state-two",
                    "source": {
                        "type": "responsibility",
                        "id": "RESP-90",
                    },
                },
            ],
            "controlled_processes": [
                {"cp_id": "process-one", "description": "Process one"},
                {"cp_id": "process-two", "description": "Process two"},
            ],
        },
    )
    client.set_response_for(
        CoordinationAnalysis,
        {
            "coordination_links": [
                {
                    "link_id": "link-20",
                    "source": "RESP-90",
                    "target": "RESP-3",
                    "shared_pm": "state-one",
                    "coordination_mechanism": {
                        "cm_id": "mechanism-99",
                        "description": "Shared state",
                        "payload": "state payload",
                    },
                    "description": "Coordinate controllers",
                }
            ],
            "integrity_findings": [],
        },
    )

    normalized, warnings = derive_control_structure(
        llm_client=client,
        use_case_text="Test",
        loss_analysis=_make_loss_analysis(),
        run_dir=tmp_path,
    )

    assert warnings == []
    assert [resp.resp_id for resp in normalized.responsibilities] == [
        "RESP-1",
        "RESP-2",
    ]
    assert (
        normalized.responsibilities[0].responsibility_constraints[0].rc_id == "RC-1-1"
    )
    assert (
        normalized.responsibilities[1].responsibility_constraints[0].rc_id == "RC-2-1"
    )
    assert normalized.responsibilities[0].control_actions[0].ca_id == "CA-1-1"
    assert normalized.responsibilities[1].feedback_channels[0].fb_id == "FB-2-1"
    assert normalized.responsibilities[0].control_actions[0].target is not None
    assert normalized.responsibilities[0].control_actions[0].target.id == "CP-2"
    assert normalized.coordination_links[0].link_id == "CL-1"
    assert normalized.coordination_links[0].shared_pm == "PM-1-1"
