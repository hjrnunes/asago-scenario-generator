"""Stage 2 keeps every control action's typed fields and refuses an untyped one.

The fixtures are a reviewed Klarna control structure and the revision reply a
saved run merged into it.  The reply restates RESP-1 and RESP-4: CA-1-1 comes
back with no target, effect, or temporality, and every restated action carries
the prompt's display labels in its description.
"""

from __future__ import annotations

import json
from pathlib import Path

from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.infra.yaml_io import read_yaml
from asago_scenario_generator.stpa.models.control_structure import (
    ControlActionEffectKind,
    ControlActionTemporality,
    ControlStructure,
    ReferenceType,
)
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.system_model.critic import (
    CriticFindings,
    RevisionDelta,
    _merge_revision_delta,
    _revision_delta_from_wire,
    _validate_revision_wire,
)
from asago_scenario_generator.stpa.system_model.heuristics import (
    untyped_control_actions,
)
from asago_scenario_generator.stpa.system_model.run import _run_stage_2_block
from tests.stpa.sp1_helpers import valid_loss_analysis_dict
from tests.stpa.test_unified_stage2 import (
    USE_CASE,
    _capability_profile,
    _stage2_mock_client,
)

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "stpa"


def _reviewed() -> ControlStructure:
    return read_yaml(  # type: ignore[return-value]
        FIXTURES_DIR / "control_structure_reviewed_klarna.yaml", ControlStructure
    )


def _restating_reply() -> dict:
    return json.loads(
        (FIXTURES_DIR / "revision_restated_actions_klarna.json").read_text(
            encoding="utf-8"
        )
    )


def _actions(structure: ControlStructure) -> dict:
    return {
        ca.ca_id: ca
        for resp in structure.responsibilities
        for ca in resp.control_actions
    }


def test_reply_restates_an_action_without_its_typed_fields() -> None:
    restated = {
        ca["ca_id"]: ca
        for resp in _restating_reply()["modified_responsibilities"]
        for ca in resp["control_actions"]
    }

    assert restated["CA-1-1"].get("target") is None
    assert restated["CA-1-1"].get("effect_kind") is None
    assert restated["CA-1-1"].get("temporality") is None


def test_revision_keeps_the_typed_fields_of_every_reviewed_action() -> None:
    reviewed = _reviewed()
    reply = _restating_reply()
    _validate_revision_wire(reply)

    merged, _ = _merge_revision_delta(reviewed, _revision_delta_from_wire(reply))

    merged_actions = _actions(merged)
    for ca_id, before in _actions(reviewed).items():
        after = merged_actions[ca_id]
        assert (after.target, after.effect_kind, after.temporality) == (
            before.target,
            before.effect_kind,
            before.temporality,
        ), ca_id
    response = merged_actions["CA-1-1"]
    assert response.target is not None
    assert response.target.type is ReferenceType.controlled_process
    assert response.target.id == "CP-1"
    assert response.effect_kind is ControlActionEffectKind.model_output
    assert response.temporality is ControlActionTemporality.instantaneous


def test_a_typed_structure_passes_the_final_check() -> None:
    assert untyped_control_actions(_reviewed()) == []


def test_final_check_names_each_action_and_its_missing_fields() -> None:
    structure = _reviewed()
    response = structure.responsibilities[0].control_actions[0]
    response.target = None
    response.effect_kind = None
    response.temporality = None

    assert untyped_control_actions(structure) == [
        "control action CA-1-1 of RESP-1 lacks target, effect_kind"
    ]


def test_final_check_does_not_require_temporality() -> None:
    structure = _reviewed()
    structure.responsibilities[0].control_actions[0].temporality = None

    assert untyped_control_actions(structure) == []


def test_stage_2_refuses_a_final_structure_with_an_untyped_action(tmp_path) -> None:
    client, _ = _stage2_mock_client()
    client.set_response_for(
        CriticFindings,
        {
            "gaps": [
                {
                    "gap_type": "missing_responsibility",
                    "description": "No controller escalates regulated topics",
                    "related_attack_path": "A regulated question is answered",
                    "suggested_remedy": "Add an escalation responsibility",
                }
            ],
            "checklist_results": {},
            "taxonomy_probe_results": {},
        },
    )
    client.set_response_for(
        RevisionDelta,
        {
            "new_responsibilities": [
                {
                    "resp_id": "RESP-9",
                    "description": "Escalate regulated topics to a human agent",
                    "process_model_parts": [
                        {"pm_id": "PM-9-1", "description": "Topic is regulated"}
                    ],
                    "control_actions": [
                        {"ca_id": "CA-9-1", "description": "Hand over to an agent"}
                    ],
                    "feedback_channels": [
                        {
                            "fb_id": "FB-9-1",
                            "description": "Customer message",
                            "updates": "PM-9-1",
                            "source": {"type": "responsibility", "id": "RESP-1"},
                        }
                    ],
                }
            ],
            "new_controlled_processes": [],
            "new_coordination_links": [],
            "modified_responsibilities": [],
            "dismissed_gaps": [],
        },
    )
    stage_errors: list[str] = []

    result = _run_stage_2_block(
        client,
        USE_CASE,
        LossAnalysis.model_validate(valid_loss_analysis_dict()),
        _capability_profile(),
        tmp_path,
        TemplateLoader(PROMPTS_DIR),
        0.4,
        stage_errors,
        [],
    )

    # The added responsibility is published as the structure's second one.
    assert result.control_structure is None
    assert stage_errors == [
        "stage_2/typed_control_actions: control action CA-2-1 of RESP-2 lacks "
        "target, effect_kind"
    ]
    assert not (tmp_path / "control-structure.yaml").exists()
    refused = read_yaml(tmp_path / "control-structure-refused.yaml", ControlStructure)
    assert untyped_control_actions(refused) == [  # type: ignore[arg-type]
        "control action CA-2-1 of RESP-2 lacks target, effect_kind"
    ]
