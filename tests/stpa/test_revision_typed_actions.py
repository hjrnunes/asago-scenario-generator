"""Stage 2 keeps every control action's typed fields and refuses an untyped one.

The fixtures are a reviewed Klarna control structure and the revision reply a
saved run merged into it.  The reply restates RESP-1 and RESP-4: CA-1-1 comes
back with no target, effect, or temporality, and every restated action carries
the prompt's display labels in its description.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from asago_scenario_generator.stpa.infra.llm_helpers import StageError
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.infra.yaml_io import VersionChain, read_yaml
from asago_scenario_generator.stpa.models.control_structure import (
    ControlActionEffectKind,
    ControlActionTemporality,
    ControlStructure,
    ReferenceType,
)
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.system_model.control_structure import (
    ControlElementSet,
    CoordinationAnalysis,
    derive_control_structure,
)
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
from asago_scenario_generator.stpa.system_model.publication import (
    publish_control_structure,
)
from asago_scenario_generator.stpa.system_model.run import _run_stage_2_block
from tests.stpa.sp1_helpers import (
    valid_empty_coordination_analysis_dict,
    valid_loss_analysis_dict,
)
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


def _restated_action(reply: dict, ca_id: str) -> dict:
    return next(
        ca
        for resp in reply["modified_responsibilities"]
        for ca in resp["control_actions"]
        if ca["ca_id"] == ca_id
    )


def _merged(reply: dict) -> ControlStructure:
    _validate_revision_wire(reply)
    merged, _ = _merge_revision_delta(_reviewed(), _revision_delta_from_wire(reply))
    return merged


def test_revision_keeps_an_explicit_temporality_change() -> None:
    reply = _restating_reply()
    _restated_action(reply, "CA-1-1")["temporality"] = "discrete"
    _restated_action(reply, "CA-4-1")["temporality"] = "continuous"

    actions = _actions(_merged(reply))

    assert actions["CA-1-1"].temporality is ControlActionTemporality.discrete
    assert actions["CA-1-1"].effect_kind is ControlActionEffectKind.model_output
    assert actions["CA-4-1"].temporality is ControlActionTemporality.continuous


def test_retargeted_action_without_an_effect_keeps_none_and_is_refused(
    tmp_path,
) -> None:
    reply = _restating_reply()
    _restated_action(reply, "CA-1-1")["target"] = {
        "type": "controlled_process",
        "id": "CP-2",
    }

    merged = _merged(reply)
    retargeted = _actions(merged)["CA-1-1"]

    assert retargeted.target is not None
    assert retargeted.target.id == "CP-2"
    assert retargeted.effect_kind is None
    with VersionChain(tmp_path) as versions:
        with pytest.raises(StageError) as refused:
            publish_control_structure(versions, merged, tmp_path)
    assert str(refused.value) == (
        "stage_2/typed_control_actions: control action CA-1-1 of RESP-1 lacks "
        "effect_kind"
    )


def test_refusal_removes_an_earlier_canonical_structure(tmp_path) -> None:
    stale = tmp_path / "control-structure.yaml"
    stale.write_text("responsibilities: []\n", encoding="utf-8")
    structure = _reviewed()
    structure.responsibilities[0].control_actions[0].effect_kind = None

    with VersionChain(tmp_path) as versions:
        with pytest.raises(StageError):
            publish_control_structure(versions, structure, tmp_path)

    assert not stale.exists()
    assert (
        read_yaml(tmp_path / "control-structure-refused.yaml", ControlStructure)
        == structure
    )


def test_a_typed_structure_is_published_as_the_canonical_file(tmp_path) -> None:
    with VersionChain(tmp_path) as versions:
        path = publish_control_structure(versions, _reviewed(), tmp_path)

    assert path == tmp_path / "control-structure.yaml"
    assert read_yaml(path, ControlStructure) == _reviewed()
    assert not (tmp_path / "control-structure-refused.yaml").exists()


# Call 2b may leave ``effect_kind`` out for a controlled-process target, and the
# Call 3 semantic review, whose effect is the one in force, may keep it unknown.
_UNTYPED_CALL_2B = {
    "control_actions": [
        {
            "ca_id": "CA-1-1",
            "description": "Send the reply",
            "target": {"type": "controlled_process", "id": "CP-1"},
        }
    ],
    "feedback": [
        {
            "fb_id": "FB-1-1",
            "description": "Action result",
            "updates": "PM-1-1",
            "source": {"type": "controlled_process", "id": "CP-1"},
        }
    ],
    "controlled_processes": [{"cp_id": "CP-1", "description": "Conversation"}],
}

_UNTYPED_ERROR = (
    "stage_2/typed_control_actions: control action CA-1-1 of RESP-1 lacks effect_kind"
)


def _untyped_stage2_client():
    client, _ = _stage2_mock_client()
    client.set_response_for(ControlElementSet, _UNTYPED_CALL_2B)
    review = valid_empty_coordination_analysis_dict(
        constraint_ids=("SC-1", "SC-2"), hazard_ids=("H-1", "H-2")
    )
    [action] = review["semantic_review"]["actions"]
    action["effect_kind"] = None
    action["rationale"] = "The use case does not say what the reply changes."
    client.set_response_for(CoordinationAnalysis, review)
    return client


def _stage_2(client, run_dir: Path) -> tuple[object, list[str]]:
    stage_errors: list[str] = []
    result = _run_stage_2_block(
        client,
        USE_CASE,
        LossAnalysis.model_validate(valid_loss_analysis_dict()),
        _capability_profile(),
        run_dir,
        TemplateLoader(PROMPTS_DIR),
        0.4,
        stage_errors,
        [],
    )
    return result, stage_errors


def test_stage_2_refuses_an_untyped_action_without_a_revision(tmp_path) -> None:
    (tmp_path / "control-structure.yaml").write_text("stale\n", encoding="utf-8")
    client = _untyped_stage2_client()

    result, stage_errors = _stage_2(client, tmp_path)

    # Calls 1, 2a, 2b and 3, then the critic; no gap, so no revision.
    assert len(client.calls) == 5
    assert result.control_structure is None  # type: ignore[attr-defined]
    assert stage_errors == [_UNTYPED_ERROR]
    assert not (tmp_path / "control-structure.yaml").exists()
    assert (tmp_path / "control-structure-refused.yaml").exists()


def test_stage_2_refuses_an_untyped_action_after_a_discarded_revision(
    tmp_path,
) -> None:
    client = _untyped_stage2_client()
    client.set_response_for(
        CriticFindings,
        {
            "gaps": [
                {
                    "gap_type": "missing_feedback",
                    "description": "The reply has no delivery feedback",
                    "related_attack_path": "A reply is lost unnoticed",
                    "suggested_remedy": "Add delivery feedback",
                }
            ],
            "checklist_results": {},
            "taxonomy_probe_results": {},
        },
    )
    # The merged structure names an unknown process, so the reply and its
    # correction are rejected and the pre-revision structure, with its untyped
    # action, stays in force.
    client.set_response_for(
        RevisionDelta,
        {
            "new_responsibilities": [],
            "new_controlled_processes": [],
            "new_coordination_links": [
                {
                    "link_id": "CL-1",
                    "source": "RESP-1",
                    "target": "CP-9",
                    "shared_pm": "PM-1-1",
                    "coordination_mechanism": {
                        "cm_id": "CM-1",
                        "description": "Share delivery state",
                        "payload": "delivery status",
                    },
                    "description": "Report reply delivery",
                }
            ],
            "modified_responsibilities": [],
            "dismissed_gaps": [],
        },
    )

    result, stage_errors = _stage_2(client, tmp_path)

    # Calls 1, 2a, 2b and 3, the critic, the revision and its correction.
    assert len(client.calls) == 7
    assert result.control_structure is None  # type: ignore[attr-defined]
    assert stage_errors == [_UNTYPED_ERROR]
    assert not (tmp_path / "control-structure.yaml").exists()
    refused = read_yaml(tmp_path / "control-structure-refused.yaml", ControlStructure)
    assert refused.coordination_links == []  # type: ignore[attr-defined]


def test_standalone_derivation_refuses_an_untyped_action(tmp_path) -> None:
    (tmp_path / "control-structure.yaml").write_text("stale\n", encoding="utf-8")

    with pytest.raises(StageError) as refused:
        derive_control_structure(
            llm_client=_untyped_stage2_client(),
            use_case_text=USE_CASE,
            loss_analysis=LossAnalysis.model_validate(valid_loss_analysis_dict()),
            capability_profile=_capability_profile(),
            run_dir=tmp_path,
        )

    assert str(refused.value) == _UNTYPED_ERROR
    assert not (tmp_path / "control-structure.yaml").exists()
    assert (tmp_path / "control-structure-refused.yaml").exists()
