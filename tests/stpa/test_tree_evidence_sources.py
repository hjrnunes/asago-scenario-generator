"""Exact structural sources that scenario trees may cite.

Validation and presentation collect the same defender and control-path
sources, but validation also accepts the scenario's target control action and
the path's controller and control action, while presentation adds the
selected lineage.  These tests pin both sets so neither widens silently.
"""

from __future__ import annotations

from asago_scenario_generator.stpa.models.causal_factor import (
    CausalFactor,
    CausalFactorKind,
)
from asago_scenario_generator.stpa.models.control_structure import ReferenceType
from asago_scenario_generator.stpa.models.scenario_context import (
    DescribedControlAction,
    DescribedElement,
    ScenarioControlPath,
    ScenarioCoordinationPath,
)
from asago_scenario_generator.stpa.models.scenario_spec import (
    AttackerBDI,
    DefenderBDI,
    DefenderBelief,
    DefenderDesire,
    DefenderIntention,
    ScenarioSpec,
)
from asago_scenario_generator.stpa.scenario_prod.presentation import (
    _allowed_tree_sources,
    _semantic_account,
    render_scenario_summary,
)
from asago_scenario_generator.stpa.scenario_prod.validators import (
    _allowed_tree_evidence_refs,
    validate_tree_factor_evidence_coverage,
)
from tests.helpers.stpa_producer_seams import _spec

_DEFENDER_SOURCES = {"PM-2-1", "PM-2-2", "RESP-2", "SC-2", "RESP-3", "CA-2-1"}
_FACTOR_SOURCES = {"FB-1-1", "PM-4-4"}


def _element(element_id: str) -> DescribedElement:
    return DescribedElement(element_id=element_id, description=f"{element_id} text")


def _responsibility_path() -> ScenarioControlPath:
    return ScenarioControlPath(
        controller=_element("RESP-9"),
        responsibility=_element("RESP-8"),
        control_action=DescribedControlAction(
            action_id="CA-9-1",
            description="Selected action",
            target_id="CP-1",
            target_kind=ReferenceType.controlled_process,
        ),
        controlled_process=_element("CP-1"),
        process_model_parts=(_element("PM-9-1"), _element("PM-9-2")),
        feedback=(_element("FB-9-1"),),
        related_control_actions=(
            DescribedControlAction(
                action_id="CA-9-2", description="Related action", target_id="CP-1"
            ),
        ),
    )


def _coordination_path() -> ScenarioControlPath:
    return ScenarioControlPath(
        controller=_element("RESP-7"),
        coordination_path=ScenarioCoordinationPath(
            link_id="CL-3",
            description="Coordination link",
            source=_element("RESP-5"),
            target=_element("RESP-6"),
            shared_process_model=_element("PM-5-1"),
            coordination_mechanism=_element("CM-4"),
        ),
        control_action=DescribedControlAction(
            action_id="CA-7-1",
            description="Coordinated action",
            target_id="CL-3",
            target_kind="coordination_path",
        ),
        process_model_parts=(_element("PM-7-1"),),
        feedback=(_element("FB-7-1"),),
    )


def _grounded_spec(path: ScenarioControlPath | None) -> ScenarioSpec:
    base = _spec()
    context = (
        None
        if path is None
        else base.scenario_context.model_copy(update={"target_control_path": path})
    )
    return base.model_copy(
        update={
            "target_controller": "RESP-1",
            "target_control_action": "CA-1-1",
            "defender_bdi": DefenderBDI(
                beliefs=[
                    DefenderBelief(pm_id="PM-2-1", content="State", vulnerability="v"),
                    DefenderBelief(pm_id="PM-2-2", content="State", vulnerability="v"),
                ],
                desires=[
                    DefenderDesire(
                        resp_id="RESP-2", content="Duty", constraint_id="SC-2"
                    ),
                    DefenderDesire(resp_id="RESP-3", content="Other duty"),
                ],
                intentions=[DefenderIntention(ca_id="CA-2-1", content="Act")],
            ),
            "causal_factors": [
                CausalFactor(
                    kind=CausalFactorKind.feedback_delay,
                    source_id="FB-1-1",
                    description="Feedback is delayed.",
                ),
                CausalFactor(
                    kind=CausalFactorKind.process_model_flaw,
                    source_id="PM-4-4",
                    description="State is stale.",
                ),
            ],
            "unsafe_outcome_hazard_refs": ["H-1"],
            "unsafe_outcome_constraint_refs": ["SC-1"],
            "scenario_context": context,
        }
    )


def test_validation_allows_responsibility_path_controller_and_actions():
    spec = _grounded_spec(_responsibility_path())

    assert _allowed_tree_evidence_refs(spec) == {
        *_FACTOR_SOURCES,
        *_DEFENDER_SOURCES,
        "CA-1-1",
        "RESP-9",
        "RESP-8",
        "CA-9-1",
        "CA-9-2",
        "PM-9-1",
        "PM-9-2",
        "FB-9-1",
    }


def test_validation_allows_coordination_path_endpoints():
    spec = _grounded_spec(_coordination_path())

    assert _allowed_tree_evidence_refs(spec) == {
        *_FACTOR_SOURCES,
        *_DEFENDER_SOURCES,
        "CA-1-1",
        "RESP-7",
        "CA-7-1",
        "PM-7-1",
        "FB-7-1",
        "CL-3",
        "RESP-5",
        "RESP-6",
        "PM-5-1",
        "CM-4",
    }


def test_validation_without_context_allows_factors_target_action_and_defender():
    spec = _grounded_spec(None)

    assert _allowed_tree_evidence_refs(spec) == {
        *_FACTOR_SOURCES,
        *_DEFENDER_SOURCES,
        "CA-1-1",
    }


def test_presentation_allows_responsibility_path_and_lineage():
    account = _semantic_account(_grounded_spec(_responsibility_path()))

    assert _allowed_tree_sources(account) == {
        *_FACTOR_SOURCES,
        *_DEFENDER_SOURCES,
        "RESP-9",
        "CA-9-1",
        "H-1",
        "SC-1",
        "L-1",
        "RESP-8",
        "CA-9-2",
        "PM-9-1",
        "PM-9-2",
        "FB-9-1",
    }


def test_presentation_allows_coordination_path_and_lineage():
    account = _semantic_account(_grounded_spec(_coordination_path()))

    assert _allowed_tree_sources(account) == {
        *_FACTOR_SOURCES,
        *_DEFENDER_SOURCES,
        "RESP-7",
        "CA-7-1",
        "H-1",
        "SC-1",
        "L-1",
        "PM-7-1",
        "FB-7-1",
        "CL-3",
        "RESP-5",
        "RESP-6",
        "PM-5-1",
        "CM-4",
    }


def test_presentation_without_context_allows_spec_lineage():
    account = _semantic_account(_grounded_spec(None))

    assert _allowed_tree_sources(account) == {
        *_FACTOR_SOURCES,
        *_DEFENDER_SOURCES,
        "RESP-1",
        "CA-1-1",
        "H-1",
        "SC-1",
    }


def _tree(*labels: str) -> dict:
    return {"branches": [{"label": label} for label in ("FB-1-1", *labels)]}


def test_validation_accepts_only_selected_sources_in_tree_text():
    spec = _grounded_spec(_coordination_path())

    accepted = validate_tree_factor_evidence_coverage(
        _tree("CA-1-1", "RESP-7", "CA-7-1", "CL-3", "CM-4", "RESP-5", "SC-2"),
        spec,
    )
    rejected = validate_tree_factor_evidence_coverage(
        _tree("RESP-1", "CA-9-1", "PM-9-1"), spec
    )

    assert accepted.passed, accepted.errors
    assert sorted(rejected.errors) == [
        f"Attack tree references unsupported causal bridge {reference}; "
        "only selected-path and declared-factor evidence is allowed."
        for reference in ("CA-9-1", "PM-9-1", "RESP-1")
    ]


def test_presentation_marks_only_unselected_actor_sources():
    spec = _grounded_spec(_coordination_path()).model_copy(
        update={
            "attacker_bdi": AttackerBDI(
                beliefs=["Exploit CL-3 through CM-4 and RESP-5"],
                desires=["Bypass CA-1-1"],
                intentions=["Reach RESP-7"],
            )
        }
    )

    _narrative, tree, _gherkin = render_scenario_summary(spec)

    actor_nodes = {
        node["category"]: node
        for node in tree["branches"][1]["children"]
        if node["category"].startswith("actor_")
    }
    assert "source_uncertainty" not in actor_nodes["actor_belief"]
    assert "source_uncertainty" not in actor_nodes["actor_intention"]
    assert actor_nodes["actor_desire"]["source_uncertainty"] == (
        "unsupported structural source omitted from tree label"
    )
    assert "CA-1-1" not in actor_nodes["actor_desire"]["label"]
