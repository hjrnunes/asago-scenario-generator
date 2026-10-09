"""The model declares each constraint's behavior class from a closed list.

Code validates membership only; it never matches constraint text against
keywords.  Graphs that declare no class (pinned or historical) read as
unclassified and skip the class-ownership check.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.models.loss_analysis import (
    BEHAVIOR_CLASSES,
    LossAnalysis,
    SecurityConstraint,
)
from asago_scenario_generator.stpa.system_model import loss_analysis_gates as gates
from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.system_model.loss_analysis import (
    _ProviderConstraint,
    _RevisionConstraintAddition,
    _RevisionConstraintEdit,
    _Stage1aRevisionPatch,
)
from asago_scenario_generator.stpa.system_model.loss_analysis_gates import (
    UNCLASSIFIED,
    _revision_patch_to_draft,
    check_hazard_graph_density,
)
from asago_scenario_generator.stpa.infra.llm import _json_schema_response_format

CLASSES = (
    "disclosure",
    "unauthorized_write",
    "wrong_information",
    "missed_escalation",
    "harmful_or_discriminatory_output",
    "manipulation",
)


def _constraint(constraint_id: str, hazards: list[str], **extra) -> dict:
    return {
        "constraint_id": constraint_id,
        "rule": f"Neutral wording for {constraint_id}.",
        "applies_when": [],
        "related_hazards": hazards,
        **extra,
    }


def _analysis(constraints: list[dict], hazard_count: int = 2) -> LossAnalysis:
    return LossAnalysis.model_validate(
        {
            "risk_card_losses": [
                {
                    "loss_id": "L-1",
                    "description": "A loss.",
                    "provenance": "risk_card",
                    "source_risk_cards": ["atlas-001"],
                }
            ],
            "use_case_losses": [],
            "hazards": [
                {
                    "hazard_id": f"H-{index}",
                    "description": f"Hazard {index}.",
                    "related_losses": ["L-1"],
                }
                for index in range(1, hazard_count + 1)
            ],
            "security_constraints": constraints,
        }
    )


class TestModel:
    def test_the_class_list_is_closed(self) -> None:
        assert BEHAVIOR_CLASSES == CLASSES

    @pytest.mark.parametrize("name", CLASSES)
    def test_a_declared_class_round_trips(self, name: str) -> None:
        constraint = SecurityConstraint.model_validate(
            _constraint("SC-1", ["H-1"], behavior_class=name)
        )
        dumped = constraint.model_dump(mode="json", exclude_none=True)
        assert dumped["behavior_class"] == name
        assert SecurityConstraint.model_validate(dumped).behavior_class == name

    def test_a_class_outside_the_list_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            SecurityConstraint.model_validate(
                _constraint("SC-1", ["H-1"], behavior_class="other")
            )

    def test_an_undeclared_class_is_omitted_from_the_persisted_bytes(self) -> None:
        constraint = SecurityConstraint.model_validate(_constraint("SC-1", ["H-1"]))
        assert constraint.behavior_class is None
        assert "behavior_class" not in constraint.model_dump(mode="json")


def _wire_constraint(**extra) -> dict:
    return {
        "handle": "constraint_1",
        "rule": "Rule.",
        "applies_when": [],
        "related_hazards": ["hazard_1"],
        **extra,
    }


class TestProviderWire:
    @pytest.mark.parametrize("name", CLASSES)
    def test_provider_constraint_accepts_each_class(self, name: str) -> None:
        item = _ProviderConstraint.model_validate(_wire_constraint(behavior_class=name))
        assert item.behavior_class == name

    def test_provider_constraint_accepts_null_when_no_class_applies(self) -> None:
        item = _ProviderConstraint.model_validate(_wire_constraint(behavior_class=None))
        assert item.behavior_class is None

    def test_provider_constraint_rejects_an_unknown_class(self) -> None:
        with pytest.raises(ValidationError):
            _ProviderConstraint.model_validate(_wire_constraint(behavior_class="x"))

    @pytest.mark.parametrize(
        "model",
        [_ProviderConstraint, _RevisionConstraintAddition, _RevisionConstraintEdit],
    )
    def test_the_request_schema_lists_the_classes_and_allows_null(
        self, model: type
    ) -> None:
        node = _json_schema_response_format(model)["json_schema"]["schema"]
        text = json.dumps(node["properties"]["behavior_class"])
        for name in CLASSES:
            assert f'"{name}"' in text
        assert '"null"' in text

    def test_a_revision_edit_may_omit_the_class_to_keep_the_existing_one(self) -> None:
        edit = _RevisionConstraintEdit.model_validate(
            {
                "constraint_id": "SC-1",
                "rule": "Rule.",
                "applies_when": [],
                "related_hazards": ["H-1"],
            }
        )
        assert edit.behavior_class is None


class TestRevisionCarriesTheClass:
    def _prior(self) -> LossAnalysis:
        return _analysis(
            [_constraint("SC-1", ["H-1", "H-2"], behavior_class="disclosure")]
        )

    def _patch(self, **fields) -> _Stage1aRevisionPatch:
        return _Stage1aRevisionPatch.model_validate(
            {
                "hazard_edits": [],
                "hazard_additions": [],
                "security_constraint_edits": fields.get("edits", []),
                "security_constraint_additions": fields.get("additions", []),
            }
        )

    def test_an_edit_without_a_class_keeps_the_prior_class(self) -> None:
        edit = {
            "constraint_id": "SC-1",
            "rule": "Neutral wording for SC-1.",
            "applies_when": [],
            "related_hazards": ["H-1"],
        }
        draft = _revision_patch_to_draft(self._prior(), self._patch(edits=[edit]), [])
        assert draft.security_constraints[0].behavior_class == "disclosure"

    def test_an_edit_with_a_class_replaces_the_prior_class(self) -> None:
        edit = {
            "constraint_id": "SC-1",
            "rule": "Neutral wording for SC-1.",
            "applies_when": [],
            "related_hazards": ["H-1"],
            "behavior_class": "manipulation",
        }
        draft = _revision_patch_to_draft(self._prior(), self._patch(edits=[edit]), [])
        assert draft.security_constraints[0].behavior_class == "manipulation"

    def test_an_addition_carries_its_declared_class(self) -> None:
        addition = {
            "handle": "new_constraint",
            "rule": "Another neutral rule.",
            "applies_when": [],
            "related_hazards": ["H-2"],
            "behavior_class": "missed_escalation",
        }
        draft = _revision_patch_to_draft(
            self._prior(), self._patch(additions=[addition]), []
        )
        by_class = {c.behavior_class for c in draft.security_constraints}
        assert by_class == {"disclosure", "missed_escalation"}


class TestGateUsesTheDeclaredClass:
    def test_two_declared_classes_cannot_share_their_only_hazard(self) -> None:
        report = check_hazard_graph_density(
            _analysis(
                [
                    _constraint("SC-1", ["H-1"], behavior_class="disclosure"),
                    _constraint("SC-2", ["H-1"], behavior_class="manipulation"),
                ],
                hazard_count=1,
            )
        )
        checks = "\n".join(report.failing_checks)
        assert "behavior class disclosure has no hazard of its own" in checks
        assert "behavior class manipulation has no hazard of its own" in checks
        assert report.unclassified_constraints == ()

    def test_distinct_hazards_per_declared_class_pass(self) -> None:
        report = check_hazard_graph_density(
            _analysis(
                [
                    _constraint("SC-1", ["H-1"], behavior_class="disclosure"),
                    _constraint("SC-2", ["H-2"], behavior_class="manipulation"),
                ]
            )
        )
        assert report.passed
        assert report.constraint_classes == (
            ("SC-1", "disclosure"),
            ("SC-2", "manipulation"),
        )

    def test_constraint_text_never_decides_the_class(self) -> None:
        # The wording is full of keywords the deleted table matched.  With no
        # declaration the constraints are unclassified and the class check
        # does not run.
        text = "Never disclose, leak or expose PII; never refund or cancel."
        report = check_hazard_graph_density(
            _analysis(
                [
                    _constraint("SC-1", ["H-1"], rule=text),
                    _constraint("SC-2", ["H-1"], rule=text + " Again."),
                ],
                hazard_count=1,
            )
        )
        assert report.passed
        assert report.unclassified_constraints == ("SC-1", "SC-2")
        assert {name for _, name in report.constraint_classes} == {UNCLASSIFIED}

    def test_the_keyword_table_is_gone(self) -> None:
        for name in (
            "load_behavior_classes",
            "classify_constraint",
            "BehaviorClassTable",
            "default_behavior_classes_path",
        ):
            assert not hasattr(gates, name)
        root = Path(__file__).resolve().parents[2]
        assert not (root / "data" / "loss-analysis" / "behavior-classes.yaml").exists()


class TestPrompts:
    @pytest.mark.parametrize(
        "template",
        [
            "stage1a_risk_system.j2",
            "stage1a_gap_system.j2",
            "stage1a_graph_revision_system.j2",
        ],
    )
    def test_each_system_prompt_explains_every_class(self, template: str) -> None:
        text = TemplateLoader(PROMPTS_DIR).render_prompt(template)
        assert "behavior_class" in text
        for name in CLASSES:
            line = next(
                (item for item in text.splitlines() if f"`{name}`" in item), None
            )
            assert line is not None, name
            assert len(line.split("—")) == 2 and len(line.split("—")[1].split()) >= 4

    def test_the_prompts_name_no_keyword_list(self) -> None:
        text = TemplateLoader(PROMPTS_DIR).render_prompt("stage1a_risk_system.j2")
        assert "keyword" not in text.lower()


def test_pinned_loss_analysis_without_classes_still_loads(tmp_path: Path) -> None:
    analysis = _analysis([_constraint("SC-1", ["H-1"])], hazard_count=1)
    path = tmp_path / "pinned.yaml"
    path.write_text(
        yaml.safe_dump(analysis.model_dump(mode="json", exclude_none=True)),
        encoding="utf-8",
    )
    loaded = LossAnalysis.model_validate(yaml.safe_load(path.read_text()))
    assert loaded.security_constraints[0].behavior_class is None
