"""Focused unit tests for the decomposed scenario model validators."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from asago_scenario_generator.models.realization import _realization_cover_error
from asago_scenario_generator.models.scenario import (
    BehaviorAction,
    NarrativeStep,
    SemanticValidation,
    _actions_in_grouping_order,
    _applicable_claim_error,
    _candidate_hex_error,
    _category_counts,
    _duplicate_category_error,
    _extra_category_error,
    _grouped_step_ids,
    _has_duplicate_items,
    _invalid_projected_step_id,
    _known_step_ids,
    _missing_category_error,
    _missing_grouped_ids,
    _not_applicable_claim_error,
    _scenario_grouping_error,
    _unknown_grouped_ids,
)

_REQUIRED = frozenset({"entry_points", "tool_inventory"})


class TestProjectedStepIdHelpers:
    """Invalid-ID detection and duplicate detection for step ID lists."""

    def test_invalid_projected_step_id_none_for_valid_ids(self) -> None:
        assert _invalid_projected_step_id(("s1", "s2")) is None

    def test_invalid_projected_step_id_none_for_empty_list(self) -> None:
        assert _invalid_projected_step_id(()) is None

    def test_invalid_projected_step_id_returns_empty_string(self) -> None:
        assert _invalid_projected_step_id(("s1", "")) == ""

    def test_invalid_projected_step_id_returns_non_alnum_leading(self) -> None:
        assert _invalid_projected_step_id(("-s1",)) == "-s1"

    def test_invalid_projected_step_id_returns_first_bad(self) -> None:
        assert _invalid_projected_step_id(("s1", "", "s3")) == ""

    def test_has_duplicate_items_false_when_unique(self) -> None:
        assert _has_duplicate_items(("a", "b")) is False

    def test_has_duplicate_items_true_when_repeated(self) -> None:
        assert _has_duplicate_items(("a", "b", "a")) is True

    def test_has_duplicate_items_false_when_empty(self) -> None:
        assert _has_duplicate_items(()) is False


class TestScenarioGroupingHelpers:
    """BehaviorSpec scenario-grouping helpers."""

    @staticmethod
    def _step(*step_ids: str) -> SimpleNamespace:
        return SimpleNamespace(step_ids=step_ids)

    @staticmethod
    def _action(action_id: str) -> SimpleNamespace:
        return SimpleNamespace(action_id=action_id)

    @staticmethod
    def _assertion(assertion_id: str) -> SimpleNamespace:
        return SimpleNamespace(assertion_id=assertion_id)

    def test_grouped_step_ids_flattens_in_grouping_order(self) -> None:
        scenarios = (self._step("a1", "b1"), self._step("a2"))
        assert _grouped_step_ids(scenarios) == ("a1", "b1", "a2")

    def test_known_step_ids_unions_and_preserves_action_order(self) -> None:
        actions = (self._action("a2"), self._action("a1"))
        assertions = (self._assertion("b1"),)
        known, action_ids = _known_step_ids(actions, assertions)
        assert known == {"a1", "a2", "b1"}
        assert action_ids == ("a2", "a1")

    def test_unknown_grouped_ids_subtracts_known(self) -> None:
        grouped = ("a1", "ghost")
        assert _unknown_grouped_ids(grouped, {"a1"}) == {"ghost"}

    def test_unknown_grouped_ids_empty_when_all_known(self) -> None:
        assert _unknown_grouped_ids(("a1",), {"a1"}) == set()

    def test_missing_grouped_ids_returns_unplaced_known(self) -> None:
        assert _missing_grouped_ids(("a1",), {"a1", "b1"}) == {"b1"}

    def test_missing_grouped_ids_empty_when_all_placed(self) -> None:
        assert _missing_grouped_ids(("a1",), {"a1"}) == set()

    def test_actions_in_grouping_order_true_when_preserved(self) -> None:
        grouped = ("a1", "b1", "a2")
        assert _actions_in_grouping_order(grouped, ("a1", "a2")) is True

    def test_actions_in_grouping_order_false_when_reversed(self) -> None:
        grouped = ("a2", "b1", "a1")
        assert _actions_in_grouping_order(grouped, ("a1", "a2")) is False

    def test_grouping_error_none_when_valid(self) -> None:
        scenarios = (self._step("a1", "b1", "a2"),)
        actions = (self._action("a1"), self._action("a2"))
        assertions = (self._assertion("b1"),)
        assert _scenario_grouping_error(scenarios, actions, assertions) is None

    def test_grouping_error_unknown_step_id(self) -> None:
        scenarios = (self._step("ghost"),)
        error = _scenario_grouping_error(scenarios, (), ())
        assert error is not None
        assert "unknown step IDs" in error

    def test_grouping_error_duplicate_placement(self) -> None:
        scenarios = (self._step("a1", "a1"),)
        actions = (self._action("a1"),)
        error = _scenario_grouping_error(scenarios, actions, ())
        assert error is not None
        assert "exactly once" in error

    def test_grouping_error_missing_step(self) -> None:
        scenarios = (self._step("a1"),)
        actions = (self._action("a1"), self._action("a2"))
        error = _scenario_grouping_error(scenarios, actions, ())
        assert error is not None
        assert "omit canonical step IDs" in error

    def test_grouping_error_order_violation(self) -> None:
        scenarios = (self._step("a2", "a1"),)
        actions = (self._action("a1"), self._action("a2"))
        error = _scenario_grouping_error(scenarios, actions, ())
        assert error is not None
        assert "preserve canonical action order" in error


class TestCorpusClaimStatusHelpers:
    """Payload coherence errors for applicable/not_applicable claims."""

    def test_applicable_claim_error_none_when_valid(self) -> None:
        assert _applicable_claim_error("entry_points", None, ("evidence 1",)) is None

    def test_applicable_claim_error_reason_present(self) -> None:
        error = _applicable_claim_error("entry_points", "why", ("e",))
        assert error is not None
        assert "must not carry a reason" in error

    def test_applicable_claim_error_no_evidence(self) -> None:
        error = _applicable_claim_error("entry_points", None, ())
        assert error is not None
        assert "requires at least one" in error

    def test_applicable_claim_error_blank_evidence(self) -> None:
        error = _applicable_claim_error("entry_points", None, ("e", "   "))
        assert error is not None
        assert "blank/whitespace-only" in error

    def test_not_applicable_claim_error_none_when_valid(self) -> None:
        assert _not_applicable_claim_error("entry_points", "because", ()) is None

    def test_not_applicable_claim_error_missing_reason(self) -> None:
        error = _not_applicable_claim_error("entry_points", None, ())
        assert error is not None
        assert "nonblank reason" in error

    def test_not_applicable_claim_error_blank_reason(self) -> None:
        error = _not_applicable_claim_error("entry_points", "   ", ())
        assert error is not None
        assert "nonblank reason" in error

    def test_not_applicable_claim_error_evidence_present(self) -> None:
        error = _not_applicable_claim_error("entry_points", "because", ("e",))
        assert error is not None
        assert "must not carry evidence" in error


class TestCorpusCompletenessHelpers:
    """Corpus claim category completeness errors."""

    @staticmethod
    def _claim(category_value: str) -> SimpleNamespace:
        return SimpleNamespace(category=SimpleNamespace(value=category_value))

    def test_category_counts_counts_records_per_value(self) -> None:
        claims = (
            self._claim("entry_points"),
            self._claim("tool_inventory"),
            self._claim("entry_points"),
        )
        assert _category_counts(claims) == {
            "entry_points": 2,
            "tool_inventory": 1,
        }

    def test_category_counts_empty(self) -> None:
        assert _category_counts(()) == {}

    def test_missing_category_error_none_when_complete(self) -> None:
        counts = {"entry_points": 1, "tool_inventory": 1}
        assert _missing_category_error(counts, _REQUIRED) is None

    def test_missing_category_error_reports_absent(self) -> None:
        error = _missing_category_error({"entry_points": 1}, _REQUIRED)
        assert error is not None
        assert "missing required category" in error

    def test_duplicate_category_error_none_when_unique(self) -> None:
        counts = {"entry_points": 1, "tool_inventory": 1}
        assert _duplicate_category_error(counts) is None

    def test_duplicate_category_error_reports_repeats(self) -> None:
        error = _duplicate_category_error({"entry_points": 2})
        assert error is not None
        assert "duplicate category" in error

    def test_extra_category_error_none_when_closed(self) -> None:
        counts = {"entry_points": 1, "tool_inventory": 1}
        assert _extra_category_error(counts, _REQUIRED) is None

    def test_extra_category_error_reports_unexpected(self) -> None:
        error = _extra_category_error({"other": 1}, _REQUIRED)
        assert error is not None
        assert "unexpected category" in error


class TestCandidateIdHexHelper:
    """candidate_id hex-part validation errors."""

    def test_candidate_hex_error_none_for_valid_hex(self) -> None:
        assert _candidate_hex_error("ab" * 16) is None

    def test_candidate_hex_error_wrong_length(self) -> None:
        error = _candidate_hex_error("ab" * 15)
        assert error is not None
        assert "must be 32 chars" in error

    def test_candidate_hex_error_uppercase_rejected(self) -> None:
        error = _candidate_hex_error("AB" * 16)
        assert error is not None
        assert "must be lowercase" in error

    def test_candidate_hex_error_invalid_hex_rejected(self) -> None:
        error = _candidate_hex_error("zz" + "ab" * 15)
        assert error is not None
        assert "must be valid hex" in error


class TestRealizationCoverError:
    """Shared realization-coverage message helper."""

    @staticmethod
    def _realization(projected_step_id: str) -> SimpleNamespace:
        return SimpleNamespace(projected_step_id=projected_step_id)

    def test_none_when_exact_cover(self) -> None:
        realizations = (self._realization("s1"), self._realization("s2"))
        assert _realization_cover_error(realizations, ("s1", "s2"), "subject") is None

    def test_none_when_both_empty(self) -> None:
        assert _realization_cover_error((), (), "subject") is None

    def test_duplicate_records_error(self) -> None:
        realizations = (self._realization("s1"), self._realization("s1"))
        error = _realization_cover_error(realizations, ("s1",), "subject")
        assert error is not None
        assert "duplicate realization records" in error

    def test_count_mismatch_error(self) -> None:
        realizations = (self._realization("s1"),)
        error = _realization_cover_error(realizations, ("s1", "s2"), "subject")
        assert error is not None
        assert "exactly one record per projected_step_id" in error

    def test_id_mismatch_error(self) -> None:
        realizations = (self._realization("s9"),)
        error = _realization_cover_error(realizations, ("s1",), "subject")
        assert error is not None
        assert "do not match projected_step_ids" in error

    def test_subject_appears_in_messages(self) -> None:
        realizations = (self._realization("s1"), self._realization("s1"))
        error = _realization_cover_error(realizations, ("s1",), "narrative step 3")
        assert error is not None
        assert error.startswith("narrative step 3")


class TestProjectedStepIdValidators:
    """NarrativeStep/BehaviorAction validator raise paths."""

    @staticmethod
    def _narrative_step(**overrides: object) -> NarrativeStep:
        base: dict[str, object] = {
            "step_number": 1,
            "projected_step_ids": ("s1",),
            "realizations": (),
        }
        base.update(overrides)
        return NarrativeStep.model_construct(**base)

    @staticmethod
    def _behavior_action(**overrides: object) -> BehaviorAction:
        base: dict[str, object] = {
            "action_id": "a1",
            "projected_step_ids": ("s1",),
            "realizations": (),
        }
        base.update(overrides)
        return BehaviorAction.model_construct(**base)

    @pytest.mark.parametrize("validator", ["_narrative_step", "_behavior_action"])
    def test_valid_record_passes(self, validator: str) -> None:
        model = getattr(self, validator)()
        assert model._validate_projected_step_ids() is model

    @pytest.mark.parametrize("validator", ["_narrative_step", "_behavior_action"])
    def test_rejects_invalid_step_id(self, validator: str) -> None:
        model = getattr(self, validator)(projected_step_ids=("-s1",))
        with pytest.raises(ValueError, match="contains invalid ID"):
            model._validate_projected_step_ids()

    @pytest.mark.parametrize("validator", ["_narrative_step", "_behavior_action"])
    def test_rejects_duplicate_step_ids(self, validator: str) -> None:
        model = getattr(self, validator)(projected_step_ids=("s1", "s1"))
        with pytest.raises(ValueError, match="duplicate projected_step_ids"):
            model._validate_projected_step_ids()

    @pytest.mark.parametrize("validator", ["_narrative_step", "_behavior_action"])
    def test_rejects_duplicate_realization_records(self, validator: str) -> None:
        model = getattr(self, validator)(
            realizations=(SimpleNamespace(projected_step_id="s1"),) * 2
        )
        with pytest.raises(ValueError, match="duplicate realization records"):
            model._validate_projected_step_ids()

    @pytest.mark.parametrize("validator", ["_narrative_step", "_behavior_action"])
    def test_rejects_uncovered_realizations(self, validator: str) -> None:
        model = getattr(self, validator)(
            realizations=(SimpleNamespace(projected_step_id="s9"),)
        )
        with pytest.raises(ValueError, match="do not match projected_step_ids"):
            model._validate_projected_step_ids()

    @pytest.mark.parametrize("validator", ["_narrative_step", "_behavior_action"])
    def test_rejects_realization_count_mismatch(self, validator: str) -> None:
        model = getattr(self, validator)(
            realizations=(SimpleNamespace(projected_step_id="s1"),),
            projected_step_ids=("s1", "s2"),
        )
        with pytest.raises(ValueError, match="exactly one record"):
            model._validate_projected_step_ids()


class TestCorpusCompletenessValidator:
    """SemanticValidation._validate_corpus_claim_completeness raise paths."""

    @staticmethod
    def _claim(category_value: str) -> SimpleNamespace:
        return SimpleNamespace(category=SimpleNamespace(value=category_value))

    def _validation(self, *claims: SimpleNamespace) -> SemanticValidation:
        return SemanticValidation.model_construct(
            corpus_claim_applicability=claims
        )

    def test_valid_completeness_passes(self) -> None:
        validation = self._validation(
            self._claim("entry_points"), self._claim("tool_inventory")
        )
        assert validation._validate_corpus_claim_completeness() is validation

    def test_rejects_missing_category(self) -> None:
        validation = self._validation(self._claim("entry_points"))
        with pytest.raises(ValueError, match="missing required category"):
            validation._validate_corpus_claim_completeness()

    def test_rejects_duplicate_category(self) -> None:
        validation = self._validation(
            self._claim("entry_points"),
            self._claim("entry_points"),
            self._claim("tool_inventory"),
        )
        with pytest.raises(ValueError, match="duplicate category"):
            validation._validate_corpus_claim_completeness()

    def test_rejects_extra_category(self) -> None:
        validation = self._validation(
            self._claim("entry_points"),
            self._claim("tool_inventory"),
            self._claim("other"),
        )
        with pytest.raises(ValueError, match="unexpected category"):
            validation._validate_corpus_claim_completeness()
