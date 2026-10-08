"""One neutral-brief builder serves routing, the hub, and the pipeline."""

from __future__ import annotations

import pytest

from asago_scenario_generator.models.attack_pattern_chain import AttackPattern
from asago_scenario_generator.pipeline import obligation_consideration as pipeline
from asago_scenario_generator.stpa.obligation_aware import briefs as shared
from asago_scenario_generator.stpa.obligation_aware import routing
from tests.helpers.obligation_factory import make_plan
from tests.helpers.projection_factory import get_test_raw_pattern


def _pattern() -> AttackPattern:
    return AttackPattern.model_validate(get_test_raw_pattern())


def test_every_public_builder_name_is_the_shared_function() -> None:
    assert routing.build_neutral_briefs is shared.build_neutral_briefs
    assert routing.build_neutral_brief is shared.build_neutral_brief
    assert routing.create_obligation_batches is shared.create_obligation_batches
    assert pipeline.build_neutral_briefs is shared.build_neutral_briefs


def test_the_pipeline_batches_under_its_own_name_only() -> None:
    assert "create_obligation_batches" not in pipeline.__all__
    assert not hasattr(pipeline, "create_obligation_batches")
    assert "batch_neutral_obligation_briefs" in pipeline.__all__


def test_a_catalog_may_be_a_sequence_or_a_mapping_of_the_same_patterns() -> None:
    plan, pattern = make_plan(), _pattern()

    as_tuple = shared.build_neutral_briefs(plan, (pattern,))
    as_mapping = shared.build_neutral_briefs(plan, {pattern.id: pattern})

    assert as_tuple == as_mapping
    assert [b.semantic_digest for b in as_tuple] == [
        b.semantic_digest for b in as_mapping
    ]


@pytest.mark.parametrize(
    ("catalog", "error", "message"),
    [
        ("not a catalog", TypeError, "must contain AttackPattern values"),
        ((object(),), TypeError, "must contain AttackPattern values"),
        (
            (_pattern(), _pattern()),
            ValueError,
            "attack pattern catalog contains duplicate id",
        ),
    ],
)
def test_a_malformed_catalog_is_rejected(catalog, error, message) -> None:
    with pytest.raises(error, match=message):
        shared.build_neutral_briefs(make_plan(), catalog)


def test_the_pipeline_batcher_checks_the_batch_size_before_the_briefs() -> None:
    with pytest.raises(ValueError, match="max_batch_size must be positive"):
        pipeline.batch_neutral_obligation_briefs("not briefs", 0)
    with pytest.raises(TypeError, match="briefs must be an iterable"):
        pipeline.batch_neutral_obligation_briefs("not briefs", 1)


def test_only_the_pipeline_batcher_checks_brief_integrity() -> None:
    brief = shared.build_neutral_briefs(make_plan(), (_pattern(),))[0]
    stale = brief.model_copy(update={"obligation_id": "ob:v1:" + "f" * 64})

    assert shared.create_obligation_batches((stale,), 1) == ((stale,),)
    with pytest.raises(ValueError, match="digest mismatch"):
        pipeline.batch_neutral_obligation_briefs((stale,), 1)
