"""The rendered Stage 5 contract separates evidence, causes and outcomes."""

from asago_scenario_generator.stpa.models.causal_factor import CausalFactorKind
from asago_scenario_generator.stpa.scenario_prod.stage5.prompt_view import (
    _context_source_choices_yaml,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.wire import (
    _CausalSourceChoice,
)


def test_stage5_source_handles_remain_distinct_for_nearby_process_model_states():
    """Two process-model states retain separate explained request handles."""
    rendered = _context_source_choices_yaml(
        (
            _CausalSourceChoice(
                handle="cause_1",
                kind=CausalFactorKind.process_model_flaw,
                source_id="PM-3-1",
                description="Tool parameter schemas and constraints.",
            ),
            _CausalSourceChoice(
                handle="cause_2",
                kind=CausalFactorKind.process_model_flaw,
                source_id="PM-3-2",
                description="Status of requested tool execution.",
            ),
        ),
    )
    assert "source_handle: cause_1" in rendered
    assert "source_handle: cause_2" in rendered
    assert "Tool parameter schemas and constraints." in rendered
    assert "Status of requested tool execution." in rendered
