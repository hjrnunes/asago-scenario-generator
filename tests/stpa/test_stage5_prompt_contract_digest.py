"""The Stage 5 prompts render the observation contract without its digest.

The digest identifies the contract file for code checks; the model has no
use for it, and rendering it moves every Stage 5 request whenever any
contract byte changes, including bytes the prompt does not otherwise show.
"""

from __future__ import annotations

from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.observation_contract import (
    default_observation_contract,
)
from asago_scenario_generator.stpa.scenario_prod._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.scenario_prod.stage5.prompt_view import (
    build_context_bdi_prompts,
)
from tests.helpers.normal_authoring_wire import _wrong_timing_context


def test_stage5_prompts_render_the_contract_without_its_digest() -> None:
    contract = default_observation_contract()
    assert contract.content_digest

    system, user = build_context_bdi_prompts(
        _wrong_timing_context(),
        TemplateLoader(PROMPTS_DIR),
        observation_contract=contract,
    )

    for prompt in (system, user):
        assert contract.contract_id in prompt
        assert "content_digest" not in prompt
        assert contract.content_digest not in prompt
