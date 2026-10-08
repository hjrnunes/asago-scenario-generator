"""Stage 5 sees each reachable capability with its evidence and access path."""

from __future__ import annotations

from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.models.scenario_context import ReachableCapability
from asago_scenario_generator.stpa.scenario_prod._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.scenario_prod.context import (
    build_scenario_generation_context,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.prompt_view import (
    build_context_bdi_prompts,
)
from tests.helpers.sp3_scenario_continuity import (
    _control_structure,
    _loss_analysis,
    _threat,
)

_MECHANISMS = (
    ("CAP-PROMPT", "prompt injection"),
    ("CAP-TOOL-RESULT", "tool result fabrication"),
    ("CAP-MEMORY", "memory poisoning"),
    ("CAP-AGENT", "agent impersonation"),
    ("CAP-RETRIEVAL", "retrieval poisoning"),
)


def test_every_reachable_capability_reaches_the_user_prompt() -> None:
    context = build_scenario_generation_context(
        _threat(),
        _control_structure(),
        _loss_analysis(),
        scenario_id="SCN-001",
        reachable_capabilities=tuple(
            ReachableCapability(
                capability_id=capability_id,
                description=description,
                evidence=f"The selected input path reaches {description}.",
                access_path=("RESP-1", "CP-1"),
            )
            for capability_id, description in _MECHANISMS
        ),
    )

    _, user = build_context_bdi_prompts(context, TemplateLoader(PROMPTS_DIR))

    for capability_id, description in _MECHANISMS:
        assert f"capability_ref: {capability_id}" in user
        assert f"description: {description}" in user
        assert f"evidence: The selected input path reaches {description}." in user
