"""Stage 5 keeps the unsafe reason the selected unsafe control action states.

Saved handoffs showed failure criteria that replaced a permission, identity or
verification reason with an eligibility, amount or record-state condition,
although the request carried the reason verbatim. Each case below takes its
statement and hazardous context from such a handoff: the reason reaches the
model unchanged, and the system prompt asks it to test that reason.
"""

from __future__ import annotations

import re

import pytest
import yaml

from asago_scenario_generator.stpa.infra.templates import TemplateLoader
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

STATED_REASONS = {
    "session-authorization": (
        "Execute financial operations including refunds and payment "
        "scheduling. provides 'Process a customer refund' with an unsafe "
        "value/effect because the request is not authorized for the session.",
        "an unauthorized refund is processed",
    ),
    "unauthorized-actor": (
        "Modify existing booking details. provides 'Invoke modify_booking "
        "operation' with an unsafe value/effect because the actor is "
        "unauthorized.",
        "a booking modification is executed by an unauthorized actor",
    ),
    "unknown-ownership": (
        "Select and execute backend operations to manage orders, payments, and "
        "refunds. provides 'Process refund' with an unsafe value/effect because "
        "the resource ownership is unknown.",
        "a refund is processed for an order or plan where ownership cannot be verified",
    ),
    "unverified-identity": (
        "Execute financial transactions including refund processing and "
        "payment scheduling. provides 'Process a refund' with an unsafe "
        "value/effect because the transaction target identity is unknown.",
        "a refund is processed for an identity that is not verified",
    ),
}


def _collapse(text: str) -> str:
    return re.sub(r"\s+", " ", text)


def _rendered_uca(user: str) -> dict:
    """The ``unsafe_control_action`` block of the rendered context YAML."""
    start = user.index("unsafe_control_action:")
    end = user.index("\nselected_control_path:", start)
    return yaml.safe_load(user[start:end])["unsafe_control_action"]


@pytest.mark.parametrize("case", sorted(STATED_REASONS))
def test_stage5_request_carries_the_stated_reason_and_asks_to_test_it(
    case: str,
) -> None:
    statement, hazardous_context = STATED_REASONS[case]
    threat = _threat().model_copy(
        update={"ica_text": statement, "hazardous_context": hazardous_context}
    )
    context = build_scenario_generation_context(
        threat, _control_structure(), _loss_analysis(), scenario_id="SCN-001"
    )

    system, user = build_context_bdi_prompts(context, TemplateLoader(PROMPTS_DIR))

    uca = _rendered_uca(user)
    assert uca["statement"] == statement
    assert uca["hazardous_context"] == hazardous_context
    instruction = _collapse(system)
    assert (
        "The unsafe control action's `statement` and `hazardous_context` give "
        "the reason the action is unsafe. The `semantic_proposition` tests "
        "that same reason"
    ) in instruction
    assert (
        "Do not replace the stated reason with one the statement does not give, "
        "such as an eligibility status, an amount limit or a record state"
    ) in instruction
