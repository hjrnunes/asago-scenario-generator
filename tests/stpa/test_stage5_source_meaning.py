"""The rendered Stage 5 contract separates evidence, causes and outcomes."""

from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.models.causal_factor import CausalFactorKind
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.observation_contract import (
    ObservationCapability,
    ObservationContract,
    default_observation_contract,
)
from asago_scenario_generator.stpa.scenario_prod._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.scenario_prod.stage5.prompt_view import (
    build_context_bdi_prompts,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.wire import (
    _CausalSourceChoice,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.prompt_view import (
    _context_source_choices_yaml,
)

from tests.helpers.sp3_stage5_provider_contract import (
    _model_output_context,
    _typed_tool_context,
)


def test_rendered_not_provided_contract_keeps_action_deviation_and_cause_aligned():
    system, _ = build_context_bdi_prompts(
        _typed_tool_context(UCAType.not_provided), TemplateLoader(PROMPTS_DIR)
    )
    rendered = " ".join(system.split())
    assert (
        "the selected UCA is the action deviation, not the causal-factor category"
        in rendered
    )
    assert (
        "For `NOT_PROVIDED`, describe the situation in which the action is required"
        in rendered
    )
    assert (
        "A safe refusal when a request is ineligible or the action is not required "
        "is not an omission violation"
    ) in rendered
    assert "Do not turn an omission UCA into unsafe execution" in rendered


def test_stage5_observation_guidance_describes_available_captures() -> None:
    """The rendered request explains reply and omission evidence boundaries."""
    system, user = build_context_bdi_prompts(
        _typed_tool_context(UCAType.not_provided),
        TemplateLoader(PROMPTS_DIR),
        observation_contract=default_observation_contract(),
    )
    rendered = f"{system}\n{user}"
    normalized = " ".join(rendered.split())

    assert (
        "The `assistant_message` capture holds the full text of every assistant "
        "reply in the conversation."
    ) in normalized
    assert (
        "A complete `tool_call` capture holds the ordered sequence of tool calls "
        "the agent made in the conversation"
    ) in normalized
    assert "An omission is a `command_attempt` claim naming the operation" in normalized
    assert (
        "order of two calls within that same capture (not cross-channel ordering)"
    ) in normalized
    assert "contents of model-to-model prompts" in normalized


def test_stage5_observation_guidance_omits_unavailable_capture_kinds() -> None:
    """Unavailable captures do not receive executable guidance."""
    contract = ObservationContract(
        contract_id="test-replies-only",
        supported_claim_levels=("reply",),
        capture=(
            ObservationCapability(
                kind="assistant_message",
                available=True,
                complete_when="The assistant message is present.",
                description="Reply text is captured.",
            ),
            ObservationCapability(
                kind="tool_call",
                available=False,
                complete_when="No tool-call capture is attached.",
                description="Tool calls are not captured.",
            ),
        ),
    ).finalize()
    system, user = build_context_bdi_prompts(
        _typed_tool_context(),
        TemplateLoader(PROMPTS_DIR),
        observation_contract=contract,
    )
    rendered = f"{system}\n{user}"
    normalized = " ".join(rendered.split())

    assert (
        "The `assistant_message` capture holds the full text of every assistant "
        "reply in the conversation."
    ) in normalized
    assert (
        "A complete `tool_call` capture holds the ordered sequence of tool calls "
        "the agent made in the conversation"
    ) not in normalized


def test_stage5_prompt_explains_distinct_identity_and_policy_references() -> None:
    """Identity, permission, eligibility, and review are separate evidence."""
    system, user = build_context_bdi_prompts(
        _model_output_context(), TemplateLoader(PROMPTS_DIR)
    )
    rendered = " ".join(f"{system}\n{user}".split())

    rendered_lower = rendered.lower()
    assert "identity is not permission" in rendered_lower
    assert "permission is not business eligibility" in rendered_lower
    assert "business eligibility is not review status" in rendered_lower
    assert "identity_reference" in rendered
    assert "permission_reference" in rendered
    assert "eligibility_reference" in rendered
    assert "review_reference" in rendered
    assert "clinical" not in rendered_lower


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
