"""Property tests for the ``max_completion_tokens`` cap in ``call_with_policy``.

``call_with_policy`` forwards the optional token cap to ``llm_client.complete``
only when it is provided and passes None when it is not.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from hypothesis import HealthCheck, given, settings, strategies as st
from pydantic import BaseModel

from tests.stpa.sp1_helpers import MockLLMClient
from asago_scenario_generator.stpa.infra.llm_helpers import (
    CorrectionPolicy,
    call_with_policy,
)
from asago_scenario_generator.stpa.system_model.critic import (
    REVISION_MAX_COMPLETION_TOKENS,
    RevisionDelta,
    run_revision,
    CriticFindings,
)
from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlStructure,
    FeedbackChannel,
    ProcessModelPart,
    Responsibility,
)


# ---------------------------------------------------------------------------
# max_completion_tokens threading through call_with_policy
# ---------------------------------------------------------------------------


class _DummyModel(BaseModel):
    """Simple model for LLM call testing."""

    name: str = "test"


class TestMaxCompletionTokensThreading:
    """Property tests for max_completion_tokens forwarding in call_with_policy."""

    @given(
        token_cap=st.integers(min_value=1, max_value=32768),
    )
    @settings(
        max_examples=20,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_token_cap_forwarded_to_complete(
        self, tmp_path: Path, token_cap: int
    ) -> None:
        """When max_completion_tokens is provided, it reaches complete()."""
        client = MockLLMClient()
        client.set_response_for(_DummyModel, _DummyModel(name="ok").model_dump())

        call_with_policy(
            llm_client=client,
            system_prompt="sys",
            user_prompt="usr",
            response_format=_DummyModel,
            run_dir=tmp_path,
            stage="test",
            step="test_step",
            max_completion_tokens=token_cap,
            policy=CorrectionPolicy(),
        )

        assert len(client.calls) == 1
        assert client.calls[0].max_completion_tokens == token_cap

    @given(
        data=st.none(),
    )
    @settings(
        max_examples=5,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_no_token_cap_passes_none(self, tmp_path: Path, data: Any) -> None:
        """When max_completion_tokens is not provided, complete() receives None."""
        client = MockLLMClient()
        client.set_response_for(_DummyModel, _DummyModel(name="ok").model_dump())

        call_with_policy(
            llm_client=client,
            system_prompt="sys",
            user_prompt="usr",
            response_format=_DummyModel,
            run_dir=tmp_path,
            stage="test",
            step="test_step",
            policy=CorrectionPolicy(),
        )

        assert len(client.calls) == 1
        assert client.calls[0].max_completion_tokens is None

    def test_revision_uses_8192_token_cap(self, tmp_path: Path) -> None:
        """The critic revision call uses REVISION_MAX_COMPLETION_TOKENS (8192)."""
        assert REVISION_MAX_COMPLETION_TOKENS == 8192

        # Verify the revision LLM call receives the token cap
        client = MockLLMClient()
        client.set_response_for(RevisionDelta, RevisionDelta().model_dump())

        # Build a minimal control structure for the revision call

        cs = ControlStructure(
            responsibilities=[
                Responsibility(
                    resp_id="RESP-1",
                    description="Test controller",
                    process_model_parts=[
                        ProcessModelPart(pm_id="PM-1-1", description="State")
                    ],
                    control_actions=[
                        ControlAction(ca_id="CA-1-1", description="Action")
                    ],
                    feedback_channels=[
                        FeedbackChannel(
                            fb_id="FB-1-1",
                            description="Feedback",
                            updates="PM-1-1",
                        )
                    ],
                )
            ]
        )

        findings = CriticFindings(
            checklist_results={"Input validation": "absent_unjustified"},
            gaps=[
                {
                    "gap_type": "missing_responsibility",
                    "description": "Input validation responsibility is missing",
                    "related_attack_path": "The input path has no validation owner",
                    "suggested_remedy": "Add an input validation responsibility",
                }
            ],
        )

        run_revision(
            llm_client=client,
            control_structure=cs,
            critic_findings=findings,
            use_case_text="Test use case",
            run_dir=tmp_path,
        )

        # Find the revision call
        revision_calls = [
            c for c in client.calls if c.max_completion_tokens is not None
        ]
        assert len(revision_calls) == 1
        assert revision_calls[0].max_completion_tokens == 8192
