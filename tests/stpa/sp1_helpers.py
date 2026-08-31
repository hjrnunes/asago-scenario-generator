"""Shared test helpers for SP1 system model tests.

Provides a mock LLM client that returns canned responses for different
stages and records call metadata (prompts, temperature, call count).
Also provides shared fixture data builders used across multiple test modules.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

from asago_scenario_generator.models.risk_card import RiskCard
from asago_scenario_generator.stpa.infra.llm import LLMResult


def valid_empty_coordination_analysis_dict() -> dict:
    """Minimal CoordinationAnalysis with no links and no findings.

    Used by tests that only need Call 3 to produce a valid (but empty)
    CoordinationAnalysis so the assembled ControlStructure has no
    coordination links.
    """
    return {
        "coordination_links": [],
        "integrity_findings": [],
    }


@dataclass
class MockCall:
    """A recorded LLM call."""

    system_prompt: str
    user_prompt: str
    response_format: type | None
    temperature: float | None
    max_completion_tokens: int | None


class MockLLMClient:
    """A mock LLM client for SP1 tests.

    Returns canned responses based on a queue or a response map keyed
    by response_format. Records all calls for inspection.
    """

    def __init__(
        self,
        base_url: str = "http://test:8080",
        model: str = "test-model",
        temperature: float = 0.4,
    ) -> None:
        self.base_url = base_url
        self.model = model
        self.temperature = temperature
        self.max_completion_tokens = None
        self.calls: list[MockCall] = []
        self._response_queue: list[Any] = []
        self._response_map: dict[type, Any] = {}
        self._invalid_response_types: set[type] = set()
        self._exception_response_types: dict[type, Exception] = {}

    def set_invalid_response_for(self, model_class: type) -> None:
        """Configure the mock to return an invalid response for a type.

        The mock returns a dict with an obviously invalid field that
        will fail Pydantic validation for the target model_class.
        """
        self._invalid_response_types.add(model_class)

    def set_exception_for(self, model_class: type, exc: Exception) -> None:
        """Configure the mock to raise *exc* when called for *model_class*."""
        self._exception_response_types[model_class] = exc

    @property
    def _client(self) -> Any:
        return MagicMock()

    def set_response_queue(self, responses: list[Any]) -> None:
        """Set a FIFO queue of responses to return in order."""
        self._response_queue = list(responses)

    def set_response_for(self, model_class: type, response: Any) -> None:
        """Set a response for a specific response_format type.

        If *response* is a list, each call for this type pops the next
        item from the list (FIFO). This allows different responses for
        sequential calls with the same response_format (e.g. the two
        Stage 1a calls that both use LossAnalysisDraft).
        """
        if isinstance(response, list):
            self._response_map[model_class] = list(response)
        else:
            self._response_map[model_class] = response

    def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        response_format: type | None = None,
        max_completion_tokens: int | None = None,
        temperature: float | None = None,
    ) -> LLMResult:
        call = MockCall(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response_format=response_format,
            temperature=temperature,
            max_completion_tokens=max_completion_tokens,
        )
        self.calls.append(call)

        # Raise exception if configured for this response_format
        if response_format in self._exception_response_types:
            raise self._exception_response_types[response_format]

        # Determine which response to return
        if self._response_queue:
            content = self._response_queue.pop(0)
        elif (
            response_format is not None
            and response_format in self._invalid_response_types
        ):
            # Return a non-JSON string that will fail parsing/validation
            content = "THIS_IS_NOT_VALID_JSON{{{"
        elif response_format is not None and response_format in self._response_map:
            mapped = self._response_map[response_format]
            if isinstance(mapped, list):
                if mapped:
                    content = mapped.pop(0)
                else:
                    content = None
            else:
                content = mapped
        elif response_format is None and None in self._response_map:
            content = self._response_map[None]
        else:
            content = None

        return LLMResult(
            content=content,
            prompt_tokens=100,
            completion_tokens=50,
            duration_ms=5000,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
        )

    @property
    def call_count(self) -> int:
        return len(self.calls)

    def find_call_by_step_prompt(self, substring: str) -> MockCall | None:
        """Find a call whose user_prompt contains the given substring."""
        for call in self.calls:
            if substring in call.user_prompt:
                return call
        return None


# ---------------------------------------------------------------------------
# Shared fixture data builders (used by multiple test modules)
# ---------------------------------------------------------------------------


def make_risk_cards() -> list[RiskCard]:
    """Return a minimal list of RiskCards for SP1 pipeline tests."""
    return [
        RiskCard(
            risk_id="atlas-001",
            risk_name="Prompt injection",
            risk_description="Risk of prompt injection",
            taxonomy="ibm-risk-atlas",
            confidence=0.9,
            grounding_confidence="high",
        ),
    ]


def read_calls_jsonl(run_dir: Path) -> list[dict]:
    """Read calls.jsonl and return parsed entries."""
    calls_file = run_dir / "calls.jsonl"
    if not calls_file.exists():
        return []
    return [json.loads(line) for line in calls_file.read_text().splitlines()]


def valid_stage1_profile_dict() -> dict:
    """Return a valid Stage1Profile dict for tests that need Stage 1b.

    Boolean flags (has_persistent_memory, multi_agent, hitl) are no longer
    LLM-inferred fields — they are computed from kc_subcodes on
    CapabilityProfile.  Any extra keys in the dict are silently ignored
    by Pydantic.
    """
    return {
        "has_persistent_memory": False,
        "multi_agent": False,
        "hitl": False,
        "entry_points": [
            {"name": "User chat", "direction": "input", "controllability": "direct"},
        ],
        "confidence": "medium",
        "kc_subcodes": ["KC1.1", "KC5.1", "KC6.1.1"],
        "tool_inventory": [{"name": "tool1", "description": "A tool"}],
    }


def valid_risk_draft_dict() -> dict:
    """Return a valid LossAnalysisDraft dict for the risk_derivation call."""
    return {
        "risk_card_losses": [
            {
                "loss_id": "L-1",
                "description": "Unauthorized transaction",
                "provenance": "risk_card",
                "source_risk_cards": ["atlas-001"],
            }
        ],
        "use_case_losses": [],
        "hazards": [
            {
                "hazard_id": "H-1",
                "description": "Agent executes unintended action",
                "related_losses": ["L-1"],
            }
        ],
        "security_constraints": [
            {
                "constraint_id": "SC-1",
                "description": "Must confirm before action",
                "related_hazards": ["H-1"],
            }
        ],
    }


def valid_gap_draft_dict() -> dict:
    """Return a valid LossAnalysisDraft dict for the gap_analysis call."""
    return {
        "risk_card_losses": [],
        "use_case_losses": [
            {
                "loss_id": "L-2",
                "description": "Loss of trust",
                "provenance": "use_case",
                "source_risk_cards": [],
            }
        ],
        "hazards": [
            {
                "hazard_id": "H-2",
                "description": "Agent erodes user trust",
                "related_losses": ["L-2"],
            }
        ],
        "security_constraints": [
            {
                "constraint_id": "SC-2",
                "description": "Must maintain transparency",
                "related_hazards": ["H-2"],
            }
        ],
    }


def valid_loss_analysis_dict() -> dict:
    """Return a valid LossAnalysis dict (merged result) for tests that
    construct a LossAnalysis directly.

    This represents the *merged* output after risk_derivation + gap_analysis.
    Tests that mock the LLM should use ``valid_risk_draft_dict`` and
    ``valid_gap_draft_dict`` instead.
    """
    return {
        "risk_card_losses": [
            {
                "loss_id": "L-1",
                "description": "Unauthorized transaction",
                "provenance": "risk_card",
                "source_risk_cards": ["atlas-001"],
            }
        ],
        "use_case_losses": [
            {
                "loss_id": "L-2",
                "description": "Loss of trust",
                "provenance": "use_case",
                "source_risk_cards": [],
            }
        ],
        "hazards": [
            {
                "hazard_id": "H-1",
                "description": "Agent executes unintended action",
                "related_losses": ["L-1"],
            },
            {
                "hazard_id": "H-2",
                "description": "Agent erodes user trust",
                "related_losses": ["L-2"],
            },
        ],
        "security_constraints": [
            {
                "constraint_id": "SC-1",
                "description": "Must confirm before action",
                "related_hazards": ["H-1"],
            },
            {
                "constraint_id": "SC-2",
                "description": "Must maintain transparency",
                "related_hazards": ["H-2"],
            },
        ],
    }


def valid_requirement_set_dict() -> dict:
    """Return a valid RequirementSet dict for Stage 2 Call 1."""
    return {
        "requirements": [
            {
                "req_id": "REQ-1",
                "description": "Verify user identity",
                "classification": "control",
                "source_constraint": "SC-1",
            }
        ]
    }


def valid_responsibility_set_dict() -> dict:
    """Return a valid ResponsibilitySet dict for Stage 2 Call 2a.

    Only responsibilities with RCs and PM parts — no CAs, FBs, or CPs
    (those come from Call 2b).
    """
    return {
        "responsibilities": [
            {
                "resp_id": "RESP-1",
                "description": "Authorization controller",
                "security_constraint_refs": ["SC-1"],
                "responsibility_constraints": [
                    {"rc_id": "RC-1-1", "description": "Must confirm before action"}
                ],
                "process_model_parts": [
                    {"pm_id": "PM-1-1", "description": "User intent state"}
                ],
            }
        ]
    }


def valid_control_element_set_dict() -> dict:
    """Return a valid ControlElementSet dict for Stage 2 Call 2b.

    Contains CAs, FBs, and CPs that match the responsibilities from
    ``valid_responsibility_set_dict``.
    """
    return {
        "control_actions": [{"ca_id": "CA-1-1", "description": "Execute action"}],
        "feedback_channels": [
            {
                "fb_id": "FB-1-1",
                "description": "Action result",
                "updates": "PM-1-1",
                "source": {"type": "responsibility", "id": "RESP-1"},
            }
        ],
        "controlled_processes": [],
    }


def valid_critic_findings_dict_no_gaps() -> dict:
    """Return a CriticFindings dict with no gaps (all checklist items present)."""
    return {
        "gaps": [],
        "checklist_results": {
            "Input validation": "present",
            "Authorization": "present",
            "Action selection": "present",
            "Outcome verification": "present",
            "Context management": "present",
            "Multi-agent coordination": "present",
            "Human-in-the-loop": "present",
        },
        "taxonomy_probe_results": {},
    }


def setup_sp1_mock_client() -> MockLLMClient:
    """Set up a mock LLM client with valid responses for all SP1 stages."""
    from asago_scenario_generator.models.capability_profile import Stage1Profile
    from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysisDraft
    from asago_scenario_generator.stpa.system_model.control_structure import (
        ControlElementSet,
        CoordinationAnalysis,
        RequirementSet,
        ResponsibilitySet,
    )
    from asago_scenario_generator.stpa.system_model.critic import CriticFindings

    client = MockLLMClient()
    # Stage 1a: two calls (risk_derivation + gap_analysis) both use LossAnalysisDraft.
    # Provide a list so the first call gets the risk draft and the second gets the gap draft.
    client.set_response_for(
        LossAnalysisDraft, [valid_risk_draft_dict(), valid_gap_draft_dict()]
    )
    # Stage 1b: Stage1Profile (no loss_analysis parameter)
    client.set_response_for(Stage1Profile, valid_stage1_profile_dict())
    client.set_response_for(RequirementSet, valid_requirement_set_dict())
    client.set_response_for(ResponsibilitySet, valid_responsibility_set_dict())
    client.set_response_for(ControlElementSet, valid_control_element_set_dict())
    client.set_response_for(
        CoordinationAnalysis, valid_empty_coordination_analysis_dict()
    )
    client.set_response_for(CriticFindings, valid_critic_findings_dict_no_gaps())
    return client
