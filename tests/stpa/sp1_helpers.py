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

from pydantic import BaseModel

from acceptance.fixture_adapters import legacy_stage1a_provider_payload

from asago_scenario_generator.models.risk_card import RiskCard
from asago_scenario_generator.stpa.infra.llm import LLMResult


def valid_empty_coordination_analysis_dict(
    *,
    constraint_ids: tuple[str, ...] = ("SC-1",),
    hazard_ids: tuple[str, ...] | None = None,
    responsibility_ids: tuple[str, ...] = ("RESP-1",),
    action_ids: tuple[str, ...] = ("CA-1-1",),
) -> dict:
    """Minimal CoordinationAnalysis with no links and no findings.

    Used by tests that only need Call 3 to produce a valid (but empty)
    CoordinationAnalysis so the assembled ControlStructure has no
    coordination links.
    """
    constraints = []
    if hazard_ids is None:
        hazard_ids = tuple(
            f"H-{constraint_id.rsplit('-', 1)[-1]}" for constraint_id in constraint_ids
        )
    hazard_id_set = set(hazard_ids)
    hazards = [
        {
            "hazard_id": hazard_id,
            "disposition": "preserve",
            "revised_description": None,
            "missing_fact": None,
            "source_evidence": [],
            "rationale": "The supplied hazard wording is retained.",
        }
        for hazard_id in hazard_ids
    ]
    for constraint_id in constraint_ids:
        suffix = constraint_id.rsplit("-", 1)[-1]
        related_hazards = [f"H-{suffix}"] if f"H-{suffix}" in hazard_id_set else []
        constraints.append(
            {
                "constraint_id": constraint_id,
                "disposition": "preserve",
                "revised_description": None,
                "missing_fact": None,
                "related_hazards": related_hazards,
                "source_evidence": [],
                "rationale": "The supplied constraint retains its hazard relation.",
            }
        )
    return {
        "coordination_links": [],
        "semantic_review": {
            "hazards": hazards,
            "constraints": constraints,
            "responsibilities": [
                {
                    "responsibility_id": responsibility_id,
                    "constraint_refs": (
                        [constraint_ids[index]] if index < len(constraint_ids) else []
                    ),
                    "rationale": "The action owner enforces the supplied confirmation constraint.",
                }
                for index, responsibility_id in enumerate(responsibility_ids)
            ],
            "actions": [
                {
                    "control_action_id": action_id,
                    "effect_kind": "agent_message",
                    "rationale": "The action targets an internal responsibility.",
                }
                for action_id in action_ids
            ],
        },
    }


@dataclass
class MockCall:
    """A recorded LLM call."""

    system_prompt: str
    user_prompt: str
    response_format: type | None
    temperature: float | None
    max_completion_tokens: int | None


def coverage_review_response_from_prompt(
    response_format: type,
    user_prompt: str,
) -> dict | None:
    """Synthesize a valid risk-coverage review response from the rendered prompt.

    The review wire is a closed schema whose ids are literals of the supplied
    cards and constraints, so a canned dict cannot serve every test.  This
    helper reads the ids from the schema and the quotable text from the
    prompt, then builds one valid row per card: a cited card reports ``full``
    against the first supplied constraint, and a ``not_applicable`` card
    reports ``not_applicable_confirmed``.
    """
    import re
    from typing import get_args

    from asago_scenario_generator.stpa.system_model.risk_coverage_review import (
        RiskCoverageReview,
    )

    if not (
        isinstance(response_format, type)
        and issubclass(response_format, RiskCoverageReview)
    ):
        return None
    rows_field = response_format.model_fields.get("rows")
    if rows_field is None:
        return None
    row_args = get_args(rows_field.annotation)
    if not row_args:
        return None
    row_type = row_args[0]
    risk_ids = tuple(get_args(row_type.model_fields["risk_id"].annotation))
    constraint_ids: tuple[str, ...] = ()
    constraints_field = row_type.model_fields.get("covering_constraints")
    if constraints_field is not None:
        inner = get_args(constraints_field.annotation)
        if inner:
            constraint_type = inner[0]
            constraint_ids = tuple(
                get_args(constraint_type.model_fields["constraint_id"].annotation)
            )

    evidence_field = row_type.model_fields.get("evidence")
    evidence_refs: tuple[str, ...] = ()
    if evidence_field is not None:
        inner = get_args(evidence_field.annotation)
        if inner:
            evidence_refs = tuple(
                get_args(inner[0].model_fields["source_ref"].annotation)
            )
    source_canonical: dict[str, str] = {}
    for line in user_prompt.splitlines():
        source = re.match(r"^\[(source_\d+)\] \(([^)]+)\) ", line)
        if source:
            source_canonical[source.group(1)] = source.group(2)

    dispositions: dict[str, str] = {}
    current: str | None = None
    for line in user_prompt.splitlines():
        heading = re.match(r"^### (\S+) — ", line)
        if heading:
            current = heading.group(1)
            continue
        if current is None:
            continue
        disposition = re.match(r"^- \*\*Disposition:\*\* (\S+)", line)
        if disposition:
            dispositions[current] = disposition.group(1)

    constraint_rules: dict[str, str] = {}
    constraint: str | None = None
    for line in user_prompt.splitlines():
        heading = re.match(r"^- \*\*(SC-[^*]+)\*\* \(related hazards:", line)
        if heading:
            constraint = heading.group(1)
            continue
        if constraint is None:
            continue
        rule = re.match(r"^  Rule: (.*)$", line)
        if rule:
            constraint_rules[constraint] = rule.group(1)

    refs_by_canonical: dict[str, str] = {}
    for local_ref, canonical_ref in source_canonical.items():
        refs_by_canonical.setdefault(canonical_ref, local_ref)

    rows = []
    for risk_id in risk_ids:
        card_ref = refs_by_canonical.get(risk_id) or (
            evidence_refs[0] if evidence_refs else "source_1"
        )
        evidence = [{"source_ref": card_ref, "meaning": "The card."}]
        cited = dispositions.get(risk_id, "cited") != "not_applicable"
        if cited and constraint_ids and constraint_rules:
            constraint_id = constraint_ids[0]
            constraint_ref = refs_by_canonical.get(constraint_id) or card_ref
            row = {
                "risk_id": risk_id,
                "protects": "the protected interest",
                "against": None,
                "covering_constraints": [
                    {
                        "constraint_id": constraint_id,
                        "evidence": [
                            {
                                "source_ref": constraint_ref,
                                "meaning": "The governing rule.",
                            }
                        ],
                    }
                ],
                "coverage": "full",
                "missing_protection": None,
                "evidence": evidence,
                "rationale": "The rule protects the same interest.",
            }
        elif cited:
            row = {
                "risk_id": risk_id,
                "protects": "the protected interest",
                "against": None,
                "covering_constraints": [],
                "coverage": "none",
                "missing_protection": "No constraint protects this interest.",
                "evidence": evidence,
                "rationale": "No supplied rule covers the card.",
            }
        else:
            row = {
                "risk_id": risk_id,
                "protects": "the protected interest",
                "against": None,
                "covering_constraints": [],
                "coverage": "not_applicable_confirmed",
                "missing_protection": None,
                "evidence": evidence,
                "rationale": "The card cannot materialize here.",
            }
        rows.append(row)
    return {"rows": rows}


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
        exception = self._compatible_value(
            response_format, self._exception_response_types
        )
        if exception is not None:
            raise exception

        # Determine which response to return
        if self._response_queue:
            content = self._response_queue.pop(0)
        elif self._compatible_type(response_format, self._invalid_response_types):
            # Return a non-JSON string that will fail parsing/validation
            content = "THIS_IS_NOT_VALID_JSON{{{"
        elif (
            mapped := self._compatible_value(response_format, self._response_map)
        ) is not None:
            if isinstance(mapped, list):
                if mapped:
                    content = mapped.pop(0)
                else:
                    content = None
            else:
                content = mapped
        elif (
            synthesized := coverage_review_response_from_prompt(
                response_format, user_prompt
            )
        ) is not None:
            # The advisory risk-coverage review wire closes its ids to the
            # supplied cards, so tests synthesize a valid response instead of
            # registering one canned dict per fixture.
            content = synthesized
        elif response_format is None and None in self._response_map:
            content = self._response_map[None]
        else:
            content = None

        # Legacy Stage 1a tests historically registered ``LossAnalysisDraft``
        # responses.  Adapt those dictionaries only at this explicit test
        # client boundary; production parsing remains current-wire strict.
        if response_format is not None:
            response_name = getattr(response_format, "__name__", "")
            if response_name in {
                "_Stage1aRiskProviderDraft",
                "_Stage1aGapProviderDraft",
            }:
                if isinstance(content, BaseModel):
                    content = content.model_dump(mode="json")
                if isinstance(content, str):
                    try:
                        decoded = json.loads(content)
                    except (TypeError, ValueError):
                        decoded = None
                    if isinstance(decoded, dict):
                        content = decoded
                if isinstance(content, dict):
                    content = legacy_stage1a_provider_payload(
                        content,
                        risk=response_name == "_Stage1aRiskProviderDraft",
                        preserve_gap_extras=(
                            response_name == "_Stage1aGapProviderDraft"
                        ),
                    )

        return LLMResult(
            content=content,
            prompt_tokens=100,
            completion_tokens=50,
            duration_ms=5000,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
        )

    @staticmethod
    def _compatible_type(model_class: type | None, configured: set[type]) -> bool:
        """Match exact or provider-specialized subclasses in deterministic tests."""
        return bool(
            model_class
            and any(
                issubclass(model_class, candidate)
                or (
                    candidate.__name__ == "LossAnalysisDraft"
                    and model_class.__name__
                    in {"_Stage1aRiskProviderDraft", "_Stage1aGapProviderDraft"}
                )
                or (
                    candidate.__name__ == "CoordinationAnalysis"
                    and model_class.__name__
                    in {
                        "ProviderCoordinationAnalysis",
                        "_CoordinationProviderEnvelope",
                    }
                )
                for candidate in configured
            )
        )

    @staticmethod
    def _compatible_value(model_class: type | None, configured: dict[type, Any]) -> Any:
        """Return the exact or nearest configured base response value."""
        if model_class in configured:
            return configured[model_class]
        if model_class is None:
            return None
        for candidate, value in configured.items():
            if isinstance(candidate, type) and (
                issubclass(model_class, candidate)
                or (
                    candidate.__name__ == "LossAnalysisDraft"
                    and model_class.__name__
                    in {"_Stage1aRiskProviderDraft", "_Stage1aGapProviderDraft"}
                )
                or (
                    candidate.__name__ == "CoordinationAnalysis"
                    and model_class.__name__
                    in {
                        "ProviderCoordinationAnalysis",
                        "_CoordinationProviderEnvelope",
                    }
                )
            ):
                return value
        return None

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
    """Return a valid LossAnalysisDraft dict for the risk_derivation call.

    The hazard/constraint wording shares an explicit subject phrase, so the
    merged graph has no subject-phrase advisory and needs no bounded revision
    call.
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
        "use_case_losses": [],
        "hazards": [
            {
                "hazard_id": "H-1",
                "description": "The agent executes an unintended payment.",
                "related_losses": ["L-1"],
            }
        ],
        "security_constraints": [
            {
                "constraint_id": "SC-1",
                "rule": "The agent must confirm every unintended payment.",
                "applies_when": ["before execution"],
                "related_hazards": ["H-1"],
            }
        ],
        "risk_dispositions": [
            {
                "risk_ref": "atlas-001",
                "disposition": "cited",
                "loss_ids": ["L-1"],
                "reason": None,
            }
        ],
    }


def valid_gap_draft_dict() -> dict:
    """Return a valid LossAnalysisDraft dict for the gap_analysis call.

    Like the risk draft, the wording shares an explicit subject phrase, so
    the merged graph has no subject-phrase advisory.
    """
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
                "description": "The agent erodes user trust.",
                "related_losses": ["L-2"],
            }
        ],
        "security_constraints": [
            {
                "constraint_id": "SC-2",
                "rule": "The agent must preserve user trust.",
                "applies_when": ["through transparency"],
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
                "description": "The agent executes an unintended payment.",
                "related_losses": ["L-1"],
            },
            {
                "hazard_id": "H-2",
                "description": "The agent erodes user trust.",
                "related_losses": ["L-2"],
            },
        ],
        "security_constraints": [
            {
                "constraint_id": "SC-1",
                "rule": "The agent must confirm every unintended payment.",
                "applies_when": ["before execution"],
                "related_hazards": ["H-1"],
            },
            {
                "constraint_id": "SC-2",
                "rule": "The agent must preserve user trust.",
                "applies_when": ["through transparency"],
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
        "control_actions": [
            {
                "ca_id": "CA-1-1",
                "description": "Execute action",
                "target": {"type": "responsibility", "id": "RESP-1"},
            }
        ],
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
        _CoordinationProviderEnvelope,
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
        CoordinationAnalysis,
        valid_empty_coordination_analysis_dict(constraint_ids=("SC-1", "SC-2")),
    )
    # Call 3 uses a generated provider subclass of the closed envelope.  Keep
    # a direct registration as an explicit test fixture seam; the old
    # ``integrity_findings`` code-owned field is intentionally absent.
    client.set_response_for(
        _CoordinationProviderEnvelope,
        valid_empty_coordination_analysis_dict(constraint_ids=("SC-1", "SC-2")),
    )
    client.set_response_for(CriticFindings, valid_critic_findings_dict_no_gaps())
    return client
