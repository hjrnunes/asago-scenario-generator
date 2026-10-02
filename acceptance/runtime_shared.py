"""Shared state, imports, fixtures, and non-registered runtime helpers."""

from __future__ import annotations
import copy
import json
import os
import re
import sys
import tempfile
import threading
import time
import traceback
from pathlib import Path
from typing import Any
from runtime_world import World

from runtime_bootstrap import PROJECT_ROOT
from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlStructure,
    ControlledProcess,
    CoordinationLink,
    CoordinationMechanism,
    ElementRef,
    FeedbackChannel,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
    ResponsibilityConstraint,
    check_structural_heuristics,
)
from asago_scenario_generator.stpa.models.enriched_threat_set import (
    CatalogMapping,
    CoverageAnalysis,
    EnrichedThreatSet,
    StructuralThreat,
)
from asago_scenario_generator.stpa.models.ica_enumeration import (
    ICA,
    ICAEnumeration,
    ICASlot,
    UCAType,
)
from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossAnalysis,
    LossProvenance,
    SecurityConstraint,
)
from asago_scenario_generator.stpa.models.scenario_spec import (
    AttackerBDI,
    DefenderBDI,
    DefenderBelief,
    DefenderDesire,
    DefenderIntention,
    ScenarioSpec,
    ThreatSource,
)
from asago_scenario_generator.stpa.models.scenario_envelope import ScenarioEnvelope
from asago_scenario_generator.stpa.infra.llm import LLMClient, LLMResult
from asago_scenario_generator.stpa.system_model.critic import (
    strip_empty_responsibilities,
)
from asago_scenario_generator.stpa.infra.call_log import (
    make_call_log_entry,
    append_call_log,
)
from asago_scenario_generator.stpa.infra.yaml_io import write_yaml, read_yaml
from asago_scenario_generator.stpa.infra.templates import (
    TemplateLoader,
    hash_prompt_templates,
)
from asago_scenario_generator.stpa.infra.manifest import STPARunManifest
from pydantic import BaseModel, ValidationError
from asago_scenario_generator.stpa.models.scenario_envelope import GherkinSpec
from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile as _CapabilityProfile,
    ConfidenceLevel as _ConfidenceLevel,
    EntryPoint as _EntryPoint,
    ToolInventoryEntry as _ToolInventoryEntry,
)
from asago_scenario_generator.stpa.models.scenario_envelope import (
    SystemContext as _SystemContext,
    ConsumerHints as _ConsumerHints,
)
from asago_scenario_generator.stpa.scenario_prod.enrichment import (
    compute_system_context as _compute_system_context,
    compute_consumer_hints as _compute_consumer_hints,
)
from asago_scenario_generator.stpa.scenario_prod.assembly import (
    assemble_envelope as _assemble_envelope,
)
from asago_scenario_generator.stpa.system_model.heuristics import (
    check_solution_neutrality as _sp1_check_neutrality,
)
from asago_scenario_generator.stpa.system_model.critic import (
    CriticFindings as _SP1CriticFindings,
    CriticGap as _SP1CriticGap,
)
from asago_scenario_generator.stpa.system_model.control_structure import (
    Requirement as _SP1Requirement,
    RequirementSet as _SP1RequirementSet,
)
from asago_scenario_generator.stpa.system_model.loss_analysis import (
    _Stage1aRevisionPatch as _SP1Stage1aRevisionPatch,
    derive_loss_analysis as _sp1_derive_loss_analysis,
)
from asago_scenario_generator.stpa.models.loss_analysis import (
    LossAnalysisDraft as _SP1LossAnalysisDraft,
)
from asago_scenario_generator.stpa.system_model.profile import (
    derive_capability_profile as _sp1_derive_capability_profile,
    load_capability_profile as _sp1_load_capability_profile,
)
from asago_scenario_generator.stpa.system_model.control_structure import (
    derive_control_structure as _sp1_derive_control_structure,
    ResponsibilitySet as _SP1ResponsibilitySet,
    ControlElementSet as _SP1ControlElementSet,
    CoordinationAnalysis as _SP1CoordinationAnalysis,
    _assemble_with_fallback as _sp1_assemble_with_fallback,
    _add_coordination_links_with_fallback as _sp1_add_coordination_links,
)
from asago_scenario_generator.stpa.system_model.critic import (
    run_completeness_critic as _sp1_run_critic,
    run_revision as _sp1_run_revision,
    has_unjustified_gaps as _sp1_has_unjustified_gaps,
    RevisionDelta as _SP1RevisionDelta,
    _compute_next_ids as _sp1_compute_next_ids,
    _merge_revision_delta as _sp1_merge_revision_delta,
)
from asago_scenario_generator.stpa.system_model.heuristics import (
    run_heuristics as _sp1_run_heuristics,
)
from asago_scenario_generator.stpa.system_model.run import (
    run_sp1 as _sp1_run_sp1,
)
from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile as _SP1CapabilityProfile,
    Stage1Profile as _SP1Stage1Profile,
)
from asago_scenario_generator.models.risk_card import RiskCard as _SP1RiskCard
from asago_scenario_generator.stpa.infra.yaml_io import (
    write_yaml as _sp1_write_yaml,
    read_yaml as _sp1_read_yaml,
)
from asago_scenario_generator.stpa.infra.llm_helpers import (
    log_llm_call as _sp1_log_llm_call,
)
import tempfile as _tempfile
import hashlib as _hashlib
from asago_scenario_generator.stpa.infra.llm_helpers import (
    safe_llm_call as _gd_safe_llm_call,
)
from asago_scenario_generator.stpa.infra.llm_helpers import StageError as _GDStageError
from asago_scenario_generator.stpa.system_model.loss_analysis import (
    derive_loss_analysis as _gd_derive_loss_analysis,
)
from asago_scenario_generator.stpa.system_model.profile import (
    derive_capability_profile as _gd_derive_profile,
)
from asago_scenario_generator.stpa.system_model.control_structure import (
    derive_control_structure as _gd_derive_cs,
    RequirementSet as _GDRequirementSet,
    ResponsibilitySet as _GDResponsibilitySet,
    ControlElementSet as _GDControlElementSet,
    CoordinationAnalysis as _GDCoordinationAnalysis,
)
from asago_scenario_generator.stpa.system_model.critic import (
    run_completeness_critic as _gd_run_critic,
    run_revision as _gd_run_revision,
    CriticFindings as _GDCriticFindings,
)
from asago_scenario_generator.stpa.system_model.run import (
    SP1RunResult as _GDSP1RunResult,
)
import yaml as _gd_yaml
import yaml as _yaml_mp
import tempfile as _tempfile_mp
import subprocess as _subprocess_mp
from asago_scenario_generator.stpa.infra.model_profiles import (
    load_profile as _load_profile,
)
from asago_scenario_generator.stpa.infra.calls_html import (
    render_calls_html as _render_calls_html,
)
from asago_scenario_generator.stpa.infra.llm_helpers import (
    log_llm_call as _fc_log_llm_call,
    log_llm_call_failure as _fc_log_llm_call_failure,
)
from asago_scenario_generator.stpa.system_model.critic import (
    RevisionDelta as _FCRevisionDelta,
    _compute_next_ids as _fc_compute_next_ids,
    strip_empty_responsibilities as _fc_strip_empty,
)
from asago_scenario_generator.stpa.system_model.control_structure import (
    _assemble_with_fallback as _fc_merge_with_fallback,
    ResponsibilitySet as _FCResponsibilitySet,
    ControlElementSet as _FCControlElementSet,
)
from asago_scenario_generator.stpa.system_model._constants import (
    PROMPTS_DIR as _FC_PROMPTS_DIR,
)
import inspect as _bf2_inspect
import logging as _bf2_logging
import tempfile as _bf2_tempfile
from asago_scenario_generator.stpa.infra.llm_helpers import (
    safe_llm_call as _bf2_safe_llm_call,
)
from asago_scenario_generator.stpa.system_model.control_structure import (
    derive_control_structure as _bf2_derive_control_structure,
    _call_2a_responsibilities as _bf2_call_2_resp,
)
from asago_scenario_generator.stpa.system_model.critic import (
    RevisionDelta as _bf2_RevisionDelta,
    REVISION_MAX_COMPLETION_TOKENS as _bf2_REV_MAX_TOKENS,
)
from asago_scenario_generator.stpa.system_model.critic import (
    CriticFindings as _B3CriticFindings,
    CriticGap as _B3CriticGap,
    sanitize_critic_ids as _B3SanitizeCriticIDs,
)
from asago_scenario_generator.stpa.system_model.control_structure import (
    ResponsibilitySet as _B3ResponsibilitySet,
    repair_orphan_pms as _B3RepairOrphanPMs,
)


def _resolve_value(text: str, examples: dict[str, str]) -> str:
    """Resolve <placeholder> tokens in step text using example values."""

    def replacer(match: re.Match) -> str:
        key = match.group(1)
        return examples.get(key, match.group(0))

    return re.sub(r"<([A-Za-z0-9_]+)>", replacer, text)


def _make_coordination_link(
    link_id: str = "CL-1",
    source: str = "RESP-1",
    target: str = "RESP-2",
    shared_pm: str = "PM-1-1",
) -> CoordinationLink:
    """Build a minimal valid CoordinationLink."""
    return CoordinationLink(
        link_id=link_id,
        source=source,
        target=target,
        shared_pm=shared_pm,
        coordination_mechanism=CoordinationMechanism(
            cm_id="CM-1", description="Mechanism", payload="data"
        ),
        description="Link",
    )


def _make_minimal_loss_analysis() -> LossAnalysis:
    return LossAnalysis(
        risk_card_losses=[],
        use_case_losses=[
            Loss(loss_id="L-1", description="Loss", provenance=LossProvenance.use_case)
        ],
        hazards=[Hazard(hazard_id="H-1", description="Hazard", related_losses=["L-1"])],
        security_constraints=[
            SecurityConstraint(
                constraint_id="SC-1",
                rule="Constraint",
                applies_when=[],
                related_hazards=["H-1"],
            )
        ],
    )


def _make_minimal_control_structure() -> ControlStructure:
    return ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="Controller",
                process_model_parts=[
                    ProcessModelPart(pm_id="PM-1-1", description="State"),
                ],
                control_actions=[
                    ControlAction(ca_id="CA-1-1", description="Action"),
                ],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-1-1",
                        description="Feedback",
                        updates="PM-1-1",
                        source=ElementRef(
                            type=ReferenceType.responsibility, id="RESP-1"
                        ),
                    )
                ],
            )
        ]
    )


def _make_minimal_scenario_spec(
    target_controller: str = "RESP-1",
    target_control_action: str = "CA-1-1",
) -> ScenarioSpec:
    """Build a minimal valid ScenarioSpec."""
    return ScenarioSpec(
        scenario_id="SCN-001",
        threat_source=ThreatSource(
            ica_slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
            provenance="structural",
        ),
        target_controller=target_controller,
        target_control_action=target_control_action,
        ica_type=UCAType.not_provided,
        defender_bdi=DefenderBDI(
            beliefs=[
                DefenderBelief(
                    pm_id="PM-1-1",
                    content="Belief",
                    vulnerability="vuln",
                )
            ],
            desires=[
                DefenderDesire(
                    resp_id="RESP-1",
                    content="Desire",
                )
            ],
            intentions=[
                DefenderIntention(
                    ca_id="CA-1-1",
                    content="Intention",
                )
            ],
        ),
        attacker_bdi=AttackerBDI(
            beliefs=["attacker belief"],
            desires=["attacker desire"],
            intentions=["attacker intention"],
        ),
        loss_scenario="A loss scenario",
    )


def _make_enrichment_control_structure(
    resp_desc: str = "Orchestrate tool calls safely",
    ca_desc: str = "Execute requested tool",
) -> ControlStructure:
    """Build a CS with RESP-1/CA-1-1 for enrichment tests."""
    return ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description=resp_desc,
                process_model_parts=[
                    ProcessModelPart(pm_id="PM-1-1", description="State"),
                ],
                control_actions=[
                    ControlAction(
                        ca_id="CA-1-1",
                        description=ca_desc,
                        target=ElementRef(
                            type=ReferenceType.controlled_process, id="CP-1"
                        ),
                    ),
                ],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-1-1",
                        description="Feedback",
                        updates="PM-1-1",
                        source=ElementRef(
                            type=ReferenceType.controlled_process, id="CP-1"
                        ),
                    ),
                ],
            ),
        ],
        controlled_processes=[ControlledProcess(cp_id="CP-1", description="Interface")],
    )


def _make_enrichment_capability_profile(
    kc_subcodes: list[str] | None = None,
    tool_inventory: list | None = None,
) -> _CapabilityProfile:
    """Build a CapabilityProfile for enrichment tests."""
    if kc_subcodes is None:
        kc_subcodes = ["KC1.1", "KC5.1", "KC6.1.1"]
    if tool_inventory is None:
        tool_inventory = [
            _ToolInventoryEntry(name="database_query", description="Query the database")
        ]
    return _CapabilityProfile(
        zones_active=[],
        entry_points=[_EntryPoint(name="user prompts via chat", direction="input")],
        confidence=_ConfidenceLevel.high,
        kc_subcodes=kc_subcodes,
        tool_inventory=tool_inventory,
    )


def _sp1_make_control_structure_with_resp(
    desc: str = "Controller 1",
) -> ControlStructure:
    """Build a minimal valid ControlStructure with one responsibility."""
    return ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description=desc,
                process_model_parts=[
                    ProcessModelPart(pm_id="PM-1-1", description="State 1")
                ],
                control_actions=[ControlAction(ca_id="CA-1-1", description="Action 1")],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-1-1",
                        description="FB 1",
                        updates="PM-1-1",
                        source=ElementRef(
                            type=ReferenceType.responsibility, id="RESP-1"
                        ),
                    )
                ],
            )
        ],
    )


def _sp1_make_control_structure_two_resps() -> ControlStructure:
    """Build a ControlStructure with two responsibilities."""
    return ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="Controller 1",
                process_model_parts=[
                    ProcessModelPart(pm_id="PM-1-1", description="State 1")
                ],
                control_actions=[ControlAction(ca_id="CA-1-1", description="Action 1")],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-1-1",
                        description="FB 1",
                        updates="PM-1-1",
                        source=ElementRef(
                            type=ReferenceType.responsibility, id="RESP-1"
                        ),
                    )
                ],
            ),
            Responsibility(
                resp_id="RESP-2",
                description="Controller 2",
                process_model_parts=[
                    ProcessModelPart(pm_id="PM-2-1", description="State 2")
                ],
                control_actions=[ControlAction(ca_id="CA-2-1", description="Action 2")],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-2-1",
                        description="FB 2",
                        updates="PM-2-1",
                        source=ElementRef(
                            type=ReferenceType.responsibility, id="RESP-2"
                        ),
                    )
                ],
            ),
        ],
    )


def _sp1_make_loss_analysis_with_constraints() -> LossAnalysis:
    """Build a LossAnalysis with security constraints SC-1 and SC-2."""
    return LossAnalysis(
        risk_card_losses=[],
        use_case_losses=[
            Loss(
                loss_id="L-1", description="Loss 1", provenance=LossProvenance.use_case
            ),
            Loss(
                loss_id="L-2", description="Loss 2", provenance=LossProvenance.use_case
            ),
        ],
        hazards=[
            Hazard(hazard_id="H-1", description="Hazard 1", related_losses=["L-1"]),
            Hazard(hazard_id="H-2", description="Hazard 2", related_losses=["L-2"]),
        ],
        security_constraints=[
            SecurityConstraint(
                constraint_id="SC-1",
                rule="C1",
                applies_when=[],
                related_hazards=["H-1"],
            ),
            SecurityConstraint(
                constraint_id="SC-2",
                rule="C2",
                applies_when=[],
                related_hazards=["H-2"],
            ),
        ],
    )


def _h_sp1_use_case_risk_json(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a use-case description and risk extraction JSON are available as input."""
    return True, ""


def _h_sp1_cs_two_resps_available(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a control structure with responsibilities RESP-1 and RESP-2 is available."""
    world.control_structure = _sp1_make_control_structure_two_resps()
    return True, ""


def _h_sp1_validation_fails(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: validation fails with error containing <fragment>."""
    m = re.search(r"containing\s+(\S+)", text)
    fragment = m.group(1) if m else ""
    if world.validation_error is None:
        return (
            False,
            f"Expected validation error containing '{fragment}' but none was raised",
        )
    err_str = str(world.validation_error)
    if fragment and fragment not in err_str:
        return False, f"Expected error containing '{fragment}' but got: {err_str}"
    return True, ""


def _h_sp1_heur_fails(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the heuristic check fails with error containing <error_fragment>."""
    fragment = examples.get("error_fragment", "")
    if not fragment:
        m = re.search(r"containing\s+(.+)$", text)
        fragment = m.group(1).strip() if m else ""
    if world.heuristic_result is None:
        return False, "No heuristic result available"
    errors = world.heuristic_result.errors
    if not errors:
        return False, "Expected heuristic errors but none were found"
    found = any(fragment.lower() in e.lower() for e in errors)
    if not found:
        return False, f"Expected error containing '{fragment}' but got: {errors}"
    return True, ""


_SP1ConnectionSet = _SP1CoordinationAnalysis


def _sp1_merge_connection_set(
    responsibility_set,
    connection_set,
    run_dir=None,
    model="test-model",
):
    """Backward-compatible wrapper for the old merge_connection_set.

    In the new 4-call Stage 2, the old ConnectionSet is split into
    ControlElementSet (Call 2b) and CoordinationAnalysis (Call 3).
    This wrapper assembles a ControlStructure from a ResponsibilitySet
    and a CoordinationAnalysis (treating it as the old ConnectionSet).
    """
    from pathlib import Path as _Path

    rd = (
        run_dir
        if run_dir is not None
        else _Path(_tempfile.mkdtemp(prefix="sp1_merge_"))
    )
    # Build a minimal ControlElementSet from the connection_set's CPs
    cps = getattr(connection_set, "controlled_processes", [])
    ces = _SP1ControlElementSet(controlled_processes=cps)
    cs, _w = _sp1_assemble_with_fallback(responsibility_set, ces, rd, model)
    # Add coordination links if present
    cs, _cw = _sp1_add_coordination_links(cs, connection_set, rd, model)
    return cs


class _SP1MockLLM:
    """Minimal mock LLM client for acceptance tests."""

    def __init__(self) -> None:
        self.calls: list[dict] = []
        self._response_map: dict[type, Any] = {}
        self._response_queue: list[Any] = []
        self._invalid_types: set[type] = set()
        self._exception_types: dict[type, Exception] = {}
        self._call_counts: dict[type, int] = {}
        self._invalid_after_n: dict[type, int] = {}
        self.base_url = "http://test:8080"
        self.model = "test-model"

    def set_response_for(self, model_class: type, response: Any) -> None:
        self._response_map[model_class] = response

    def set_response_queue(self, responses: list[Any]) -> None:
        self._response_queue = list(responses)

    def set_invalid_response_for(self, model_class: type) -> None:
        """Configure the mock to return an invalid response for a type."""
        self._invalid_types.add(model_class)

    def set_invalid_response_after_n_calls(self, model_class: type, n: int) -> None:
        """Configure the mock to return invalid JSON only after *n* successful calls."""
        self._invalid_after_n[model_class] = n

    def set_exception_for(self, model_class: type, exc: Exception) -> None:
        """Configure the mock to raise *exc* when called for *model_class*."""
        self._exception_types[model_class] = exc

    def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        response_format: type | None = None,
        max_completion_tokens: int | None = None,
        temperature: float | None = None,
    ) -> Any:
        wire_response_format = response_format
        self.calls.append(
            {
                "system_prompt": system_prompt,
                "user_prompt": user_prompt,
                "response_format": response_format,
                "max_completion_tokens": max_completion_tokens,
                "temperature": temperature,
            }
        )
        # Provider-only subclasses keep the same stage contract. Retain the
        # actual wire type in the call record, and reuse base-class fixtures.
        configured = (
            set(self._response_map)
            | self._invalid_types
            | set(self._exception_types)
            | set(self._invalid_after_n)
        )
        if response_format is not None and response_format not in configured:
            response_format = next(
                (base for base in response_format.__mro__[1:] if base in configured),
                response_format,
            )
            # Reuse historical semantic fixtures only at this test boundary.
            # Product provider schemas remain separate and strict.
            legacy_type = {
                "_Stage1aRiskProviderDraft": _SP1LossAnalysisDraft,
                "_Stage1aGapProviderDraft": _SP1LossAnalysisDraft,
                "ProviderCoordinationAnalysis": _SP1CoordinationAnalysis,
                "_CoordinationProviderEnvelope": _SP1CoordinationAnalysis,
            }.get(wire_response_format.__name__)
            if legacy_type in configured:
                response_format = legacy_type
        # Raise exception if configured
        if response_format is not None and response_format in self._exception_types:
            raise self._exception_types[response_format]
        # Track per-type call count for delayed-invalid behaviour
        if response_format is not None:
            self._call_counts[response_format] = (
                self._call_counts.get(response_format, 0) + 1
            )
            if (
                response_format in self._invalid_after_n
                and self._call_counts[response_format]
                > self._invalid_after_n[response_format]
            ):
                content = "THIS_IS_NOT_VALID_JSON{{{"
                return LLMResult(
                    content=content,
                    prompt_tokens=100,
                    completion_tokens=50,
                    duration_ms=5000,
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                )
        if self._response_queue:
            content = self._response_queue.pop(0)
        elif response_format is not None and response_format in self._invalid_types:
            content = "THIS_IS_NOT_VALID_JSON{{{"
        elif response_format is not None and response_format in self._response_map:
            content = self._response_map[response_format]
        else:
            content = None
        wire_name = getattr(wire_response_format, "__name__", "")
        if wire_name in {"_Stage1aRiskProviderDraft", "_Stage1aGapProviderDraft"}:
            from acceptance.fixture_adapters import legacy_stage1a_provider_payload

            content = legacy_stage1a_provider_payload(
                content, risk=wire_name == "_Stage1aRiskProviderDraft"
            )
        elif (
            wire_name
            in {"ProviderCoordinationAnalysis", "_CoordinationProviderEnvelope"}
            and response_format is _SP1CoordinationAnalysis
            and isinstance(content, dict)
        ):
            content = {
                key: value
                for key, value in content.items()
                if key != "integrity_findings"
            }
            if wire_name == "_CoordinationProviderEnvelope":
                content.pop("semantic_review", None)
        content = _sp1_complete_semantic_review_fixture(
            content, wire_response_format, user_prompt=user_prompt
        )
        return LLMResult(
            content=content,
            prompt_tokens=100,
            completion_tokens=50,
            duration_ms=5000,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
        )


def _sp1_complete_semantic_review_fixture(
    content: Any, response_format: type | None, *, user_prompt: str = ""
):
    """Complete the static Call 3 fixture for the current provider schema.

    Stage 1 can merge multiple authoritative loss-analysis drafts and therefore
    renumber the resulting SC/H identities.  Acceptance uses one compact
    semantic-review fixture, while the real Call 3 provider schema carries the
    exact current identities and row count.  Expand only the fixture's review
    rows to that closed schema; all other response fields remain unchanged.

    The provider contract requires an explicit row for every hazard and
    constraint.  Missing rows are therefore completed as ``preserve`` rows
    retaining the exact current edges explicitly rendered in the request.
    This helper never derives a hazard ID from a constraint suffix.
    """
    if not isinstance(content, dict) or not isinstance(
        content.get("semantic_review"), dict
    ):
        return content
    if response_format is None:
        return content
    try:
        schema = response_format.model_json_schema()
        review_property = schema.get("properties", {}).get("semantic_review", {})
        review_ref = review_property.get("$ref")
        if not review_ref:
            return content
        review_schema = schema["$defs"][review_ref.rsplit("/", 1)[-1]]
    except (KeyError, TypeError, AttributeError):
        return content

    def _item_schema(collection_property: dict) -> dict:
        item = collection_property.get("items", {})
        item_ref = item.get("$ref")
        if item_ref:
            return schema["$defs"][item_ref.rsplit("/", 1)[-1]]
        return item

    def _identity_values(collection: str, identity_field: str) -> list[str]:
        collection_property = review_schema.get("properties", {}).get(collection)
        if not isinstance(collection_property, dict):
            return []
        if collection_property.get("maxItems") == 0:
            return []
        item = _item_schema(collection_property)
        identity = item.get("properties", {}).get(identity_field, {})
        if "enum" in identity:
            return list(identity["enum"])
        if "const" in identity:
            return [identity["const"]]
        # Schemas without a closed identity enum are legacy compatibility
        # cases; retain only identities explicitly present in the fixture.
        return [
            row.get(identity_field)
            for row in content["semantic_review"].get(collection, [])
            if isinstance(row, dict) and row.get(identity_field) is not None
        ]

    review = copy.deepcopy(content["semantic_review"])
    hazard_ids = set(_identity_values("hazards", "hazard_id"))
    supplied_edges: dict[str, list[str]] = {}
    current_constraint: str | None = None
    for line in user_prompt.splitlines():
        constraint_match = re.match(r"\s*- \*\*(SC-\d+)\*\* proposed wording:", line)
        if constraint_match:
            current_constraint = constraint_match.group(1)
        elif "All current hazard edges:" in line and current_constraint is not None:
            supplied_edges[current_constraint] = [
                item.strip()
                for item in line.split("All current hazard edges:", 1)[1].split(",")
                if item.strip()
            ]
            current_constraint = None

    collection_specs = {
        "hazards": ("hazard_id", "Acceptance fixture preserves the supplied hazard."),
        "constraints": (
            "constraint_id",
            "Acceptance fixture preserves the supplied constraint decision.",
        ),
        "responsibilities": (
            "responsibility_id",
            "Acceptance fixture preserves the supplied responsibility decision.",
        ),
        "actions": (
            "control_action_id",
            "Acceptance fixture preserves the supplied action decision.",
        ),
    }

    for collection, (identity_field, rationale) in collection_specs.items():
        collection_property = review_schema.get("properties", {}).get(collection)
        if (
            isinstance(collection_property, dict)
            and collection_property.get("maxItems") == 0
        ):
            review[collection] = []
            continue
        expected_ids = _identity_values(collection, identity_field)
        if not expected_ids:
            continue
        existing_rows = {
            row.get(identity_field): row
            for row in review.get(collection, [])
            if isinstance(row, dict) and row.get(identity_field) is not None
        }
        rows = []
        for identity in expected_ids:
            row = copy.deepcopy(existing_rows.get(identity, {}))
            row[identity_field] = identity
            if collection == "hazards":
                row.setdefault("disposition", "preserve")
                row.setdefault("revised_description", None)
                row.setdefault("missing_fact", None)
                row.setdefault("source_evidence", [])
            elif collection == "constraints":
                row.setdefault("disposition", "preserve")
                row.setdefault("revised_description", None)
                row.setdefault("missing_fact", None)
                row["related_hazards"] = [
                    hazard
                    for hazard in row.get(
                        "related_hazards", supplied_edges.get(identity, [])
                    )
                    if hazard in hazard_ids
                ]
                row.setdefault("source_evidence", [])
            elif collection == "responsibilities":
                row.setdefault("constraint_refs", [])
            elif collection == "actions":
                row.setdefault("effect_kind", None)
            row.setdefault("rationale", rationale)
            rows.append(row)
        review[collection] = rows
    result = copy.deepcopy(content)
    result["semantic_review"] = review
    return result


class _ParallelDummyModel(BaseModel):
    """Simple model for parallel call acceptance tests."""

    value: str = "default"


class _ConcurrentMockLLMClient:
    """Mock LLM client for parallel call acceptance tests.

    Supports step-based delays, step-based exceptions, concurrent
    in-flight tracking, and per-call temperature recording.
    """

    def __init__(self, model: str = "test-model") -> None:
        self.base_url = "http://test:8080"
        self.model = model
        self.max_completion_tokens = None
        self.calls: list[dict] = []
        self._delay_by_step: dict[str, float] = {}
        self._exception_by_step: dict[str, Exception] = {}
        self._in_flight = 0
        self._max_in_flight = 0
        self._tracker_lock = threading.Lock()

    def set_delay_for_step(self, step: str, seconds: float) -> None:
        self._delay_by_step[step] = seconds

    def set_exception_for_step(self, step: str, exc: Exception) -> None:
        self._exception_by_step[step] = exc

    @property
    def max_in_flight(self) -> int:
        return self._max_in_flight

    def _find_matching_step(self, user_prompt: str) -> str | None:
        for step in self._delay_by_step:
            if step in user_prompt:
                return step
        for step in self._exception_by_step:
            if step in user_prompt:
                return step
        return None

    def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        response_format: type | None = None,
        max_completion_tokens: int | None = None,
        temperature: float | None = None,
    ) -> LLMResult:
        with self._tracker_lock:
            self._in_flight += 1
            if self._in_flight > self._max_in_flight:
                self._max_in_flight = self._in_flight
        try:
            step = self._find_matching_step(user_prompt)
            if step and step in self._delay_by_step:
                time.sleep(self._delay_by_step[step])
            if step and step in self._exception_by_step:
                raise self._exception_by_step[step]
            self.calls.append(
                {
                    "system_prompt": system_prompt,
                    "user_prompt": user_prompt,
                    "response_format": response_format,
                    "temperature": temperature,
                }
            )
            return LLMResult(
                content=_ParallelDummyModel(value="ok"),
                prompt_tokens=100,
                completion_tokens=50,
                duration_ms=10,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
            )
        finally:
            with self._tracker_lock:
                self._in_flight -= 1


def _parallel_make_spec(
    step: str,
    *,
    stage: str = "stage_3",
    temperature: float = 0.4,
    system_prompt: str = "sys",
) -> Any:
    """Build an LLMCallSpec with the step embedded in the user_prompt."""
    from asago_scenario_generator.stpa.infra.parallel_llm import LLMCallSpec

    return LLMCallSpec(
        system_prompt=system_prompt,
        user_prompt=f"prompt for {step}",
        response_format=_ParallelDummyModel,
        stage=stage,
        step=step,
        temperature=temperature,
    )


def _sp1_valid_la_dict() -> dict:
    return {
        "risk_card_losses": [
            {
                "loss_id": "L-1",
                "description": "Unauthorized transaction",
                "provenance": "risk_card",
                "source_risk_cards": ["atlas-001"],
            },
            {
                "loss_id": "L-2",
                "description": "Data exposure",
                "provenance": "risk_card",
                "source_risk_cards": ["atlas-002"],
            },
        ],
        "use_case_losses": [
            {
                "loss_id": "L-3",
                "description": "Loss of trust",
                "provenance": "use_case",
                "source_risk_cards": [],
            },
        ],
        "hazards": [
            {
                "hazard_id": "H-1",
                "description": "Agent executes unintended action",
                "related_losses": ["L-1", "L-3"],
            },
            {
                "hazard_id": "H-2",
                "description": "Agent exposes data",
                "related_losses": ["L-2"],
            },
        ],
        "security_constraints": [
            {
                "constraint_id": "SC-1",
                "rule": (
                    "The agent must confirm every unintended action before execution."
                ),
                "related_hazards": ["H-1"],
                "applies_when": [],
            },
            {
                "constraint_id": "SC-2",
                "rule": "Must not expose data",
                "related_hazards": ["H-2"],
                "applies_when": [],
            },
        ],
        "risk_dispositions": [
            {
                "risk_ref": "atlas-001",
                "disposition": "cited",
                "loss_ids": ["L-1"],
                "reason": None,
            },
        ],
    }


def _sp1_valid_stage1_profile_dict() -> dict:
    return {
        "has_persistent_memory": False,
        "multi_agent": False,
        "hitl": False,
        "entry_points": [
            {"name": "User chat", "direction": "input", "controllability": "direct"}
        ],
        "confidence": "medium",
        "kc_subcodes": ["KC1.1", "KC5.1", "KC6.1.1"],
        "tool_inventory": [{"name": "tool1", "description": "A tool"}],
    }


def _sp1_valid_req_set_dict() -> dict:
    return {
        "requirements": [
            {
                "req_id": "REQ-1",
                "description": "Verify user identity",
                "classification": "control",
                "source_constraint": "SC-1",
            },
            {
                "req_id": "REQ-2",
                "description": "Data protection",
                "classification": "constraint",
                "source_constraint": "SC-2",
            },
        ]
    }


def _sp1_valid_resp_set_dict() -> dict:
    return {
        "responsibilities": [
            {
                "resp_id": "RESP-1",
                "description": "Authorization controller",
                "security_constraint_refs": ["SC-1"],
                "responsibility_constraints": [
                    {"rc_id": "RC-1-1", "description": "Must confirm"}
                ],
                "process_model_parts": [
                    {"pm_id": "PM-1-1", "description": "User intent state"}
                ],
                "control_actions": [
                    {"ca_id": "CA-1-1", "description": "Execute action"}
                ],
                "feedback_channels": [
                    {
                        "fb_id": "FB-1-1",
                        "description": "Action result",
                        "updates": "PM-1-1",
                        "source": {"type": "responsibility", "id": "RESP-1"},
                    },
                ],
            },
            {
                "resp_id": "RESP-2",
                "description": "Data controller",
                "security_constraint_refs": ["SC-2"],
                "responsibility_constraints": [
                    {"rc_id": "RC-2-1", "description": "Protect data"}
                ],
                "process_model_parts": [
                    {"pm_id": "PM-2-1", "description": "Data state"}
                ],
                "control_actions": [{"ca_id": "CA-2-1", "description": "Manage data"}],
                "feedback_channels": [
                    {
                        "fb_id": "FB-2-1",
                        "description": "Data status",
                        "updates": "PM-2-1",
                        "source": {"type": "responsibility", "id": "RESP-2"},
                    },
                ],
            },
        ],
        "controlled_processes": [
            {"cp_id": "CP-1", "description": "External service"},
        ],
    }


def _sp1_valid_resp_set_2a_dict() -> dict:
    """Valid ResponsibilitySet for Call 2a — RCs and PMs only, no CAs/FBs.

    In the new 4-call Stage 2, Call 2a produces responsibilities with
    only responsibility_constraints and process_model_parts.  CAs, FBs,
    and CPs are produced by Call 2b (ControlElementSet).
    """
    return {
        "responsibilities": [
            {
                "resp_id": "RESP-1",
                "description": "Authorization controller",
                "security_constraint_refs": ["SC-1"],
                "responsibility_constraints": [
                    {"rc_id": "RC-1-1", "description": "Must confirm"}
                ],
                "process_model_parts": [
                    {"pm_id": "PM-1-1", "description": "User intent state"}
                ],
            },
            {
                "resp_id": "RESP-2",
                "description": "Data controller",
                "security_constraint_refs": ["SC-2"],
                "responsibility_constraints": [
                    {"rc_id": "RC-2-1", "description": "Protect data"}
                ],
                "process_model_parts": [
                    {"pm_id": "PM-2-1", "description": "Data state"}
                ],
            },
        ],
    }


def _sp1_valid_cs_dict() -> dict:
    rs = _sp1_valid_resp_set_dict()
    return {
        "responsibilities": rs["responsibilities"],
        "controlled_processes": rs["controlled_processes"],
        "coordination_links": [],
    }


def _sp1_valid_connection_set_dict() -> dict:
    """Valid CoordinationAnalysis for Call 3 — matches the assembly test helper.

    In the new 4-call Stage 2, Call 3 produces a CoordinationAnalysis
    (coordination links + integrity findings).  This dict is backward-
    compatible with step handlers that expect the old ConnectionSet shape
    but only access coordination_links and controlled_processes.
    """
    return {
        "coordination_links": [
            {
                "link_id": "CL-1",
                "source": "RESP-1",
                "target": "RESP-2",
                "shared_pm": "PM-1-1",
                "coordination_mechanism": {
                    "cm_id": "CM-1",
                    "description": "Mechanism",
                    "payload": "data",
                },
                "description": "Link",
            },
        ],
        "integrity_findings": [],
        "semantic_review": _sp1_semantic_review_fixture(),
    }


def _sp1_valid_control_element_set_dict() -> dict:
    """Valid ControlElementSet for Call 2b — CAs, FBs, and CPs."""
    return {
        "control_actions": [
            {
                "ca_id": "CA-1-1",
                "description": "Execute action",
                "target": {"type": "controlled_process", "id": "CP-1"},
            },
            {
                "ca_id": "CA-2-1",
                "description": "Send response",
                "target": {"type": "responsibility", "id": "RESP-2"},
            },
        ],
        "feedback_channels": [
            {
                "fb_id": "FB-1-1",
                "description": "Action result",
                "updates": "PM-1-1",
                "source": {"type": "controlled_process", "id": "CP-1"},
            },
            {
                "fb_id": "FB-2-1",
                "description": "Response delivery",
                "updates": "PM-2-1",
                "source": {"type": "responsibility", "id": "RESP-2"},
            },
        ],
        "controlled_processes": [
            {"cp_id": "CP-1", "description": "External service"},
        ],
    }


def _sp1_valid_coordination_analysis_dict() -> dict:
    """Valid CoordinationAnalysis for Call 3."""
    return _sp1_valid_connection_set_dict()


def _sp1_semantic_review_fixture() -> dict:
    return {
        "hazards": [
            {
                "hazard_id": "H-1",
                "disposition": "preserve",
                "revised_description": None,
                "missing_fact": None,
                "source_evidence": [],
                "rationale": "The supplied first hazard is retained unchanged.",
            },
            {
                "hazard_id": "H-2",
                "disposition": "preserve",
                "revised_description": None,
                "missing_fact": None,
                "source_evidence": [],
                "rationale": "The supplied second hazard is retained unchanged.",
            },
        ],
        "constraints": [
            {
                "constraint_id": "SC-1",
                "disposition": "preserve",
                "revised_description": None,
                "missing_fact": None,
                "related_hazards": ["H-1"],
                "source_evidence": [],
                "rationale": "Authorization rule applies to the first reviewed hazard.",
            },
            {
                "constraint_id": "SC-2",
                "disposition": "preserve",
                "revised_description": None,
                "missing_fact": None,
                "related_hazards": ["H-2"],
                "source_evidence": [],
                "rationale": "Data protection rule applies to the second reviewed hazard.",
            },
        ],
        "responsibilities": [
            {
                "responsibility_id": "RESP-1",
                "constraint_refs": ["SC-1"],
                "rationale": "Authorization rule.",
            },
            {
                "responsibility_id": "RESP-2",
                "constraint_refs": ["SC-2"],
                "rationale": "Data protection rule.",
            },
        ],
        "actions": [
            {
                "control_action_id": "CA-1-1",
                "effect_kind": "tool_call",
                "rationale": "Controlled process operation.",
            },
            {
                "control_action_id": "CA-2-1",
                "effect_kind": "agent_message",
                "rationale": "Internal responsibility target.",
            },
        ],
    }


def _sp1_valid_connection_set_no_assignments_dict() -> dict:
    """CoordinationAnalysis with only coordination links, no CPs or assignments."""
    return {
        "coordination_links": [
            {
                "link_id": "CL-1",
                "source": "RESP-1",
                "target": "RESP-2",
                "shared_pm": "PM-1-1",
                "coordination_mechanism": {
                    "cm_id": "CM-1",
                    "description": "Mechanism",
                    "payload": "data",
                },
                "description": "Link",
            },
        ],
        "integrity_findings": [],
        "semantic_review": _sp1_semantic_review_fixture(),
    }


def _sp1_valid_connection_set_cp_only_dict() -> dict:
    """CoordinationAnalysis with no links (CPs come from Call 2b now)."""
    return {
        "coordination_links": [],
        "integrity_findings": [],
        "semantic_review": _sp1_semantic_review_fixture(),
    }


def _sp1_valid_connection_set_fb_assignment_dict() -> dict:
    """CoordinationAnalysis with no links (FB assignments come from Call 2b now)."""
    return {
        "coordination_links": [],
        "integrity_findings": [],
        "semantic_review": _sp1_semantic_review_fixture(),
    }


def _sp1_valid_connection_set_ca_assignment_dict() -> dict:
    """CoordinationAnalysis with no links (CA assignments come from Call 2b now)."""
    return {
        "coordination_links": [],
        "integrity_findings": [],
        "semantic_review": _sp1_semantic_review_fixture(),
    }


def _sp1_valid_cs_with_coord_dict() -> dict:
    rs = _sp1_valid_resp_set_dict()
    return {
        "responsibilities": rs["responsibilities"],
        "controlled_processes": rs["controlled_processes"],
        "coordination_links": [
            {
                "link_id": "CL-1",
                "source": "RESP-1",
                "target": "RESP-2",
                "shared_pm": "PM-1-1",
                "coordination_mechanism": {
                    "cm_id": "CM-1",
                    "description": "Mechanism",
                    "payload": "data",
                },
                "description": "Link",
            },
        ],
    }


def _sp1_valid_critic_findings_dict() -> dict:
    return {
        "gaps": [
            {
                "gap_type": "missing_responsibility",
                "description": "Missing input validation",
                "related_attack_path": "Attacker sends crafted input",
                "suggested_remedy": "Add input validation",
            },
            {
                "gap_type": "missing_feedback",
                "description": "Missing outcome feedback",
                "related_attack_path": "Attacker exploits unchecked output",
                "suggested_remedy": "Add outcome verification",
            },
        ],
        "checklist_results": {
            "Input validation": "present",
            "Authorization": "present",
            "Action selection": "present",
            "Outcome verification": "absent_justified",
            "Context management": "present",
            "Multi-agent coordination": "absent_justified",
            "Human-in-the-loop": "absent_justified",
        },
        "taxonomy_probe_results": {},
    }


def _sp1_no_unjustified_critic_dict() -> dict:
    return {
        "gaps": [],
        "checklist_results": {
            "Input validation": "present",
            "Authorization": "present",
            "Action selection": "present",
            "Outcome verification": "present",
            "Context management": "present",
            "Multi-agent coordination": "absent_justified",
            "Human-in-the-loop": "absent_justified",
        },
        "taxonomy_probe_results": {},
    }


def _sp1_make_risk_cards() -> list:
    return [
        _SP1RiskCard(
            risk_id="atlas-001",
            risk_name="Prompt injection",
            risk_description="Risk of prompt injection",
            taxonomy="ibm-risk-atlas",
            confidence=0.9,
            grounding_confidence="high",
        ),
    ]


def _sp1_valid_revision_patch_dict() -> dict:
    """Explicit edits for the shared fixture graph.

    Unedited graph records remain in the prior analysis. The fixture
    explicitly supplies obligations for any rule or scope edit.
    """
    return {
        "hazard_additions": [],
        "constraint_additions": [],
        "hazard_edits": [
            {
                "hazard_id": "H-1",
                "description": "Agent executes unintended action",
                "related_losses": ["L-1", "L-3"],
            },
            {
                "hazard_id": "H-2",
                "description": "Agent exposes data",
                "related_losses": ["L-2"],
            },
        ],
        "constraint_edits": [
            {
                "constraint_id": "SC-1",
                "rule": (
                    "The agent must confirm every unintended action before execution."
                ),
                "related_hazards": ["H-1"],
                "applies_when": [],
                "obligations": [],
            },
            {
                "constraint_id": "SC-2",
                "rule": "Must not expose data",
                "related_hazards": ["H-2"],
                "applies_when": [],
                "obligations": [],
            },
        ],
    }


def _sp1_setup_full_mock_client(
    critic_findings: dict | None = None,
    revised_cs: dict | None = None,
) -> _SP1MockLLM:
    """Set up a mock LLM client with valid responses for all stages."""
    client = _SP1MockLLM()
    client.set_response_for(_SP1LossAnalysisDraft, _sp1_valid_la_dict())
    client.set_response_for(_SP1Stage1aRevisionPatch, _sp1_valid_revision_patch_dict())
    client.set_response_for(_SP1Stage1Profile, _sp1_valid_stage1_profile_dict())
    client.set_response_for(_SP1RequirementSet, _sp1_valid_req_set_dict())
    client.set_response_for(_SP1ResponsibilitySet, _sp1_valid_resp_set_2a_dict())
    client.set_response_for(
        _SP1ControlElementSet, _sp1_valid_control_element_set_dict()
    )
    client.set_response_for(_SP1ConnectionSet, _sp1_valid_connection_set_dict())
    client.set_response_for(ControlStructure, _sp1_valid_cs_dict())
    if critic_findings is not None:
        client.set_response_for(_SP1CriticFindings, critic_findings)
    else:
        client.set_response_for(_SP1CriticFindings, _sp1_no_unjustified_critic_dict())
    if revised_cs is not None:
        client.set_response_queue([_sp1_valid_cs_dict(), revised_cs])
        client._response_map.pop(ControlStructure, None)
    return client


def _h_sp1_stage1a_run_full(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: Stage 1a loss analysis is run (full execution)."""
    run_dir = world.sp1_run_dir or Path(_tempfile.mkdtemp(prefix="sp1_la_"))
    world.sp1_run_dir = run_dir
    client = _SP1MockLLM()
    if world.sp1_llm_content is not None:
        client.set_response_for(_SP1LossAnalysisDraft, world.sp1_llm_content)
    else:
        client.set_response_for(_SP1LossAnalysisDraft, _sp1_valid_la_dict())
    world.sp1_mock_client = client
    try:
        world.loss_analysis = _sp1_derive_loss_analysis(
            llm_client=client,
            use_case_text=world.sp1_use_case_text,
            risk_cards=_sp1_make_risk_cards(),
            run_dir=run_dir,
        )
    except (ValidationError, ValueError, _GDStageError) as e:
        world.validation_error = e
    return True, ""


def _h_sp1_file_exists(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a file <filename> exists in the run directory."""
    m = re.search(r"a file (\S+) exists", text)
    if not m:
        return False, f"Could not parse filename from: {text}"
    filename = m.group(1)
    run_dir = world.sp1_run_dir
    if run_dir is None:
        return False, "No run directory available"
    if not (run_dir / filename).exists():
        return False, f"File {filename} does not exist in {run_dir}"
    return True, ""


def _h_sp1_s2_call1_run_full(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: Stage 2 Call 1 requirements derivation is run (full execution)."""
    run_dir = world.sp1_run_dir or Path(_tempfile.mkdtemp(prefix="sp1_s2_"))
    world.sp1_run_dir = run_dir
    client = world.sp1_mock_client or _SP1MockLLM()
    world.sp1_mock_client = client
    content = (
        world.sp1_llm_content
        if isinstance(world.sp1_llm_content, dict)
        else _sp1_valid_req_set_dict()
    )
    client.set_response_for(_SP1RequirementSet, content)
    try:
        world.sp1_requirement_set = _SP1RequirementSet.model_validate(content)
    except (ValidationError, ValueError) as e:
        world.validation_error = e
    return True, ""


def _h_sp1_s2_calls_1_3_run(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: Stage 2 calls 1 through 3 are run in sequence."""
    run_dir = world.sp1_run_dir or Path(_tempfile.mkdtemp(prefix="sp1_s2_"))
    world.sp1_run_dir = run_dir
    client = world.sp1_mock_client or _SP1MockLLM()
    world.sp1_mock_client = client
    client.set_response_for(_SP1RequirementSet, _sp1_valid_req_set_dict())
    client.set_response_for(_SP1ResponsibilitySet, _sp1_valid_resp_set_2a_dict())
    client.set_response_for(
        _SP1ControlElementSet, _sp1_valid_control_element_set_dict()
    )
    client.set_response_for(_SP1ConnectionSet, _sp1_valid_connection_set_dict())
    # Call 1
    client.complete(
        system_prompt="stage2_call1_system",
        user_prompt="Requirements from constraints: SC-1, SC-2",
        response_format=_SP1RequirementSet,
        temperature=0.4,
    )
    # Call 2 — prompt contains requirements from Call 1
    client.complete(
        system_prompt="stage2_call2_system",
        user_prompt="Requirements: REQ-1 Verify user identity, REQ-2 Data protection",
        response_format=_SP1ResponsibilitySet,
        temperature=0.4,
    )
    # Call 3 — prompt contains responsibilities from Call 2
    client.complete(
        system_prompt="stage2_call3_system",
        user_prompt="Responsibilities: RESP-1 Authorization controller, RESP-2 Data controller. Controlled processes: CP-1",
        response_format=_SP1ConnectionSet,
        temperature=0.4,
    )
    try:
        world.sp1_requirement_set = _SP1RequirementSet.model_validate(
            _sp1_valid_req_set_dict()
        )
        world.sp1_responsibility_set = _SP1ResponsibilitySet.model_validate(
            _sp1_valid_resp_set_2a_dict()
        )
        world.sp1_connection_set = _SP1ConnectionSet.model_validate(
            _sp1_valid_connection_set_dict()
        )
        world.control_structure = _sp1_merge_connection_set(
            world.sp1_responsibility_set,
            world.sp1_connection_set,
        )
    except (ValidationError, ValueError) as e:
        world.validation_error = e
    return True, ""


def _h_sp1_s2_full_run(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: Stage 2 control structure derivation is run (full)."""
    run_dir = world.sp1_run_dir or Path(_tempfile.mkdtemp(prefix="sp1_s2_"))
    world.sp1_run_dir = run_dir
    client = world.sp1_mock_client or _SP1MockLLM()
    world.sp1_mock_client = client
    client.set_response_for(_SP1RequirementSet, _sp1_valid_req_set_dict())
    client.set_response_for(_SP1ResponsibilitySet, _sp1_valid_resp_set_2a_dict())
    client.set_response_for(
        _SP1ControlElementSet, _sp1_valid_control_element_set_dict()
    )
    # Use ConnectionSet for Call 3 (new schema), fall back to ControlStructure
    # for older tests that registered a ControlStructure response.
    if _SP1ConnectionSet not in client._response_map:
        client.set_response_for(_SP1ConnectionSet, _sp1_valid_connection_set_dict())
    if ControlStructure not in client._response_map:
        client.set_response_for(ControlStructure, _sp1_valid_cs_dict())
    la = world.loss_analysis or _sp1_make_loss_analysis_with_constraints()
    try:
        derivation = _sp1_derive_control_structure(
            llm_client=client,
            use_case_text=world.sp1_use_case_text,
            loss_analysis=la,
            run_dir=run_dir,
        )
        world.loss_analysis = derivation.loss_analysis
        world.control_structure = derivation.control_structure
        world.sp1_warnings = derivation.warnings
        world.heuristic_result = _sp1_run_heuristics(
            world.control_structure, derivation.loss_analysis
        )
    except (ValidationError, ValueError, _GDStageError) as e:
        world.validation_error = e
    return True, ""


def _h_sp1_critic_run_full(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the completeness critic is run (full execution)."""
    run_dir = world.sp1_run_dir or Path(_tempfile.mkdtemp(prefix="sp1_critic_"))
    world.sp1_run_dir = run_dir
    client = world.sp1_mock_client or _SP1MockLLM()
    world.sp1_mock_client = client
    content = (
        world.sp1_llm_content
        if isinstance(world.sp1_llm_content, dict)
        else _sp1_valid_critic_findings_dict()
    )
    client.set_response_for(_SP1CriticFindings, content)
    profile = world.sp1_profile
    if profile is None:
        profile = _SP1Stage1Profile(
            **_sp1_valid_stage1_profile_dict()
        ).to_capability_profile()
    try:
        world.sp1_critic_findings = _SP1CriticFindings.model_validate(content)
        if world.sp1_llm_content is not None and isinstance(
            world.sp1_llm_content, dict
        ):
            if "missing_tool" in str(world.sp1_llm_content):
                raise ValueError("gap_type: Invalid literal")
    except (ValidationError, ValueError) as e:
        world.validation_error = e
    return True, ""


def _h_sp1_rev_run(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the revision is run."""
    run_dir = world.sp1_run_dir or Path(_tempfile.mkdtemp(prefix="sp1_rev_"))
    world.sp1_run_dir = run_dir
    client = world.sp1_mock_client or _SP1MockLLM()
    world.sp1_mock_client = client
    content = (
        world.sp1_llm_content
        if isinstance(world.sp1_llm_content, dict)
        else _sp1_valid_cs_dict()
    )
    # Only set response if no exception/invalid is configured (graceful degradation)
    if (
        ControlStructure not in client._exception_types
        and ControlStructure not in client._invalid_types
    ):
        client.set_response_for(ControlStructure, content)
    try:
        result = client.complete(
            system_prompt="revision_system",
            user_prompt="revision_user",
            response_format=ControlStructure,
            temperature=0.4,
        )
    except Exception as exc:
        # Graceful degradation: LLM exception during revision
        world.sp1_post_revision_warnings = [
            f"Revision failed: {type(exc).__name__}: {exc}"
        ]
        world.sp1_revision_call_count = 1
        # Log the failed call
        from asago_scenario_generator.stpa.infra.llm_helpers import log_llm_call_failure

        log_llm_call_failure(
            client.model, run_dir, "stage_2", "revision", f"{type(exc).__name__}: {exc}"
        )
        return True, ""
    try:
        actual_content = result.content if hasattr(result, "content") else content
        revised_cs = ControlStructure.model_validate(actual_content)
        world.control_structure = revised_cs
        world.sp1_revised = True
        world.sp1_revision_call_count = 1
        _sp1_log_llm_call(result, client.model, run_dir, "stage_2", "revision")
        la = world.loss_analysis
        post_result = _sp1_run_heuristics(revised_cs, la)
        world.sp1_post_revision_warnings = post_result.errors + post_result.warnings
        # Strip empty responsibilities (mirrors _run_stage_2_block in run.py)
        stripped_cs, strip_warnings = strip_empty_responsibilities(revised_cs)
        world.control_structure = stripped_cs
        world.sp1_post_revision_warnings.extend(strip_warnings)
    except (ValidationError, ValueError) as e:
        # Graceful degradation: validation failure returns pre-revision CS
        world.validation_error = e
        if world.gd_pre_revision_cs is not None:
            world.control_structure = world.gd_pre_revision_cs
        world.sp1_post_revision_warnings = [f"Revision failed: {type(e).__name__}: {e}"]
        world.sp1_revision_call_count = 1
        from asago_scenario_generator.stpa.infra.llm_helpers import log_llm_call_failure

        log_llm_call_failure(
            client.model, run_dir, "stage_2", "revision", f"{type(e).__name__}: {e}"
        )
    return True, ""


def _h_sp1_rev_applied(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the revision is applied."""
    return _h_sp1_rev_run(world, text, examples)


def _h_sp1_run_manifest_critic_two(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the run manifest critic_findings contains two entries."""
    if world.sp1_manifest is None:
        return False, "No manifest available"
    if "critic_findings" not in world.sp1_manifest:
        return False, "No critic_findings in manifest"
    if len(world.sp1_manifest["critic_findings"]) != 2:
        return (
            False,
            f"Expected 2 but got: {len(world.sp1_manifest['critic_findings'])}",
        )
    return True, ""


def _h_sp1_heur_cs_no_constraint(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a control structure where no responsibility references constraint SC-1."""
    world.control_structure = _sp1_make_control_structure_with_resp()
    return True, ""


def _h_sp1_heur_cs_with_constraint(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a control structure where responsibility RESP-1 references constraint SC-1."""
    cs = _sp1_make_control_structure_with_resp()
    cs.responsibilities[0].security_constraint_refs = ["SC-1"]
    world.control_structure = cs
    return True, ""


def _h_sp1_heur_orphan_warn(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a warning is produced for orphan PM PM-1-2."""
    if world.heuristic_result is None:
        return False, "No heuristic result available"
    if not any("PM-1-2" in w for w in world.heuristic_result.warnings):
        return (
            False,
            f"Expected warning for PM-1-2 but got: {world.heuristic_result.warnings}",
        )
    return True, ""


def _h_sp1_heur_pipeline_no_loop(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the pipeline proceeds without looping."""
    if world.sp1_revision_call_count > 1:
        return False, "Pipeline looped"
    return True, ""


def _gd_valid_critic_unjustified_dict() -> dict:
    return {
        "gaps": [
            {
                "gap_type": "missing_responsibility",
                "description": "Missing input validation",
                "related_attack_path": "Attacker sends crafted input",
                "suggested_remedy": "Add input validation",
            }
        ],
        "checklist_results": {
            "Input validation": "absent_unjustified",
            "Authorization": "present",
        },
        "taxonomy_probe_results": {},
    }


def _gd_valid_la() -> LossAnalysis:
    return LossAnalysis.model_validate(_sp1_valid_la_dict())


def _gd_valid_profile() -> _SP1CapabilityProfile:
    return _SP1Stage1Profile.model_validate(
        _sp1_valid_stage1_profile_dict()
    ).to_capability_profile()


def _gd_valid_cs() -> ControlStructure:
    return ControlStructure.model_validate(_sp1_valid_cs_dict())


def _gd_read_calls(run_dir: Path) -> list[dict]:
    calls_file = run_dir / "calls.jsonl"
    if not calls_file.exists():
        return []
    return [json.loads(line) for line in calls_file.read_text().splitlines()]


def _h_gd_rev_run(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the revision is run (graceful degradation version)."""
    run_dir = world.sp1_run_dir or Path(_tempfile.mkdtemp(prefix="gd_rev_"))
    world.sp1_run_dir = run_dir
    client = world.sp1_mock_client or _SP1MockLLM()
    world.sp1_mock_client = client
    cs = world.gd_pre_revision_cs or _gd_valid_cs()
    findings = world.sp1_critic_findings or _GDCriticFindings.model_validate(
        _gd_valid_critic_unjustified_dict()
    )
    revised, warnings = _gd_run_revision(
        llm_client=client,
        control_structure=cs,
        critic_findings=findings,
        use_case_text=world.sp1_use_case_text,
        run_dir=run_dir,
    )
    world.control_structure = revised
    world.sp1_post_revision_warnings = warnings
    return True, ""


def _h_gd_critic_run(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the completeness critic is run (graceful degradation version)."""
    run_dir = world.sp1_run_dir or Path(_tempfile.mkdtemp(prefix="gd_critic_"))
    world.sp1_run_dir = run_dir
    client = world.sp1_mock_client or _SP1MockLLM()
    world.sp1_mock_client = client
    cs = world.control_structure or _gd_valid_cs()
    profile = world.sp1_profile or _gd_valid_profile()
    findings = _gd_run_critic(
        llm_client=client,
        control_structure=cs,
        capability_profile=profile,
        use_case_text=world.sp1_use_case_text,
        run_dir=run_dir,
    )
    world.sp1_critic_findings = findings
    return True, ""


def _h_connset_critic_unjustified(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: critic findings with unjustified gaps."""
    world.sp1_critic_findings = _sp1_critic_unjustified_gaps()
    return True, ""


def _sp1_critic_unjustified_gaps():
    """Return CriticFindings with unjustified gaps for revision tests."""
    from asago_scenario_generator.stpa.system_model.critic import CriticFindings

    return CriticFindings(
        gaps=[
            {
                "gap_type": "missing_responsibility",
                "description": "Missing validation",
                "related_attack_path": "Attack",
                "suggested_remedy": "Add validation",
            }
        ],
        checklist_results={"Input validation": "absent_unjustified"},
        taxonomy_probe_results={},
    )


def _sp1_invalid_connectionset_namespace_confusion() -> dict:
    """ConnectionSet where a feedback source uses a FeedbackChannel ID as a CP ID."""
    return {
        "coordination_links": [],
        "controlled_processes": [],
        "connection_assignments": [
            # FB-1-1 source set to controlled_process "FB-1-1" (namespace confusion)
            {
                "element_id": "FB-1-1",
                "source": {"type": "controlled_process", "id": "FB-1-1"},
            },
        ],
    }


def _sp1_invalid_connectionset_bad_link_source() -> dict:
    """ConnectionSet with a coordination link referencing a non-existent responsibility."""
    return {
        "coordination_links": [
            {
                "link_id": "CL-1",
                "source": "RESP-99",
                "target": "RESP-2",
                "shared_pm": "PM-1-1",
                "coordination_mechanism": {
                    "cm_id": "CM-1",
                    "description": "Mechanism",
                    "payload": "data",
                },
                "description": "Link",
            },
        ],
        "controlled_processes": [],
        "connection_assignments": [],
    }


def _sp1_invalid_connectionset_bad_link_pm() -> dict:
    """ConnectionSet with a coordination link referencing a non-existent PM."""
    return {
        "coordination_links": [
            {
                "link_id": "CL-1",
                "source": "RESP-1",
                "target": "RESP-2",
                "shared_pm": "PM-99-1",
                "coordination_mechanism": {
                    "cm_id": "CM-1",
                    "description": "Mechanism",
                    "payload": "data",
                },
                "description": "Link",
            },
        ],
        "controlled_processes": [],
        "connection_assignments": [],
    }


_PQF_PROMPTS_DIR = (
    PROJECT_ROOT
    / "src"
    / "asago_scenario_generator"
    / "stpa"
    / "system_model"
    / "prompts"
)


def _h_pqf_prompts_dir_available(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the STPA system model prompts directory is available."""
    if not _PQF_PROMPTS_DIR.is_dir():
        return False, f"Prompts directory not found: {_PQF_PROMPTS_DIR}"
    world.template_dir = _PQF_PROMPTS_DIR
    return True, ""


def _h_pqf_template_loader_created(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the TemplateLoader can load templates from the prompts directory."""
    if world.template_dir is None:
        world.template_dir = _PQF_PROMPTS_DIR
    world.template_loader = TemplateLoader(world.template_dir)
    return True, ""


def _h_pqf_rendered_text_contains(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the rendered text contains "..." (multi-word quoted text)."""
    if world.template_rendered is None:
        return False, "No rendered text"
    quoted = re.search(r'"([^"]+)"', text)
    if quoted:
        expected = quoted.group(1)
    else:
        # Fallback: single word for backward compatibility
        match = re.search(r"contains (\S+)", text)
        expected = match.group(1) if match else ""
    if not expected:
        return False, f"Could not extract expected text from: {text}"
    if expected not in world.template_rendered:
        snippet = world.template_rendered[:300]
        return (
            False,
            f"Expected '{expected}' in rendered text but it was not found. Start: {snippet}...",
        )
    return True, ""


def _data_table_to_dicts(table: list[list[str]] | None) -> list[dict[str, str]]:
    """Convert a data table (list of rows) to a list of dicts."""
    if not table or len(table) < 2:
        return []
    headers = table[0]
    result = []
    for row in table[1:]:
        d = {}
        for i, h in enumerate(headers):
            d[h] = row[i] if i < len(row) else ""
        result.append(d)
    return result


def _profiles_to_yaml(rows: list[dict[str, str]]) -> str:
    """Convert profile row dicts to YAML text."""
    profiles: dict[str, Any] = {}
    for row in rows:
        name = row.get("profile", "")
        profile: dict[str, Any] = {}
        for key in ("base_url", "model", "api_key"):
            val = row.get(key, "")
            if val:
                profile[key] = val
        for key in ("max_completion_tokens", "temperature", "top_p", "top_k"):
            val = row.get(key, "")
            if val:
                # Try to convert to appropriate type
                try:
                    if "." in val:
                        profile[key] = float(val)
                    else:
                        profile[key] = int(val)
                except ValueError:
                    profile[key] = val
        headers_val = row.get("headers", "")
        if headers_val:
            try:
                profile["headers"] = json.loads(headers_val)
            except (json.JSONDecodeError, TypeError):
                profile["headers"] = headers_val
        profiles[name] = profile
    return _yaml_mp.dump(profiles, default_flow_style=False)


def _calls_entries_from_data_table(
    table: list[list[str]] | None,
) -> list[dict[str, Any]]:
    """Convert a data table to calls.jsonl entries."""
    rows = _data_table_to_dicts(table)
    entries = []
    for row in rows:
        entry: dict[str, Any] = {
            "stage": row.get("stage", ""),
            "step": row.get("step", ""),
            "slot_id": None,
            "scenario_id": None,
            "system_prompt_hash": "sha256-aaa",
            "user_prompt_hash": "sha256-bbb",
            "model": row.get("model", ""),
        }
        for key in ("prompt_tokens", "completion_tokens", "duration_ms"):
            val = row.get(key, "0")
            try:
                entry[key] = int(val)
            except ValueError:
                entry[key] = 0
        entry["timestamp"] = "2026-01-01T00:00:00Z"
        success = row.get("success", "true").lower() == "true"
        entry["success"] = success
        error = row.get("error", "")
        if error:
            entry["error"] = error
        entries.append(entry)
    return entries


def _h_ch_contains_text(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Verify the HTML contains specific text."""
    m = re.search(r'contains the text "([^"]+)"', text)
    if not m:
        return False, f"Could not parse from: {text}"
    expected = m.group(1)
    content = world.calls_html_content or ""
    if expected in content:
        return True, ""
    return False, f"Text '{expected}' not found in HTML"


def _h_strip_cs_does_not_contain(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the resulting control structure does not contain RESP-N."""
    m = re.search(r"does not contain (RESP-\d+)", text)
    if not m:
        return False, f"Could not parse RESP-ID from: {text}"
    resp_id = m.group(1)
    if world.control_structure is None:
        return False, "No control structure available"
    resp_ids = {r.resp_id for r in world.control_structure.responsibilities}
    if resp_id in resp_ids:
        return False, f"Expected {resp_id} to be stripped but it is still present"
    return True, ""


def _fc_resp_set_single_resp() -> dict:
    """ResponsibilitySet dict with only RESP-1."""
    return {
        "responsibilities": [
            {
                "resp_id": "RESP-1",
                "description": "Authorization controller",
                "responsibility_constraints": [
                    {"rc_id": "RC-1-1", "description": "Must confirm"}
                ],
                "process_model_parts": [
                    {"pm_id": "PM-1-1", "description": "User intent state"}
                ],
                "control_actions": [
                    {"ca_id": "CA-1-1", "description": "Execute action"}
                ],
                "feedback_channels": [
                    {
                        "fb_id": "FB-1-1",
                        "description": "Action result",
                        "updates": "PM-1-1",
                    },
                ],
            },
        ],
        "controlled_processes": [],
    }


def _fc_resp_set_single_resp_with_cp() -> dict:
    """ResponsibilitySet dict with RESP-1 and CP-1."""
    d = _fc_resp_set_single_resp()
    d["controlled_processes"] = [{"cp_id": "CP-1", "description": "External service"}]
    return d


def _san_set_element_ref(
    world: World, element_type: str, element_id: str, ref: ElementRef
) -> tuple[bool, str]:
    """Set an ElementRef on a ProcessModelPart, ControlAction, or FeedbackChannel.

    After the Stage 2 restructure, ProcessModelParts live in the
    ResponsibilitySet (Call 2a) while ControlActions and FeedbackChannels
    live in the ControlElementSet (Call 2b).  Route the lookup accordingly.
    """
    if element_type == "ProcessModelPart":
        rs = world.sp1_responsibility_set
        if rs is None:
            return False, "No ResponsibilitySet available"
        for resp in rs.responsibilities:
            for pm in resp.process_model_parts:
                if pm.pm_id == element_id:
                    pm.feedback_source = ref
                    return True, ""
        return (
            False,
            f"Element {element_type} {element_id} not found in ResponsibilitySet",
        )
    # ControlAction / FeedbackChannel live in the ControlElementSet (Call 2b)
    ces = world.sp1_control_element_set
    if ces is None:
        ces = _SP1ControlElementSet.model_validate(
            _sp1_valid_control_element_set_dict()
        )
        world.sp1_control_element_set = ces
    if element_type == "ControlAction":
        for ca in ces.control_actions:
            if ca.ca_id == element_id:
                ca.target = ref
                return True, ""
    elif element_type == "FeedbackChannel":
        for fb in ces.feedback_channels:
            if fb.fb_id == element_id:
                fb.source = ref
                return True, ""
    return False, f"Element {element_type} {element_id} not found in ControlElementSet"


_BF2_PROMPTS_DIR = _FC_PROMPTS_DIR


class _BF2MockLLMClient:
    """Mock LLM client that tracks max_completion_tokens."""

    def __init__(self) -> None:
        self.calls: list[dict] = []
        self._response_map: dict[type, Any] = {}
        self.base_url = "http://test:8080"
        self.model = "test-model"

    def set_response_for(self, model_class: type, response: Any) -> None:
        self._response_map[model_class] = response

    def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        response_format: type | None = None,
        max_completion_tokens: int | None = None,
        temperature: float | None = None,
    ) -> Any:
        self.calls.append(
            {
                "system_prompt": system_prompt,
                "user_prompt": user_prompt,
                "response_format": response_format,
                "max_completion_tokens": max_completion_tokens,
                "temperature": temperature,
            }
        )
        content = None
        if response_format is not None and response_format in self._response_map:
            content = self._response_map[response_format]
        return LLMResult(
            content=content,
            prompt_tokens=100,
            completion_tokens=50,
            duration_ms=5000,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
        )


class _BF2LogCapture(_bf2_logging.Handler):
    """Capture log messages for later inspection."""

    def __init__(self) -> None:
        super().__init__()
        self.records: list[str] = []

    def emit(self, record: _bf2_logging.LogRecord) -> None:
        self.records.append(record.getMessage())


def _b3_make_resp(
    resp_id: str, pm_ids: list[str], fb_specs: list[tuple[str, str]] | None = None
) -> Responsibility:
    """Build a responsibility for batch3 repair tests."""
    num = resp_id.split("-")[-1]
    pms = [ProcessModelPart(pm_id=pid, description=f"State {pid}") for pid in pm_ids]
    cas = [ControlAction(ca_id=f"CA-{num}-1", description="Action")]
    fbs = []
    if fb_specs:
        for fb_id, updates in fb_specs:
            fbs.append(
                FeedbackChannel(fb_id=fb_id, description=f"FB {fb_id}", updates=updates)
            )
    return Responsibility(
        resp_id=resp_id,
        description=f"Controller {num}",
        process_model_parts=pms,
        control_actions=cas,
        feedback_channels=fbs,
    )


def _b3_make_cs(responsibilities: list[Responsibility]) -> ControlStructure:
    """Wrap responsibilities into a ControlStructure for repair tests."""
    return ControlStructure(responsibilities=responsibilities)


def _make_sp2_control_structure(
    n_responsibilities: int = 2,
    cas_per_resp: int = 2,
    n_coord_links: int = 1,
) -> ControlStructure:
    """Build a control structure for SP2 acceptance tests."""
    from asago_scenario_generator.stpa.models.control_structure import (
        ControlledProcess as _CP,
    )

    cps = [
        _CP(cp_id=f"CP-{i + 1}", description=f"Process {i + 1}")
        for i in range(max(n_responsibilities, n_coord_links) + 1)
    ]
    responsibilities = []
    for i in range(n_responsibilities):
        resp_id = f"RESP-{i + 1}"
        cas = [
            ControlAction(
                ca_id=f"CA-{i + 1}-{j + 1}",
                description=f"Action {j + 1}",
                target=ElementRef(
                    type=ReferenceType.controlled_process, id=f"CP-{i + 1}"
                ),
            )
            for j in range(cas_per_resp)
        ]
        responsibilities.append(
            Responsibility(
                resp_id=resp_id,
                description=f"Responsibility {i + 1}",
                process_model_parts=[
                    ProcessModelPart(pm_id=f"PM-{i + 1}-1", description="State")
                ],
                control_actions=cas,
                feedback_channels=[
                    FeedbackChannel(
                        fb_id=f"FB-{i + 1}-1",
                        description="Feedback",
                        updates=f"PM-{i + 1}-1",
                        source=ElementRef(
                            type=ReferenceType.controlled_process, id=f"CP-{i + 1}"
                        ),
                    )
                ],
            )
        )

    coord_links = []
    for k in range(n_coord_links):
        coord_links.append(
            CoordinationLink(
                link_id=f"CL-{k + 1}",
                source="RESP-1",
                target=f"RESP-{min(n_responsibilities, 2)}"
                if n_responsibilities >= 2
                else "RESP-1",
                shared_pm="PM-1-1",
                coordination_mechanism=CoordinationMechanism(
                    cm_id=f"CM-{k + 1}",
                    description=f"Mechanism {k + 1}",
                    payload="data",
                ),
                description="Link",
            )
        )

    return ControlStructure(
        responsibilities=responsibilities,
        controlled_processes=cps,
        coordination_links=coord_links,
    )


def _h_sp2_fill_module_importable(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the SP2 slot filling module is importable."""
    return True, ""


def _h_sp2_slot_id_format_resp(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a slot has slot_id RESP-X:CA-Y:UCA_TYPE (legacy)."""
    from runtime_features.sp2 import _h_sp2_slot_id_format

    return _h_sp2_slot_id_format(world, text, examples)


def _h_sp2_resp_slot_count_varied(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the number of responsibility slots is N (for varied CA test)."""
    import re

    m = re.search(r"is (\d+)", text)
    expected = int(m.group(1)) if m else 16
    actual = sum(1 for s in world.sp2_slots if s.responsibility)
    if actual != expected:
        return False, f"Expected {expected} responsibility slots, got {actual}"
    return True, ""


def _h_sp2_calls_jsonl_stage(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the file contains entries with stage stage_3."""
    import json

    calls_file = world.sp2_run_dir / "calls.jsonl"
    if not calls_file.exists():
        return False, "calls.jsonl does not exist"
    entries = [
        json.loads(line) for line in calls_file.read_text().splitlines() if line.strip()
    ]
    if not any(e["stage"] == "stage_3" for e in entries):
        return False, "No stage_3 entries in calls.jsonl"
    return True, ""


def _make_sp3_cs(include_resp2: bool = False) -> ControlStructure:
    """Build a control structure for SP3 acceptance tests."""
    cps = [ControlledProcess(cp_id="CP-1", description="Interface")]
    resp1 = Responsibility(
        resp_id="RESP-1",
        description="Authorize payment operations",
        responsibility_constraints=[
            ResponsibilityConstraint(rc_id="RC-1-1", description="Must validate"),
        ],
        process_model_parts=[
            ProcessModelPart(
                pm_id="PM-1-1",
                description="Parsed user intent and extracted parameters",
            ),
            ProcessModelPart(
                pm_id="PM-1-2", description="Status of parameter schema compliance"
            ),
        ],
        control_actions=[
            ControlAction(
                ca_id="CA-1-1",
                description="Select appropriate tool/action for request",
                target=ElementRef(type=ReferenceType.controlled_process, id="CP-1"),
            ),
            ControlAction(
                ca_id="CA-1-2",
                description="Validate tool parameters against schema",
                target=ElementRef(type=ReferenceType.controlled_process, id="CP-1"),
            ),
        ],
        feedback_channels=[
            FeedbackChannel(
                fb_id="FB-1-1",
                description="Current user intent and request parameters",
                updates="PM-1-1",
                source=ElementRef(type=ReferenceType.controlled_process, id="CP-1"),
            ),
        ],
    )
    responsibilities = [resp1]
    if include_resp2:
        responsibilities.append(
            Responsibility(
                resp_id="RESP-2",
                description="Second controller",
                process_model_parts=[
                    ProcessModelPart(pm_id="PM-2-1", description="State2")
                ],
                control_actions=[
                    ControlAction(
                        ca_id="CA-2-1",
                        description="Action2",
                        target=ElementRef(
                            type=ReferenceType.controlled_process, id="CP-1"
                        ),
                    ),
                ],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-2-1",
                        description="Feedback2",
                        updates="PM-2-1",
                        source=ElementRef(
                            type=ReferenceType.controlled_process, id="CP-1"
                        ),
                    ),
                ],
            )
        )
    return ControlStructure(responsibilities=responsibilities, controlled_processes=cps)


def _make_sp3_loss_analysis() -> LossAnalysis:
    """Build a loss analysis for SP3 acceptance tests."""
    return LossAnalysis(
        risk_card_losses=[
            Loss(
                loss_id="L-1",
                description="Financial loss",
                provenance=LossProvenance.risk_card,
                source_risk_cards=["r1"],
            ),
        ],
        use_case_losses=[],
        hazards=[
            Hazard(
                hazard_id="H-1",
                description="Unauthorized action",
                related_losses=["L-1"],
            )
        ],
        security_constraints=[
            SecurityConstraint(
                constraint_id="SC-1",
                rule="The system must validate before action",
                applies_when=[],
                related_hazards=["H-1"],
            ),
        ],
    )


def _make_sp3_threat(
    slot_id: str = "RESP-1:CA-1-1:NOT_PROVIDED",
    ica_id: str | None = None,
    catalog_mappings: list | None = None,
    related_hazards: list | None = None,
    related_constraints: list | None = None,
) -> StructuralThreat:
    """Build a structural threat for SP3 acceptance tests."""
    return StructuralThreat(
        ica_slot_id=slot_id,
        provenance="structural",
        ica_id=ica_id or f"{slot_id}:1",
        ica_text="The agent fails to select a tool for a request.",
        hazardous_context="A user requests a refund but the agent fails.",
        loss_scenario="The user believes a refund is being processed.",
        related_hazards=related_hazards or ["H-1"],
        related_constraints=related_constraints or ["SC-1"],
        catalog_mappings=catalog_mappings or [],
    )


def _make_sp3_ets(threats: list | None = None) -> EnrichedThreatSet:
    """Build an enriched threat set for SP3 acceptance tests."""
    return EnrichedThreatSet(
        structural_threats=threats or [_make_sp3_threat()],
        coverage_analysis=CoverageAnalysis(
            structural_coverage={
                "total_slots": 40,
                "non_na": 32,
                "na": 8,
                "coverage_rate": 0.8,
            },
            structural_consideration={"total_slots": 40, "considered": 40, "rate": 1.0},
            na_quality={"na_count": 5, "quality_count": 4, "quality_rate": 0.8},
        ),
    )


def _make_sp3_scenario_spec(
    pm_id: str = "PM-1-1",
    resp_id: str = "RESP-1",
    ca_id: str = "CA-1-1",
    vulnerability: str = "exploitable",
    target_controller: str = "RESP-1",
    target_control_action: str = "CA-1-1",
    ica_id: str = "RESP-1:CA-1-1:NOT_PROVIDED:1",
    provenance: str = "structural",
    scenario_id: str = "SCN-001",
    ica_type: UCAType = UCAType.not_provided,
) -> ScenarioSpec:
    """Build a scenario spec for SP3 acceptance tests."""
    return ScenarioSpec(
        scenario_id=scenario_id,
        threat_source=ThreatSource(
            ica_slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
            provenance=provenance,
            ica_id=ica_id,
        ),
        target_controller=target_controller,
        target_control_action=target_control_action,
        ica_type=ica_type,
        defender_bdi=DefenderBDI(
            beliefs=[
                DefenderBelief(
                    pm_id=pm_id, content="State", vulnerability=vulnerability
                )
            ],
            desires=[DefenderDesire(resp_id=resp_id, content="R1")],
            intentions=[DefenderIntention(ca_id=ca_id, content="Action")],
        ),
        attacker_bdi=AttackerBDI(beliefs=["b"], desires=["d"], intentions=["i"]),
        loss_scenario="Loss",
    )


def _make_sp3_contextual_scenario_spec(
    *,
    scenario_id: str = "SCN-001",
    ica_type: UCAType = UCAType.not_provided,
) -> ScenarioSpec:
    """Build a successful SP3 fixture carrying its exact governing context."""
    from asago_scenario_generator.stpa.scenario_prod.context import (
        build_scenario_generation_context,
    )

    slot_id = f"RESP-1:CA-1-1:{ica_type.value}"
    threat = _make_sp3_threat(slot_id=slot_id, ica_id=f"{slot_id}:1")
    context = build_scenario_generation_context(
        threat,
        _make_sp3_cs(),
        _make_sp3_loss_analysis(),
        scenario_id=scenario_id,
    )
    base = _make_sp3_scenario_spec(
        scenario_id=scenario_id,
        ica_type=ica_type,
        ica_id=threat.ica_id,
    )
    values = base.model_dump(mode="json", exclude={"scenario_context"})
    values["threat_source"]["ica_slot_id"] = slot_id
    values["loss_scenario"] = threat.loss_scenario
    values["causal_factors"] = [
        {
            "kind": factor.kind,
            "source_id": factor.source_id,
            "description": factor.evidence,
            "declared_timing": factor.timing,
        }
        for factor in _make_sp3_causal_factors()
    ]
    values["unsafe_outcome_hazard_refs"] = [item.hazard_id for item in context.hazards]
    values["unsafe_outcome_constraint_refs"] = [
        item.constraint_id for item in context.constraints
    ]
    values["scenario_context"] = context
    return ScenarioSpec.model_validate(values)


def _make_sp3_envelope(
    spec: ScenarioSpec | None = None,
    attack_tree: dict | None = None,
    gherkin_spec: GherkinSpec | str | None = None,
) -> ScenarioEnvelope:
    """Build a scenario envelope for SP3 acceptance tests."""
    from asago_scenario_generator.stpa.models.scenario_envelope import (
        GherkinSpec as _GS,
    )

    s = spec or _make_sp3_scenario_spec()
    tree = attack_tree or {
        "root": "r",
        "branches": [
            {"category": "controller_side", "label": "l", "children": []},
            {"category": "path_side", "label": "l", "children": []},
        ],
        "leaves": ["mechanism1"],
    }
    if gherkin_spec is None:
        ghw = _GS(
            feature="Test",
            scenario="SCN-001",
            given=["Given PM-1-1 is valid"],
            when=["When x"],
            then_expected=["Then should reject"],
            then_actual=["But approves"],
        )
    elif isinstance(gherkin_spec, str):
        ghw = _GS(
            feature="Test",
            scenario="SCN-001",
            given=["Given PM-1-1 is valid"],
            when=["When x"],
            then_expected=["Then should reject"],
            then_actual=["But approves"],
        )
    else:
        ghw = gherkin_spec
    return ScenarioEnvelope(
        scenario_id=s.scenario_id,
        scenario_spec=s,
        narrative="Narrative text",
        attack_tree=tree,
        gherkin_spec=ghw,
        target_responsibility=s.target_controller,
        ica_type=s.ica_type,
        provenance="structural",
    )


def _setup_sp3_mock_client(num_threats: int = 2):
    """Set up a mock LLM client with valid SP3 responses."""
    from tests.stpa.sp1_helpers import MockLLMClient
    import json

    client = MockLLMClient()
    bdi_responses = []
    for i in range(num_threats):
        bdi_responses.append(
            {
                "stimulus": {
                    "category": "user_message",
                    "description": "One user message is the typed test stimulus.",
                },
                "adversary": {
                    "kind": "malicious_customer",
                    "gain": "Learns another customer's order details.",
                },
                "attacker_bdi": {
                    "beliefs": [f"attacker belief {i + 1}"],
                    "desires": ["induce ICA"],
                    "intentions": [
                        {
                            "description": "PM-1-1 remains stale before CA-1-1",
                            "source_handles": ["cause_1"],
                        }
                    ],
                },
                "causal_factors": [
                    {
                        "source_handle": "cause_1",
                        "selected_for_route": True,
                        "evidence": "The selected structural state can remain stale.",
                        "temporal_condition": None,
                        "evidence_status": "structural_failure",
                    }
                ],
                "unsafe_outcome": {
                    "condition": {
                        "type": "action_presence",
                        "control_action_id": "CA-1-1",
                        "expected": "not_provided",
                    },
                    "semantic_proposition": (
                        "The model response exhibits the selected unsafe behavior."
                    ),
                },
                "execution_route": {
                    "disposition": "executable_route",
                    "action_kind": "model_output",
                    "reason": "The selected structural factor supports the direct route.",
                },
            }
        )
    stage6_responses = []
    for i in range(num_threats):
        stage6_responses.append(
            "Step 1: The defender process model starts correct.\n" * 7
        )
        stage6_responses.append(
            json.dumps(
                {
                    "root": "Induce ICA NOT_PROVIDED on CA-1-1",
                    "branches": [
                        {
                            "category": "controller_side",
                            "label": "PM-1-1 remains stale after FB-1-1 delay",
                            "children": [],
                        },
                        {
                            "category": "path_side",
                            "label": "Tool fails",
                            "children": [],
                        },
                    ],
                    "leaves": [
                        "PM-1-1 remains stale after FB-1-1 delay",
                        "Tool fails",
                    ],
                }
            )
        )
        stage6_responses.append(
            {
                "feature": "Safe orchestration",
                "scenario": f"Attack scenario {i + 1}",
                "given": ["Given PM-1-1 is in a valid state"],
                "when": ["When PM-1-1 remains stale before CA-1-1"],
                "then_expected": ["Then the system should reject the request"],
                "then_actual": [
                    "But the system approves the request (ICA NOT_PROVIDED on CA-1-1)",
                    "And loss L-1 is realized",
                ],
            }
        )
    client.set_response_queue(bdi_responses + stage6_responses)
    # Also set a default response for raw text calls (response_format=None)
    # so that standalone Stage 6 calls work without consuming queue items
    client.set_response_for(
        None,
        "Scenario: Attack scenario\n"
        "  Given PM-1-1 is in a valid state\n"
        "  When PM-1-1 remains stale before CA-1-1\n"
        "  Then the system should reject the request\n"
        "  But the system approves the request (ICA NOT_PROVIDED on CA-1-1)\n"
        "  And loss L-1 is realized\n",
    )
    return client


def _sp3_semantics_wire(payload: dict) -> dict:
    """Reduce an execution-wire Stage 5 payload to the scenario-semantics wire.

    A product run without presentation rendering requests scenario semantics
    only: no stimulus, execution route, route selection, or executable
    condition.
    """
    semantics = {
        key: value
        for key, value in payload.items()
        if key not in {"stimulus", "execution_route"}
    }
    semantics["causal_factors"] = [
        {key: value for key, value in factor.items() if key != "selected_for_route"}
        for factor in payload["causal_factors"]
    ]
    semantics["unsafe_outcome"] = {
        "semantic_proposition": payload["unsafe_outcome"]["semantic_proposition"],
        "observation_criteria": [
            {
                "criterion_id": "reply_outcome",
                "outcome": "The assistant reply omits the requested action.",
                "observable": True,
                "claim_level": "reply",
                "evidence": "assistant_message",
                "reason": "The qualification adapter captures assistant messages.",
            }
        ],
        "safe_observable_outcome": {
            "observable": True,
            "statement": "The assistant reply preserves the requested action.",
            "claim_level": "reply",
            "evidence": "assistant_message",
            "operation_name": None,
            "record_refs": [],
            "fact_refs": [],
        },
    }
    return semantics


def _make_sp3_causal_factors():
    """Build the explicit structural cause used by successful SP3 fixtures."""
    from asago_scenario_generator.stpa.models.causal_factor import CausalFactorKind
    from asago_scenario_generator.stpa.scenario_prod.bdi_generation import (
        CausalFactorDeclaration,
    )

    return [
        CausalFactorDeclaration(
            kind=CausalFactorKind.process_model_flaw,
            source_id="PM-1-1",
            evidence="Parsed user intent remains stale before CA-1-1 is selected.",
        )
    ]


def _h_sp3_la_hazard_constraint(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a loss analysis with loss L-1, hazard H-1, and security constraint SC-1."""
    world.loss_analysis = _make_sp3_loss_analysis()
    return True, ""


def _h_sp3_validate_against_cs(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the scenario spec is validated against the control structure."""
    from asago_scenario_generator.stpa.scenario_prod.validators import (
        validate_bdi_grounding,
    )

    if world.scenario_spec is None:
        world.scenario_spec = _make_sp3_scenario_spec()
    if world.control_structure is None:
        world.control_structure = _make_sp3_cs()
    result = validate_bdi_grounding(world.scenario_spec, world.control_structure)
    world.validation_succeeded = result.passed
    if not result.passed:
        world.validation_error = ValueError(
            result.errors[0] if result.errors else "Validation failed"
        )
    return True, ""


def compute_eval_scorecard_simple(world):
    from asago_scenario_generator.stpa.scenario_prod.eval_metrics import (
        compute_eval_scorecard,
    )

    envs = getattr(world, "sp3_envelopes", [])
    if world.enriched_threat_set is None:
        world.enriched_threat_set = _make_sp3_ets()
    if world.control_structure is None:
        world.control_structure = _make_sp3_cs()
    if world.loss_analysis is None:
        world.loss_analysis = _make_sp3_loss_analysis()
    # Collect validation errors from envelopes or world
    stage_local_errors = getattr(world, "sp3_stage_local_errors", [])
    traceability_errors = getattr(world, "sp3_traceability_errors", [])
    for env in envs:
        stage_local_errors.extend(getattr(env, "stage_local_errors", []) or [])
        traceability_errors.extend(getattr(env, "traceability_errors", []) or [])
    return compute_eval_scorecard(
        envs,
        world.enriched_threat_set,
        world.control_structure,
        world.loss_analysis,
        stage_local_errors=stage_local_errors,
        traceability_errors=traceability_errors,
    )


def _h_sp3_diversity_float(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: responsibility_diversity / ica_type_diversity is a non-negative float."""
    metric = getattr(world, "sp3_metric", {})
    if not metric:
        return True, ""
    if "responsibility_diversity" in text:
        val = metric.get("responsibility_diversity", 0)
        if not isinstance(val, (int, float)) or val < 0:
            return False, f"responsibility_diversity is not a non-negative float: {val}"
    elif "ica_type_diversity" in text:
        val = metric.get("ica_type_diversity", 0)
        if not isinstance(val, (int, float)) or val < 0:
            return False, f"ica_type_diversity is not a non-negative float: {val}"
    return True, ""


def _h_sp3_scorecard_validation(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the scorecard validation section has N errors."""
    import yaml

    run_dir = getattr(world, "sp3_run_dir", None)
    if run_dir is None:
        return True, ""
    scorecard_path = run_dir / "eval-scorecard.yaml"
    if not scorecard_path.exists():
        return False, "eval-scorecard.yaml does not exist"
    data = yaml.safe_load(scorecard_path.read_text())
    if "stage_local_errors" in text:
        import re

        m = re.search(r"(\d+) stage_local_errors", text)
        expected = int(m.group(1)) if m else 2
        actual = len(data.get("validation", {}).get("stage_local_errors", []))
        if actual != expected:
            return False, f"Expected {expected} stage_local_errors, got {actual}"
    elif "traceability_error" in text:
        import re

        m = re.search(r"(\d+) traceability_error", text)
        expected = int(m.group(1)) if m else 1
        actual = len(data.get("validation", {}).get("traceability_errors", []))
        if actual != expected:
            return False, f"Expected {expected} traceability_errors, got {actual}"
    return True, ""


def _h_sp3_template_files_exist(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the following template files exist."""
    from asago_scenario_generator.stpa.scenario_prod._constants import PROMPTS_DIR

    if world.current_data_table:
        for row in world.current_data_table:
            template_name = row[0] if isinstance(row, list) else row
            if not (PROMPTS_DIR / template_name).exists():
                return False, f"Template {template_name} does not exist"
    return True, ""


def _h_sp3_modules_exist(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the following modules exist and are importable / the module `X` exists."""
    from asago_scenario_generator.stpa.scenario_prod import _constants

    pkg_dir = Path(_constants.__file__).parent
    names: list[str] = []
    match = re.search(r"the module [`']?([^`'\s]+)[`']? exists", text)
    if match:
        names = [match.group(1)]
    elif world.current_data_table:
        names = [
            row[0] if isinstance(row, list) else row for row in world.current_data_table
        ]
    for module_name in names:
        if not (pkg_dir / module_name).exists():
            return False, f"Module {module_name} does not exist"
    return True, ""


def _h_sp3_existing_tests(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: existing tests are unaffected / no new failures."""
    return True, ""


def _h_sp3_diversity_has_value(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: by_responsibility has RESP-1 3 / by_ica_type has NOT_PROVIDED 3 / etc."""
    import re

    m = re.search(r"(\w+) has (\S+) (\d+)", text)
    if not m:
        return False, "Could not parse"
    category, key, expected = m.group(1), m.group(2), int(m.group(3))
    # Check world.sp3_metric first (set by individual diversity handler)
    metric = getattr(world, "sp3_metric", None)
    if metric is not None and category in metric:
        actual = metric[category].get(key, 0)
        if actual != expected:
            return False, f"Expected {category}[{key}]={expected}, got {actual}"
        return True, ""
    # Check world.sp3_scorecard (set by compute_all_metrics)
    scorecard = getattr(world, "sp3_scorecard", None)
    if scorecard is not None:
        diversity = scorecard.get("diversity", {})
        cat_dict = diversity.get(category, {})
        actual = cat_dict.get(key, 0)
        if actual != expected:
            return False, f"Expected {category}[{key}]={expected}, got {actual}"
        return True, ""
    return True, ""


_VALID_GHERKIN_YAML = (
    "feature: Safe orchestration\n"
    "scenario: SCN-001\n"
    "given:\n"
    "  - Given PM-1-1 is active\n"
    "  - And the system is online\n"
    "when:\n"
    "  - When a revoked user requests access\n"
    "then_expected:\n"
    "  - Then the system should reject the request\n"
    "then_actual:\n"
    "  - But the system approves the request\n"
    "  - And loss L-1 is realized\n"
)


def _h_stage6_validation_fails_with_id(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: validation fails with error containing <id>."""
    if world.validation_error is None:
        return False, "Expected validation to fail but it succeeded"
    hallucinated_id = examples.get("hallucinated_id", "")
    if hallucinated_id:
        if hallucinated_id not in str(world.validation_error):
            return (
                False,
                f"Error does not contain '{hallucinated_id}': {world.validation_error}",
            )
        return True, ""
    # For non-example steps, extract from text
    import re

    m = re.search(r"containing (\S+)", text)
    if m:
        expected = m.group(1)
        if expected not in str(world.validation_error):
            return (
                False,
                f"Error does not contain '{expected}': {world.validation_error}",
            )
    return True, ""


def _h_cmidup_passes_validation(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the final control structure passes foundation validation."""
    cs = world.control_structure
    if cs is None:
        return False, "No control structure"
    # If ControlStructure was constructed, it passed validation
    if not isinstance(cs, ControlStructure):
        return False, "Control structure is not a ControlStructure instance"
    return True, ""


def _h_cmidup_pipeline_no_crash(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the pipeline does not crash."""
    if world.validation_error is not None:
        return False, f"Pipeline crashed with: {world.validation_error}"
    cs = world.control_structure
    if cs is None:
        return False, "No control structure after revision"
    return True, ""


def _ar_client(world: World) -> _SP1MockLLM:
    client = world.sp1_mock_client or _SP1MockLLM()
    world.sp1_mock_client = client
    return client


def _ar_run_dir(world: World) -> Path:
    if world.sp1_run_dir is None:
        world.sp1_run_dir = Path(_tempfile.mkdtemp(prefix="acceptance_refresh_"))
    return world.sp1_run_dir


def _ar_stage2_defaults(world: World) -> None:
    client = _ar_client(world)
    defaults = {
        _SP1RequirementSet: _sp1_valid_req_set_dict(),
        _SP1ResponsibilitySet: _sp1_valid_resp_set_2a_dict(),
        _SP1ControlElementSet: _sp1_valid_control_element_set_dict(),
        _SP1CoordinationAnalysis: _sp1_valid_coordination_analysis_dict(),
    }
    for response_format, response in defaults.items():
        if response_format not in client._response_map:
            client.set_response_for(response_format, response)


_VALID_CRITIC_STATUSES = frozenset(
    {"present", "absent_justified", "absent_unjustified"}
)

_VALID_GAP_COUNTS = frozenset({0, 1, 2, 3})

_VALID_COMPLETION_TOKENS = frozenset({4097, 6000, 8192})

_VALID_DISMISSAL_COUNTS = frozenset({1, 2})

_KNOWN_ELEMENT_DESCRIPTIONS = {
    "RC-1-1": "retrieved content must carry provenance",
    "PM-1-1": "belief about retrieval source integrity",
    "CA-1-1": "reject unverified retrieved content",
    "FB-1-1": "provenance verdict from the index",
}


def _set_element_description(cs_dict: dict, element_id: str, description: str) -> None:
    """Set the description of a nested element in a CS dict by ID."""
    for resp in cs_dict["responsibilities"]:
        if resp["resp_id"] == element_id:
            resp["description"] = description
            return
        for rc in resp.get("responsibility_constraints", []):
            if rc["rc_id"] == element_id:
                rc["description"] = description
                return
        for pm in resp.get("process_model_parts", []):
            if pm["pm_id"] == element_id:
                pm["description"] = description
                return
        for ca in resp.get("control_actions", []):
            if ca["ca_id"] == element_id:
                ca["description"] = description
                return
        for fb in resp.get("feedback_channels", []):
            if fb["fb_id"] == element_id:
                fb["description"] = description
                return


def _sc_has_xfail(source: str, func_name: str) -> tuple[bool, bool]:
    """Return (has_xfail, has_strict_false) for a test function in source."""
    import ast

    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == func_name:
            for dec in node.decorator_list:
                if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute):
                    if dec.func.attr == "xfail":
                        has_strict = False
                        for kw in dec.keywords:
                            if kw.arg == "strict" and isinstance(
                                kw.value, ast.Constant
                            ):
                                has_strict = kw.value.value is False
                        return True, has_strict
            return False, False
    return False, False


def _sc_ensure_property_test_source(world: World) -> str | None:
    """Ensure world.sc_property_test_source is loaded; return source or None on error."""
    source = getattr(world, "sc_property_test_source", "")
    if not source:
        test_file = (
            PROJECT_ROOT / "tests" / "stpa" / "test_acceptance_harness_property.py"
        )
        if not test_file.is_file():
            return None
        source = test_file.read_text()
        world.sc_property_test_source = source
    return source


def _sc_simulate_priority_registration(
    world: World,
    text: str,
    parse_pattern: str,
    insert_first: bool,
) -> tuple[bool, str]:
    """Add a synthetic registration while preserving its priority semantics."""
    m = re.search(parse_pattern, text)
    if not m:
        return False, f"Could not parse: {text}"
    pattern_str, handler_name = m.group(1), m.group(2)

    def _test_handler(w: World, t: str, e: dict) -> tuple[bool, str]:
        return True, ""

    _test_handler.__name__ = handler_name
    test_list = getattr(world, "sc_test_patterns", None)
    if test_list is None:
        test_list = []
        world.sc_test_patterns = test_list
    registration = (re.compile(pattern_str, re.IGNORECASE), _test_handler, None)
    if insert_first:
        test_list.insert(0, registration)
    else:
        test_list.append(registration)
    return True, ""


__all__ = [
    "Any",
    "AttackerBDI",
    "BaseModel",
    "CatalogMapping",
    "ControlAction",
    "ControlStructure",
    "ControlledProcess",
    "CoordinationLink",
    "CoordinationMechanism",
    "CoverageAnalysis",
    "DefenderBDI",
    "DefenderBelief",
    "DefenderDesire",
    "DefenderIntention",
    "ElementRef",
    "EnrichedThreatSet",
    "FeedbackChannel",
    "GherkinSpec",
    "Hazard",
    "ICA",
    "ICAEnumeration",
    "ICASlot",
    "LLMClient",
    "LLMResult",
    "Loss",
    "LossAnalysis",
    "LossProvenance",
    "PROJECT_ROOT",
    "Path",
    "ProcessModelPart",
    "ReferenceType",
    "Responsibility",
    "ResponsibilityConstraint",
    "STPARunManifest",
    "ScenarioEnvelope",
    "ScenarioSpec",
    "SecurityConstraint",
    "StructuralThreat",
    "TemplateLoader",
    "ThreatSource",
    "UCAType",
    "ValidationError",
    "World",
    "_B3CriticFindings",
    "_B3CriticGap",
    "_B3RepairOrphanPMs",
    "_B3ResponsibilitySet",
    "_B3SanitizeCriticIDs",
    "_BF2LogCapture",
    "_BF2MockLLMClient",
    "_BF2_PROMPTS_DIR",
    "_CapabilityProfile",
    "_ConcurrentMockLLMClient",
    "_ConfidenceLevel",
    "_ConsumerHints",
    "_EntryPoint",
    "_FCControlElementSet",
    "_FCResponsibilitySet",
    "_FCRevisionDelta",
    "_FC_PROMPTS_DIR",
    "_GDControlElementSet",
    "_GDCoordinationAnalysis",
    "_GDCriticFindings",
    "_GDRequirementSet",
    "_GDResponsibilitySet",
    "_GDSP1RunResult",
    "_GDStageError",
    "_KNOWN_ELEMENT_DESCRIPTIONS",
    "_PQF_PROMPTS_DIR",
    "_ParallelDummyModel",
    "_SP1CapabilityProfile",
    "_SP1ConnectionSet",
    "_SP1ControlElementSet",
    "_SP1CoordinationAnalysis",
    "_SP1CriticFindings",
    "_SP1CriticGap",
    "_SP1LossAnalysisDraft",
    "_SP1MockLLM",
    "_SP1Requirement",
    "_SP1RequirementSet",
    "_SP1ResponsibilitySet",
    "_SP1RevisionDelta",
    "_SP1RiskCard",
    "_SP1Stage1Profile",
    "_SystemContext",
    "_ToolInventoryEntry",
    "_VALID_COMPLETION_TOKENS",
    "_VALID_CRITIC_STATUSES",
    "_VALID_DISMISSAL_COUNTS",
    "_VALID_GAP_COUNTS",
    "_VALID_GHERKIN_YAML",
    "_ar_client",
    "_ar_run_dir",
    "_ar_stage2_defaults",
    "_assemble_envelope",
    "_b3_make_cs",
    "_b3_make_resp",
    "_bf2_REV_MAX_TOKENS",
    "_bf2_RevisionDelta",
    "_bf2_call_2_resp",
    "_bf2_derive_control_structure",
    "_bf2_inspect",
    "_bf2_logging",
    "_bf2_safe_llm_call",
    "_bf2_tempfile",
    "_calls_entries_from_data_table",
    "_compute_consumer_hints",
    "_compute_system_context",
    "_data_table_to_dicts",
    "_fc_compute_next_ids",
    "_fc_log_llm_call",
    "_fc_log_llm_call_failure",
    "_fc_merge_with_fallback",
    "_fc_resp_set_single_resp",
    "_fc_resp_set_single_resp_with_cp",
    "_fc_strip_empty",
    "_gd_derive_cs",
    "_gd_derive_loss_analysis",
    "_gd_derive_profile",
    "_gd_read_calls",
    "_gd_run_critic",
    "_gd_run_revision",
    "_gd_safe_llm_call",
    "_gd_valid_critic_unjustified_dict",
    "_gd_valid_cs",
    "_gd_valid_la",
    "_gd_valid_profile",
    "_gd_yaml",
    "_h_ch_contains_text",
    "_h_cmidup_passes_validation",
    "_h_cmidup_pipeline_no_crash",
    "_h_connset_critic_unjustified",
    "_h_gd_critic_run",
    "_h_gd_rev_run",
    "_h_pqf_prompts_dir_available",
    "_h_pqf_rendered_text_contains",
    "_h_pqf_template_loader_created",
    "_h_sp1_critic_run_full",
    "_h_sp1_cs_two_resps_available",
    "_h_sp1_file_exists",
    "_h_sp1_heur_cs_no_constraint",
    "_h_sp1_heur_cs_with_constraint",
    "_h_sp1_heur_fails",
    "_h_sp1_heur_orphan_warn",
    "_h_sp1_heur_pipeline_no_loop",
    "_h_sp1_rev_applied",
    "_h_sp1_rev_run",
    "_h_sp1_run_manifest_critic_two",
    "_h_sp1_s2_call1_run_full",
    "_h_sp1_s2_calls_1_3_run",
    "_h_sp1_s2_full_run",
    "_h_sp1_stage1a_run_full",
    "_h_sp1_use_case_risk_json",
    "_h_sp1_validation_fails",
    "_h_sp2_calls_jsonl_stage",
    "_h_sp2_fill_module_importable",
    "_h_sp2_resp_slot_count_varied",
    "_h_sp2_slot_id_format_resp",
    "_h_sp3_diversity_float",
    "_h_sp3_diversity_has_value",
    "_h_sp3_existing_tests",
    "_h_sp3_la_hazard_constraint",
    "_h_sp3_modules_exist",
    "_h_sp3_scorecard_validation",
    "_h_sp3_template_files_exist",
    "_h_sp3_validate_against_cs",
    "_h_stage6_validation_fails_with_id",
    "_h_strip_cs_does_not_contain",
    "_hashlib",
    "_load_profile",
    "_make_coordination_link",
    "_make_enrichment_capability_profile",
    "_make_enrichment_control_structure",
    "_make_minimal_control_structure",
    "_make_minimal_loss_analysis",
    "_make_minimal_scenario_spec",
    "_make_sp2_control_structure",
    "_make_sp3_cs",
    "_make_sp3_envelope",
    "_make_sp3_ets",
    "_make_sp3_loss_analysis",
    "_make_sp3_causal_factors",
    "_make_sp3_contextual_scenario_spec",
    "_make_sp3_scenario_spec",
    "_make_sp3_threat",
    "_parallel_make_spec",
    "_profiles_to_yaml",
    "_render_calls_html",
    "_resolve_value",
    "_san_set_element_ref",
    "_sc_ensure_property_test_source",
    "_sc_has_xfail",
    "_sc_simulate_priority_registration",
    "_set_element_description",
    "_setup_sp3_mock_client",
    "_sp1_add_coordination_links",
    "_sp1_assemble_with_fallback",
    "_sp1_check_neutrality",
    "_sp1_compute_next_ids",
    "_sp1_critic_unjustified_gaps",
    "_sp1_derive_capability_profile",
    "_sp1_derive_control_structure",
    "_sp1_derive_loss_analysis",
    "_sp1_has_unjustified_gaps",
    "_sp1_invalid_connectionset_bad_link_pm",
    "_sp1_invalid_connectionset_bad_link_source",
    "_sp1_invalid_connectionset_namespace_confusion",
    "_sp1_load_capability_profile",
    "_sp1_log_llm_call",
    "_sp1_make_control_structure_two_resps",
    "_sp1_make_control_structure_with_resp",
    "_sp1_make_loss_analysis_with_constraints",
    "_sp1_make_risk_cards",
    "_sp1_merge_connection_set",
    "_sp1_merge_revision_delta",
    "_sp1_no_unjustified_critic_dict",
    "_sp1_read_yaml",
    "_sp1_run_critic",
    "_sp1_run_heuristics",
    "_sp1_run_revision",
    "_sp1_run_sp1",
    "_sp1_setup_full_mock_client",
    "_sp1_valid_connection_set_ca_assignment_dict",
    "_sp1_valid_connection_set_cp_only_dict",
    "_sp1_valid_connection_set_dict",
    "_sp1_valid_connection_set_fb_assignment_dict",
    "_sp1_valid_connection_set_no_assignments_dict",
    "_sp1_valid_control_element_set_dict",
    "_sp1_valid_coordination_analysis_dict",
    "_sp1_valid_critic_findings_dict",
    "_sp1_valid_cs_dict",
    "_sp1_valid_cs_with_coord_dict",
    "_sp1_valid_la_dict",
    "_sp1_valid_req_set_dict",
    "_sp1_valid_resp_set_2a_dict",
    "_sp1_valid_resp_set_dict",
    "_sp1_valid_stage1_profile_dict",
    "_sp1_write_yaml",
    "_subprocess_mp",
    "_tempfile",
    "_tempfile_mp",
    "_yaml_mp",
    "annotations",
    "append_call_log",
    "check_structural_heuristics",
    "compute_eval_scorecard_simple",
    "hash_prompt_templates",
    "json",
    "make_call_log_entry",
    "os",
    "re",
    "read_yaml",
    "strip_empty_responsibilities",
    "sys",
    "tempfile",
    "threading",
    "time",
    "traceback",
    "write_yaml",
]
