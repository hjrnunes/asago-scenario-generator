"""Acceptance handlers for the standalone MCP target primitive.

The feature intentionally exercises only public producer seams.  Its fakes
stand in for transport and provider adapters; no MCP endpoint or model
provider is contacted while the acceptance snapshot runs.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from runtime_bootstrap import PROJECT_ROOT
from runtime_shared import (
    World,
    _make_sp3_cs,
    _make_sp3_loss_analysis,
)

from asago_scenario_generator.models.target_realization import (
    SystemicStpaBaseline,
    TargetDerivedICAProviderResponse,
    TargetRealizationDisposition,
    TargetRealizationResult,
    TargetRealizationSummary,
)
from asago_scenario_generator.pipeline.obligation_planner import (
    plan_taxonomy_obligations,
)
from asago_scenario_generator.pipeline.synthesis import (
    CONSIDERATION_FILENAME,
    PLAN_FILENAME,
    SynthesisAdapters,
    run_synthesis,
)
from asago_scenario_generator.pipeline.target_realization import (
    project_target_realization_to_stpa,
    realize_target_derived_icas,
    realize_target_operations,
)
from asago_scenario_generator.stpa.models.control_structure import (
    ControlStructure,
)
from asago_scenario_generator.stpa.models.ica_enumeration import ICAEnumeration
from asago_scenario_generator.stpa.models.execution_classification import (
    DiscoveryMode,
    ExecutionResourcePurpose,
    ExecutionTargetProfile,
    InventoryAuthority,
    SemanticAuthority,
    TargetOperationEffect,
    TargetStateEffect,
    TargetInterpretationDisposition,
    mcp_resource_id,
)
from asago_scenario_generator.stpa.scenario_prod.bdi_generation import (
    build_context_bdi_prompts,
    generate_bdi_for_context,
)
from asago_scenario_generator.stpa.scenario_prod.context import (
    build_scenario_generation_context,
)
from asago_scenario_generator.stpa.models.enriched_threat_set import StructuralThreat
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.scenario_prod._constants import PROMPTS_DIR
from asago_scenario_generator.target_discovery import (
    McpTargetDiscoveryInputs,
    TargetDiscoveryResult,
    TargetInterpretationDraft,
    TargetInterpretationResponse,
    discover_mcp_target,
    write_target_discovery,
)
from asago_scenario_generator.stpa.obligation_aware.routing import RoutingRunResult
from tests.helpers.synthesis_fixture import (
    baseline_control_structure,
    baseline_loss_analysis,
    obligation_routes,
    structural_revision,
    synthesis_capability_profile,
    synthesis_inputs,
    synthesis_taxonomy_inputs,
)
from tests.stpa.sp1_helpers import MockLLMClient


FEATURE_ID = "mcp_target_discovery_primitive_input"

_ROOT = Path(PROJECT_ROOT)
_INVENTORY_FIXTURE = (
    _ROOT / "data" / "contracts" / "target-discovery" / "mcp-tools-list.json"
)
_MUTATING_TOOLS = {
    "schedule_payment": (TargetOperationEffect.create, TargetStateEffect.changes),
    "process_refund": (TargetOperationEffect.update, TargetStateEffect.changes),
    "escalate_to_human": (
        TargetOperationEffect.escalate,
        TargetStateEffect.changes,
    ),
}
_READ_TOOLS = {
    "lookup_order": (TargetOperationEffect.read, TargetStateEffect.none),
    "get_account_details": (TargetOperationEffect.read, TargetStateEffect.none),
    "retrieve_policy": (TargetOperationEffect.read, TargetStateEffect.none),
    "get_klarna_state_summary": (TargetOperationEffect.observe, TargetStateEffect.none),
}


def _state(world: World) -> dict[str, Any]:
    """Return isolated state for one generated scenario."""
    state = getattr(world, "mcp_target_state", None)
    if state is None:
        state = {}
        world.mcp_target_state = state
    return state


def _fixture_tools(names: tuple[str, ...] | None = None) -> list[dict[str, Any]]:
    payload = json.loads(_INVENTORY_FIXTURE.read_text(encoding="utf-8"))
    tools = list(payload["tools"])
    if names is None:
        return tools
    wanted = set(names)
    return [tool for tool in tools if tool["name"] in wanted]


class _InventoryAdapter:
    """Deterministic tools/list adapter retaining secret data out of results."""

    def __init__(self, tools: list[dict[str, Any]]) -> None:
        self.tools = tools
        self.endpoint = "https://mcp.example.invalid/private"
        self.authorization = "Bearer acceptance-secret"
        self.calls: list[str] = []

    def list_tools(self, cursor: str | None = None) -> dict[str, Any]:
        del cursor
        self.calls.append("tools/list")
        return {"tools": self.tools}

    def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> Any:
        del tool_name, arguments
        raise AssertionError("schema-only acceptance must not call an MCP tool")


class _DiscoveryInterpreter:
    """Fixed offline interpretation/verifier pair for scanner acceptance."""

    def __init__(self) -> None:
        self.requests: list[Any] = []
        self.verifications: int = 0

    def interpret(self, request: Any) -> TargetInterpretationResponse:
        self.requests.append(request)
        drafts = []
        for view in request.tools:
            effect, state_effect = _MUTATING_TOOLS.get(
                view.name,
                _READ_TOOLS.get(
                    view.name,
                    (TargetOperationEffect.unknown, TargetStateEffect.unknown),
                ),
            )
            drafts.append(
                TargetInterpretationDraft(
                    tool_handle=view.handle,
                    disposition=TargetInterpretationDisposition.supported,
                    likely_effect=effect,
                    likely_state_effect=state_effect,
                    semantic_roles=("target_operation",),
                    evidence_refs=(
                        next(
                            ref
                            for ref in view.evidence_refs
                            if ref.startswith(f"inventory:tool:{view.name}:")
                        ),
                    ),
                    rationale="The fixed acceptance interpreter cites the exact tool row.",
                )
            )
        return TargetInterpretationResponse(interpretations=tuple(drafts))

    def verify(self, request: Any, response: TargetInterpretationResponse) -> bool:
        del request, response
        self.verifications += 1
        return True


def _discover(
    names: tuple[str, ...] | None = None,
) -> tuple[TargetDiscoveryResult, _InventoryAdapter]:
    adapter = _InventoryAdapter(_fixture_tools(names))
    interpreter = _DiscoveryInterpreter()
    inputs = McpTargetDiscoveryInputs(
        target_id="target:acceptance",
        authorization_scope_id="scope:acceptance",
        mode=DiscoveryMode.schema_only,
        scanner_id="acceptance-scanner",
        interpreter_id="acceptance-interpreter",
        verifier_id="acceptance-verifier",
        interpretation_batch_size=128,
    )
    result = discover_mcp_target(inputs, adapter, interpreter)
    return result, adapter


def _profile(names: tuple[str, ...] | None = None) -> ExecutionTargetProfile:
    result, _adapter = _discover(names)
    if result.profile is None:
        raise AssertionError("fixed discovery did not produce a profile")
    return result.profile


def _make_one_action_control_structure() -> ControlStructure:
    """Return the exact SP3 fixture with only the mapped control action."""
    payload = _make_sp3_cs().model_dump(mode="json")
    payload["responsibilities"][0]["control_actions"] = [
        payload["responsibilities"][0]["control_actions"][0]
    ]
    # This fixture's target-derived ICA is governed by the known H-1/SC-1
    # authority supplied by _make_sp3_loss_analysis.  Keep that ownership
    # explicit so the target compiler can resolve omitted provider refs.
    payload["responsibilities"][0]["security_constraint_refs"] = ["SC-1"]
    return ControlStructure.model_validate(payload)


def _baseline(*, one_action: bool = False) -> SystemicStpaBaseline:
    control_structure = (
        _make_one_action_control_structure() if one_action else _make_sp3_cs()
    )
    return SystemicStpaBaseline.from_stpa(
        loss_analysis=_make_sp3_loss_analysis(),
        control_structure=control_structure,
        ica_enumeration=ICAEnumeration(slots=[]),
        baseline_id="baseline:acceptance",
        prompt_hashes=("baseline-prompt",),
        reference_inventory=("RESP-1", "CA-1-1"),
    )


class _ExactRealizationInterpreter:
    def __init__(self, selected_operation: str) -> None:
        self.selected_operation = selected_operation
        self.calls: list[tuple[Any, Any]] = []

    def __call__(self, *, action: dict[str, Any], operations: Any) -> dict[str, Any]:
        self.calls.append((action, operations))
        if action["control_action_id"] != "CA-1-1":
            return {
                "control_action_id": action["control_action_id"],
                "disposition": "unmapped",
                "evidence_refs": ("acceptance:unmapped",),
                "rationale": "The fixed acceptance mapping leaves this action unmapped.",
            }
        resource_id = mcp_resource_id("target:acceptance", self.selected_operation)
        reference = {
            "resource_id": resource_id,
            "operation_id": self.selected_operation,
        }
        return {
            "control_action_id": action["control_action_id"],
            "disposition": "supported",
            "candidate_operations": (reference,),
            "selected_operation": reference,
            "evidence_refs": (f"inventory:tool:{self.selected_operation}",),
            "rationale": "The fixed acceptance interpreter selects one exact observed operation.",
            "verifier": {
                "status": "verified",
                "detail": "The fixed acceptance verifier confirmed the exact operation.",
                "evidence_refs": (f"inventory:tool:{self.selected_operation}",),
            },
        }


class _AmbiguousRealizationInterpreter:
    def __call__(self, *, action: dict[str, Any], operations: Any) -> dict[str, Any]:
        del operations
        reference = {
            "resource_id": mcp_resource_id("target:acceptance", "process_refund"),
            "operation_id": "process_refund",
        }
        return {
            "control_action_id": action["control_action_id"],
            "disposition": "ambiguous",
            "candidate_operations": (reference,),
            "evidence_refs": ("inventory:tool:process_refund",),
            "rationale": "The fixed acceptance evidence does not establish a unique relationship.",
        }


class _UnmappedRealizationInterpreter:
    def __call__(self, *, action: dict[str, Any], operations: Any) -> dict[str, Any]:
        del operations
        return {
            "control_action_id": action["control_action_id"],
            "disposition": "unmapped",
            "evidence_refs": ("inventory:tool:schedule_payment",),
            "rationale": "No baseline relationship was established.",
        }


class _ExtensionFactory:
    def __init__(self) -> None:
        self.calls = 0
        self.requests: list[Any] = []

    def __call__(self):
        self.calls += 1

        def extend(request: Any) -> dict[str, Any]:
            self.requests.append(request)
            operation = request.operations[0]
            return {
                "outcomes": (
                    {
                        "operation": {
                            "resource_id": operation.resource_id,
                            "operation_id": operation.operation_id,
                        },
                        "disposition": "accepted",
                        "control_action": {
                            "controller_id": "RESP-1",
                        },
                        "ica_slots": (
                            {
                                "action_temporality": "instantaneous",
                                "uca_type": "NOT_PROVIDED",
                            },
                        ),
                        "evidence_refs": ("inventory:tool:schedule_payment",),
                        "rationale": "The observed operation is an additive target action.",
                        "verification": {
                            "status": "verified",
                            "detail": "The fixed acceptance verifier confirmed the exact operation.",
                            "evidence_refs": (
                                "inventory:tool:schedule_payment:description",
                            ),
                        },
                    },
                )
            }

        return extend


class _DerivedFindingFactory:
    def __init__(self) -> None:
        self.calls = 0
        self.requests: list[Any] = []

    def __call__(self):
        self.calls += 1

        def find(request: Any) -> TargetDerivedICAProviderResponse:
            self.requests.append(request)
            slot = request.target_derived_ica_slots[0]
            return TargetDerivedICAProviderResponse.model_validate(
                {
                    "findings": (
                        {
                            "slot_id": slot.slot_id,
                            "ica_id": f"{slot.slot_id}:1",
                            "ica_text": "The target operation is issued without a required check.",
                            "hazardous_context": "The observed operation is available to the controller.",
                            "loss_scenario": "An unauthorized payment is scheduled.",
                            "related_hazards": ("H-1",),
                            # Omit the provider's constraint citation so the
                            # target compiler must derive SC-1 from the exact
                            # responsibility owner and cited H-1 hazard.
                            "related_constraints": (),
                            "verification": {
                                "status": "verified",
                                "detail": "The fixed acceptance verifier confirmed the finding.",
                                "evidence_refs": ("verification:target-derived",),
                            },
                        },
                    )
                }
            )

        return find


def _empty_target_result(profile: ExecutionTargetProfile) -> TargetRealizationResult:
    return TargetRealizationResult(
        baseline_id="baseline:acceptance",
        baseline_digest="baseline-digest",
        profile_id=profile.target_id,
        profile_digest=profile.semantic_digest,
        summary=TargetRealizationSummary(
            baseline_control_actions=0,
            observed_operations=0,
            supported=0,
            ambiguous=0,
            unmapped=0,
            contradictory=0,
        ),
    )


class _FixedSynthesis:
    """Small deterministic composition adapter with a target boundary."""

    def __init__(self, profile: ExecutionTargetProfile | None = None) -> None:
        self.profile = profile
        self.calls: list[str] = []

    def prepare_capability(self, **_: Any) -> Any:
        return synthesis_capability_profile()

    def build_taxonomy_inputs(self, **_: Any) -> Any:
        return synthesis_taxonomy_inputs()

    def plan_obligations(self, *, taxonomy_inputs: Any, **_: Any) -> Any:
        self.calls.append("plan")
        return plan_taxonomy_obligations(taxonomy_inputs)

    def baseline(self, **_: Any) -> Any:
        self.calls.append("baseline")
        return SimpleNamespace(
            loss_analysis=baseline_loss_analysis(),
            control_structure=baseline_control_structure(),
        )

    def consider(self, *, briefs: tuple[Any, ...], **_: Any) -> Any:
        self.calls.append("consider")
        briefs = tuple(briefs)
        return RoutingRunResult(
            briefs=briefs,
            routes=obligation_routes(briefs, "targeted"),
            requests=(),
            call_evidence=(),
        )

    def revise(
        self,
        *,
        gaps: tuple[Any, ...],
        loss_analysis: Any,
        control_structure: Any,
        **_: Any,
    ) -> Any:
        self.calls.append("revision")
        return structural_revision(
            gaps,
            loss_analysis=loss_analysis,
            control_structure=control_structure,
            outcome="rejected",
        )

    def recheck(self, *, briefs: tuple[Any, ...], **_: Any) -> Any:
        self.calls.append("recheck")
        briefs = tuple(briefs)
        return RoutingRunResult(
            briefs=briefs,
            routes=obligation_routes(briefs, "targeted"),
            requests=(),
            call_evidence=(),
        )

    def enrich_actions(self, **_: Any) -> None:
        # The enrichment grounding stage runs for every normal synthesis
        # invocation; the fake keeps the offline pair endpoint-free and
        # records the call so both runs share the pre-realization sequence.
        self.calls.append("enrich")
        return None

    def fill_icas(self, **_: Any) -> Any:
        self.calls.append("ica")
        return "fixed-ica-enumeration"

    def scenarios(self, **_: Any) -> Any:
        self.calls.append("scenarios")
        return SimpleNamespace(
            scenario_envelopes=("fixed-scenario",), candidate_outcomes=None
        )

    def account(self, *, plan: Any, **_: Any) -> Any:
        self.calls.append("account")
        return SimpleNamespace(
            rows=(),
            summary=SimpleNamespace(addressed=0, total=len(plan.obligations)),
            model_dump=lambda **__: {
                "schema_version": "stpa-obligation-accounting-v1",
                "rows": [],
            },
        )

    def realize(self, **_: Any) -> Any:
        self.calls.append("realize")
        return SimpleNamespace(
            records=(),
            summary=SimpleNamespace(total=0, realized=0, unresolved=0, not_requested=0),
            model_dump=lambda **__: {
                "schema_version": "stpa-scenario-realization-v1",
                "records": [],
                "summary": {
                    "total": 0,
                    "realized": 0,
                    "unresolved": 0,
                    "not_requested": 0,
                },
            },
        )

    def target_realize(
        self, *, execution_target_profile: ExecutionTargetProfile, **_: Any
    ) -> TargetRealizationResult:
        self.calls.append("target_realization")
        return _empty_target_result(execution_target_profile)


def _run_synthesis_pair(
    profile: ExecutionTargetProfile,
) -> tuple[Any, Any, _FixedSynthesis, _FixedSynthesis]:
    without_dir = Path(tempfile.mkdtemp(prefix="mcp-target-baseline-without-"))
    with_dir = Path(tempfile.mkdtemp(prefix="mcp-target-baseline-with-"))
    without_fake = _FixedSynthesis()
    with_fake = _FixedSynthesis(profile)
    without = run_synthesis(
        synthesis_inputs(without_dir),
        SynthesisAdapters.from_object(without_fake),
    )
    with_profile = run_synthesis(
        synthesis_inputs(with_dir, execution_target_profile=profile),
        SynthesisAdapters.from_object(with_fake),
    )
    return without, with_profile, without_fake, with_fake


def _h_context(world: World, text: str, examples: dict[str, str]) -> tuple[bool, str]:
    del text, examples
    _state(world).clear()
    return True, ""


def _h_inventory(world: World, text: str, examples: dict[str, str]) -> tuple[bool, str]:
    del text, examples
    _state(world)["inventory_names"] = tuple(tool["name"] for tool in _fixture_tools())
    return True, ""


def _h_discover_without_calls(
    world: World, text: str, examples: dict[str, str]
) -> tuple[bool, str]:
    del text, examples
    result, adapter = _discover()
    _state(world).update(result=result, adapter=adapter)
    return True, ""


def _h_exact_inventory(
    world: World, text: str, examples: dict[str, str]
) -> tuple[bool, str]:
    del text, examples
    state = _state(world)
    result: TargetDiscoveryResult = state["result"]
    profile = result.profile
    if profile is None or result.inventory is None:
        return False, "metadata-free discovery did not produce inventory and profile"
    expected = set(state["inventory_names"])
    observed = {item.name for item in profile.inventory.tools}
    resources = {item.tool_name for item in profile.resources}
    operations = {
        operation.operation_id
        for resource in profile.resources
        for operation in resource.operations
    }
    if observed != expected or resources != expected or operations != expected:
        return False, "profile lost an exact MCP tool or operation identity"
    if any(item.get("kind") == "tool_call" for item in result.calls):
        return False, "schema-only discovery performed an active tool call"
    return True, ""


def _h_authority(world: World, text: str, examples: dict[str, str]) -> tuple[bool, str]:
    del text, examples
    profile = _state(world)["result"].profile
    if profile is None:
        return False, "profile is missing"
    if profile.inventory_authority is not InventoryAuthority.observed:
        return False, "inventory authority is not observed"
    if profile.semantic_authority is not SemanticAuthority.inferred:
        return False, "semantic authority is not inferred"
    if any(
        operation.operation_id != operation.semantic_operation
        for resource in profile.resources
        for operation in resource.operations
    ):
        return False, "MCP semantic operation identity was rewritten"
    return True, ""


def _h_discover_with_secrets(
    world: World, text: str, examples: dict[str, str]
) -> tuple[bool, str]:
    del text, examples
    result, adapter = _discover()
    output_dir = Path(tempfile.mkdtemp(prefix="mcp-target-secret-"))
    written = write_target_discovery(output_dir, result)
    artifact_text = "\n".join(
        path.read_text(encoding="utf-8") for path in written.values()
    )
    secrets = (adapter.endpoint, adapter.authorization, "acceptance-secret")
    _state(world).update(
        result=result,
        adapter=adapter,
        artifact_text=artifact_text,
        secret_free=not any(secret in artifact_text for secret in secrets),
    )
    return True, ""


def _h_secret_free(
    world: World, text: str, examples: dict[str, str]
) -> tuple[bool, str]:
    del text, examples
    return (
        _state(world).get("secret_free", False),
        "runtime connection data entered discovery artifacts",
    )


def _h_synthesis_inputs(
    world: World, text: str, examples: dict[str, str]
) -> tuple[bool, str]:
    del text, examples
    profile = _profile()
    without, with_profile, without_fake, with_fake = _run_synthesis_pair(profile)
    state = _state(world)
    state.update(
        profile=profile,
        synthesis_without=without,
        synthesis_with=with_profile,
        fake_without=without_fake,
        fake_with=with_fake,
    )
    return True, ""


def _h_synthesis_boundary(
    world: World, text: str, examples: dict[str, str]
) -> tuple[bool, str]:
    del text, examples
    state = _state(world)
    fake_without: _FixedSynthesis = state["fake_without"]
    fake_with: _FixedSynthesis = state["fake_with"]
    if "target_realization" not in fake_with.calls:
        return False, "profile-backed synthesis did not reach target realization"
    if "target_realization" in fake_without.calls:
        return False, "target-free synthesis unexpectedly reached target realization"
    boundary = fake_with.calls.index("target_realization")
    if tuple(fake_with.calls[:boundary]) != tuple(fake_without.calls[:boundary]):
        return False, "pre-realization provider sequence changed with target profile"
    without_dir = state["synthesis_without"].output_dir
    with_dir = state["synthesis_with"].output_dir
    for filename in (PLAN_FILENAME, CONSIDERATION_FILENAME):
        if (without_dir / filename).read_bytes() != (with_dir / filename).read_bytes():
            return False, f"systemic artifact {filename} changed before realization"
    return True, ""


def _h_given_target_baseline(
    world: World, text: str, examples: dict[str, str]
) -> tuple[bool, str]:
    del text, examples
    state = _state(world)
    state["baseline"] = _baseline(one_action=True)
    state["profile"] = _profile(("process_refund",))
    return True, ""


def _h_exact_realization(
    world: World, text: str, examples: dict[str, str]
) -> tuple[bool, str]:
    del text, examples
    state = _state(world)
    interpreter = _ExactRealizationInterpreter("process_refund")
    state["interpreter"] = interpreter
    state["realization"] = realize_target_operations(
        state["baseline"], state["profile"], lambda: interpreter
    )
    return True, ""


def _h_exact_selected(
    world: World, text: str, examples: dict[str, str]
) -> tuple[bool, str]:
    del text, examples
    state = _state(world)
    rows = [
        row for row in state["realization"].rows if row.control_action_id == "CA-1-1"
    ]
    expected = (
        mcp_resource_id("target:acceptance", "process_refund"),
        "process_refund",
    )
    if (
        len(rows) != 1
        or rows[0].disposition is not TargetRealizationDisposition.supported
    ):
        return False, "systemic action was not supported"
    if (
        rows[0].selected_operation is None
        or rows[0].selected_operation.identity != expected
    ):
        return False, "realization did not select the exact observed operation"
    return True, ""


def _h_realization_authority(
    world: World, text: str, examples: dict[str, str]
) -> tuple[bool, str]:
    del text, examples
    state = _state(world)
    if state["realization"].profile_digest != state["profile"].semantic_digest:
        return False, "realization profile digest is not pinned"
    if state["profile"].semantic_authority is not SemanticAuthority.inferred:
        return False, "profile semantic authority is not inferred"
    return True, ""


def _h_uncovered_operation(
    world: World, text: str, examples: dict[str, str]
) -> tuple[bool, str]:
    del text, examples
    state = _state(world)
    state["baseline"] = _baseline(one_action=True)
    state["control_structure"] = _make_one_action_control_structure()
    state["baseline_before"] = state["baseline"].model_dump(mode="json")
    state["profile"] = _profile(("schedule_payment",))
    state["extension"] = _ExtensionFactory()
    state["realization"] = realize_target_operations(
        state["baseline"],
        state["profile"],
        lambda: _UnmappedRealizationInterpreter(),
        extension_factory=state["extension"],
    )
    state["enhanced"] = realize_target_derived_icas(
        state["baseline"],
        state["realization"],
        _DerivedFindingFactory(),
    )
    state["projection"] = project_target_realization_to_stpa(
        state["baseline"],
        _make_sp3_loss_analysis(),
        state["control_structure"],
        ICAEnumeration(slots=[]),
        state["enhanced"],
    )
    return True, ""


def _h_extension_called_once(
    world: World, text: str, examples: dict[str, str]
) -> tuple[bool, str]:
    del text, examples
    extension = _state(world)["extension"]
    return (
        extension.calls == 1 and len(extension.requests) == 1,
        "bounded extension was not called exactly once",
    )


def _h_baseline_unchanged(
    world: World, text: str, examples: dict[str, str]
) -> tuple[bool, str]:
    del text, examples
    state = _state(world)
    if state["baseline"].model_dump(mode="json") != state["baseline_before"]:
        return False, "bounded extension mutated the baseline"
    if (
        state["realization"].rows[0].disposition
        is not TargetRealizationDisposition.unmapped
    ):
        return False, "target extension rewrote the systemic baseline row"
    return True, ""


def _h_extension_joined(
    world: World, text: str, examples: dict[str, str]
) -> tuple[bool, str]:
    del text, examples
    state = _state(world)
    enhanced = state["enhanced"]
    projection = state["projection"]
    if not enhanced.target_derived_ica_findings or enhanced.effective_view is None:
        return False, "verified target-derived findings were not retained"
    if any(
        finding.related_constraints != ("SC-1",)
        for finding in enhanced.target_derived_ica_findings
    ):
        return False, "target-derived constraints were not resolved from owner evidence"
    finding_ids = {
        ica.ica_id for slot in projection.ica_enumeration.slots for ica in slot.icas
    }
    expected = enhanced.target_derived_ica_findings[0].ica_id
    return (
        expected in finding_ids,
        "verified target-derived finding did not join the projected candidate universe",
    )


def _h_ambiguous_relationship(
    world: World, text: str, examples: dict[str, str]
) -> tuple[bool, str]:
    del text, examples
    state = _state(world)
    state["baseline"] = _baseline(one_action=True)
    state["profile"] = _profile(("process_refund",))
    state["realization"] = realize_target_operations(
        state["baseline"],
        state["profile"],
        lambda: _AmbiguousRealizationInterpreter(),
    )
    return True, ""


def _h_stage5_request(
    world: World, text: str, examples: dict[str, str]
) -> tuple[bool, str]:
    del text, examples
    state = _state(world)
    payload = _make_sp3_cs().model_dump(mode="json")
    payload["responsibilities"][0]["control_actions"][0]["effect_kind"] = "tool_call"
    control_structure = ControlStructure.model_validate(payload)
    context = build_scenario_generation_context(
        StructuralThreat(
            ica_slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
            provenance="structural",
            ica_id="RESP-1:CA-1-1:NOT_PROVIDED:1",
            ica_text="The action is not provided.",
            hazardous_context="Authorization state is stale.",
            loss_scenario="An unauthorized action is accepted.",
            related_hazards=["H-1"],
            related_constraints=["SC-1"],
        ),
        control_structure,
        _make_sp3_loss_analysis(),
        scenario_id="SCN-001",
    )
    target_operation = None
    prompts = build_context_bdi_prompts(
        context,
        TemplateLoader(PROMPTS_DIR),
        target_operation=target_operation,
    )
    client = MockLLMClient()
    client.set_response_queue([_stage5_payload("direct_prompt", "tool_call")])
    result, error = generate_bdi_for_context(
        client,
        context,
        Path(tempfile.mkdtemp(prefix="mcp-target-stage5-")),
        target_operation=target_operation,
    )
    state.update(
        stage5_context=context,
        stage5_prompts=prompts,
        stage5_client=client,
        stage5_result=result,
        stage5_error=error,
    )
    return True, ""


def _stage5_payload(delivery: str, action: str) -> dict[str, Any]:
    return {
        "stimulus": {
            "category": "user_message",
            "description": "A fixed user stimulus.",
        },
        "adversary": {
            "kind": "malicious_customer",
            "gain": "Learns another customer's order details.",
        },
        "attacker_bdi": {
            "beliefs": ["The controller can act on stale state."],
            "desires": ["Induce the selected unsafe action."],
            "intentions": [
                {
                    "description": "Rely on the selected factor.",
                    "source_handles": ["cause_1"],
                }
            ],
        },
        "causal_factors": [
            {
                "source_handle": "cause_1",
                "selected_for_route": True,
                "evidence": "The selected structural condition can remain stale.",
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
            "semantic_proposition": None,
        },
        "execution_route": {
            "disposition": "executable_route",
            "action_kind": action,
            "reason": "The fixed structural evidence supports this route.",
        },
    }


def _h_stage5_no_exact_operation(
    world: World, text: str, examples: dict[str, str]
) -> tuple[bool, str]:
    del text, examples
    state = _state(world)
    resource_id = mcp_resource_id("target:acceptance", "process_refund")
    operation_id = "process_refund"
    if state["stage5_error"] is not None or state["stage5_result"] is None:
        return False, f"Stage 5 failed unexpectedly: {state['stage5_error']}"
    client = state["stage5_client"]
    if not client.calls:
        return False, "Stage 5 provider was not called"
    if any(
        resource_id in call.user_prompt or operation_id in call.user_prompt
        for call in client.calls
    ):
        return False, "ambiguous target relationship was supplied to Stage 5"
    contract = state["stage5_result"].execution_contract
    requirement = next(
        item
        for item in contract.resource_requirements
        if item.purpose is ExecutionResourcePurpose.target_action
    )
    return (
        requirement.exact_resource_id is None,
        "Stage 5 received an exact target resource despite ambiguity",
    )


def register(api: object) -> None:
    """Register deterministic handlers for the MCP target primitive feature."""
    api.register(
        r"^the MCP target-discovery acceptance context is available$", _h_context
    )
    api.register(r"^a metadata-free MCP tools inventory$", _h_inventory)
    api.register(
        r"^the inventory is discovered without active tool calls$",
        _h_discover_without_calls,
    )
    api.register(
        r"^the profile retains exact MCP tool and operation identities$",
        _h_exact_inventory,
    )
    api.register(
        r"^observed inventory authority remains separate from inferred semantic authority$",
        _h_authority,
    )
    api.register(
        r"^the inventory is discovered with secret runtime connection data$",
        _h_discover_with_secrets,
    )
    api.register(
        r"^no endpoint credential or secret value appears in any discovery artifact$",
        _h_secret_free,
    )
    api.register(
        r"^identical fixed systemic provider responses with and without a target profile$",
        _h_synthesis_inputs,
    )
    api.register(
        r"^both synthesis runs reach the target-realization boundary$",
        _h_synthesis_boundary,
    )
    api.register(
        r"^every pre-realization prompt and systemic baseline artifact is identical$",
        _h_synthesis_boundary,
    )
    api.register(
        r"^a target-blind systemic baseline and an observed target profile$",
        _h_given_target_baseline,
    )
    api.register(
        r"^target realization supports one systemic control action$",
        _h_exact_realization,
    )
    api.register(
        r"^it selects the exact observed resource and operation$", _h_exact_selected
    )
    api.register(
        r"^the target-realization artifact retains inferred semantic authority separately$",
        _h_realization_authority,
    )
    api.register(
        r"^an uncovered observed state-changing operation$", _h_uncovered_operation
    )
    api.register(r"^the bounded target extension is attempted$", _h_uncovered_operation)
    api.register(
        r"^the extension adapter is called exactly once$", _h_extension_called_once
    )
    api.register(r"^the baseline records remain unchanged$", _h_baseline_unchanged)
    api.register(
        r"^verified target-derived ICA findings join the scenario candidate universe$",
        _h_extension_joined,
    )
    api.register(
        r"^a target realization whose relationship is ambiguous$",
        _h_ambiguous_relationship,
    )
    api.register(r"^Stage 5 requests an exact target operation$", _h_stage5_request)
    api.register(
        r"^no target operation is supplied to the Stage 5 provider$",
        _h_stage5_no_exact_operation,
    )


__all__ = ["FEATURE_ID", "register"]
