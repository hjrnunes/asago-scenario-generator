"""Pure composition seam for metadata-free MCP target discovery."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from asago_scenario_generator.models.canonical import canonical_json_bytes
from asago_scenario_generator.stpa.models.execution_classification import (
    DiscoveryProvenance,
    ExecutionSurface,
    ExecutionTargetProfile,
    InventoryAuthority,
    InventoryCompleteness,
    InterpreterVerifierAgreement,
    McpInventoryObservation,
    McpToolObservation,
    ProfileBasis,
    SemanticAuthority,
    SourceProtocol,
    TargetDiscoveryDiagnostic,
    TargetDiscoveryDiagnosticCode,
    TargetDiscoverySeverity,
    TargetOperationEffect,
    TargetProfileOperation,
    TargetProfileResource,
    TargetSemanticInterpretation,
    TargetStateEffect,
    TargetInterpretationDisposition,
    mcp_inventory_evidence_refs,
    mcp_resource_id,
)

from .contracts import (
    McpInventoryAdapter,
    McpInventoryPage,
    McpTargetDiscoveryInputs,
    TargetDiscoveryResult,
    TargetInterpretationDraft,
    TargetInterpretationRequest,
    TargetInterpretationResponse,
    TargetInterpretationVerification,
    TargetInterpreterFactory,
    TargetToolPromptView,
)
from .redaction import sanitize_tool_fields
from .transport import (
    canonical_tool_fields,
    looks_like_incomplete_page,
    normalize_page,
    tool_digest_payload,
    tool_name_hint,
)
from .prompts import (
    batch_prompt_hashes,
    build_verifier_prompt,
    prompt_hash,
)


@dataclass(frozen=True)
class _InterpretationBatch:
    """Validated response and accounting produced for one request batch."""

    response: TargetInterpretationResponse
    agreements: Mapping[str, InterpreterVerifierAgreement]
    adapter_supplied: bool
    diagnostics: tuple[TargetDiscoveryDiagnostic, ...] = ()
    calls: tuple[Mapping[str, Any], ...] = ()


def discover_mcp_target(
    inputs: McpTargetDiscoveryInputs,
    inventory_adapter: McpInventoryAdapter,
    interpreter_factory: TargetInterpreterFactory | None = None,
) -> TargetDiscoveryResult:
    """Discover one MCP target through inventory and typed interpretation.

    The caller supplies transport and interpretation adapters, but does not
    orchestrate pages, batches, identity mapping, or verification.  Runtime
    endpoint and credential values are intentionally absent from every result
    field and call record.
    """
    _validate_discovery_inputs(inputs, inventory_adapter)

    pages, observations, inventory_diagnostics, calls = _collect_inventory(
        inputs, inventory_adapter
    )
    if not pages:
        return _empty_discovery_result(inputs, inventory_diagnostics, calls)

    inventory = _build_inventory(inputs, pages, observations, inventory_diagnostics)
    resources = tuple(
        _resource_for_tool(inputs.target_id, tool) for tool in inventory.tools
    )
    requests = _build_interpretation_requests(inputs, inventory.tools)
    interpretations, interpretation_diagnostics, interpretation_calls, provenance = (
        _interpret_inventory(
            inputs, inventory, resources, requests, interpreter_factory
        )
    )
    calls.extend(interpretation_calls)
    diagnostics = list(inventory_diagnostics) + list(interpretation_diagnostics)

    profile = _build_profile(
        inputs,
        inventory,
        resources,
        interpretations,
        provenance,
        diagnostics,
    )
    return _discovery_result(inputs, profile, inventory, provenance, diagnostics, calls)


def _validate_discovery_inputs(
    inputs: McpTargetDiscoveryInputs, inventory_adapter: McpInventoryAdapter
) -> None:
    if not isinstance(inputs, McpTargetDiscoveryInputs):
        raise TypeError("inputs must be McpTargetDiscoveryInputs")
    if inventory_adapter is None or not hasattr(inventory_adapter, "list_tools"):
        raise TypeError("inventory_adapter must provide list_tools")


def _empty_discovery_result(
    inputs: McpTargetDiscoveryInputs,
    diagnostics: Sequence[TargetDiscoveryDiagnostic],
    calls: Sequence[Mapping[str, Any]],
) -> TargetDiscoveryResult:
    return TargetDiscoveryResult(
        mode=inputs.mode,
        controls=_scan_controls(inputs),
        profile=None,
        inventory=None,
        provenance=None,
        diagnostics=tuple(diagnostics),
        calls=tuple(calls),
    )


def _build_inventory(
    inputs: McpTargetDiscoveryInputs,
    pages: Sequence[McpInventoryPage],
    observations: Sequence[McpToolObservation],
    diagnostics: Sequence[TargetDiscoveryDiagnostic],
) -> McpInventoryObservation:
    pagination_complete = not any(
        item.code
        in {
            TargetDiscoveryDiagnosticCode.incomplete_pagination,
            TargetDiscoveryDiagnosticCode.inventory_protocol_failure,
        }
        for item in diagnostics
    )
    return McpInventoryObservation(
        target_id=inputs.target_id,
        authorization_scope_id=inputs.authorization_scope_id,
        tools=tuple(observations),
        pagination_complete=pagination_complete,
        page_count=len(pages),
    )


def _inventory_completeness(
    diagnostics: Sequence[TargetDiscoveryDiagnostic],
    pagination_complete: bool,
) -> InventoryCompleteness:
    error_codes = {
        TargetDiscoveryDiagnosticCode.inventory_protocol_failure,
        TargetDiscoveryDiagnosticCode.unsupported_protocol,
        TargetDiscoveryDiagnosticCode.duplicate_tool_name,
        TargetDiscoveryDiagnosticCode.malformed_tool,
        TargetDiscoveryDiagnosticCode.malformed_schema,
        TargetDiscoveryDiagnosticCode.incomplete_pagination,
    }
    return (
        InventoryCompleteness.observed_complete
        if pagination_complete
        and not any(item.code in error_codes for item in diagnostics)
        else InventoryCompleteness.observed_partial
    )


def _build_profile(
    inputs: McpTargetDiscoveryInputs,
    inventory: McpInventoryObservation,
    resources: Sequence[TargetProfileResource],
    interpretations: Sequence[TargetSemanticInterpretation],
    provenance: DiscoveryProvenance,
    diagnostics: Sequence[TargetDiscoveryDiagnostic],
) -> ExecutionTargetProfile:
    return ExecutionTargetProfile(
        target_id=inputs.target_id,
        authorization_scope_id=inputs.authorization_scope_id,
        basis=ProfileBasis.target,
        inventory_authority=InventoryAuthority.observed,
        semantic_authority=SemanticAuthority.inferred,
        inventory_completeness=_inventory_completeness(
            diagnostics, inventory.pagination_complete
        ),
        source_protocol=SourceProtocol.mcp,
        source_inventory_digest=inventory.semantic_digest,
        discovery_provenance=provenance,
        inventory=inventory,
        resources=tuple(resources),
        interpretations=tuple(interpretations),
        diagnostics=tuple(diagnostics),
    )


def _discovery_result(
    inputs: McpTargetDiscoveryInputs,
    profile: ExecutionTargetProfile,
    inventory: McpInventoryObservation,
    provenance: DiscoveryProvenance,
    diagnostics: Sequence[TargetDiscoveryDiagnostic],
    calls: Sequence[Mapping[str, Any]],
) -> TargetDiscoveryResult:
    return TargetDiscoveryResult(
        mode=inputs.mode,
        controls=_scan_controls(inputs),
        profile=profile,
        inventory=inventory,
        provenance=provenance,
        diagnostics=tuple(diagnostics),
        calls=tuple(calls),
    )


def _collect_inventory(
    inputs: McpTargetDiscoveryInputs,
    adapter: McpInventoryAdapter,
) -> tuple[
    list[McpInventoryPage],
    list[McpToolObservation],
    list[TargetDiscoveryDiagnostic],
    list[dict[str, Any]],
]:
    """Collect and normalize one logical paginated tools/list operation."""
    pages: list[McpInventoryPage] = []
    observations: list[McpToolObservation] = []
    diagnostics: list[TargetDiscoveryDiagnostic] = []
    calls: list[dict[str, Any]] = []
    seen_names: set[str] = set()
    seen_cursors: set[str] = set()
    cursor: str | None = None

    while True:
        continue_collection, next_cursor = _collect_inventory_page(
            adapter,
            cursor,
            pages,
            observations,
            diagnostics,
            calls,
            seen_names,
            seen_cursors,
        )
        if not continue_collection:
            break
        cursor = next_cursor

    observations.sort(key=lambda item: item.name)
    return pages, observations, diagnostics, calls


def _collect_inventory_page(
    adapter: McpInventoryAdapter,
    cursor: str | None,
    pages: list[McpInventoryPage],
    observations: list[McpToolObservation],
    diagnostics: list[TargetDiscoveryDiagnostic],
    calls: list[dict[str, Any]],
    seen_names: set[str],
    seen_cursors: set[str],
) -> tuple[bool, str | None]:
    """Collect one page and report whether another page should be fetched."""
    page, failure_code, call = _fetch_inventory_page(adapter, cursor)
    if failure_code is not None:
        return _record_inventory_failure(failure_code, call, pages, diagnostics, calls)
    if page is None:  # pragma: no cover - fetch helper always returns one
        return False, None
    pages.append(page)
    calls.append(_inventory_page_call(page, cursor))
    page_observations, page_diagnostics = _collect_page_tools(page, seen_names)
    observations.extend(page_observations)
    diagnostics.extend(page_diagnostics)
    if page.complete:
        return False, None
    next_cursor, cursor_diagnostic = _next_inventory_cursor(page, seen_cursors)
    if cursor_diagnostic is not None:
        diagnostics.append(cursor_diagnostic)
        return False, None
    seen_cursors.add(next_cursor)
    return True, next_cursor


def _record_inventory_failure(
    failure_code: TargetDiscoveryDiagnosticCode,
    call: Mapping[str, Any],
    pages: list[McpInventoryPage],
    diagnostics: list[TargetDiscoveryDiagnostic],
    calls: list[dict[str, Any]],
) -> tuple[bool, str | None]:
    diagnostics.append(_diagnostic(failure_code, call["detail"]))
    calls.append({key: value for key, value in call.items() if key != "detail"})
    if (
        not pages
        and failure_code is TargetDiscoveryDiagnosticCode.incomplete_pagination
    ):
        pages.append(McpInventoryPage(tools=()))
    return False, None


def _fetch_inventory_page(
    adapter: McpInventoryAdapter,
    cursor: str | None,
) -> tuple[
    McpInventoryPage | None, TargetDiscoveryDiagnosticCode | None, dict[str, Any]
]:
    """Fetch and normalize one page, retaining a secret-free call view."""
    raw_page: Any = None
    try:
        raw_page = (
            adapter.list_tools() if cursor is None else adapter.list_tools(cursor)
        )
        page = normalize_page(raw_page)
    except Exception as exc:  # noqa: BLE001 - adapter boundary normalization
        code = (
            TargetDiscoveryDiagnosticCode.incomplete_pagination
            if looks_like_incomplete_page(raw_page)
            else TargetDiscoveryDiagnosticCode.inventory_protocol_failure
        )
        return (
            None,
            code,
            {
                "kind": "tools/list",
                "cursor_present": cursor is not None,
                "status": "error",
                "error_type": type(exc).__name__,
                "detail": f"tools/list page failed closed: {type(exc).__name__}",
            },
        )
    return page, None, _inventory_page_call(page, cursor)


def _inventory_page_call(page: McpInventoryPage, cursor: str | None) -> dict[str, Any]:
    """Build secret-free accounting for one successful inventory page."""
    return {
        "kind": "tools/list",
        "cursor_present": cursor is not None,
        "status": "ok",
        "tool_count": len(page.tools),
        "page_digest": _digest_json([tool_digest_payload(item) for item in page.tools]),
    }


def _collect_page_tools(
    page: McpInventoryPage,
    seen_names: set[str],
) -> tuple[list[McpToolObservation], list[TargetDiscoveryDiagnostic]]:
    """Normalize one page and retain malformed/duplicate evidence."""
    observations: list[McpToolObservation] = []
    diagnostics: list[TargetDiscoveryDiagnostic] = []
    for index, raw_tool in enumerate(page.tools):
        tool, diagnostic = _normalize_page_tool(index, raw_tool)
        if diagnostic is not None:
            diagnostics.append(diagnostic)
            continue
        if tool is None:  # pragma: no cover - diagnostic branch always returns
            continue
        if tool.name in seen_names:
            diagnostics.append(
                _diagnostic(
                    TargetDiscoveryDiagnosticCode.duplicate_tool_name,
                    "duplicate exact MCP tool name was retained only once",
                    tool_name=tool.name,
                    evidence_refs=_tool_evidence_refs(tool.name),
                )
            )
            continue
        seen_names.add(tool.name)
        observations.append(tool)
    return observations, diagnostics


def _normalize_page_tool(
    index: int,
    raw_tool: Any,
) -> tuple[McpToolObservation | None, TargetDiscoveryDiagnostic | None]:
    """Normalize one page row or return its typed malformed-row diagnostic."""
    try:
        tool = _normalize_tool(raw_tool)
    except Exception as exc:  # noqa: BLE001 - retain malformed evidence
        code = (
            TargetDiscoveryDiagnosticCode.malformed_schema
            if _looks_like_schema_failure(exc)
            else TargetDiscoveryDiagnosticCode.malformed_tool
        )
        return None, _diagnostic(
            code,
            f"tool row {index} is invalid: {type(exc).__name__}: {exc}",
            tool_name=tool_name_hint(raw_tool),
        )
    return tool, None


def _next_inventory_cursor(
    page: McpInventoryPage,
    seen_cursors: set[str],
) -> tuple[str | None, TargetDiscoveryDiagnostic | None]:
    """Select a fresh pagination cursor or report a partial inventory."""
    next_cursor = page.next_cursor
    if next_cursor is None or next_cursor in seen_cursors:
        return None, _diagnostic(
            TargetDiscoveryDiagnosticCode.incomplete_pagination,
            "MCP tools/list pagination stopped without a fresh cursor",
        )
    return next_cursor, None


def _scan_controls(inputs: McpTargetDiscoveryInputs) -> dict[str, Any]:
    """Return non-secret scanner controls for manifest accounting."""
    return {
        "interpretation_batch_size": inputs.interpretation_batch_size,
        "model_name": inputs.model_name,
        "model_profile": inputs.model_profile,
        "scanner_id": inputs.scanner_id,
        "interpreter_id": inputs.interpreter_id,
        "verifier_id": inputs.verifier_id,
    }


def _normalize_tool(raw_tool: Any) -> McpToolObservation:
    """Map one MCP transport row into canonical snake_case observation fields."""
    if isinstance(raw_tool, McpToolObservation):
        return raw_tool
    source = canonical_tool_fields(raw_tool)
    normalized = _select_tool_fields(source)
    source_digest = _digest_json(normalized)
    normalized = sanitize_tool_fields(normalized)
    normalized["source_observation_sha256"] = source_digest
    if "input_schema" not in normalized:
        raise ValueError("MCP tool row is missing inputSchema")
    return McpToolObservation.model_validate(normalized)


def _select_tool_fields(source: Mapping[str, Any]) -> dict[str, Any]:
    """Retain only the MCP fields represented by the profile contract."""
    allowed = {
        "name",
        "title",
        "description",
        "input_schema",
        "output_schema",
        "annotations",
        "argument_names",
    }
    return {key: value for key, value in source.items() if key in allowed}


def _build_interpretation_requests(
    inputs: McpTargetDiscoveryInputs,
    tools: Sequence[McpToolObservation],
) -> tuple[TargetInterpretationRequest, ...]:
    """Create stable request-local handles in canonical tool order."""
    views = tuple(
        TargetToolPromptView(
            handle=f"TOOL-{index}",
            name=tool.name,
            title=tool.title,
            description=tool.description,
            input_schema=tool.input_schema,
            output_schema=tool.output_schema,
            annotations=tool.annotations,
            argument_names=tool.argument_names,
            evidence_refs=_tool_evidence_refs(tool.name),
        )
        for index, tool in enumerate(sorted(tools, key=lambda item: item.name), start=1)
    )
    batch_size = inputs.interpretation_batch_size
    return tuple(
        TargetInterpretationRequest(
            batch_id=f"BATCH-{index}",
            tools=views[offset : offset + batch_size],
        )
        for index, offset in enumerate(range(0, len(views), batch_size), start=1)
    )


def _interpret_inventory(
    inputs: McpTargetDiscoveryInputs,
    inventory: McpInventoryObservation,
    resources: Sequence[TargetProfileResource],
    requests: Sequence[TargetInterpretationRequest],
    factory: TargetInterpreterFactory | None,
) -> tuple[
    tuple[TargetSemanticInterpretation, ...],
    tuple[TargetDiscoveryDiagnostic, ...],
    list[dict[str, Any]],
    DiscoveryProvenance,
]:
    """Interpret every observed tool and independently verify each batch."""
    del resources  # resource IDs are derived again from exact inventory identity
    diagnostics: list[TargetDiscoveryDiagnostic] = []
    calls: list[dict[str, Any]] = []
    drafts_by_handle: dict[str, TargetInterpretationDraft] = {}
    agreement_by_handle: dict[str, InterpreterVerifierAgreement] = {}
    interpreter_hashes = batch_prompt_hashes(requests)
    verifier_hashes: list[str] = []

    _collect_interpretation_batches(
        requests,
        interpreter_hashes,
        factory,
        drafts_by_handle,
        agreement_by_handle,
        diagnostics,
        calls,
    )

    interpretations, materialization_diagnostics = _materialize_interpretations(
        inputs.target_id,
        requests,
        drafts_by_handle,
        agreement_by_handle,
    )
    diagnostics.extend(materialization_diagnostics)

    provenance = DiscoveryProvenance(
        scanner_id=inputs.scanner_id,
        interpreter_id=inputs.interpreter_id,
        verifier_id=inputs.verifier_id,
        interpreter_prompt_hash=_aggregate_hashes(interpreter_hashes),
        verifier_prompt_hash=_aggregate_hashes(verifier_hashes),
        model_profile=inputs.model_profile,
        model_name=inputs.model_name,
    )
    return tuple(interpretations), tuple(diagnostics), calls, provenance


def _collect_interpretation_batches(
    requests: Sequence[TargetInterpretationRequest],
    interpreter_hashes: Sequence[str],
    factory: TargetInterpreterFactory | None,
    drafts_by_handle: dict[str, TargetInterpretationDraft],
    agreement_by_handle: dict[str, InterpreterVerifierAgreement],
    diagnostics: list[TargetDiscoveryDiagnostic],
    calls: list[dict[str, Any]],
) -> None:
    for request, interpreter_hash in zip(requests, interpreter_hashes):
        _collect_interpretation_batch(
            request,
            interpreter_hash,
            factory,
            drafts_by_handle,
            agreement_by_handle,
            diagnostics,
            calls,
        )


def _collect_interpretation_batch(
    request: TargetInterpretationRequest,
    interpreter_hash: str,
    factory: TargetInterpreterFactory | None,
    drafts_by_handle: dict[str, TargetInterpretationDraft],
    agreement_by_handle: dict[str, InterpreterVerifierAgreement],
    diagnostics: list[TargetDiscoveryDiagnostic],
    calls: list[dict[str, Any]],
) -> None:
    batch = _interpret_batch(request, interpreter_hash, factory)
    diagnostics.extend(batch.diagnostics)
    calls.extend(dict(item) for item in batch.calls)
    _record_interpretation_drafts(
        request, batch, drafts_by_handle, agreement_by_handle, diagnostics
    )
    if batch.adapter_supplied:
        diagnostics.extend(_missing_draft_diagnostics(request, drafts_by_handle))


def _record_interpretation_drafts(
    request: TargetInterpretationRequest,
    batch: _InterpretationBatch,
    drafts_by_handle: dict[str, TargetInterpretationDraft],
    agreement_by_handle: dict[str, InterpreterVerifierAgreement],
    diagnostics: list[TargetDiscoveryDiagnostic],
) -> None:
    for draft in batch.response.interpretations:
        expected_view, draft_diagnostic = _validate_draft(
            request, draft, drafts_by_handle
        )
        if draft_diagnostic is not None:
            diagnostics.append(draft_diagnostic)
            continue
        if expected_view is None:  # pragma: no cover - guarded by validator
            continue
        drafts_by_handle[draft.tool_handle] = draft
        agreement_by_handle[draft.tool_handle] = batch.agreements.get(
            draft.tool_handle, InterpreterVerifierAgreement.unverified
        )
        if draft.disposition is TargetInterpretationDisposition.contradictory:
            diagnostics.append(
                _diagnostic(
                    TargetDiscoveryDiagnosticCode.interpretation_contradictory,
                    "interpreter marked the observed tool interpretation contradictory",
                    tool_name=expected_view.name,
                    severity=TargetDiscoverySeverity.warning,
                    evidence_refs=draft.evidence_refs,
                )
            )


def _interpret_batch(
    request: TargetInterpretationRequest,
    interpreter_hash: str,
    factory: TargetInterpreterFactory | None,
) -> _InterpretationBatch:
    """Run and account for one interpretation/verifier request batch."""
    if factory is None:
        diagnostics = tuple(
            _diagnostic(
                TargetDiscoveryDiagnosticCode.interpretation_missing,
                "no interpretation adapter was supplied; retained unresolved record",
                tool_name=tool.name,
                severity=TargetDiscoverySeverity.warning,
                evidence_refs=tool.evidence_refs,
            )
            for tool in request.tools
        )
        return _InterpretationBatch(
            response=_empty_interpretation_response(),
            agreements={},
            adapter_supplied=False,
            diagnostics=diagnostics,
        )

    response, verifier, owner, interpreter_diagnostics = _run_interpreter_batch(
        factory, request
    )
    verifier_hash = prompt_hash(*build_verifier_prompt(request, response))
    agreements, verifier_diagnostics = _verify_batch(verifier, request, response)
    records = _drain_call_records(owner)
    if not records:
        records = [
            _default_interpretation_call(
                request,
                interpreter_hash,
                verifier_hash,
                response,
                agreements,
            )
        ]
    return _InterpretationBatch(
        response=response,
        agreements=agreements,
        adapter_supplied=True,
        diagnostics=interpreter_diagnostics + verifier_diagnostics,
        calls=tuple(records),
    )


def _run_interpreter_batch(
    factory: TargetInterpreterFactory,
    request: TargetInterpretationRequest,
) -> tuple[
    TargetInterpretationResponse,
    Any,
    Any,
    tuple[TargetDiscoveryDiagnostic, ...],
]:
    """Invoke and coerce one provider response, retaining provider failures."""
    owner: Any = factory
    try:
        raw_response, verifier, owner = _invoke_interpreter(factory, request)
        response = _coerce_interpretation_response(raw_response)
    except Exception as exc:  # noqa: BLE001 - provider boundary
        response = _empty_interpretation_response()
        verifier = None
        diagnostics = (
            _diagnostic(
                TargetDiscoveryDiagnosticCode.interpreter_failure,
                f"interpretation batch failed: {type(exc).__name__}",
                severity=TargetDiscoverySeverity.error,
            ),
        )
    else:
        diagnostics = ()
    return response, verifier, owner, diagnostics


_BatchVerification = tuple[
    dict[str, InterpreterVerifierAgreement], tuple[TargetDiscoveryDiagnostic, ...]
]


def _verify_batch(
    verifier: Any,
    request: TargetInterpretationRequest,
    response: TargetInterpretationResponse,
) -> _BatchVerification:
    """Verify one response and normalize verifier-boundary outcomes per handle.

    A per-tool verification assigns each handle its own verdict. A
    batch-level boolean or enum still applies to every handle in the batch.
    """
    try:
        raw = _verify_response(verifier, request, response)
        verification = _coerce_verification(raw)
    except Exception as exc:  # noqa: BLE001 - verifier boundary
        return _uniform_verification(
            request,
            InterpreterVerifierAgreement.unverified,
            _diagnostic(
                TargetDiscoveryDiagnosticCode.interpretation_invalid,
                f"verifier call failed: {type(exc).__name__}",
                severity=TargetDiscoverySeverity.warning,
            ),
        )
    if verification is not None:
        return _per_tool_verification(request, verification)
    agreement = _coerce_verifier_agreement(raw)
    if agreement is InterpreterVerifierAgreement.disagree:
        return _uniform_verification(
            request,
            agreement,
            _diagnostic(
                TargetDiscoveryDiagnosticCode.verifier_disagreement,
                "independent verifier rejected one or more interpretations",
                severity=TargetDiscoverySeverity.warning,
            ),
        )
    if agreement is None:
        return _uniform_verification(
            request,
            InterpreterVerifierAgreement.unverified,
            _diagnostic(
                TargetDiscoveryDiagnosticCode.interpretation_invalid,
                "verifier must return per-tool verdicts, a typed agreement enum, "
                "or a boolean",
                severity=TargetDiscoverySeverity.warning,
            ),
        )
    return _uniform_verification(request, agreement)


def _uniform_verification(
    request: TargetInterpretationRequest,
    agreement: InterpreterVerifierAgreement,
    *diagnostics: TargetDiscoveryDiagnostic,
) -> _BatchVerification:
    """Apply one verifier outcome to every handle of a batch."""
    return {tool.handle: agreement for tool in request.tools}, diagnostics


def _per_tool_verification(
    request: TargetInterpretationRequest,
    verification: TargetInterpretationVerification,
) -> _BatchVerification:
    """Assign each handle its own verdict; a foreign handle voids the batch."""
    expected = {tool.handle for tool in request.tools}
    foreign = sorted(
        item.tool_handle
        for item in verification.verdicts
        if item.tool_handle not in expected
    )
    if foreign:
        return _uniform_verification(
            request,
            InterpreterVerifierAgreement.unverified,
            _diagnostic(
                TargetDiscoveryDiagnosticCode.interpretation_invalid,
                "verifier returned verdicts for handles outside the batch: "
                + ", ".join(foreign),
                severity=TargetDiscoverySeverity.warning,
            ),
        )
    verdicts = {item.tool_handle: item for item in verification.verdicts}
    agreements: dict[str, InterpreterVerifierAgreement] = {}
    diagnostics: list[TargetDiscoveryDiagnostic] = []
    for tool in request.tools:
        verdict = verdicts.get(tool.handle)
        if verdict is None:
            agreements[tool.handle] = InterpreterVerifierAgreement.unverified
            diagnostics.append(
                _diagnostic(
                    TargetDiscoveryDiagnosticCode.interpretation_invalid,
                    "verifier returned no verdict for this interpretation",
                    tool_name=tool.name,
                    severity=TargetDiscoverySeverity.warning,
                )
            )
            continue
        agreements[tool.handle] = verdict.agreement
        if verdict.agreement is InterpreterVerifierAgreement.disagree:
            diagnostics.append(
                _diagnostic(
                    TargetDiscoveryDiagnosticCode.verifier_disagreement,
                    "independent verifier rejected this interpretation: "
                    + verdict.reason,
                    tool_name=tool.name,
                    severity=TargetDiscoverySeverity.warning,
                )
            )
    return agreements, tuple(diagnostics)


def _coerce_verification(raw: Any) -> TargetInterpretationVerification | None:
    """Return per-tool verdicts, or ``None`` for a batch-level result."""
    if isinstance(raw, TargetInterpretationVerification):
        return raw
    if isinstance(raw, Mapping) and "verdicts" in raw:
        return TargetInterpretationVerification.model_validate(raw)
    return None


def _default_interpretation_call(
    request: TargetInterpretationRequest,
    interpreter_hash: str,
    verifier_hash: str,
    response: TargetInterpretationResponse,
    agreements: Mapping[str, InterpreterVerifierAgreement],
) -> dict[str, Any]:
    """Build the fallback accounting record for adapters without a call log."""
    return {
        "kind": "interpretation",
        "batch_id": request.batch_id,
        "prompt_hash": interpreter_hash,
        "response_digest": response.response_digest
        or _digest_json(response.model_dump(mode="json", exclude={"response_digest"})),
        "verifier_prompt_hash": verifier_hash,
        "agreements": {
            handle: agreements[handle].value for handle in sorted(agreements)
        },
        "tool_handles": sorted(tool.handle for tool in request.tools),
    }


def _validate_draft(
    request: TargetInterpretationRequest,
    draft: TargetInterpretationDraft,
    drafts_by_handle: Mapping[str, TargetInterpretationDraft],
) -> tuple[TargetToolPromptView | None, TargetDiscoveryDiagnostic | None]:
    """Validate one provider draft against its request-local evidence."""
    expected_handles = {tool.handle for tool in request.tools}
    if draft.tool_handle not in expected_handles:
        return None, _unknown_draft_handle_diagnostic()
    if draft.tool_handle in drafts_by_handle:
        return None, _duplicate_draft_handle_diagnostic()
    expected_view = _view_by_handle(request, draft.tool_handle)
    diagnostic = _draft_evidence_diagnostic(expected_view, draft)
    if diagnostic is not None:
        return None, diagnostic
    diagnostic = _draft_observer_diagnostic(expected_view, draft, expected_handles)
    if diagnostic is not None:
        return None, diagnostic
    return expected_view, None


def _unknown_draft_handle_diagnostic() -> TargetDiscoveryDiagnostic:
    return _diagnostic(
        TargetDiscoveryDiagnosticCode.interpretation_unknown_reference,
        "interpretation returned a handle outside its request batch",
        severity=TargetDiscoverySeverity.error,
    )


def _duplicate_draft_handle_diagnostic() -> TargetDiscoveryDiagnostic:
    return _diagnostic(
        TargetDiscoveryDiagnosticCode.interpretation_invalid,
        "interpretation returned a duplicate tool handle",
        severity=TargetDiscoverySeverity.error,
    )


def _draft_evidence_diagnostic(
    expected_view: TargetToolPromptView,
    draft: TargetInterpretationDraft,
) -> TargetDiscoveryDiagnostic | None:
    if any(ref not in expected_view.evidence_refs for ref in draft.evidence_refs):
        return _diagnostic(
            TargetDiscoveryDiagnosticCode.interpretation_unknown_reference,
            "interpretation cited an evidence reference outside inventory",
            tool_name=expected_view.name,
            severity=TargetDiscoverySeverity.error,
            evidence_refs=draft.evidence_refs,
        )
    if not draft.evidence_refs:
        return _diagnostic(
            TargetDiscoveryDiagnosticCode.interpretation_invalid,
            "interpretation must cite at least one inventory field",
            tool_name=expected_view.name,
            severity=TargetDiscoverySeverity.error,
        )
    exact_prefix = f"inventory:tool:{expected_view.name}:"
    if not any(ref.startswith(exact_prefix) for ref in draft.evidence_refs):
        return _diagnostic(
            TargetDiscoveryDiagnosticCode.interpretation_invalid,
            "interpretation must cite an exact observed field",
            tool_name=expected_view.name,
            severity=TargetDiscoverySeverity.error,
            evidence_refs=draft.evidence_refs,
        )
    return None


def _draft_observer_diagnostic(
    expected_view: TargetToolPromptView,
    draft: TargetInterpretationDraft,
    expected_handles: set[str],
) -> TargetDiscoveryDiagnostic | None:
    if any(
        handle not in expected_handles or handle == draft.tool_handle
        for handle in draft.observer_tool_handles
    ):
        return _diagnostic(
            TargetDiscoveryDiagnosticCode.interpretation_unknown_reference,
            "interpretation cited an unknown or self observer handle",
            tool_name=expected_view.name,
            severity=TargetDiscoverySeverity.error,
        )
    return None


def _missing_draft_diagnostics(
    request: TargetInterpretationRequest,
    drafts_by_handle: Mapping[str, TargetInterpretationDraft],
) -> tuple[TargetDiscoveryDiagnostic, ...]:
    """Report request-local handles omitted by an otherwise working adapter."""
    return tuple(
        _diagnostic(
            TargetDiscoveryDiagnosticCode.interpretation_missing,
            "interpreter omitted this request-local tool handle; retained unresolved record",
            tool_name=tool.name,
            severity=TargetDiscoverySeverity.warning,
            evidence_refs=tool.evidence_refs,
        )
        for tool in request.tools
        if tool.handle not in drafts_by_handle
    )


def _empty_interpretation_response() -> TargetInterpretationResponse:
    """Build an internal empty response for no-adapter/failure accounting."""
    return TargetInterpretationResponse.model_construct(interpretations=())


def _materialize_interpretations(
    target_id: str,
    requests: Sequence[TargetInterpretationRequest],
    drafts_by_handle: Mapping[str, TargetInterpretationDraft],
    agreement_by_handle: Mapping[str, InterpreterVerifierAgreement],
) -> tuple[
    tuple[TargetSemanticInterpretation, ...],
    tuple[TargetDiscoveryDiagnostic, ...],
]:
    """Compile accepted request-local drafts into exact target identities."""
    interpretations: list[TargetSemanticInterpretation] = []
    diagnostics: list[TargetDiscoveryDiagnostic] = []
    for request in requests:
        for view in request.tools:
            interpretation, diagnostic = _materialize_interpretation(
                target_id,
                request,
                view,
                drafts_by_handle.get(view.handle),
                agreement_by_handle.get(
                    view.handle, InterpreterVerifierAgreement.unverified
                ),
            )
            interpretations.append(interpretation)
            if diagnostic is not None:
                diagnostics.append(diagnostic)
    return tuple(interpretations), tuple(diagnostics)


def _materialize_interpretation(
    target_id: str,
    request: TargetInterpretationRequest,
    view: TargetToolPromptView,
    draft: TargetInterpretationDraft | None,
    agreement: InterpreterVerifierAgreement,
) -> tuple[TargetSemanticInterpretation, TargetDiscoveryDiagnostic | None]:
    """Compile one draft, retaining unresolved output on a closed failure."""
    if draft is None:
        return (
            _unresolved_interpretation(
                target_id, view, agreement=InterpreterVerifierAgreement.unverified
            ),
            None,
        )
    observer_ids = tuple(
        mcp_resource_id(target_id, _view_by_handle(request, handle).name)
        for handle in draft.observer_tool_handles
    )
    try:
        interpretation = TargetSemanticInterpretation(
            resource_id=mcp_resource_id(target_id, view.name),
            tool_name=view.name,
            disposition=draft.disposition,
            likely_effect=draft.likely_effect,
            likely_state_effect=draft.likely_state_effect,
            semantic_roles=draft.semantic_roles,
            observer_resource_ids=observer_ids,
            evidence_refs=draft.evidence_refs,
            rationale=draft.rationale,
            interpreter_verifier_agreement=agreement,
        )
    except (TypeError, ValueError, ValidationError) as exc:
        return (
            _unresolved_interpretation(
                target_id, view, agreement=InterpreterVerifierAgreement.unverified
            ),
            _diagnostic(
                TargetDiscoveryDiagnosticCode.interpretation_invalid,
                f"interpretation for {view.name} failed closed: {type(exc).__name__}",
                tool_name=view.name,
                severity=TargetDiscoverySeverity.error,
            ),
        )
    return interpretation, None


def _invoke_interpreter(
    factory: Any, request: TargetInterpretationRequest
) -> tuple[Any, Any, Any]:
    """Invoke one declared adapter shape without arity guessing.

    The public protocol is a zero-argument factory returning an object with
    ``interpret(request)`` and (optionally) ``verify(request, response)``.  A
    caller may also pass that already-constructed object directly.  We do not
    retry a failed call with a different signature: a provider ``TypeError``
    is an adapter failure and must remain visible as such.
    """
    if callable(getattr(factory, "interpret", None)):
        adapter = factory
    else:
        if not callable(factory):
            raise TypeError(
                "interpreter factory must be a zero-argument callable returning "
                "a typed adapter"
            )
        adapter = factory()
    if not callable(getattr(adapter, "interpret", None)):
        raise TypeError(
            "interpreter factory must return an adapter with interpret(request)"
        )
    return _invoke_interpreter_object(adapter, adapter, request)


def _invoke_interpreter_object(
    interpreter: Any,
    owner: Any,
    request: TargetInterpretationRequest,
) -> tuple[Any, Any, Any]:
    return (
        interpreter.interpret(request),
        getattr(interpreter, "verify", None),
        owner,
    )


def _drain_call_records(owner: Any) -> list[Mapping[str, Any]]:
    """Collect optional provider call records from one adapter instance."""
    drain = getattr(owner, "drain_call_records", None)
    if not callable(drain):
        return []
    records = drain()
    if records is None:
        return []
    return [record for record in records if isinstance(record, Mapping)]


def _coerce_interpretation_response(raw_response: Any) -> TargetInterpretationResponse:
    """Validate one closed typed response from an interpretation adapter."""
    if isinstance(raw_response, TargetInterpretationResponse):
        return raw_response
    if isinstance(raw_response, Mapping):
        return TargetInterpretationResponse.model_validate(raw_response)
    if isinstance(raw_response, Sequence) and not isinstance(
        raw_response, (str, bytes, bytearray)
    ):
        return TargetInterpretationResponse(interpretations=tuple(raw_response))
    raise TypeError("interpreter must return a typed response or mapping")


def _verify_response(
    verifier: Any,
    request: TargetInterpretationRequest,
    response: TargetInterpretationResponse,
) -> Any:
    """Return the verifier's raw result, or ``unverified`` without a verifier."""
    if verifier is None:
        return InterpreterVerifierAgreement.unverified
    return _invoke_verifier(verifier, request, response)


def _invoke_verifier(
    verifier: Any,
    request: TargetInterpretationRequest,
    response: TargetInterpretationResponse,
) -> Any:
    """Invoke the verifier's one typed two-argument protocol."""
    if not callable(verifier):
        raise TypeError("interpreter verifier must be callable")
    return verifier(request, response)


def _coerce_verifier_agreement(raw: Any) -> InterpreterVerifierAgreement | None:
    """Coerce one closed verifier result without accepting free text."""
    if isinstance(raw, bool):
        return (
            InterpreterVerifierAgreement.agree
            if raw
            else InterpreterVerifierAgreement.disagree
        )
    if isinstance(raw, InterpreterVerifierAgreement):
        return raw
    if isinstance(raw, Mapping):
        return _coerce_mapping_agreement(raw)
    return None


def _coerce_mapping_agreement(
    raw: Mapping[str, Any],
) -> InterpreterVerifierAgreement | None:
    """Coerce the two supported mapping keys for verifier agreement."""
    value = (
        raw["agreement"]
        if "agreement" in raw
        else raw.get("interpreter_verifier_agreement")
    )
    if isinstance(value, bool):
        return (
            InterpreterVerifierAgreement.agree
            if value
            else InterpreterVerifierAgreement.disagree
        )
    try:
        return InterpreterVerifierAgreement(value)
    except (TypeError, ValueError):
        return None


def _resource_for_tool(
    target_id: str, tool: McpToolObservation
) -> TargetProfileResource:
    """Copy exact observation fields into one MCP semantic resource."""
    return TargetProfileResource(
        resource_id=mcp_resource_id(target_id, tool.name),
        resource_kind="tool",
        target_id=target_id,
        tool_name=tool.name,
        title=tool.title,
        description=tool.description,
        input_schema=tool.input_schema,
        output_schema=tool.output_schema,
        annotations=tool.annotations,
        argument_names=tool.argument_names,
        surfaces=(ExecutionSurface.tool_call, ExecutionSurface.tool_result),
        operations=(
            TargetProfileOperation(
                operation_id=tool.name,
                semantic_operation=tool.name,
                argument_names=tool.argument_names,
            ),
        ),
        evidence_refs=_tool_evidence_refs(tool.name),
    )


def _unresolved_interpretation(
    target_id: str,
    view: TargetToolPromptView,
    *,
    agreement: InterpreterVerifierAgreement,
) -> TargetSemanticInterpretation:
    """Retain an explicit unresolved interpretation for missing/invalid output."""
    return TargetSemanticInterpretation(
        resource_id=mcp_resource_id(target_id, view.name),
        tool_name=view.name,
        disposition=TargetInterpretationDisposition.unresolved,
        likely_effect=TargetOperationEffect.unknown,
        likely_state_effect=TargetStateEffect.unknown,
        evidence_refs=(view.evidence_refs[0],),
        rationale="No verified semantic interpretation was supplied.",
        interpreter_verifier_agreement=agreement,
    )


def _view_by_handle(
    request: TargetInterpretationRequest, handle: str
) -> TargetToolPromptView:
    """Resolve a request-local handle after closed validation."""
    for tool in request.tools:
        if tool.handle == handle:
            return tool
    raise ValueError("unknown request-local tool handle")


def _tool_evidence_refs(tool_name: str) -> tuple[str, ...]:
    """Return exact field refs available to interpretation prompts."""
    return mcp_inventory_evidence_refs(tool_name)


def _looks_like_schema_failure(exc: Exception) -> bool:
    text = str(exc).lower()
    return "schema" in text or "input" in text or "output" in text


def _diagnostic(
    code: TargetDiscoveryDiagnosticCode,
    detail: str,
    *,
    tool_name: str | None = None,
    severity: TargetDiscoverySeverity = TargetDiscoverySeverity.error,
    evidence_refs: Sequence[str] = (),
) -> TargetDiscoveryDiagnostic:
    """Construct a closed deterministic diagnostic."""
    return TargetDiscoveryDiagnostic(
        code=code,
        severity=severity,
        detail=detail,
        tool_name=tool_name,
        evidence_refs=tuple(evidence_refs),
    )


def _digest_json(value: Any) -> str:
    """Hash JSON-compatible accounting values without retaining raw output."""
    try:
        encoded = canonical_json_bytes(value)
    except Exception:
        encoded = canonical_json_bytes(str(value))
    return hashlib.sha256(encoded).hexdigest()


def _aggregate_hashes(values: Sequence[str]) -> str | None:
    """Hash an ordered set of prompt hashes for provenance."""
    return _digest_json(list(values)) if values else None


__all__ = ["discover_mcp_target"]
