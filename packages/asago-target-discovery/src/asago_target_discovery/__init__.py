"""Independent MCP target-discovery primitive and persistence helpers.

Every name loads on first use (PEP 562), so importing one module of this
package does not load the others. The runtime-contract builder depends on that:
orch runs it in the producer's interpreter, and a target's declaration needs
neither STPA, the LLM interpreter, the MCP transport nor the prompt templates.
"""

from __future__ import annotations

import importlib
from typing import Any

_EXPORTS: dict[str, str] = {
    "InventoryAdapterResponse": "asago_target_discovery.contracts",
    "McpInventoryAdapter": "asago_target_discovery.contracts",
    "McpInventoryPage": "asago_target_discovery.contracts",
    "McpTargetDiscoveryInputs": "asago_target_discovery.contracts",
    "TargetDiscoveryResult": "asago_target_discovery.contracts",
    "TargetInterpretationDraft": "asago_target_discovery.contracts",
    "TargetInterpretationRequest": "asago_target_discovery.contracts",
    "TargetInterpretationResponse": "asago_target_discovery.contracts",
    "TargetInterpretationVerdict": "asago_target_discovery.contracts",
    "TargetInterpretationVerification": "asago_target_discovery.contracts",
    "TargetInterpreterAdapter": "asago_target_discovery.contracts",
    "TargetInterpreterFactory": "asago_target_discovery.contracts",
    "TargetToolPromptView": "asago_target_discovery.contracts",
    "discover_mcp_target": "asago_target_discovery.discovery",
    "TargetDiscoveryLlmError": "asago_target_discovery.llm_interpreter",
    "TargetDiscoveryLlmInterpreter": "asago_target_discovery.llm_interpreter",
    "CALLS_FILENAME": "asago_target_discovery.persistence",
    "INVENTORY_FILENAME": "asago_target_discovery.persistence",
    "MANIFEST_FILENAME": "asago_target_discovery.persistence",
    "PROFILE_FILENAME": "asago_target_discovery.persistence",
    "TARGET_DISCOVERY_MANIFEST_SCHEMA_VERSION": ("asago_target_discovery.persistence"),
    "write_target_discovery": "asago_target_discovery.persistence",
    "PLANTED_ITEM": "asago_target_discovery.runtime_contract",
    "RuntimeContractViolation": ("asago_target_discovery.runtime_contract"),
    "declared_runtime_contract": "asago_target_discovery.runtime_contract",
    "FileMcpInventoryAdapter": "asago_target_discovery.transport",
    "HttpMcpInventoryAdapter": "asago_target_discovery.transport",
    "McpToolsListFileError": "asago_target_discovery.transport",
    "McpTransportError": "asago_target_discovery.transport",
}

# The child modules callers reach as attributes of the package.
_SUBMODULES = frozenset(
    {
        "cli",
        "contracts",
        "discovery",
        "llm_interpreter",
        "model_adapter",
        "persistence",
        "prompts",
        "redaction",
        "runtime_contract",
        "transport",
    }
)


def __getattr__(name: str) -> Any:
    module = _EXPORTS.get(name)
    if module is not None:
        value = getattr(importlib.import_module(module), name)
        globals()[name] = value
        return value
    if name in _SUBMODULES:
        return importlib.import_module(f"{__name__}.{name}")
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted({*globals(), *_EXPORTS, *_SUBMODULES})


__all__ = sorted(_EXPORTS)
