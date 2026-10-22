"""Independent MCP target-discovery primitive and persistence helpers."""

from .contracts import (
    InventoryAdapterResponse,
    McpInventoryAdapter,
    McpInventoryPage,
    McpTargetDiscoveryInputs,
    TargetDiscoveryResult,
    TargetInterpretationDraft,
    TargetInterpretationRequest,
    TargetInterpretationResponse,
    TargetInterpretationVerdict,
    TargetInterpretationVerification,
    TargetInterpreterAdapter,
    TargetInterpreterFactory,
    TargetToolPromptView,
)
from .discovery import discover_mcp_target
from .llm_interpreter import TargetDiscoveryLlmError, TargetDiscoveryLlmInterpreter
from .persistence import (
    CALLS_FILENAME,
    INVENTORY_FILENAME,
    MANIFEST_FILENAME,
    PROFILE_FILENAME,
    TARGET_DISCOVERY_MANIFEST_SCHEMA_VERSION,
    write_target_discovery,
)
from .runtime_contract import PLANTED_ITEM, declared_runtime_contract
from .transport import (
    FileMcpInventoryAdapter,
    HttpMcpInventoryAdapter,
    McpToolsListFileError,
    McpTransportError,
)

__all__ = [
    "InventoryAdapterResponse",
    "McpInventoryAdapter",
    "McpInventoryPage",
    "McpTargetDiscoveryInputs",
    "TargetDiscoveryResult",
    "TargetInterpretationDraft",
    "TargetInterpretationRequest",
    "TargetInterpretationResponse",
    "TargetInterpretationVerdict",
    "TargetInterpretationVerification",
    "TargetInterpreterAdapter",
    "TargetInterpreterFactory",
    "TargetToolPromptView",
    "discover_mcp_target",
    "TargetDiscoveryLlmError",
    "TargetDiscoveryLlmInterpreter",
    "CALLS_FILENAME",
    "INVENTORY_FILENAME",
    "MANIFEST_FILENAME",
    "PROFILE_FILENAME",
    "TARGET_DISCOVERY_MANIFEST_SCHEMA_VERSION",
    "write_target_discovery",
    "PLANTED_ITEM",
    "declared_runtime_contract",
    "FileMcpInventoryAdapter",
    "HttpMcpInventoryAdapter",
    "McpToolsListFileError",
    "McpTransportError",
]
