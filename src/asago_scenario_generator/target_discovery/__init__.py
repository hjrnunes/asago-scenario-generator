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
    load_execution_target_profile,
    persist_target_discovery,
    read_execution_target_profile,
    write_target_discovery,
)
from .transport import HttpMcpInventoryAdapter, McpTransportError

__all__ = [
    "InventoryAdapterResponse",
    "McpInventoryAdapter",
    "McpInventoryPage",
    "McpTargetDiscoveryInputs",
    "TargetDiscoveryResult",
    "TargetInterpretationDraft",
    "TargetInterpretationRequest",
    "TargetInterpretationResponse",
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
    "load_execution_target_profile",
    "persist_target_discovery",
    "read_execution_target_profile",
    "write_target_discovery",
    "HttpMcpInventoryAdapter",
    "McpTransportError",
]
