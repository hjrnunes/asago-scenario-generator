"""The one seam between target discovery and the model.

The composition seam (:mod:`discovery`) and the command (:mod:`cli`) reach the
MCP inventory transport, the structured interpretation and the prompt templates
only through this module. The three implementation modules stay private to the
adapter: a new inventory source or provider client is wired here, and the rest
of the scanner keeps depending on the protocols in :mod:`contracts` plus the
pure helpers re-exported below.

The provider-aware interpreter renders the prompt templates itself, so it is
part of this seam rather than of the composition.
"""

from __future__ import annotations

from .llm_interpreter import TargetDiscoveryLlmError, TargetDiscoveryLlmInterpreter
from .prompts import (
    batch_prompt_hashes,
    build_verifier_prompt,
    prompt_hash,
)
from .transport import (
    FileMcpInventoryAdapter,
    HttpMcpInventoryAdapter,
    McpToolsListFileError,
    McpTransportError,
    canonical_tool_fields,
    looks_like_incomplete_page,
    normalize_page,
    tool_digest_payload,
    tool_name_hint,
)

__all__ = [
    "FileMcpInventoryAdapter",
    "HttpMcpInventoryAdapter",
    "McpToolsListFileError",
    "McpTransportError",
    "TargetDiscoveryLlmError",
    "TargetDiscoveryLlmInterpreter",
    "batch_prompt_hashes",
    "build_verifier_prompt",
    "canonical_tool_fields",
    "looks_like_incomplete_page",
    "normalize_page",
    "prompt_hash",
    "tool_digest_payload",
    "tool_name_hint",
]
