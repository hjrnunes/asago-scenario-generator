"""Only the model adapter reaches the interpreter, the MCP transport and the prompts.

The scanner composes inventories and interpretations behind the protocols in
``contracts``. The provider client, the optional MCP SDK and the prompt text
stay behind one seam: ``model_adapter``. The provider-aware interpreter renders
its prompts itself, so it belongs to that seam and not to the composition.

A source scan keeps the boundary honest: once the test suite has loaded the
whole package, a runtime probe can no longer tell which module imported what.
"""

from __future__ import annotations

import importlib
import re
from pathlib import Path

import asago_target_discovery

PACKAGE_ROOT = Path(asago_target_discovery.__file__).resolve().parent

# The adapter modules the asago-dcpl.12 12b close reason names: the seam the
# scanner uses, plus the provider-aware interpreter that renders its own
# prompts.
ADAPTER_MODULES = frozenset({"model_adapter.py", "llm_interpreter.py"})

MODEL_FACING_IMPORT = re.compile(r"(import|from) .*(llm_interpreter|transport|prompts)")

_REEXPORTS: dict[str, str] = {
    "TargetDiscoveryLlmError": "llm_interpreter",
    "TargetDiscoveryLlmInterpreter": "llm_interpreter",
    "batch_prompt_hashes": "prompts",
    "build_verifier_prompt": "prompts",
    "prompt_hash": "prompts",
    "FileMcpInventoryAdapter": "transport",
    "HttpMcpInventoryAdapter": "transport",
    "McpToolsListFileError": "transport",
    "McpTransportError": "transport",
    "canonical_tool_fields": "transport",
    "looks_like_incomplete_page": "transport",
    "normalize_page": "transport",
    "tool_digest_payload": "transport",
    "tool_name_hint": "transport",
}


def _model_facing_import_lines(path: Path) -> list[int]:
    """Line numbers where one module imports a model-facing module."""
    return [
        number
        for number, line in enumerate(
            path.read_text(encoding="utf-8").splitlines(), start=1
        )
        if MODEL_FACING_IMPORT.search(line)
    ]


def test_only_the_adapter_modules_import_the_model_facing_modules() -> None:
    offenders = {
        path.name: _model_facing_import_lines(path)
        for path in sorted(PACKAGE_ROOT.glob("*.py"))
        if path.name not in ADAPTER_MODULES and _model_facing_import_lines(path)
    }

    assert offenders == {}


def test_the_adapter_reexports_the_implementation_objects() -> None:
    adapter = importlib.import_module("asago_target_discovery.model_adapter")

    for name, module_name in _REEXPORTS.items():
        implementation = importlib.import_module(
            f"asago_target_discovery.{module_name}"
        )
        assert getattr(adapter, name) is getattr(implementation, name), name
