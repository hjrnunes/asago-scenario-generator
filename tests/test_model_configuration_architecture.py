"""Architecture guards for shared model-profile loading.

Generation configuration and STPA infrastructure both consume the shared
``model_profiles`` leaf. Generation must not import STPA, and the shared
loader must stay off either workflow façade.
"""

from __future__ import annotations

import ast
from pathlib import Path

SRC_DIR = (
    Path(__file__).resolve().parent.parent / "src" / "asago_scenario_generator"
)

_SHARED_LEAF = "asago_scenario_generator.model_profiles"
_STPA_PREFIX = "asago_scenario_generator.stpa"
_PIPELINE_PREFIX = "asago_scenario_generator.pipeline"
_LLM_CLIENT = "asago_scenario_generator.llm.client"
_FORBIDDEN_NEAR_IO = (
    "asago_scenario_generator.cli",
    "asago_scenario_generator.prompts",
    "asago_scenario_generator.manifest",
    "asago_scenario_generator.report",
)


def _imported_modules(path: Path) -> set[str]:
    """Return absolute module names imported by a source file."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module)
    return modules


def _starts_with(imports: set[str], prefix: str) -> list[str]:
    return sorted(
        imp for imp in imports if imp == prefix or imp.startswith(prefix + ".")
    )


class TestSharedProfileLeafStaysOffWorkflowFacades:
    """The YAML loader is a shared leaf, not a workflow implementation."""

    def test_shared_leaf_does_not_import_workflows_or_io(self) -> None:
        """Profile loading stays off generation, STPA, and delivery modules."""
        imports = _imported_modules(SRC_DIR / "model_profiles.py")
        forbidden = (
            _STPA_PREFIX,
            _PIPELINE_PREFIX,
            _LLM_CLIENT,
            *_FORBIDDEN_NEAR_IO,
        )
        violations = [
            imp
            for prefix in forbidden
            for imp in _starts_with(imports, prefix)
        ]
        assert not violations, f"shared profile leaf imports {violations}"


class TestGenerationConfigDependsInward:
    """Generation configuration consumes the shared leaf, not STPA infra."""

    def test_model_configuration_imports_shared_leaf(self) -> None:
        """Effective config reaches YAML profiles through the shared leaf."""
        imports = _imported_modules(SRC_DIR / "pipeline" / "model_configuration.py")
        assert _SHARED_LEAF in imports
        assert not _starts_with(imports, _STPA_PREFIX)
        assert not _starts_with(imports, _LLM_CLIENT)
        assert not _starts_with(imports, "asago_scenario_generator.cli")


class TestStpaProfileFacadeDependsInward:
    """The historical STPA import path re-exports the shared leaf."""

    def test_stpa_facade_imports_shared_leaf(self) -> None:
        """STPA keeps its public path without owning the loader."""
        imports = _imported_modules(SRC_DIR / "stpa" / "infra" / "model_profiles.py")
        assert _SHARED_LEAF in imports
        assert not _starts_with(imports, _PIPELINE_PREFIX)
        assert not _starts_with(imports, _LLM_CLIENT)


class TestLlmClientsStayOffOppositeWorkflows:
    """Each LLM client stays on its own workflow side of the shared leaf."""

    def test_generation_client_does_not_import_stpa_or_pipeline(self) -> None:
        """The generation client is an adapter, not a workflow orchestrator."""
        imports = _imported_modules(SRC_DIR / "llm" / "client.py")
        assert not _starts_with(imports, _STPA_PREFIX)
        assert not _starts_with(imports, _PIPELINE_PREFIX)
        assert not _starts_with(imports, "asago_scenario_generator.cli")

    def test_stpa_client_does_not_import_generation_client(self) -> None:
        """The STPA client remains a clean copy, not a wrapper."""
        imports = _imported_modules(SRC_DIR / "stpa" / "infra" / "llm.py")
        assert not _starts_with(imports, _LLM_CLIENT)
        assert not _starts_with(imports, _PIPELINE_PREFIX)
