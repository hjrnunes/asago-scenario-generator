"""Architecture guards for shared model-profile loading.

STPA infrastructure consumes the shared ``model_profiles`` leaf. The shared
loader must stay off either workflow façade.
"""

from __future__ import annotations

from pathlib import Path
from tests.helpers.architecture import imported_modules

SRC_DIR = Path(__file__).resolve().parent.parent / "src" / "asago_scenario_generator"

_SHARED_LEAF = "asago_scenario_generator.model_profiles"
_STPA_PREFIX = "asago_scenario_generator.stpa"
_PIPELINE_PREFIX = "asago_scenario_generator.pipeline"
_FORBIDDEN_NEAR_IO = (
    "asago_scenario_generator.cli",
    "asago_scenario_generator.prompts",
    "asago_scenario_generator.manifest",
    "asago_scenario_generator.report",
)


def _starts_with(imports: set[str], prefix: str) -> list[str]:
    return sorted(
        imp for imp in imports if imp == prefix or imp.startswith(prefix + ".")
    )


class TestSharedProfileLeafStaysOffWorkflowFacades:
    """The YAML loader is a shared leaf, not a workflow implementation."""

    def test_shared_leaf_does_not_import_workflows_or_io(self) -> None:
        """Profile loading stays off generation, STPA, and delivery modules."""
        imports = imported_modules(SRC_DIR / "model_profiles.py")
        forbidden = (
            _STPA_PREFIX,
            _PIPELINE_PREFIX,
            *_FORBIDDEN_NEAR_IO,
        )
        violations = [
            imp for prefix in forbidden for imp in _starts_with(imports, prefix)
        ]
        assert not violations, f"shared profile leaf imports {violations}"


class TestStpaProfileFacadeDependsInward:
    """The historical STPA import path re-exports the shared leaf."""

    def test_stpa_facade_imports_shared_leaf(self) -> None:
        """STPA keeps its public path without owning the loader."""
        imports = imported_modules(SRC_DIR / "stpa" / "infra" / "model_profiles.py")
        assert _SHARED_LEAF in imports
        assert not _starts_with(imports, _PIPELINE_PREFIX)


class TestLlmClientStaysOffPipeline:
    """The STPA client stays on its own side of the shared leaf."""

    def test_stpa_client_does_not_import_pipeline(self) -> None:
        """The STPA client is an adapter, not a workflow orchestrator."""
        imports = imported_modules(SRC_DIR / "stpa" / "infra" / "llm.py")
        assert not _starts_with(imports, _PIPELINE_PREFIX)
