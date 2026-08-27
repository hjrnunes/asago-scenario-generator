"""Architecture guard tests for the taxonomy report package split.

These tests enforce structural invariants of the ``report`` package after
its split out of the monolithic ``template.py``:

1. **No import cycles**: every ``report`` module imports cleanly on its own.
2. **Dependency direction**: ``scenario_common`` and ``provenance`` are
   leaves — they must not import section builders, the facade, or the
   orchestrator.  Section modules render fragments and must not depend on
   the ``template`` facade or the ``generator`` orchestrator, which sit
   above them.  The facade and the data/scorecard loaders stay below the
   orchestrator.
3. **Facade completeness**: the public ``build_*`` section entry points
   moved into the ``sections_*`` modules remain importable from
   ``report.template``, so downstream callers (the generator, unit tests)
   keep their import surface after the split.
4. **Acceptance boundary**: the ``taxonomy_report_sections`` runtime
   handlers reach report behavior only through the public entry
   (``report.data`` / ``report.generator`` / ``html_utils``), never
   through ``template`` section internals.
"""

from __future__ import annotations

import ast
import importlib
from pathlib import Path

import pytest

REPORT_DIR = (
    Path(__file__).resolve().parent.parent
    / "src"
    / "asago_scenario_generator"
    / "report"
)
ACCEPTANCE_DIR = (
    Path(__file__).resolve().parent.parent / "acceptance" / "runtime_features"
)

# Modules that may sit above the section builders and the facade.
_FORBIDDEN_SECTION_TARGETS = (
    "asago_scenario_generator.report.template",
    "asago_scenario_generator.report.generator",
)

# Leaves: shared helpers that no other report module boundary may invert.
_LEAF_MODULES = {
    "scenario_common": "asago_scenario_generator.report.scenario_common",
    "provenance": "asago_scenario_generator.report.provenance",
}


def _extract_imports(file_path: Path) -> list[str]:
    """Return fully-qualified module names imported in *file_path*."""
    source = file_path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(file_path))
    imports: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.append(node.module)
    return imports


def _public_function_names(file_path: Path) -> set[str]:
    """Return top-level public function names defined in *file_path*."""
    tree = ast.parse(file_path.read_text(encoding="utf-8"), filename=str(file_path))
    return {
        node.name
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and not node.name.startswith("_")
    }


# ---------------------------------------------------------------------------
# Import cycles
# ---------------------------------------------------------------------------


class TestReportNoImportCycles:
    """All report modules must import without circular dependency errors."""

    @pytest.mark.parametrize(
        "module_name",
        [
            "asago_scenario_generator.report",
            "asago_scenario_generator.report.data",
            "asago_scenario_generator.report.generator",
            "asago_scenario_generator.report.provenance",
            "asago_scenario_generator.report.scenario_common",
            "asago_scenario_generator.report.scorecard",
            "asago_scenario_generator.report.template",
            "asago_scenario_generator.report.sections_atlas",
            "asago_scenario_generator.report.sections_attack_tree",
            "asago_scenario_generator.report.sections_behavior_spec",
            "asago_scenario_generator.report.sections_coverage",
            "asago_scenario_generator.report.sections_diversity",
            "asago_scenario_generator.report.sections_generation_inputs",
            "asago_scenario_generator.report.sections_pipeline_calls",
            "asago_scenario_generator.report.sections_profile",
            "asago_scenario_generator.report.sections_profile_block",
            "asago_scenario_generator.report.sections_raw",
            "asago_scenario_generator.report.sections_scenario_cards",
            "asago_scenario_generator.report.sections_scenarios",
            "asago_scenario_generator.report.sections_summary",
            "asago_scenario_generator.report.sections_techniques",
            "asago_scenario_generator.report.sections_threats",
        ],
    )
    def test_module_imports_cleanly(self, module_name):
        """Module can be imported without errors."""
        mod = importlib.import_module(module_name)
        assert mod is not None


# ---------------------------------------------------------------------------
# Dependency direction
# ---------------------------------------------------------------------------


class TestReportDependencyDirection:
    """Section builders stay below the facade and orchestrator."""

    def test_section_modules_do_not_import_facade_or_generator(self):
        """sections_* must not import template (facade) or generator."""
        violations: list[str] = []
        for path in sorted(REPORT_DIR.glob("sections_*.py")):
            for imp in _extract_imports(path):
                for forbidden in _FORBIDDEN_SECTION_TARGETS:
                    if imp == forbidden or imp.startswith(forbidden + "."):
                        violations.append(
                            f"{path.name}: imports '{imp}' — section "
                            "builders must stay below the facade"
                        )
        assert not violations, (
            "Section modules importing facade/orchestrator:\n" + "\n".join(violations)
        )

    def test_leaves_do_not_import_sections_or_facade(self):
        """scenario_common and provenance import nothing report-internal."""
        for leaf_name, leaf_module in _LEAF_MODULES.items():
            path = REPORT_DIR / f"{leaf_name}.py"
            report_imports = [
                imp
                for imp in _extract_imports(path)
                if imp.startswith("asago_scenario_generator.report.")
                and imp != leaf_module
            ]
            assert not report_imports, (
                f"{leaf_name}.py imports report-internal modules: {report_imports}"
            )

    def test_template_does_not_import_generator(self):
        """The facade must not depend on the orchestrator."""
        imports = _extract_imports(REPORT_DIR / "template.py")
        forbidden = "asago_scenario_generator.report.generator"
        assert not any(
            imp == forbidden or imp.startswith(forbidden + ".") for imp in imports
        )

    def test_data_and_scorecard_stay_below_facade_and_orchestrator(self):
        """data.py and scorecard.py must not import template/generator."""
        violations: list[str] = []
        for name in ("data.py", "scorecard.py"):
            for imp in _extract_imports(REPORT_DIR / name):
                for forbidden in _FORBIDDEN_SECTION_TARGETS:
                    if imp == forbidden or imp.startswith(forbidden + "."):
                        violations.append(
                            f"{name}: imports '{imp}' — loader must stay "
                            "below the facade and orchestrator"
                        )
        assert not violations, "Loaders importing facade/orchestrator:\n" + "\n".join(
            violations
        )


# ---------------------------------------------------------------------------
# Facade completeness
# ---------------------------------------------------------------------------


class TestTemplateFacadeCompleteness:
    """Public section entry points stay importable from report.template."""

    def test_every_public_section_builder_is_reexported(self):
        """Every public build_* function in sections_* is on the facade."""
        facade = importlib.import_module("asago_scenario_generator.report.template")
        missing: list[str] = []
        for path in sorted(REPORT_DIR.glob("sections_*.py")):
            for name in _public_function_names(path):
                if name.startswith("build_") and not hasattr(facade, name):
                    missing.append(f"{path.name}: {name}")
        assert not missing, (
            "Public section builders not re-exported by template facade:\n"
            + "\n".join(missing)
        )

    def test_generator_imports_sections_through_the_facade(self):
        """generator.py must not import sections_* modules directly."""
        violations: list[str] = []
        for imp in _extract_imports(REPORT_DIR / "generator.py"):
            if imp.startswith("asago_scenario_generator.report.sections_"):
                violations.append(imp)
        assert not violations, (
            "generator.py imports section modules directly: " + ", ".join(violations)
        )


# ---------------------------------------------------------------------------
# Acceptance boundary
# ---------------------------------------------------------------------------


class TestReportAcceptanceBoundary:
    """taxonomy_report_sections handlers use the public report entry only."""

    def test_runtime_does_not_import_template_internals(self):
        """No report section in the runtime imports template or sections_*."""
        violations: list[str] = []
        root = ACCEPTANCE_DIR / "taxonomy_report_sections"
        for path in sorted(root.glob("*.py")):
            if path.name == "__init__.py":
                continue
            for imp in _extract_imports(path):
                if imp.startswith("asago_scenario_generator.report.template") or (
                    imp.startswith("asago_scenario_generator.report.sections_")
                ):
                    violations.append(f"{path.name}: imports '{imp}'")
        assert not violations, (
            "Runtime handlers importing report internals:\n" + "\n".join(violations)
        )

    def test_shared_report_entry_imports_only_public_surface(self):
        """taxonomy_report.py reaches the report only via data/generator."""
        path = ACCEPTANCE_DIR / "taxonomy_report.py"
        imports = _extract_imports(path)
        forbidden = [
            imp
            for imp in imports
            if imp.startswith("asago_scenario_generator.report.")
            and not (
                imp.startswith("asago_scenario_generator.report.data")
                or imp.startswith("asago_scenario_generator.report.generator")
            )
        ]
        assert not forbidden, (
            "taxonomy_report.py imports report internals: " + ", ".join(forbidden)
        )
