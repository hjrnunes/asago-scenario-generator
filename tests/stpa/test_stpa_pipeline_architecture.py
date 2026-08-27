"""Architecture guard and property tests for the STPA pipeline module.

Architecture guards enforce structural invariants:

1. **Dependency direction**: ``pipeline/`` (orchestrator, high-level) may
   import from ``system_model``, ``threat_enum``, ``scenario_prod``,
   ``report``, ``infra``, and ``data`` (lower-level).  The reverse must
   never happen — lower-level modules must not import from ``pipeline/``.
2. **No CLI coupling**: ``pipeline/`` must not import from
   ``asago_scenario_generator.cli`` — the CLI is a delivery layer above the
   pipeline, not a dependency of it.
3. **No reverse intra-package coupling**: ``llm_config.py`` must not
   import from ``runner.py`` — ``runner`` depends on ``llm_config``,
   never the other way around.
4. **Public API contract**: ``pipeline/__init__.py`` exports exactly
   ``run_stpa_pipeline`` and ``STPARunResult``.
5. **No import cycles**: The pipeline package imports without circular
   dependency errors.

Property tests validate behavioral invariants:

- Resume skip decisions are deterministic (same artifacts → same skips).
- Summary output is well-formed (contains expected section headers).
- Error handling preserves stage errors across stages.
- ``STPARunResult`` has correct default field values.
"""

from __future__ import annotations

import ast
import importlib
import io
import sys
from dataclasses import fields, is_dataclass
from pathlib import Path
from unittest.mock import MagicMock, patch

from asago_scenario_generator.stpa.pipeline import STPARunResult, run_stpa_pipeline
from asago_scenario_generator.stpa.pipeline.runner import (
    SP1_ARTIFACT_NAMES,
    SP2_ARTIFACT_NAMES,
    _maybe_skip_stage,
    _sp1_artifacts_exist,
    _sp2_artifacts_exist,
    _sp3_artifacts_exist,
)

PIPELINE_DIR = (
    Path(__file__).resolve().parent.parent.parent
    / "src"
    / "asago_scenario_generator"
    / "stpa"
    / "pipeline"
)
RUNNER_PATH = PIPELINE_DIR / "runner.py"
LLM_CONFIG_PATH = PIPELINE_DIR / "llm_config.py"
INIT_PATH = PIPELINE_DIR / "__init__.py"

STPA_ROOT = PIPELINE_DIR.parent


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


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


def _python_files_in_dir(directory: Path) -> list[Path]:
    """Return all .py files in *directory* (non-recursive)."""
    return sorted(directory.glob("*.py"))


def _all_python_files_in_stpa_subdir(subdir: str) -> list[Path]:
    """Return all .py files in a stpa subdirectory (recursive)."""
    root = STPA_ROOT / subdir
    if not root.exists():
        return []
    return sorted(root.rglob("*.py"))


# ---------------------------------------------------------------------------
# Architecture guard tests — dependency direction
# ---------------------------------------------------------------------------


class TestPipelineDependencyDirection:
    """pipeline/ may import from lower-level modules; reverse is forbidden."""

    # Modules that pipeline/ is allowed to import from.
    _ALLOWED_PREFIXES = (
        "asago_scenario_generator.stpa.system_model",
        "asago_scenario_generator.stpa.threat_enum",
        "asago_scenario_generator.stpa.scenario_prod",
        "asago_scenario_generator.stpa.report",
        "asago_scenario_generator.stpa.infra",
        "asago_scenario_generator.stpa.pipeline",
        "asago_scenario_generator.stpa.models",
        "asago_scenario_generator.models",
        "asago_scenario_generator.data",
        # stdlib and third-party
        "__future__",
        "logging",
        "dataclasses",
        "pathlib",
        "os",
        "typing",
    )

    def test_runner_imports_allowed_modules_only(self):
        """runner.py imports only from allowed lower-level modules."""
        imports = _extract_imports(RUNNER_PATH)
        violations = [
            imp
            for imp in imports
            if imp.startswith("asago_scenario_generator.")
            and not imp.startswith(self._ALLOWED_PREFIXES)
        ]
        assert not violations, f"runner.py imports from forbidden modules: {violations}"

    def test_llm_config_imports_allowed_modules_only(self):
        """llm_config.py imports only from allowed lower-level modules."""
        imports = _extract_imports(LLM_CONFIG_PATH)
        violations = [
            imp
            for imp in imports
            if imp.startswith("asago_scenario_generator.")
            and not imp.startswith(self._ALLOWED_PREFIXES)
        ]
        assert not violations, (
            f"llm_config.py imports from forbidden modules: {violations}"
        )

    def test_pipeline_does_not_import_cli(self):
        """pipeline/ must never import from asago_scenario_generator.cli."""
        for py_file in _python_files_in_dir(PIPELINE_DIR):
            imports = _extract_imports(py_file)
            violations = [
                imp for imp in imports if imp.startswith("asago_scenario_generator.cli")
            ]
            assert not violations, (
                f"{py_file.name} imports from cli (forbidden): {violations}"
            )

    def test_system_model_does_not_import_pipeline(self):
        """system_model/ must not import from pipeline/."""
        for py_file in _all_python_files_in_stpa_subdir("system_model"):
            imports = _extract_imports(py_file)
            violations = [
                imp
                for imp in imports
                if "asago_scenario_generator.stpa.pipeline" in imp
            ]
            assert not violations, (
                f"system_model/{py_file.name} imports from pipeline (forbidden): {violations}"
            )

    def test_threat_enum_does_not_import_pipeline(self):
        """threat_enum/ must not import from pipeline/."""
        for py_file in _all_python_files_in_stpa_subdir("threat_enum"):
            imports = _extract_imports(py_file)
            violations = [
                imp
                for imp in imports
                if "asago_scenario_generator.stpa.pipeline" in imp
            ]
            assert not violations, (
                f"threat_enum/{py_file.name} imports from pipeline (forbidden): {violations}"
            )

    def test_scenario_prod_does_not_import_pipeline(self):
        """scenario_prod/ must not import from pipeline/."""
        for py_file in _all_python_files_in_stpa_subdir("scenario_prod"):
            imports = _extract_imports(py_file)
            violations = [
                imp
                for imp in imports
                if "asago_scenario_generator.stpa.pipeline" in imp
            ]
            assert not violations, (
                f"scenario_prod/{py_file.name} imports from pipeline (forbidden): {violations}"
            )

    def test_report_does_not_import_pipeline(self):
        """report/ must not import from pipeline/."""
        for py_file in _all_python_files_in_stpa_subdir("report"):
            imports = _extract_imports(py_file)
            violations = [
                imp
                for imp in imports
                if "asago_scenario_generator.stpa.pipeline" in imp
            ]
            assert not violations, (
                f"report/{py_file.name} imports from pipeline (forbidden): {violations}"
            )

    def test_infra_does_not_import_pipeline(self):
        """infra/ must not import from pipeline/."""
        for py_file in _all_python_files_in_stpa_subdir("infra"):
            imports = _extract_imports(py_file)
            violations = [
                imp
                for imp in imports
                if "asago_scenario_generator.stpa.pipeline" in imp
            ]
            assert not violations, (
                f"infra/{py_file.name} imports from pipeline (forbidden): {violations}"
            )


class TestIntraPackageDependencyDirection:
    """llm_config.py must not import from runner.py (no reverse coupling)."""

    def test_llm_config_does_not_import_runner(self):
        """llm_config.py has zero imports from runner.py."""
        imports = _extract_imports(LLM_CONFIG_PATH)
        violations = [
            imp
            for imp in imports
            if "asago_scenario_generator.stpa.pipeline.runner" in imp
        ]
        assert not violations, (
            f"llm_config.py must not import from runner.py: {violations}"
        )

    def test_runner_imports_from_llm_config(self):
        """runner.py imports from llm_config.py (correct direction)."""
        imports = _extract_imports(RUNNER_PATH)
        assert any(
            "asago_scenario_generator.stpa.pipeline.llm_config" in imp
            for imp in imports
        ), "runner.py should import from llm_config.py"


# ---------------------------------------------------------------------------
# Architecture guard tests — public API contract
# ---------------------------------------------------------------------------


class TestPipelinePublicApi:
    """pipeline/__init__.py exports exactly the public API."""

    def test_init_has_all_declaration(self):
        """__init__.py declares __all__."""
        mod = importlib.import_module("asago_scenario_generator.stpa.pipeline")
        assert hasattr(mod, "__all__"), "pipeline/__init__.py must declare __all__"

    def test_all_contains_expected_names(self):
        """__all__ contains exactly run_stpa_pipeline and STPARunResult."""
        mod = importlib.import_module("asago_scenario_generator.stpa.pipeline")
        assert set(mod.__all__) == {"run_stpa_pipeline", "STPARunResult"}

    def test_all_names_are_public(self):
        """Every name in __all__ is public (no underscore prefix)."""
        mod = importlib.import_module("asago_scenario_generator.stpa.pipeline")
        private = [n for n in mod.__all__ if n.startswith("_")]
        assert not private, f"__all__ must not contain private names: {private}"

    def test_all_names_exist_as_attributes(self):
        """Every name in __all__ is a real attribute of the module."""
        mod = importlib.import_module("asago_scenario_generator.stpa.pipeline")
        missing = [n for n in mod.__all__ if not hasattr(mod, n)]
        assert not missing, f"__all__ lists names that don't exist: {missing}"

    def test_run_stpa_pipeline_is_callable(self):
        """run_stpa_pipeline is callable."""
        assert callable(run_stpa_pipeline)

    def test_stpa_run_result_is_dataclass(self):
        """STPARunResult is a dataclass."""
        assert is_dataclass(STPARunResult)


# ---------------------------------------------------------------------------
# Architecture guard tests — no import cycles
# ---------------------------------------------------------------------------


class TestNoImportCycles:
    """The pipeline package must import without circular dependency errors."""

    def test_import_package(self):
        """Importing the pipeline package succeeds."""
        mod = importlib.import_module("asago_scenario_generator.stpa.pipeline")
        assert hasattr(mod, "run_stpa_pipeline")

    def test_import_runner(self):
        """Importing runner.py succeeds."""
        mod = importlib.import_module("asago_scenario_generator.stpa.pipeline.runner")
        assert hasattr(mod, "run_stpa_pipeline")

    def test_import_llm_config(self):
        """Importing llm_config.py succeeds."""
        mod = importlib.import_module(
            "asago_scenario_generator.stpa.pipeline.llm_config"
        )
        assert hasattr(mod, "resolve_llm_client")


# ---------------------------------------------------------------------------
# Architecture guard tests — scripts use llm_config (no duplication)
# ---------------------------------------------------------------------------


class TestScriptsUseExtractedLlmConfig:
    """Scripts must import from llm_config, not define their own copies."""

    SCRIPTS_DIR = Path(__file__).resolve().parent.parent.parent / "scripts"

    def test_run_sp1_imports_from_llm_config(self):
        """run_sp1.py imports resolve_llm_client functions from llm_config."""
        imports = _extract_imports(self.SCRIPTS_DIR / "run_sp1.py")
        assert any(
            "asago_scenario_generator.stpa.pipeline.llm_config" in imp
            for imp in imports
        ), "run_sp1.py should import from llm_config"

    def test_run_sp2_imports_from_llm_config(self):
        """run_sp2.py imports resolve_llm_client functions from llm_config."""
        imports = _extract_imports(self.SCRIPTS_DIR / "run_sp2.py")
        assert any(
            "asago_scenario_generator.stpa.pipeline.llm_config" in imp
            for imp in imports
        ), "run_sp2.py should import from llm_config"

    def test_run_sp3_imports_from_llm_config(self):
        """run_sp3.py imports resolve_llm_client functions from llm_config."""
        imports = _extract_imports(self.SCRIPTS_DIR / "run_sp3.py")
        assert any(
            "asago_scenario_generator.stpa.pipeline.llm_config" in imp
            for imp in imports
        ), "run_sp3.py should import from llm_config"

    def test_run_sp1_does_not_define_resolve_llm_client(self):
        """run_sp1.py does not define resolve_llm_client_from_profile locally."""
        source = (self.SCRIPTS_DIR / "run_sp1.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        func_names = {
            node.name
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
        }
        assert "resolve_llm_client_from_profile" not in func_names
        assert "resolve_llm_client_from_env" not in func_names

    def test_run_sp2_does_not_define_resolve_llm_client(self):
        """run_sp2.py does not define resolve_llm_client_from_profile locally."""
        source = (self.SCRIPTS_DIR / "run_sp2.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        func_names = {
            node.name
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
        }
        assert "resolve_llm_client_from_profile" not in func_names
        assert "resolve_llm_client_from_env" not in func_names

    def test_run_sp3_does_not_define_resolve_llm_client(self):
        """run_sp3.py does not define resolve_llm_client_from_profile locally."""
        source = (self.SCRIPTS_DIR / "run_sp3.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        func_names = {
            node.name
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
        }
        assert "resolve_llm_client_from_profile" not in func_names
        assert "resolve_llm_client_from_env" not in func_names


# ---------------------------------------------------------------------------
# Property tests — resume determinism
# ---------------------------------------------------------------------------


class TestResumeDeterminism:
    """Resume skip decisions must be deterministic."""

    def test_maybe_skip_stage_is_deterministic(self):
        """Calling _maybe_skip_stage twice with same args gives same result."""
        for resume, artifacts_exist in [
            (True, True),
            (True, False),
            (False, True),
            (False, False),
        ]:
            result1 = _maybe_skip_stage(resume, artifacts_exist, "SP1")
            result2 = _maybe_skip_stage(resume, artifacts_exist, "SP1")
            assert result1 == result2, (
                f"Non-deterministic for resume={resume}, "
                f"artifacts_exist={artifacts_exist}"
            )

    def test_maybe_skip_stage_only_skips_on_resume_with_artifacts(self):
        """Skip is True only when resume=True AND artifacts exist."""
        assert _maybe_skip_stage(True, True, "SP1") is True
        assert _maybe_skip_stage(True, False, "SP1") is False
        assert _maybe_skip_stage(False, True, "SP1") is False
        assert _maybe_skip_stage(False, False, "SP1") is False

    def test_artifact_existence_is_deterministic(self, tmp_path):
        """Checking artifact existence twice gives the same result."""
        # Empty dir
        assert _sp1_artifacts_exist(tmp_path) is False
        assert _sp1_artifacts_exist(tmp_path) is False

        # Create SP1 artifacts
        for name in SP1_ARTIFACT_NAMES:
            (tmp_path / name).write_text("dummy")
        assert _sp1_artifacts_exist(tmp_path) is True
        assert _sp1_artifacts_exist(tmp_path) is True

        # Remove one — should flip to False
        (tmp_path / SP1_ARTIFACT_NAMES[0]).unlink()
        assert _sp1_artifacts_exist(tmp_path) is False

    def test_sp2_artifact_existence_deterministic(self, tmp_path):
        """SP2 artifact existence is deterministic."""
        assert _sp2_artifacts_exist(tmp_path) is False
        for name in SP2_ARTIFACT_NAMES:
            (tmp_path / name).write_text("dummy")
        assert _sp2_artifacts_exist(tmp_path) is True
        (tmp_path / SP2_ARTIFACT_NAMES[0]).unlink()
        assert _sp2_artifacts_exist(tmp_path) is False

    def test_sp3_artifact_existence_deterministic(self, tmp_path):
        """SP3 artifact existence is deterministic."""
        assert _sp3_artifacts_exist(tmp_path) is False
        scenarios_dir = tmp_path / "scenarios"
        scenarios_dir.mkdir()
        assert _sp3_artifacts_exist(tmp_path) is False
        (scenarios_dir / "scenario-001.yaml").write_text("dummy")
        assert _sp3_artifacts_exist(tmp_path) is True
        (scenarios_dir / "scenario-001.yaml").unlink()
        assert _sp3_artifacts_exist(tmp_path) is False

    def test_resume_all_stages_same_decision(self, tmp_path):
        """When all artifacts exist, resume skips all stages deterministically."""
        # Create all artifacts
        for name in SP1_ARTIFACT_NAMES:
            (tmp_path / name).write_text("dummy")
        for name in SP2_ARTIFACT_NAMES:
            (tmp_path / name).write_text("dummy")
        scenarios_dir = tmp_path / "scenarios"
        scenarios_dir.mkdir()
        (scenarios_dir / "s.yaml").write_text("dummy")

        skip_sp1 = _maybe_skip_stage(
            True,
            _sp1_artifacts_exist(tmp_path),
            "SP1",
        )
        skip_sp2 = _maybe_skip_stage(
            True,
            _sp2_artifacts_exist(tmp_path),
            "SP2",
        )
        skip_sp3 = _maybe_skip_stage(
            True,
            _sp3_artifacts_exist(tmp_path),
            "SP3",
        )

        assert skip_sp1 is True
        assert skip_sp2 is True
        assert skip_sp3 is True

    def test_resume_no_artifacts_skips_nothing(self, tmp_path):
        """When no artifacts exist, resume skips nothing."""
        assert (
            _maybe_skip_stage(
                True,
                _sp1_artifacts_exist(tmp_path),
                "SP1",
            )
            is False
        )
        assert (
            _maybe_skip_stage(
                True,
                _sp2_artifacts_exist(tmp_path),
                "SP2",
            )
            is False
        )
        assert (
            _maybe_skip_stage(
                True,
                _sp3_artifacts_exist(tmp_path),
                "SP3",
            )
            is False
        )


# ---------------------------------------------------------------------------
# Property tests — STPARunResult well-formedness
# ---------------------------------------------------------------------------


class TestSTPARunResultDefaults:
    """STPARunResult must have correct default field values."""

    def test_default_all_none(self):
        """Default STPARunResult has all stage results as None."""
        result = STPARunResult()
        assert result.sp1_result is None
        assert result.sp2_result is None
        assert result.sp3_result is None
        assert result.report_path is None

    def test_default_stage_errors_is_empty_list(self):
        """Default STPARunResult has an empty stage_errors list."""
        result = STPARunResult()
        assert result.stage_errors == []
        assert isinstance(result.stage_errors, list)

    def test_default_stage_errors_not_shared(self):
        """Each STPARunResult instance gets its own stage_errors list."""
        r1 = STPARunResult()
        r2 = STPARunResult()
        r1.stage_errors.append("error1")
        assert r2.stage_errors == [], (
            "stage_errors must not be shared between instances"
        )

    def test_default_stage_warnings_is_independent_empty_list(self):
        """Each result owns an empty recoverable-warning collection."""
        first = STPARunResult()
        second = STPARunResult()
        first.stage_warnings.append("repaired")
        assert second.stage_warnings == []

    def test_has_expected_fields(self):
        """STPARunResult has exactly the expected fields."""
        field_names = {f.name for f in fields(STPARunResult)}
        assert field_names == {
            "sp1_result",
            "sp2_result",
            "sp3_result",
            "report_path",
            "stage_errors",
            "stage_warnings",
        }

    def test_can_set_all_fields(self):
        """STPARunResult accepts all field values."""
        sp1 = MagicMock()
        sp2 = MagicMock()
        sp3 = MagicMock()
        report_path = Path("/tmp/report.html")
        errors = ["err1", "err2"]
        warnings = ["repaired"]
        result = STPARunResult(
            sp1_result=sp1,
            sp2_result=sp2,
            sp3_result=sp3,
            report_path=report_path,
            stage_errors=errors,
            stage_warnings=warnings,
        )
        assert result.sp1_result is sp1
        assert result.sp2_result is sp2
        assert result.sp3_result is sp3
        assert result.report_path == report_path
        assert result.stage_errors == errors
        assert result.stage_warnings == warnings


# ---------------------------------------------------------------------------
# Property tests — error handling preserves stage errors
# ---------------------------------------------------------------------------


class TestErrorHandlingPreservesStageErrors:
    """Stage errors from individual stages must be accumulated in stage_errors."""

    def test_sp1_errors_propagate_to_stage_errors(self, tmp_path):
        """SP1 stage_errors are collected into the pipeline's stage_errors."""
        from asago_scenario_generator.stpa.pipeline.runner import _run_sp1_stage
        from asago_scenario_generator.stpa.system_model.run import SP1RunResult

        fake_result = SP1RunResult(
            loss_analysis=None,
            capability_profile=None,
            control_structure=None,
            heuristic_errors=[],
            heuristic_warnings=[],
            critic_findings=None,
            revised=False,
            stage_errors=["SP1 error A", "SP1 error B"],
            solution_neutrality_warnings=[],
            post_revision_warnings=[],
        )

        stage_errors: list[str] = []
        mock_llm = MagicMock()
        with (
            patch(
                "asago_scenario_generator.stpa.pipeline.runner.resolve_llm_client",
                return_value=(mock_llm, None),
            ),
            patch(
                "asago_scenario_generator.stpa.pipeline.runner.read_use_case",
                return_value="test",
            ),
            patch(
                "asago_scenario_generator.stpa.pipeline.runner.load_risk_extraction",
                return_value=[],
            ),
            patch(
                "asago_scenario_generator.stpa.pipeline.runner.run_sp1",
                return_value=fake_result,
            ),
        ):
            result = _run_sp1_stage(
                skip=False,
                use_case_path="test.txt",
                risk_extraction_path="test.json",
                output_dir=tmp_path,
                profile=None,
                sp1_profile=None,
                profiles_file="config/model-profiles.yaml",
                capability_profile_path=None,
                max_workers=1,
                stage_errors=stage_errors,
            )

        assert result is not None
        assert "SP1 error A" in stage_errors
        assert "SP1 error B" in stage_errors

    def test_sp1_repair_diagnostics_propagate_only_to_stage_warnings(self, tmp_path):
        """A usable SP1 artifact does not become fatal during aggregation."""
        from asago_scenario_generator.stpa.pipeline.runner import _run_sp1_stage
        from asago_scenario_generator.stpa.system_model.run import SP1RunResult

        fake_result = SP1RunResult(
            control_structure=MagicMock(),
            stage_warnings=["SP1 repaired an ElementRef"],
        )
        stage_errors: list[str] = []
        stage_warnings: list[str] = []
        mock_llm = MagicMock()
        with (
            patch(
                "asago_scenario_generator.stpa.pipeline.runner.resolve_llm_client",
                return_value=(mock_llm, None),
            ),
            patch(
                "asago_scenario_generator.stpa.pipeline.runner.read_use_case",
                return_value="test",
            ),
            patch(
                "asago_scenario_generator.stpa.pipeline.runner.load_risk_extraction",
                return_value=[],
            ),
            patch(
                "asago_scenario_generator.stpa.pipeline.runner.run_sp1",
                return_value=fake_result,
            ),
        ):
            _run_sp1_stage(
                skip=False,
                use_case_path="test.txt",
                risk_extraction_path="test.json",
                output_dir=tmp_path,
                profile=None,
                sp1_profile=None,
                profiles_file="config/model-profiles.yaml",
                capability_profile_path=None,
                max_workers=1,
                stage_errors=stage_errors,
                stage_warnings=stage_warnings,
            )

        assert stage_errors == []
        assert stage_warnings == ["SP1 repaired an ElementRef"]

    def test_multiple_stage_errors_accumulate(self, tmp_path):
        """Errors from SP1 and SP2 both appear in stage_errors."""
        from asago_scenario_generator.stpa.pipeline.runner import (
            _run_sp1_stage,
            _run_sp2_stage,
        )
        from asago_scenario_generator.stpa.system_model.run import SP1RunResult
        from asago_scenario_generator.stpa.threat_enum.run import SP2RunResult

        sp1_result = SP1RunResult(
            loss_analysis=None,
            capability_profile=None,
            control_structure=None,
            heuristic_errors=[],
            heuristic_warnings=[],
            critic_findings=None,
            revised=False,
            stage_errors=["SP1 err"],
            solution_neutrality_warnings=[],
            post_revision_warnings=[],
        )
        sp2_result = SP2RunResult(
            ica_enumeration=None,
            enriched_threat_set=None,
            na_quality_result=None,
            stage_errors=["SP2 err"],
        )

        stage_errors: list[str] = []
        mock_llm = MagicMock()
        with (
            patch(
                "asago_scenario_generator.stpa.pipeline.runner.resolve_llm_client",
                return_value=(mock_llm, None),
            ),
            patch(
                "asago_scenario_generator.stpa.pipeline.runner.read_use_case",
                return_value="test",
            ),
            patch(
                "asago_scenario_generator.stpa.pipeline.runner.load_risk_extraction",
                return_value=[],
            ),
            patch(
                "asago_scenario_generator.stpa.pipeline.runner.run_sp1",
                return_value=sp1_result,
            ),
        ):
            _run_sp1_stage(
                skip=False,
                use_case_path="test.txt",
                risk_extraction_path="test.json",
                output_dir=tmp_path,
                profile=None,
                sp1_profile=None,
                profiles_file="config/model-profiles.yaml",
                capability_profile_path=None,
                max_workers=1,
                stage_errors=stage_errors,
            )

        with (
            patch(
                "asago_scenario_generator.stpa.pipeline.runner.resolve_llm_client",
                return_value=(mock_llm, None),
            ),
            patch(
                "asago_scenario_generator.stpa.pipeline.runner.run_sp2",
                return_value=sp2_result,
            ),
        ):
            _run_sp2_stage(
                skip=False,
                output_dir=tmp_path,
                control_structure=MagicMock(),
                capability_profile=MagicMock(),
                loss_analysis=MagicMock(),
                profile=None,
                sp2_profile=None,
                profiles_file="config/model-profiles.yaml",
                max_workers=1,
                stage_errors=stage_errors,
            )

        assert "SP1 err" in stage_errors
        assert "SP2 err" in stage_errors
        assert len(stage_errors) == 2

    def test_skip_does_not_add_errors(self):
        """Skipped stages don't add errors to stage_errors."""
        from asago_scenario_generator.stpa.pipeline.runner import _run_sp1_stage

        stage_errors: list[str] = []
        result = _run_sp1_stage(
            skip=True,
            use_case_path="test.txt",
            risk_extraction_path="test.json",
            output_dir=Path("/tmp"),
            profile=None,
            sp1_profile=None,
            profiles_file="config/model-profiles.yaml",
            capability_profile_path=None,
            max_workers=1,
            stage_errors=stage_errors,
        )
        assert result is None
        assert stage_errors == []

    def test_missing_artifact_aborts_with_error(self):
        """Missing critical artifact adds a stage error and aborts."""
        from asago_scenario_generator.stpa.pipeline.runner import _abort_if_missing

        stage_errors: list[str] = []
        should_abort = _abort_if_missing(
            artifact=None,
            skip=False,
            stage="SP1",
            artifact_name="control-structure.yaml",
            stage_errors=stage_errors,
        )
        assert should_abort is True
        assert len(stage_errors) == 1
        assert "control-structure.yaml" in stage_errors[0]

    def test_missing_artifact_with_skip_does_not_abort(self):
        """Missing artifact with skip=True does not abort (expected on resume)."""
        from asago_scenario_generator.stpa.pipeline.runner import _abort_if_missing

        stage_errors: list[str] = []
        should_abort = _abort_if_missing(
            artifact=None,
            skip=True,
            stage="SP1",
            artifact_name="control-structure.yaml",
            stage_errors=stage_errors,
        )
        assert should_abort is False
        assert stage_errors == []


# ---------------------------------------------------------------------------
# Property tests — summary output well-formedness
# ---------------------------------------------------------------------------


class TestSummaryOutputWellFormedness:
    """The summary output must contain expected section headers."""

    def _capture_summary(
        self,
        sp1_result=None,
        sp2_result=None,
        sp3_result=None,
        stage_errors=None,
        stage_warnings=None,
    ):
        """Run _print_summary and capture stdout."""
        from asago_scenario_generator.stpa.pipeline.runner import _print_summary

        buf = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = buf
        try:
            _print_summary(
                sp1_result=sp1_result,
                sp2_result=sp2_result,
                sp3_result=sp3_result,
                report_path=Path("/tmp/report.html"),
                output_dir=Path("/tmp"),
                stage_errors=stage_errors or [],
                stage_warnings=stage_warnings or [],
            )
        finally:
            sys.stdout = old_stdout
        return buf.getvalue()

    def test_summary_has_header(self):
        """Summary output contains the STPA PIPELINE SUMMARY header."""
        output = self._capture_summary()
        assert "STPA PIPELINE SUMMARY" in output

    def test_summary_has_separator_lines(self):
        """Summary output contains separator lines."""
        output = self._capture_summary()
        assert "=" * 60 in output

    def test_summary_has_sp1_section(self):
        """Summary output contains SP1 section header."""
        output = self._capture_summary()
        assert "SP1: System Model" in output

    def test_summary_has_sp2_section(self):
        """Summary output contains SP2 section header."""
        output = self._capture_summary()
        assert "SP2: Threat Enumeration" in output

    def test_summary_has_sp3_section(self):
        """Summary output contains SP3 section header."""
        output = self._capture_summary()
        assert "SP3: Scenario Production" in output

    def test_summary_has_report_path(self):
        """Summary output contains the report path."""
        output = self._capture_summary()
        assert "/tmp/report.html" in output

    def test_summary_degraded_messages_when_no_results(self):
        """Summary shows DEGRADED messages when all results are None."""
        output = self._capture_summary()
        assert "DEGRADED" in output

    def test_summary_shows_stage_errors(self):
        """Summary output includes stage error count and messages."""
        errors = ["SP1 failed", "SP2 also failed"]
        output = self._capture_summary(stage_errors=errors)
        assert "Stage Errors: 2" in output
        assert "SP1 failed" in output
        assert "SP2 also failed" in output

    def test_summary_no_stage_errors_section_when_empty(self):
        """Summary omits stage errors section when there are no errors."""
        output = self._capture_summary(stage_errors=[])
        assert "Stage Errors:" not in output

    def test_summary_labels_recoverable_warnings_separately(self):
        output = self._capture_summary(
            stage_warnings=["normalized CP-5", "repaired PM update"]
        )
        assert "Stage Warnings: 2" in output
        assert "normalized CP-5" in output
        assert "Stage Errors:" not in output

    def test_summary_with_sp1_result_shows_metrics(self):
        """Summary with an SP1 result shows loss/hazard/constraint counts."""
        from tests.stpa.helpers import (
            make_minimal_control_structure,
            make_minimal_loss_analysis,
        )

        sp1 = MagicMock()
        sp1.loss_analysis = make_minimal_loss_analysis()
        sp1.control_structure = make_minimal_control_structure()
        sp1.critic_findings = None
        sp1.heuristic_errors = []
        sp1.heuristic_warnings = []
        sp1.revised = False
        sp1.stage_errors = []
        sp1.solution_neutrality_warnings = []
        sp1.post_revision_warnings = []

        output = self._capture_summary(sp1_result=sp1)
        assert "Losses:" in output
        assert "Hazards:" in output
        assert "Constraints:" in output
