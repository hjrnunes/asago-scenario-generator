"""Bespoke architecture guards for the STPA-Sec packages.

Import direction, forbidden and allowed imports, layers, and import cycles
live in ``tests/test_import_rules.py`` as tables. The tests here check what a
table row cannot: source ordering, public surfaces, call sites, and where a
class is defined.
"""

from __future__ import annotations

import ast
import importlib
import re
from pathlib import Path

import pytest
from pydantic import BaseModel

from asago_scenario_generator.stpa.infra import llm_helpers
from asago_scenario_generator.stpa.infra.llm_helpers import (
    CorrectionPolicy,
    call_with_policy,
)
from asago_scenario_generator.stpa.scenario_prod.stage5 import prompt_view
from tests.stpa.sp1_helpers import MockLLMClient

STPA_ROOT = (
    Path(__file__).resolve().parent.parent.parent
    / "src"
    / "asago_scenario_generator"
    / "stpa"
)
SYSTEM_MODEL_DIR = STPA_ROOT / "system_model"
SCENARIO_PROD_DIR = STPA_ROOT / "scenario_prod"
STAGE5_DIR = SCENARIO_PROD_DIR / "stage5"
THREAT_ENUM_DIR = STPA_ROOT / "threat_enum"


class TestSystemModelNormalizerSurface:
    """The ID normalizer is a leaf with a narrow public surface.

    Which modules may import it is a row in ``tests/test_import_rules.py``.
    """

    @pytest.fixture
    def system_model_files(self) -> dict[str, Path]:
        files: dict[str, Path] = {}
        for path in sorted(SYSTEM_MODEL_DIR.glob("*.py")):
            if path.name == "__init__.py":
                continue
            files[path.stem] = path
        return files

    def test_repair_passes_keep_required_order(self, system_model_files):
        """Wrap, then type inference, then rewrite; empty descriptions follow IDs.

        Bare-string wrapping must run first so type inference can stamp the
        newly created object.  Type inference must run before rewrite so the
        typed namespace can be selected.
        """
        source = system_model_files["id_normalization"].read_text(encoding="utf-8")
        wrap_at = source.index("_wrap_bare_string_refs(normalized)")
        # Use the final occurrence so the assertion targets the pipeline
        # invocation rather than the helper definition.  The namespace maps
        # argument is intentionally explicit in the production call.
        type_at = source.rindex("_repair_element_ref_types(")
        rewrite_at = source.index("_rewrite_references_before_id_replacement(")
        ids_at = source.index("_set_canonical_ids(normalized)")
        desc_at = source.index("_repair_empty_descriptions(normalized)")
        assert wrap_at < type_at < rewrite_at < ids_at < desc_at

    def test_acceptance_uses_public_normalizer_surface(self):
        """SP1 acceptance handlers may call the public ID policy only."""
        path = (
            Path(__file__).resolve().parent.parent.parent
            / "acceptance"
            / "runtime_features"
            / "sp1.py"
        )
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        private_names = {
            "_unique_source_map",
            "_flat_unique_source_map",
            "_source_id_entries",
            "_rewrite_typed_reference",
            "_rewrite_coordination_references",
        }
        imported: set[str] = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.ImportFrom):
                continue
            if (
                node.module
                != "asago_scenario_generator.stpa.system_model.id_normalization"
            ):
                continue
            imported.update(alias.name for alias in node.names)
        leaked = sorted(imported & private_names)
        assert not leaked, (
            "acceptance/runtime_features/sp1.py imported private "
            f"id_normalization names: {leaked}"
        )
        assert "_unique_source_map" not in source
        assert "_flat_unique_source_map" not in source

    def test_acceptance_imports_normalizer_from_leaf(self):
        """Acceptance must import the normalizer from the leaf, not a facade."""
        acceptance_root = Path(__file__).resolve().parent.parent.parent / "acceptance"
        facade_modules = {
            "asago_scenario_generator.stpa.system_model",
            "asago_scenario_generator.stpa.system_model.control_structure",
        }
        leaf = "asago_scenario_generator.stpa.system_model.id_normalization"
        name = "normalize_control_structure_payload"
        facade_hits: list[str] = []
        leaf_hits = 0
        for path in sorted(acceptance_root.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if not isinstance(node, ast.ImportFrom) or not node.module:
                    continue
                imported = {alias.name for alias in node.names}
                if name not in imported:
                    continue
                rel = path.relative_to(acceptance_root)
                if node.module in facade_modules:
                    facade_hits.append(f"{rel}: {node.module}")
                if node.module == leaf:
                    leaf_hits += 1
        assert not facade_hits, (
            "acceptance imported the normalizer via a package facade:\n"
            + "\n".join(facade_hits)
        )
        assert leaf_hits > 0, (
            "acceptance no longer imports the normalizer from the leaf"
        )

    def test_package_does_not_reexport_normalizer(self):
        """The system_model package must not re-export the payload normalizer."""
        init_path = SYSTEM_MODEL_DIR / "__init__.py"
        tree = ast.parse(init_path.read_text(encoding="utf-8"), filename=str(init_path))
        exported: list[str] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.ImportFrom):
                continue
            if not node.module or "id_normalization" not in node.module:
                continue
            exported.extend(alias.name for alias in node.names)
        assert "normalize_control_structure_payload" not in exported
        package = importlib.import_module("asago_scenario_generator.stpa.system_model")
        assert "normalize_control_structure_payload" not in package.__all__
        assert not hasattr(package, "normalize_control_structure_payload")

    def test_control_structure_uses_leaf_normalizer(self, system_model_files):
        """Stage 2 may use the leaf internally; it must not become a facade."""
        path = system_model_files["control_structure"]
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        public_names: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == "__all__":
                        if isinstance(node.value, ast.List | ast.Tuple):
                            public_names.update(
                                elt.value
                                for elt in node.value.elts
                                if isinstance(elt, ast.Constant)
                                and isinstance(elt.value, str)
                            )
        assert "normalize_control_structure_payload" not in public_names

    def test_critic_stitches_then_delegates_published_ids(self, system_model_files):
        """Revision merge stitches by source ID, then applies leaf ID policy.

        Published IDs are not assigned by the IO-near revision merge.
        The critic may keep stitch-time collision bookkeeping, but the
        complete stitched payload must go through
        ``validate_normalized_control_structure``.
        """
        source = system_model_files["critic"].read_text(encoding="utf-8")
        assert "def _stitch_revision_delta" in source
        assert "validate_normalized_control_structure" in source
        assert (
            "ControlStructure.model_validate(normalized_payload.payload)" not in source
        )


class TestSafeLlmCallExceptionSafety:
    """``call_with_policy`` must catch ``Exception`` but NOT ``BaseException``
    subclasses like ``KeyboardInterrupt`` or ``SystemExit``.

    Catching ``BaseException`` would prevent the user from interrupting
    a long-running pipeline and would swallow process-exit signals.
    """

    def test_keyboard_interrupt_not_caught(self, tmp_path):
        """KeyboardInterrupt propagates through call_with_policy."""

        class _Dummy(BaseModel):
            x: int = 1

        client = MockLLMClient()
        client.set_exception_for(_Dummy, KeyboardInterrupt("Ctrl-C"))

        with pytest.raises(KeyboardInterrupt):
            call_with_policy(
                llm_client=client,
                system_prompt="s",
                user_prompt="u",
                response_format=_Dummy,
                run_dir=tmp_path,
                stage="test",
                step="test",
                policy=CorrectionPolicy(),
            )

    def test_system_exit_not_caught(self, tmp_path):
        """SystemExit propagates through call_with_policy."""

        class _Dummy(BaseModel):
            x: int = 1

        client = MockLLMClient()
        client.set_exception_for(_Dummy, SystemExit(1))

        with pytest.raises(SystemExit):
            call_with_policy(
                llm_client=client,
                system_prompt="s",
                user_prompt="u",
                response_format=_Dummy,
                run_dir=tmp_path,
                stage="test",
                step="test",
                policy=CorrectionPolicy(),
            )

    def test_runtime_exception_caught_and_logged(self, tmp_path):
        """RuntimeError is caught by call_with_policy (not propagated)."""

        class _Dummy(BaseModel):
            x: int = 1

        client = MockLLMClient()
        client.set_exception_for(_Dummy, RuntimeError("API down"))

        outcome = call_with_policy(
            llm_client=client,
            system_prompt="s",
            user_prompt="u",
            response_format=_Dummy,
            run_dir=tmp_path,
            stage="test",
            step="test",
            policy=CorrectionPolicy(),
        )
        model, error = outcome.value, outcome.error
        assert model is None
        assert error is not None
        assert "RuntimeError" in error


class TestCallWithPolicyCanonicalEntryPoint:
    """``call_with_policy`` must be the sole caller of ``llm_client.complete()``
    in the STPA pipeline.  No stage function should call ``complete()``
    directly, bypassing error handling and call logging."""

    def test_no_direct_complete_calls_in_system_model(self):
        """No system_model module calls llm_client.complete() directly."""
        violations: list[str] = []
        for path in sorted(SYSTEM_MODEL_DIR.glob("*.py")):
            if path.name == "__init__.py":
                continue
            source = path.read_text(encoding="utf-8")
            if ".complete(" in source:
                # Exclude the client call itself (which is in infra, not here)
                violations.append(
                    f"{path.name}: calls .complete() directly — "
                    f"must use call_with_policy() instead"
                )
        assert not violations, (
            "Direct .complete() calls in system_model/:\n" + "\n".join(violations)
        )

    def test_complete_only_called_from_the_client_call(self):
        """llm_client.complete() is called only from the shared client call in infra."""
        violations: list[str] = []
        for path in sorted(STPA_ROOT.rglob("*.py")):
            if path.name == "__init__.py":
                continue
            source = path.read_text(encoding="utf-8")
            # Find all .complete( calls
            for match in re.finditer(r"\.complete\(", source):
                # Check if it is inside the shared client-call function
                # Get the function context by looking backwards for 'def '
                pos = match.start()
                # Find the enclosing function definition
                lines_before = source[:pos].split("\n")
                enclosing_func = None
                for line in reversed(lines_before):
                    stripped = line.lstrip()
                    if stripped.startswith("def "):
                        enclosing_func = stripped
                        break
                if enclosing_func and "_call_client" not in enclosing_func:
                    violations.append(
                        f"{path.name}: .complete() called outside the shared client call "
                        f"(in '{enclosing_func.strip()}')"
                    )
        assert not violations, (
            ".complete() called outside the shared client call:\n"
            + "\n".join(violations)
        )


class TestProviderClientsAreBuiltThroughTheSessionAwareResolver:
    """A client built outside ``llm_config`` has no call session, so its calls
    would be missing from the run's in-memory call evidence."""

    @staticmethod
    def _llm_client_calls(tree: ast.AST) -> list[ast.Call]:
        return [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "LLMClient"
        ]

    def test_llm_client_is_constructed_only_by_the_resolver(self):
        package = STPA_ROOT.parent
        constructing = {
            path.relative_to(package).as_posix()
            for path in sorted(package.rglob("*.py"))
            if self._llm_client_calls(ast.parse(path.read_text(encoding="utf-8")))
        }

        assert constructing == {"stpa/pipeline/llm_config.py"}

    def test_every_resolver_construction_passes_the_session(self):
        tree = ast.parse(
            (STPA_ROOT / "pipeline" / "llm_config.py").read_text(encoding="utf-8")
        )
        calls = self._llm_client_calls(tree)

        assert len(calls) == 2
        for call in calls:
            assert "session" in {keyword.arg for keyword in call.keywords}


class TestStageErrorLocation:
    """``StageError`` must be defined in the infra layer, not in system_model.

    This ensures downstream SPs (SP2, SP3) can import ``StageError`` from
    the shared infra layer without depending on SP1's system_model.
    """

    def test_stage_error_defined_in_infra(self):
        """StageError is defined in infra/llm_helpers.py."""
        assert hasattr(llm_helpers, "StageError")
        assert (
            llm_helpers.StageError.__module__
            == "asago_scenario_generator.stpa.infra.llm_helpers"
        )

    def test_stage_error_not_defined_in_system_model(self):
        """No system_model module defines its own StageError class."""
        for path in sorted(SYSTEM_MODEL_DIR.glob("*.py")):
            if path.name == "__init__.py":
                continue
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef) and node.name == "StageError":
                    pytest.fail(
                        f"{path.name}: defines StageError — "
                        f"must use the infra layer's StageError"
                    )

    def test_stage_error_importable_without_system_model(self):
        """StageError can be imported without importing system_model."""
        import importlib

        mod = importlib.import_module("asago_scenario_generator.stpa.infra.llm_helpers")
        assert hasattr(mod, "StageError")


def _stage5_files() -> list[Path]:
    return sorted(p for p in STAGE5_DIR.glob("*.py") if p.name != "__init__.py")


def _stage5_outer_imports(file_path: Path) -> list[tuple[str, list[str]]]:
    """Return (module, imported names) for imports of scenario_prod modules
    outside the stage5 package."""
    tree = ast.parse(file_path.read_text(encoding="utf-8"), filename=str(file_path))
    prefix = "asago_scenario_generator.stpa.scenario_prod."
    result: list[tuple[str, list[str]]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            names = [alias.name for alias in node.names]
            if node.level == 2 and node.module:
                result.append((node.module.split(".")[0], names))
            elif node.level == 2:
                result.extend((name, []) for name in names)
            elif node.level == 0 and (node.module or "").startswith(prefix):
                module = node.module[len(prefix) :].split(".")[0]
                if module != "stage5":
                    result.append((module, names))
    return result


def _has_local_imports(file_path: Path) -> list[str]:
    """Return descriptions of import statements inside function bodies."""
    source = file_path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(file_path))
    violations: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for child in ast.walk(node):
                if isinstance(child, ast.Import):
                    for alias in child.names:
                        violations.append(
                            f"{file_path.name}:{node.name}: local import '{alias.name}'"
                        )
                elif isinstance(child, ast.ImportFrom):
                    mod = child.module or ""
                    violations.append(
                        f"{file_path.name}:{node.name}: local from-import '{mod}'"
                    )
    return violations


def _private_imports_across_modules(file_path: Path) -> list[str]:
    """Return names starting with '_' imported from scenario_prod siblings."""
    source = file_path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(file_path))
    violations: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            # Check relative imports from scenario_prod siblings
            is_sp3_sibling = node.level == 1 or (
                node.module
                and node.module.startswith(
                    "asago_scenario_generator.stpa.scenario_prod"
                )
            )
            if not is_sp3_sibling:
                continue
            for alias in node.names:
                if alias.name.startswith("_") and alias.name != "_":
                    violations.append(
                        f"{file_path.name}: imports private name "
                        f"'{alias.name}' from sibling module"
                    )
    return violations


class TestScenarioProdNoPrivateCrossModuleImports:
    """No scenario_prod module should import private (_-prefixed) names
    from a sibling module within scenario_prod."""

    @pytest.fixture
    def scenario_prod_python_files(self) -> list[Path]:
        return sorted(
            p for p in SCENARIO_PROD_DIR.glob("*.py") if p.name != "__init__.py"
        )

    def test_no_private_imports(self, scenario_prod_python_files):
        """No file in scenario_prod/ imports private names from siblings."""
        violations: list[str] = []
        for path in scenario_prod_python_files:
            violations.extend(_private_imports_across_modules(path))
        assert not violations, (
            "Private cross-module imports in scenario_prod/:\n" + "\n".join(violations)
        )

    def test_stage5_imports_no_private_names_from_outside(self):
        """stage5 modules share private names only inside their package."""
        violations = [
            f"stage5/{path.name} imports {name} from {module}"
            for path in _stage5_files()
            for module, names in _stage5_outer_imports(path)
            for name in names
            if name.startswith("_") and name != "_"
        ]
        assert not violations, "\n".join(violations)


class TestScenarioProdNoLocalImports:
    """No scenario_prod module should have import statements inside
    function bodies. Local imports suggest circular dependencies or
    lazy-loading workarounds that should be resolved structurally."""

    @pytest.fixture
    def scenario_prod_python_files(self) -> list[Path]:
        return (
            sorted(p for p in SCENARIO_PROD_DIR.glob("*.py") if p.name != "__init__.py")
            + _stage5_files()
        )

    def test_no_function_body_imports(self, scenario_prod_python_files):
        """No import statements inside function bodies."""
        violations: list[str] = []
        for path in scenario_prod_python_files:
            violations.extend(_has_local_imports(path))
        assert not violations, (
            "Local imports inside function bodies in scenario_prod/:\n"
            + "\n".join(violations)
        )


class TestScenarioProdNoDirectCompleteCalls:
    """No scenario_prod module should call llm_client.complete() directly.
    All LLM calls must go through call_with_policy."""

    def test_no_direct_complete_calls(self):
        """No scenario_prod module calls .complete() directly."""
        violations: list[str] = []
        for path in sorted(SCENARIO_PROD_DIR.glob("*.py")) + _stage5_files():
            if path.name == "__init__.py":
                continue
            source = path.read_text(encoding="utf-8")
            if ".complete(" in source:
                violations.append(
                    f"{path.name}: calls .complete() directly — "
                    "must use call_with_policy()"
                )
        assert not violations, (
            "Direct .complete() calls in scenario_prod/:\n" + "\n".join(violations)
        )


class TestEnrichmentModuleBoundary:
    """Enrichment module must be a pure, leaf-level computation module.

    ``enrichment.py`` computes deterministic enrichment blocks from
    models and capability-profile data.  It must not depend on the
    orchestrator (``run.py``) or any other scenario_prod module —
    only on the model layer and the capability profile.
    """

    def test_enrichment_exports_compute_functions(self):
        """enrichment.py must export compute_system_context and compute_consumer_hints."""
        mod = importlib.import_module(
            "asago_scenario_generator.stpa.scenario_prod.enrichment"
        )
        assert hasattr(mod, "compute_system_context")
        assert hasattr(mod, "compute_consumer_hints")
        assert callable(mod.compute_system_context)
        assert callable(mod.compute_consumer_hints)
        assert "compute_system_context" in mod.__all__
        assert "compute_consumer_hints" in mod.__all__


class TestPromptIncludeBoundary:
    """SP3 prompt templates include only files from their own package."""

    def test_no_cross_package_prompt_includes(self):
        """SP3 templates must not include files from another package."""
        include_re = re.compile(r"{%\s*include\s+['\"]([^'\"]+)['\"]")
        roots = (
            THREAT_ENUM_DIR / "prompts",
            SCENARIO_PROD_DIR / "prompts",
        )
        violations: list[str] = []
        for root in roots:
            for path in sorted(root.glob("*.j2")):
                for match in include_re.finditer(path.read_text(encoding="utf-8")):
                    target = match.group(1)
                    if "/" in target or ".." in target:
                        violations.append(f"{path.name} includes {target!r}")
        assert not violations, (
            "Cross-package prompt includes would couple TemplateLoader roots:\n"
            + "\n".join(violations)
        )


class TestContextPropagationBoundary:
    """Technology context flows inward through public prompt builders."""

    def test_bdi_prompts_is_public(self):
        """Stage 5 prompt assembly is a public seam, not a private helper."""
        assert hasattr(prompt_view, "build_context_bdi_prompts")
        assert not hasattr(prompt_view, "_build_context_bdi_prompts")

    def test_stage5_has_no_facade_module(self):
        """Callers import the stage5 modules; no re-export module fronts them."""
        assert not (SCENARIO_PROD_DIR / "bdi_generation.py").exists()

    def test_stage5_has_no_execution_design_path(self):
        """Stage 5 renders and generates one shape; no mode flag selects another."""
        import inspect

        from asago_scenario_generator.stpa.scenario_prod.stage5 import generate

        for function in (
            generate.generate_bdi_for_context,
            prompt_view.build_context_bdi_prompts,
        ):
            parameters = inspect.signature(function).parameters
            assert "execution_design" not in parameters, function.__name__
            assert "requested_environment_basis" not in parameters, function.__name__
        assert not (SCENARIO_PROD_DIR / "stage5" / "route.py").exists()
