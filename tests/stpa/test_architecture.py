"""Architecture guard tests for the STPA-Sec foundation.

These tests enforce structural invariants that are easy to regress:

1. **Clean-copy enforcement**: ``stpa/infra/`` must not import from the
   existing pipeline modules.  The clean-copy decision is a deliberate
   architectural boundary — accidental imports would re-couple the new
   pipeline to the 85K-line manifest system and hardcoded template loader.

2. **No import cycles**: All stpa modules must import without circular
   dependency errors.

3. **Model dependency direction**: Higher-level models (scenario_spec,
   scenario_envelope) may import from lower-level models (loss_analysis,
   control_structure, enriched_threat_set, ica_enumeration), but not the
   reverse.  ``_validation`` is the lowest-level shared helper and may be
   imported by any model, but must not import any model.
"""

from __future__ import annotations

import ast
import importlib
from pathlib import Path

import pytest

STPA_ROOT = Path(__file__).resolve().parent.parent.parent / "src" / "asago_scenario_generator" / "stpa"
INFRA_DIR = STPA_ROOT / "infra"
MODELS_DIR = STPA_ROOT / "models"
SYSTEM_MODEL_DIR = STPA_ROOT / "system_model"

# Modules that stpa/infra/ must NOT import from.
_FORBIDDEN_INFRA_PREFIXES = (
    "asago_scenario_generator.pipeline",
    "asago_scenario_generator.llm",
    "asago_scenario_generator.prompts",
    "asago_scenario_generator.data",
    "asago_scenario_generator.models.capability_profile",
    "asago_scenario_generator.models.risk_card",
    "asago_scenario_generator.models.stage",
    "asago_scenario_generator.report",
    "asago_scenario_generator.cli",
    "asago_scenario_generator.config",
    "asago_scenario_generator.io",
)

# Dependency layers (lower number = lower level).
# A module may only import from same-or-lower layers.
_MODEL_LAYERS: dict[str, int] = {
    "_validation": 0,
    "loss_analysis": 1,
    "control_structure": 1,
    "enriched_threat_set": 1,
    "ica_enumeration": 2,
    "scenario_spec": 3,
    "scenario_envelope": 4,
}


def _extract_imports(file_path: Path) -> list[str]:
    """Return fully-qualified module names imported in *file_path*.

    Handles both ``import X.Y`` and ``from X.Y import ...`` forms,
    including ``TYPE_CHECKING`` guarded imports.
    """
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


def _stpa_model_imports(file_path: Path) -> list[str]:
    """Return stpa model module names imported by *file_path*.

    Returns bare module names (e.g. ``"loss_analysis"``) for any import
    starting with ``asago_scenario_generator.stpa.models``.
    """
    result: list[str] = []
    for imp in _extract_imports(file_path):
        if imp.startswith("asago_scenario_generator.stpa.models."):
            result.append(imp.rsplit(".", 1)[-1])
        elif imp == "asago_scenario_generator.stpa.models":
            result.append(imp)
    return result


# ---------------------------------------------------------------------------
# Clean-copy enforcement
# ---------------------------------------------------------------------------


class TestCleanCopyEnforcement:
    """stpa/infra/ must have zero coupling to the existing pipeline."""

    @pytest.fixture
    def infra_python_files(self) -> list[Path]:
        return sorted(INFRA_DIR.glob("*.py"))

    def test_no_forbidden_imports_in_infra(self, infra_python_files):
        """No file in stpa/infra/ imports from the existing pipeline."""
        violations: list[str] = []
        for path in infra_python_files:
            for imp in _extract_imports(path):
                for forbidden in _FORBIDDEN_INFRA_PREFIXES:
                    if imp == forbidden or imp.startswith(forbidden + "."):
                        violations.append(
                            f"{path.name}: imports '{imp}' — "
                            f"forbidden by clean-copy policy"
                        )
        assert not violations, (
            "Clean-copy violation in stpa/infra/:\n" + "\n".join(violations)
        )

    def test_infra_only_imports_stpa_or_external(self, infra_python_files):
        """infra modules may only import from stpa, stdlib, or third-party."""
        allowed_prefixes = (
            "asago_scenario_generator.stpa",
            "openai",
            "pydantic",
            "yaml",
            "jinja2",
            "hashlib",
            "json",
            "os",
            "time",
            "datetime",
            "pathlib",
            "typing",
            "functools",
            "enum",
            "dataclasses",
            "abc",
            "collections",
            "io",
            "re",
            "copy",
            "math",
            "itertools",
            "contextlib",
            "argparse",
            "threading",
            "concurrent",
        )
        violations: list[str] = []
        for path in infra_python_files:
            for imp in _extract_imports(path):
                if imp.startswith("_") or imp.startswith("."):
                    continue  # relative or private
                if any(imp.startswith(p) or imp == p for p in allowed_prefixes):
                    continue
                violations.append(f"{path.name}: unexpected import '{imp}'")
        assert not violations, (
            "Unexpected imports in stpa/infra/:\n" + "\n".join(violations)
        )


# ---------------------------------------------------------------------------
# Import cycle detection
# ---------------------------------------------------------------------------


class TestNoImportCycles:
    """All stpa modules must import without circular dependency errors."""

    @pytest.mark.parametrize(
        "module_name",
        [
            "asago_scenario_generator.stpa",
            "asago_scenario_generator.stpa.infra",
            "asago_scenario_generator.stpa.infra.llm",
            "asago_scenario_generator.stpa.infra.llm_helpers",
            "asago_scenario_generator.stpa.infra.unvalidated_decode",
            "asago_scenario_generator.stpa.infra.call_log",
            "asago_scenario_generator.stpa.infra.calls_html",
            "asago_scenario_generator.stpa.infra.model_profiles",
            "asago_scenario_generator.stpa.infra.yaml_io",
            "asago_scenario_generator.stpa.infra.templates",
            "asago_scenario_generator.stpa.infra.manifest",
            "asago_scenario_generator.stpa.infra.parallel_llm",
            "asago_scenario_generator.stpa.models",
            "asago_scenario_generator.stpa.models._validation",
            "asago_scenario_generator.stpa.models.loss_analysis",
            "asago_scenario_generator.stpa.models.control_structure",
            "asago_scenario_generator.stpa.models.ica_enumeration",
            "asago_scenario_generator.stpa.models.enriched_threat_set",
            "asago_scenario_generator.stpa.models.scenario_spec",
            "asago_scenario_generator.stpa.models.scenario_envelope",
        ],
    )
    def test_module_imports_cleanly(self, module_name):
        """Module can be imported without errors."""
        mod = importlib.import_module(module_name)
        assert mod is not None


# ---------------------------------------------------------------------------
# Model dependency direction
# ---------------------------------------------------------------------------


class TestModelDependencyDirection:
    """Higher-level models must not import lower-level models in reverse."""

    @pytest.fixture
    def model_files(self) -> dict[str, Path]:
        files: dict[str, Path] = {}
        for path in sorted(MODELS_DIR.glob("*.py")):
            if path.name == "__init__.py":
                continue
            name = path.stem  # e.g. "loss_analysis"
            files[name] = path
        return files

    def test_no_reverse_dependencies(self, model_files):
        """A model at layer N must not import from a model at layer > N."""
        violations: list[str] = []
        for name, path in model_files.items():
            my_layer = _MODEL_LAYERS.get(name, 99)
            for imported in _stpa_model_imports(path):
                if imported == "asago_scenario_generator.stpa.models":
                    continue  # package import, not a model
                target_layer = _MODEL_LAYERS.get(imported, 99)
                if target_layer > my_layer:
                    violations.append(
                        f"{name} (layer {my_layer}) imports "
                        f"{imported} (layer {target_layer}) — "
                        f"dependency direction violation"
                    )
        assert not violations, (
            "Model dependency direction violations:\n" + "\n".join(violations)
        )

    def test_validation_module_imports_no_models(self, model_files):
        """_validation.py must not import any boundary schema model."""
        path = model_files.get("_validation")
        assert path is not None, "_validation.py not found"
        model_imports = _stpa_model_imports(path)
        assert not model_imports, (
            f"_validation.py imports models: {model_imports}"
        )

    def test_loss_analysis_does_not_import_higher_models(self, model_files):
        """loss_analysis.py must not import control_structure or higher."""
        path = model_files["loss_analysis"]
        imports = _stpa_model_imports(path)
        forbidden = {"control_structure", "ica_enumeration", "enriched_threat_set",
                     "scenario_spec", "scenario_envelope"}
        found = forbidden & set(imports)
        assert not found, f"loss_analysis.py imports higher-level models: {found}"

    def test_control_structure_does_not_import_higher_models(self, model_files):
        """control_structure.py must not import ica_enumeration or higher."""
        path = model_files["control_structure"]
        imports = _stpa_model_imports(path)
        forbidden = {"ica_enumeration", "enriched_threat_set",
                     "scenario_spec", "scenario_envelope"}
        found = forbidden & set(imports)
        assert not found, f"control_structure.py imports higher-level models: {found}"

    def test_enriched_threat_set_imports_no_stpa_models(self, model_files):
        """enriched_threat_set.py is a pure data model — no stpa imports."""
        path = model_files["enriched_threat_set"]
        imports = _stpa_model_imports(path)
        assert not imports, f"enriched_threat_set.py imports stpa models: {imports}"


class TestModelsDoNotImportHigherLayers:
    """Boundary schema models must not import from scenario_prod, report,
    or any other higher-level stpa module.

    Models are the lowest-level architectural layer in stpa/; they must
    remain free of dependencies on the pipeline that consumes them.
    """

    @pytest.fixture
    def model_python_files(self) -> list[Path]:
        return sorted(
            p for p in MODELS_DIR.glob("*.py")
            if p.name != "__init__.py"
        )

    def test_no_scenario_prod_imports(self, model_python_files):
        """No model file imports from asago_scenario_generator.stpa.scenario_prod."""
        violations: list[str] = []
        for path in model_python_files:
            for imp in _extract_imports(path):
                if imp.startswith("asago_scenario_generator.stpa.scenario_prod"):
                    violations.append(
                        f"{path.name}: imports '{imp}' — "
                        f"models must not depend on scenario_prod"
                    )
        assert not violations, (
            "Model → scenario_prod dependency violations:\n" + "\n".join(violations)
        )

    def test_no_report_imports(self, model_python_files):
        """No model file imports from asago_scenario_generator.stpa.report."""
        violations: list[str] = []
        for path in model_python_files:
            for imp in _extract_imports(path):
                if imp.startswith("asago_scenario_generator.stpa.report"):
                    violations.append(
                        f"{path.name}: imports '{imp}' — "
                        f"models must not depend on report"
                    )
        assert not violations, (
            "Model → report dependency violations:\n" + "\n".join(violations)
        )

    def test_no_system_model_imports(self, model_python_files):
        """No model file imports from asago_scenario_generator.stpa.system_model."""
        violations: list[str] = []
        for path in model_python_files:
            for imp in _extract_imports(path):
                if imp.startswith("asago_scenario_generator.stpa.system_model"):
                    violations.append(
                        f"{path.name}: imports '{imp}' — "
                        f"models must not depend on system_model"
                    )
        assert not violations, (
            "Model → system_model dependency violations:\n" + "\n".join(violations)
        )


# ---------------------------------------------------------------------------
# System Model architecture guards
# ---------------------------------------------------------------------------

# Dependency layers within system_model (lower = closer to IO/constants).
# A module at layer N may import from modules at layer <= N.
_SYSTEM_MODEL_LAYERS: dict[str, int] = {
    "_constants": 0,
    "id_normalization": 0,
    "heuristics": 1,
    "loss_analysis": 1,
    "profile": 1,
    "control_structure": 1,
    "critic": 2,
    "run": 3,
}

# Existing-pipeline modules that system_model is allowed to import.
# These are the I/O contract types (CapabilityProfile, RiskCard) that
# cross the STPA/existing-pipeline boundary by design.
_ACCEPTED_PIPELINE_IMPORTS: frozenset[str] = frozenset(
    {
        "asago_scenario_generator.models.capability_profile",
        "asago_scenario_generator.models.risk_card",
    }
)

# Modules that system_model must NOT import from (existing pipeline).
_FORBIDDEN_SYSTEM_MODEL_PREFIXES = (
    "asago_scenario_generator.pipeline",
    "asago_scenario_generator.llm",
    "asago_scenario_generator.prompts",
    "asago_scenario_generator.data",
    "asago_scenario_generator.models.stage",
    "asago_scenario_generator.report",
    "asago_scenario_generator.cli",
    "asago_scenario_generator.config",
    "asago_scenario_generator.io",
)


def _system_model_internal_imports(file_path: Path) -> list[str]:
    """Return bare module names imported from within system_model.

    E.g. ``from asago_scenario_generator.stpa.system_model.heuristics import X``
    yields ``"heuristics"``.
    """
    result: list[str] = []
    for imp in _extract_imports(file_path):
        prefix = "asago_scenario_generator.stpa.system_model."
        if imp.startswith(prefix):
            result.append(imp[len(prefix):].split(".")[0])
    return result


class TestSystemModelCleanCopy:
    """system_model/ must have no coupling to the existing pipeline
    beyond the accepted I/O contract types."""

    @pytest.fixture
    def system_model_python_files(self) -> list[Path]:
        return sorted(
            p for p in SYSTEM_MODEL_DIR.glob("*.py")
            if p.name != "__init__.py"
        )

    def test_no_forbidden_imports_in_system_model(self, system_model_python_files):
        """No system_model file imports from forbidden existing-pipeline modules."""
        violations: list[str] = []
        for path in system_model_python_files:
            for imp in _extract_imports(path):
                for forbidden in _FORBIDDEN_SYSTEM_MODEL_PREFIXES:
                    if imp == forbidden or imp.startswith(forbidden + "."):
                        violations.append(
                            f"{path.name}: imports '{imp}' — "
                            f"forbidden by clean-copy policy"
                        )
        assert not violations, (
            "Clean-copy violation in system_model/:\n" + "\n".join(violations)
        )

    def test_pipeline_imports_limited_to_accepted_types(
        self, system_model_python_files
    ):
        """Any import from asago_scenario_generator.models must be an accepted contract type."""
        violations: list[str] = []
        for path in system_model_python_files:
            for imp in _extract_imports(path):
                if imp.startswith("asago_scenario_generator.models.") or imp == "asago_scenario_generator.models":
                    if imp not in _ACCEPTED_PIPELINE_IMPORTS:
                        violations.append(
                            f"{path.name}: imports '{imp}' — "
                            f"not an accepted I/O contract type"
                        )
        assert not violations, (
            "Unexpected pipeline model imports in system_model/:\n"
            + "\n".join(violations)
        )


class TestSystemModelNoImportCycles:
    """All system_model modules must import without circular dependency errors."""

    @pytest.mark.parametrize(
        "module_name",
        [
            "asago_scenario_generator.stpa.system_model",
            "asago_scenario_generator.stpa.system_model._constants",
            "asago_scenario_generator.stpa.system_model.id_normalization",
            "asago_scenario_generator.stpa.system_model.loss_analysis",
            "asago_scenario_generator.stpa.system_model.profile",
            "asago_scenario_generator.stpa.system_model.control_structure",
            "asago_scenario_generator.stpa.system_model.critic",
            "asago_scenario_generator.stpa.system_model.heuristics",
            "asago_scenario_generator.stpa.system_model.run",
        ],
    )
    def test_module_imports_cleanly(self, module_name):
        """Module can be imported without errors."""
        mod = importlib.import_module(module_name)
        assert mod is not None


class TestSystemModelDependencyDirection:
    """Higher-level system_model modules must not import lower-level ones in reverse.

    Dependency layers (lower = leaf / fewer inbound dependencies):
      0: _constants, id_normalization  (leaves — no sibling imports)
      1: heuristics, loss_analysis, profile, control_structure  (stages)
      2: critic         (uses heuristics)
      3: run            (orchestrator — uses all)
    """

    @pytest.fixture
    def system_model_files(self) -> dict[str, Path]:
        files: dict[str, Path] = {}
        for path in sorted(SYSTEM_MODEL_DIR.glob("*.py")):
            if path.name == "__init__.py":
                continue
            files[path.stem] = path
        return files

    def test_no_reverse_dependencies(self, system_model_files):
        """A module at layer N must not import from a module at layer > N."""
        violations: list[str] = []
        for name, path in system_model_files.items():
            my_layer = _SYSTEM_MODEL_LAYERS.get(name, 99)
            for imported in _system_model_internal_imports(path):
                target_layer = _SYSTEM_MODEL_LAYERS.get(imported, 99)
                if target_layer > my_layer:
                    violations.append(
                        f"{name} (layer {my_layer}) imports "
                        f"{imported} (layer {target_layer}) — "
                        f"dependency direction violation"
                    )
        assert not violations, (
            "System model dependency direction violations:\n"
            + "\n".join(violations)
        )

    def test_constants_is_leaf(self, system_model_files):
        """_constants.py must not import any other module."""
        path = system_model_files.get("_constants")
        assert path is not None, "_constants.py not found"
        all_imports = _extract_imports(path)
        # Allow only stdlib imports (from __future__ and pathlib).
        non_stdlib = [
            imp for imp in all_imports
            if not imp.startswith("_") and imp not in ("pathlib",)
        ]
        assert not non_stdlib, (
            f"_constants.py imports non-stdlib modules: {non_stdlib}"
        )

    def test_stage_modules_do_not_import_each_other(self, system_model_files):
        """Stage modules (loss_analysis, profile, control_structure, heuristics)
        must not import from each other or from critic/run."""
        stage_modules = {"loss_analysis", "profile", "control_structure", "heuristics"}
        forbidden_targets = {"critic", "run"}
        for name in stage_modules:
            path = system_model_files[name]
            imports = set(_system_model_internal_imports(path))
            cross_stage = imports & (stage_modules - {name})
            higher = imports & forbidden_targets
            assert not cross_stage, (
                f"{name}.py imports sibling stage module(s): {cross_stage}"
            )
            assert not higher, (
                f"{name}.py imports higher-level module(s): {higher}"
            )

    def test_critic_does_not_import_run(self, system_model_files):
        """critic.py must not import the orchestrator (run.py)."""
        path = system_model_files["critic"]
        imports = set(_system_model_internal_imports(path))
        assert "run" not in imports, "critic.py imports run.py — direction violation"

    def test_heuristics_imports_no_system_model_modules(self, system_model_files):
        """heuristics.py is a pure post-check — must not import any system_model module."""
        path = system_model_files["heuristics"]
        imports = _system_model_internal_imports(path)
        assert not imports, (
            f"heuristics.py imports system_model modules: {imports}"
        )

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

    def test_id_normalization_is_leaf(self, system_model_files):
        """id_normalization.py is high-level policy — no sibling or infra imports."""
        path = system_model_files.get("id_normalization")
        assert path is not None, "id_normalization.py not found"
        sibling_imports = _system_model_internal_imports(path)
        assert not sibling_imports, (
            f"id_normalization.py imports system_model modules: {sibling_imports}"
        )
        infra_imports = [
            imp
            for imp in _extract_imports(path)
            if imp.startswith("asago_scenario_generator.stpa.infra")
        ]
        assert not infra_imports, (
            "id_normalization.py imports infra (IO-near) modules: "
            f"{infra_imports}"
        )

    def test_infra_does_not_import_id_normalization(self):
        """Tolerant LLM parsing stays in infra; ID policy is not pulled downward."""
        violations: list[str] = []
        for path in sorted(INFRA_DIR.glob("*.py")):
            for imp in _extract_imports(path):
                if (
                    imp == "asago_scenario_generator.stpa.system_model.id_normalization"
                    or imp.startswith(
                        "asago_scenario_generator.stpa.system_model.id_normalization."
                    )
                ):
                    violations.append(f"{path.name}: imports '{imp}'")
        assert not violations, (
            "infra imported id_normalization (dependency-direction "
            "violation):\n" + "\n".join(violations)
        )

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
            if node.module != "asago_scenario_generator.stpa.system_model.id_normalization":
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
        acceptance_root = (
            Path(__file__).resolve().parent.parent.parent / "acceptance"
        )
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
        imports = set(_system_model_internal_imports(path))
        assert "id_normalization" in imports
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

    def test_critic_stitches_then_delegates_published_ids(
        self, system_model_files
    ):
        """Revision merge stitches by source ID, then applies leaf ID policy.

        Published IDs are not assigned by the IO-near revision merge.
        The critic may keep stitch-time collision bookkeeping, but the
        complete stitched payload must go through
        ``validate_normalized_control_structure``.
        """
        source = system_model_files["critic"].read_text(encoding="utf-8")
        imports = set(_system_model_internal_imports(system_model_files["critic"]))
        assert "id_normalization" in imports
        assert "def _stitch_revision_delta" in source
        assert "validate_normalized_control_structure" in source
        assert "ControlStructure.model_validate(normalized_payload.payload)" not in source


# ---------------------------------------------------------------------------
# Graceful degradation architecture guards
# ---------------------------------------------------------------------------


class TestSafeLlmCallExceptionSafety:
    """``safe_llm_call`` must catch ``Exception`` but NOT ``BaseException``
    subclasses like ``KeyboardInterrupt`` or ``SystemExit``.

    Catching ``BaseException`` would prevent the user from interrupting
    a long-running pipeline and would swallow process-exit signals.
    """

    def test_keyboard_interrupt_not_caught(self, tmp_path):
        """KeyboardInterrupt propagates through safe_llm_call."""
        from asago_scenario_generator.stpa.infra.llm_helpers import safe_llm_call
        from tests.stpa.sp1_helpers import MockLLMClient
        from pydantic import BaseModel

        class _Dummy(BaseModel):
            x: int = 1

        client = MockLLMClient()
        client.set_exception_for(_Dummy, KeyboardInterrupt("Ctrl-C"))

        with pytest.raises(KeyboardInterrupt):
            safe_llm_call(
                llm_client=client,
                system_prompt="s",
                user_prompt="u",
                response_format=_Dummy,
                run_dir=tmp_path,
                stage="test",
                step="test",
            )

    def test_system_exit_not_caught(self, tmp_path):
        """SystemExit propagates through safe_llm_call."""
        from asago_scenario_generator.stpa.infra.llm_helpers import safe_llm_call
        from tests.stpa.sp1_helpers import MockLLMClient
        from pydantic import BaseModel

        class _Dummy(BaseModel):
            x: int = 1

        client = MockLLMClient()
        client.set_exception_for(_Dummy, SystemExit(1))

        with pytest.raises(SystemExit):
            safe_llm_call(
                llm_client=client,
                system_prompt="s",
                user_prompt="u",
                response_format=_Dummy,
                run_dir=tmp_path,
                stage="test",
                step="test",
            )

    def test_runtime_exception_caught_and_logged(self, tmp_path):
        """RuntimeError is caught by safe_llm_call (not propagated)."""
        from asago_scenario_generator.stpa.infra.llm_helpers import safe_llm_call
        from tests.stpa.sp1_helpers import MockLLMClient
        from pydantic import BaseModel

        class _Dummy(BaseModel):
            x: int = 1

        client = MockLLMClient()
        client.set_exception_for(_Dummy, RuntimeError("API down"))

        model, result, error = safe_llm_call(
            llm_client=client,
            system_prompt="s",
            user_prompt="u",
            response_format=_Dummy,
            run_dir=tmp_path,
            stage="test",
            step="test",
        )
        assert model is None
        assert error is not None
        assert "RuntimeError" in error


class TestSafeLlmCallCanonicalEntryPoint:
    """``safe_llm_call`` must be the sole caller of ``llm_client.complete()``
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
                # Exclude safe_llm_call itself (which is in infra, not here)
                violations.append(
                    f"{path.name}: calls .complete() directly — "
                    f"must use safe_llm_call() instead"
                )
        assert not violations, (
            "Direct .complete() calls in system_model/:\n" + "\n".join(violations)
        )

    def test_complete_only_called_from_safe_llm_call(self):
        """llm_client.complete() is called only from safe_llm_call in infra."""
        import re

        violations: list[str] = []
        for path in sorted(STPA_ROOT.rglob("*.py")):
            if path.name == "__init__.py":
                continue
            source = path.read_text(encoding="utf-8")
            # Find all .complete( calls
            for match in re.finditer(r"\.complete\(", source):
                # Check if it's inside safe_llm_call function
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
                if enclosing_func and "safe_llm_call" not in enclosing_func:
                    violations.append(
                        f"{path.name}: .complete() called outside safe_llm_call "
                        f"(in '{enclosing_func.strip()}')"
                    )
        assert not violations, (
            ".complete() called outside safe_llm_call:\n" + "\n".join(violations)
        )


class TestStageErrorLocation:
    """``StageError`` must be defined in the infra layer, not in system_model.

    This ensures downstream SPs (SP2, SP3) can import ``StageError`` from
    the shared infra layer without depending on SP1's system_model.
    """

    def test_stage_error_defined_in_infra(self):
        """StageError is defined in infra/llm_helpers.py."""
        from asago_scenario_generator.stpa.infra import llm_helpers

        assert hasattr(llm_helpers, "StageError")
        assert llm_helpers.StageError.__module__ == "asago_scenario_generator.stpa.infra.llm_helpers"

    def test_stage_error_not_defined_in_system_model(self):
        """No system_model module defines its own StageError class."""
        import ast

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


# ---------------------------------------------------------------------------
# SP3 Scenario Production architecture guards
# ---------------------------------------------------------------------------

SCENARIO_PROD_DIR = STPA_ROOT / "scenario_prod"

# Dependency layers within scenario_prod (lower = closer to leaf).
# A module at layer N may import from modules at layer <= N.
_SCENARIO_PROD_LAYERS: dict[str, int] = {
    "_constants": 0,
    "enrichment": 0,
    "assembly": 1,
    "bdi_generation": 1,
    "narrative": 1,
    "attack_tree": 1,
    "gherkin": 1,
    "validators": 1,
    # Stream B deterministic projection validators/derivers.  They depend
    # only on stpa.models (execution_envelope/execution_projection), never
    # on scenario_prod siblings or IO, so they sit at the stage-module layer.
    "projection": 1,
    "prompt_alignment": 1,
    "eval_metrics": 2,
    "coverage": 2,
    "run": 3,
}


def _scenario_prod_internal_imports(file_path: Path) -> list[str]:
    """Return bare module names imported from within scenario_prod.

    Relative imports like ``from .validators import X`` yield ``"validators"``.
    """
    result: list[str] = []
    for imp in _extract_imports(file_path):
        prefix = "asago_scenario_generator.stpa.scenario_prod."
        if imp.startswith(prefix):
            result.append(imp[len(prefix):].split(".")[0])
    # Also handle relative imports (from .xxx import ...)
    source = file_path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(file_path))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.level == 1 and node.module:
                result.append(node.module)
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
                            f"{file_path.name}:{node.name}: "
                            f"local import '{alias.name}'"
                        )
                elif isinstance(child, ast.ImportFrom):
                    mod = child.module or ""
                    violations.append(
                        f"{file_path.name}:{node.name}: "
                        f"local from-import '{mod}'"
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
            is_sp3_sibling = (
                node.level == 1
                or (node.module and node.module.startswith("asago_scenario_generator.stpa.scenario_prod"))
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


class TestScenarioProdNoImportCycles:
    """All scenario_prod modules must import without circular dependency errors."""

    @pytest.mark.parametrize(
        "module_name",
        [
            "asago_scenario_generator.stpa.scenario_prod",
            "asago_scenario_generator.stpa.scenario_prod._constants",
            "asago_scenario_generator.stpa.scenario_prod.enrichment",
            "asago_scenario_generator.stpa.scenario_prod.assembly",
            "asago_scenario_generator.stpa.scenario_prod.bdi_generation",
            "asago_scenario_generator.stpa.scenario_prod.narrative",
            "asago_scenario_generator.stpa.scenario_prod.attack_tree",
            "asago_scenario_generator.stpa.scenario_prod.gherkin",
            "asago_scenario_generator.stpa.scenario_prod.validators",
            "asago_scenario_generator.stpa.scenario_prod.projection",
            "asago_scenario_generator.stpa.scenario_prod.prompt_alignment",
            "asago_scenario_generator.stpa.scenario_prod.eval_metrics",
            "asago_scenario_generator.stpa.scenario_prod.coverage",
            "asago_scenario_generator.stpa.scenario_prod.run",
        ],
    )
    def test_module_imports_cleanly(self, module_name):
        """Module can be imported without errors."""
        mod = importlib.import_module(module_name)
        assert mod is not None


class TestScenarioProdDependencyDirection:
    """scenario_prod modules must follow layer ordering."""

    @pytest.fixture
    def scenario_prod_files(self) -> dict[str, Path]:
        files: dict[str, Path] = {}
        for path in sorted(SCENARIO_PROD_DIR.glob("*.py")):
            if path.name == "__init__.py":
                continue
            files[path.stem] = path
        return files

    def test_no_reverse_dependencies(self, scenario_prod_files):
        """A module at layer N must not import from a module at layer > N."""
        violations: list[str] = []
        for name, path in scenario_prod_files.items():
            my_layer = _SCENARIO_PROD_LAYERS.get(name, 99)
            for imported in _scenario_prod_internal_imports(path):
                target_layer = _SCENARIO_PROD_LAYERS.get(imported, 99)
                if target_layer > my_layer:
                    violations.append(
                        f"{name} (layer {my_layer}) imports "
                        f"{imported} (layer {target_layer}) — "
                        f"dependency direction violation"
                    )
        assert not violations, (
            "scenario_prod dependency direction violations:\n"
            + "\n".join(violations)
        )

    def test_constants_is_leaf(self, scenario_prod_files):
        """_constants.py must not import any other module."""
        path = scenario_prod_files.get("_constants")
        assert path is not None, "_constants.py not found"
        all_imports = _extract_imports(path)
        non_stdlib = [
            imp for imp in all_imports
            if not imp.startswith("_") and imp not in ("pathlib",)
        ]
        assert not non_stdlib, (
            f"_constants.py imports non-stdlib modules: {non_stdlib}"
        )

    def test_stage_modules_do_not_import_eval_or_coverage(self, scenario_prod_files):
        """Stage modules must not import eval_metrics, coverage, or run."""
        stage_modules = {
            "assembly", "bdi_generation", "narrative",
            "attack_tree", "gherkin", "validators",
        }
        forbidden = {"eval_metrics", "coverage", "run"}
        for name in stage_modules:
            path = scenario_prod_files[name]
            imports = set(_scenario_prod_internal_imports(path))
            found = imports & forbidden
            assert not found, (
                f"{name}.py imports higher-level module(s): {found}"
            )

    def test_eval_metrics_does_not_import_run(self, scenario_prod_files):
        """eval_metrics.py must not import the orchestrator."""
        path = scenario_prod_files["eval_metrics"]
        imports = set(_scenario_prod_internal_imports(path))
        assert "run" not in imports, (
            "eval_metrics.py imports run.py — direction violation"
        )


class TestScenarioProdNoPrivateCrossModuleImports:
    """No scenario_prod module should import private (_-prefixed) names
    from a sibling module within scenario_prod."""

    @pytest.fixture
    def scenario_prod_python_files(self) -> list[Path]:
        return sorted(
            p for p in SCENARIO_PROD_DIR.glob("*.py")
            if p.name != "__init__.py"
        )

    def test_no_private_imports(self, scenario_prod_python_files):
        """No file in scenario_prod/ imports private names from siblings."""
        violations: list[str] = []
        for path in scenario_prod_python_files:
            violations.extend(_private_imports_across_modules(path))
        assert not violations, (
            "Private cross-module imports in scenario_prod/:\n"
            + "\n".join(violations)
        )


class TestScenarioProdNoLocalImports:
    """No scenario_prod module should have import statements inside
    function bodies. Local imports suggest circular dependencies or
    lazy-loading workarounds that should be resolved structurally."""

    @pytest.fixture
    def scenario_prod_python_files(self) -> list[Path]:
        return sorted(
            p for p in SCENARIO_PROD_DIR.glob("*.py")
            if p.name != "__init__.py"
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
    All LLM calls must go through safe_llm_call or safe_llm_call_raw."""

    def test_no_direct_complete_calls(self):
        """No scenario_prod module calls .complete() directly."""
        violations: list[str] = []
        for path in sorted(SCENARIO_PROD_DIR.glob("*.py")):
            if path.name == "__init__.py":
                continue
            source = path.read_text(encoding="utf-8")
            if ".complete(" in source:
                violations.append(
                    f"{path.name}: calls .complete() directly — "
                    f"must use safe_llm_call() or safe_llm_call_raw()"
                )
        assert not violations, (
            "Direct .complete() calls in scenario_prod/:\n"
            + "\n".join(violations)
        )


class TestEnrichmentModuleBoundary:
    """Enrichment module must be a pure, leaf-level computation module.

    ``enrichment.py`` computes deterministic enrichment blocks from
    models and capability-profile data.  It must not depend on the
    orchestrator (``run.py``) or any other scenario_prod module —
    only on the model layer and the capability profile.
    """

    def test_enrichment_does_not_import_run(self):
        """enrichment.py must not import from run.py (orchestrator)."""
        path = SCENARIO_PROD_DIR / "enrichment.py"
        imports = _extract_imports(path)
        violations = [imp for imp in imports if "run" in imp.split(".")[-1]]
        assert not violations, (
            f"enrichment.py imports orchestrator module(s): {violations}"
        )

    def test_enrichment_does_not_import_scenario_prod_siblings(self):
        """enrichment.py must not import from other scenario_prod modules.

        It is a leaf module (layer 0) — only model-layer imports allowed.
        """
        path = SCENARIO_PROD_DIR / "enrichment.py"
        internal = _scenario_prod_internal_imports(path)
        # Filter out self-imports (shouldn't happen, but be safe)
        siblings = [m for m in internal if m != "enrichment"]
        assert not siblings, (
            f"enrichment.py imports scenario_prod sibling(s): {siblings}"
        )

    def test_enrichment_imports_only_model_layer(self):
        """enrichment.py may only import from stpa.models or models packages."""
        path = SCENARIO_PROD_DIR / "enrichment.py"
        imports = _extract_imports(path)
        allowed_prefixes = (
            "asago_scenario_generator.stpa.models",
            "asago_scenario_generator.models.capability_profile",
            "__future__",
        )
        violations = [
            imp for imp in imports
            if not imp.startswith(allowed_prefixes)
            and imp not in ("typing", "pydantic")
        ]
        assert not violations, (
            f"enrichment.py imports non-model module(s): {violations}"
        )

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


# ---------------------------------------------------------------------------
# SP3 feedback-bridge and context-propagation architecture
# ---------------------------------------------------------------------------

THREAT_ENUM_DIR = STPA_ROOT / "threat_enum"
_BRIDGE_ANCHOR = (
    "FB-* denotes a logical information dependency that updates a "
    "process-model belief"
)
_BRIDGE_TEMPLATES = (
    THREAT_ENUM_DIR / "prompts" / "stage3_system.j2",
    SCENARIO_PROD_DIR / "prompts" / "stage5_system.j2",
    SCENARIO_PROD_DIR / "prompts" / "stage6a_narrative_system.j2",
)


def _bridge_body(path: Path) -> str:
    """Return the shared FB-bridge paragraphs of a system prompt template."""
    text = path.read_text(encoding="utf-8")
    start = text.index(_BRIDGE_ANCHOR)
    end = text.index("records that evidence.", start) + len("records that evidence.")
    return text[start:end].strip()


class TestFeedbackBridgeDuplication:
    """The FB-bridge rule is duplicated across SP3 system prompts on purpose.

    ``TemplateLoader`` is bound to one prompts directory.  Stage 3 lives
    under ``threat_enum/prompts`` and Stages 5/6a live under
    ``scenario_prod/prompts``.  A shared Jinja include would either
    couple those package loaders or invent a third prompt root.  Keep
    the templates self-contained and lock the shared prose so it cannot
    drift independently.
    """

    def test_bridge_prose_is_identical(self):
        """All three system prompts share the same FB-bridge body."""
        bodies = [_bridge_body(path) for path in _BRIDGE_TEMPLATES]
        assert all(_BRIDGE_ANCHOR in body for body in bodies)
        assert len(set(bodies)) == 1

    def test_no_cross_package_prompt_includes(self):
        """SP3 templates must not include files from another package."""
        import re

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
        from asago_scenario_generator.stpa.scenario_prod import bdi_generation

        assert "build_bdi_prompts" in bdi_generation.__all__
        assert hasattr(bdi_generation, "build_bdi_prompts")
        assert not hasattr(bdi_generation, "_build_bdi_prompts")

    def test_acceptance_uses_public_bdi_prompt_builder(self):
        """Acceptance handlers must not import the retired private name."""
        acceptance_root = (
            Path(__file__).resolve().parent.parent.parent / "acceptance"
        )
        leaked: list[str] = []
        for path in sorted(acceptance_root.rglob("*.py")):
            source = path.read_text(encoding="utf-8")
            if "_build_bdi_prompts" in source:
                leaked.append(str(path.relative_to(acceptance_root)))
        assert not leaked, (
            "acceptance still imports private _build_bdi_prompts:\n"
            + "\n".join(leaked)
        )

    def test_prompt_builders_do_not_import_run(self):
        """Stage 5/6a assemblers stay below the orchestrator."""
        for name in ("bdi_generation", "narrative"):
            path = SCENARIO_PROD_DIR / f"{name}.py"
            imports = set(_scenario_prod_internal_imports(path))
            assert "run" not in imports, f"{name}.py imports run.py"

    def test_context_for_is_the_omit_policy(self):
        """The omit-when-absent rule lives next to the context builder."""
        from asago_scenario_generator.stpa.threat_enum.technology_context import (
            context_for,
        )

        assert context_for(None) is None
