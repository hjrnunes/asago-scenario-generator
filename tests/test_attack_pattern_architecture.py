"""Architecture guards for the authoritative attack-pattern split."""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest
from tests.helpers.architecture import imported_modules

MODELS_DIR = (
    Path(__file__).resolve().parent.parent
    / "src"
    / "asago_scenario_generator"
    / "models"
)
DATA_DIR = (
    Path(__file__).resolve().parent.parent / "src" / "asago_scenario_generator" / "data"
)
PIPELINE_DIR = (
    Path(__file__).resolve().parent.parent
    / "src"
    / "asago_scenario_generator"
    / "pipeline"
)
SRC_DIR = Path(__file__).resolve().parent.parent / "src" / "asago_scenario_generator"

_FACADE_MODULE = "asago_scenario_generator.models.attack_pattern"
_FORBIDDEN_IO_NEAR_PREFIXES = (
    "asago_scenario_generator.prompts",
    "asago_scenario_generator.manifest",
    "asago_scenario_generator.report",
    "asago_scenario_generator.cli",
    "asago_scenario_generator.stpa",
    "asago_scenario_generator.pipeline",
)


class TestAttackPatternLeaves:
    """Responsibility modules stay free of the public façade and IO."""

    @pytest.mark.parametrize(
        "module_name",
        (
            "attack_pattern_contracts.py",
            "attack_pattern_digests.py",
            "attack_pattern_chain.py",
            "attack_pattern_projection.py",
            "attack_pattern_validation.py",
        ),
    )
    def test_leaf_does_not_import_facade_or_io(self, module_name: str) -> None:
        """Each responsibility module stays inward and offline."""
        imports = imported_modules(MODELS_DIR / module_name)
        assert _FACADE_MODULE not in imports, (
            f"{module_name} must not import the public attack-pattern façade"
        )
        violations = [
            imp
            for imp in imports
            if any(
                imp == forbidden or imp.startswith(forbidden + ".")
                for forbidden in _FORBIDDEN_IO_NEAR_PREFIXES
            )
        ]
        assert not violations, (
            f"{module_name} imports IO-near modules: {sorted(violations)}"
        )

    def test_digests_import_cleanly(self) -> None:
        """Digest helpers can be imported without the façade."""
        module = importlib.import_module(
            "asago_scenario_generator.models.attack_pattern_digests"
        )
        assert module._canonical_json is not None
        assert module.compute_chain_semantic_digest is not None


class TestAttackPatternConsumersDependInward:
    """Pipeline and data adapters consume attack-pattern leaves, not the façade."""

    _CONSUMERS = (
        DATA_DIR / "taxonomy_pins.py",
        PIPELINE_DIR / "projection_allocation.py",
        PIPELINE_DIR / "projection_allocator.py",
        PIPELINE_DIR / "projection_candidates.py",
        PIPELINE_DIR / "projection_qualification.py",
        PIPELINE_DIR / "projection_relations.py",
        PIPELINE_DIR / "projection_requirements.py",
        PIPELINE_DIR / "projection_resources.py",
    )

    @pytest.mark.parametrize(
        "path",
        _CONSUMERS,
        ids=lambda path: str(path.relative_to(SRC_DIR)),
    )
    def test_consumer_does_not_import_attack_pattern_facade(self, path: Path) -> None:
        """Adapters reach types through responsibility leaves."""
        imports = imported_modules(path)
        assert _FACADE_MODULE not in imports, (
            f"{path.name} must not import the public attack-pattern façade"
        )
        assert not any(imp.startswith(_FACADE_MODULE + ".") for imp in imports)
