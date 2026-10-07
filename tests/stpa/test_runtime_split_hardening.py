"""Hardening tests for the acceptance runtime split seam.

These tests cover mutation sites in ``acceptance_runtime.py`` and
``runtime_manifest.py`` that the property and acceptance suites do not
exercise.  They target the new architectural seam: the facade registry,
``_RegistrationStage``, publish/rollback, delegation wrappers, and
manifest validation error paths.

Kept separate from unit and acceptance tests per the hardening protocol.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_PROJECT_ROOT = next(
    p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").is_file()
)
_ACCEPTANCE_DIR = _PROJECT_ROOT / "acceptance"
sys.path.insert(0, str(_ACCEPTANCE_DIR))

from acceptance_runtime import (  # noqa: E402
    STEP_PATTERNS,
    _REGISTERED_PATTERN_KEYS,
    _RegistrationStage,
    _derive_feature_tag,
    _publish,
    _register,
    _register_first,
    _track_registration,
    execute_ir,
    execute_step,
    find_pattern_conflicts,
)
from runtime_shared import World  # noqa: E402
import re as _re  # noqa: E402
import acceptance_runtime as runtime  # noqa: E402
import runtime_manifest  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures: save/restore global registry state
# ---------------------------------------------------------------------------


@pytest.fixture
def isolated_registry():
    """Snapshot and restore STEP_PATTERNS and _REGISTERED_PATTERN_KEYS."""
    saved_patterns = list(STEP_PATTERNS)
    saved_keys = set(_REGISTERED_PATTERN_KEYS)
    yield
    STEP_PATTERNS[:] = saved_patterns
    _REGISTERED_PATTERN_KEYS.clear()
    _REGISTERED_PATTERN_KEYS.update(saved_keys)


def _dummy_handler(world: World, text: str, examples: dict) -> tuple[bool, str]:
    return True, ""


def _dummy_handler_b(world: World, text: str, examples: dict) -> tuple[bool, str]:
    return True, "b"


# ---------------------------------------------------------------------------
# _register / _register_first direct calls
# ---------------------------------------------------------------------------


class TestRegisterDirect:
    """Cover the module-level _register and _register_first functions."""

    def test_register_appends_to_step_patterns(self, isolated_registry):
        initial_count = len(STEP_PATTERNS)
        _register(r"hardening test pattern \d+", _dummy_handler)
        assert len(STEP_PATTERNS) == initial_count + 1
        pattern, handler, tag = STEP_PATTERNS[-1]
        assert handler is _dummy_handler
        assert tag is None

    def test_register_first_inserts_at_front(self, isolated_registry):
        _register(r"hardening baseline pattern", _dummy_handler)
        _register_first(r"hardening priority pattern", _dummy_handler_b)
        pattern, handler, tag = STEP_PATTERNS[0]
        assert handler is _dummy_handler_b
        assert pattern.pattern == "hardening priority pattern"


# ---------------------------------------------------------------------------
# _track_registration duplicate detection
# ---------------------------------------------------------------------------


class TestTrackRegistrationDuplicate:
    """Cover the duplicate-detection raise in _track_registration."""

    def test_track_registration_raises_on_exact_duplicate(self, isolated_registry):
        _track_registration("dup pattern", _dummy_handler, None)
        with pytest.raises(RuntimeError, match="Duplicate step pattern registration"):
            _track_registration("dup pattern", _dummy_handler, None)

    def test_track_registration_allows_different_handler(self, isolated_registry):
        _track_registration("shared pattern", _dummy_handler, None)
        # Different handler with same pattern is allowed at track level;
        # conflicts are detected by find_pattern_conflicts at test time.
        _track_registration("shared pattern", _dummy_handler_b, None)


# ---------------------------------------------------------------------------
# find_pattern_conflicts with actual conflicts
# ---------------------------------------------------------------------------


class TestFindPatternConflictsWithConflicts:
    """Cover the witness and conflict-append paths in find_pattern_conflicts."""

    def test_finds_conflict_with_witness(self, isolated_registry):
        _register(r"conflict pattern", _dummy_handler)
        _register(r"conflict pattern", _dummy_handler_b)
        conflicts = find_pattern_conflicts(["conflict pattern text"])
        assert len(conflicts) == 1
        witness, first, second = conflicts[0]
        assert witness == "conflict pattern text"

    def test_finds_conflict_without_witness(self, isolated_registry):
        _register(r"no witness pattern", _dummy_handler)
        _register(r"no witness pattern", _dummy_handler_b)
        conflicts = find_pattern_conflicts([])
        assert len(conflicts) == 1
        witness, _, _ = conflicts[0]
        assert witness == "<no supplied witness>"

    def test_no_conflict_for_same_handler_twice(self, isolated_registry):
        """Same handler registered twice for same pattern is not a conflict."""
        _track_registration("same handler pattern", _dummy_handler, None)
        _REGISTERED_PATTERN_KEYS.add(("same handler pattern", "_dummy_handler", None))
        # Manually add two entries with same handler to STEP_PATTERNS

        compiled = _re.compile("same handler pattern", _re.IGNORECASE)
        STEP_PATTERNS.append((compiled, _dummy_handler, None))
        STEP_PATTERNS.append((compiled, _dummy_handler, None))
        conflicts = find_pattern_conflicts(["same handler pattern text"])
        assert conflicts == []


# ---------------------------------------------------------------------------
# _RegistrationStage duplicate detection
# ---------------------------------------------------------------------------


class TestRegistrationStageDuplicate:
    """Cover the duplicate-key raise in _RegistrationStage.add."""

    def test_stage_add_raises_on_duplicate(self):
        stage = _RegistrationStage()
        stage.add("stage dup", _dummy_handler, False, None)
        with pytest.raises(RuntimeError, match="Duplicate step pattern registration"):
            stage.add("stage dup", _dummy_handler, False, None)

    def test_stage_add_preserves_keys_on_duplicate(self):
        stage = _RegistrationStage()
        stage.add("stage dup2", _dummy_handler, False, None)
        keys_before = set(stage.keys)
        try:
            stage.add("stage dup2", _dummy_handler, False, None)
        except RuntimeError:
            pass
        assert stage.keys == keys_before
        assert len(stage.entries) == 1


# ---------------------------------------------------------------------------
# execute_step with unsupported step
# ---------------------------------------------------------------------------


class TestExecuteStepUnsupported:
    """Cover the unsupported-step return in execute_step."""

    def test_unsupported_step_returns_false(self, isolated_registry):
        world = World()
        success, error = execute_step(
            world,
            {"keyword": "Then", "text": "this step matches absolutely nothing xyz123"},
            {},
        )
        assert success is False
        assert "Unsupported step" in error


# ---------------------------------------------------------------------------
# execute_ir with failing background step
# ---------------------------------------------------------------------------


class TestExecuteIrBackgroundFailure:
    """Cover the background-step-failure path in execute_ir."""

    def test_background_failure_marks_scenario_failed(
        self, isolated_registry, tmp_path
    ):
        _register(r"hardening bg ok", _dummy_handler)
        _register(r"hardening bg fail", _dummy_handler_b)

        # Override the fail handler to return failure
        def fail_handler(world: World, text: str, examples: dict) -> tuple[bool, str]:
            return False, "injected background failure"

        _register_first(r"hardening bg fail", fail_handler)

        ir = {
            "background": [{"keyword": "Given", "text": "hardening bg fail"}],
            "scenarios": [
                {"name": "bg_fail_scenario", "steps": []},
            ],
        }
        ir_path = tmp_path / "bg_fail.json"
        ir_path.write_text(json.dumps(ir))

        all_passed, output = execute_ir(str(ir_path))
        assert all_passed is False
        assert "background step failed" in output

    def test_scenario_step_failure_marks_scenario_failed(
        self, isolated_registry, tmp_path
    ):
        """Cover the scenario-step-failure path (distinct from background failure)."""
        _register(r"hardening bg ok", _dummy_handler)
        _register(r"hardening sc fail", _dummy_handler_b)

        def fail_handler(world: World, text: str, examples: dict) -> tuple[bool, str]:
            return False, "injected scenario failure"

        _register_first(r"hardening sc fail", fail_handler)

        ir = {
            "background": [{"keyword": "Given", "text": "hardening bg ok"}],
            "scenarios": [
                {
                    "name": "sc_fail_scenario",
                    "steps": [
                        {"keyword": "Then", "text": "hardening sc fail"},
                    ],
                },
            ],
        }
        ir_path = tmp_path / "sc_fail.json"
        ir_path.write_text(json.dumps(ir))

        all_passed, output = execute_ir(str(ir_path))
        assert all_passed is False
        assert "injected scenario failure" in output


# ---------------------------------------------------------------------------
# _derive_feature_tag for stage6_ prefix
# ---------------------------------------------------------------------------


class TestDeriveFeatureTagStage6:
    """Cover the stage6_ -> sp3 mapping in _derive_feature_tag."""

    def test_stage6_prefix_maps_to_sp3(self):
        assert _derive_feature_tag("stage6_jpkw_output.json") == "sp3"

    def test_flattened_sp3_stems_keep_their_tag(self):
        assert _derive_feature_tag("sp3-anti-vacuity.json") == "sp3"

    def test_non_matching_prefix_returns_none(self):
        assert _derive_feature_tag("foundation_test.json") is None


# ---------------------------------------------------------------------------
# Delegation wrappers
# ---------------------------------------------------------------------------


class TestDelegationWrappers:
    """Cover the _h_rev_revision_run and _h_sp1_rev_run delegation wrappers."""

    def test_h_rev_revision_run_delegates(self):
        world = World()
        result = runtime._h_rev_revision_run(world, "", {})
        # The delegated handler returns a tuple
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_h_sp1_rev_run_delegates(self):
        world = World()
        result = runtime._h_sp1_rev_run(world, "", {})
        assert isinstance(result, tuple)
        assert len(result) == 2


# ---------------------------------------------------------------------------
# _publish ordering
# ---------------------------------------------------------------------------


class TestPublishOrdering:
    """Cover the _publish sorting and first-insert logic."""

    def test_publish_preserves_first_priority(self, isolated_registry):
        stage = _RegistrationStage()
        stage.add("pub regular a", _dummy_handler, False, 0)
        stage.add("pub first b", _dummy_handler_b, True, 1)
        stage.add("pub regular c", _dummy_handler, False, 2)
        _publish(stage)
        # First-entry should be at position 0
        assert STEP_PATTERNS[0][1] is _dummy_handler_b
        assert STEP_PATTERNS[0][2] == stage.feature  # tag from stage.feature


# ---------------------------------------------------------------------------
# runtime_manifest error paths
# ---------------------------------------------------------------------------


class TestRuntimeManifestErrorPaths:
    """Cover the manifest mismatch set-difference operations."""

    def test_manifest_mismatch_reports_missing_and_omitted(self):
        original_modules = runtime_manifest.MODULES
        try:
            # Add a fake module and remove a real one to trigger both
            # missing and omitted paths
            runtime_manifest.MODULES = (*original_modules[:-1], "nonexistent_module")
            with pytest.raises(RuntimeError, match="manifest mismatch"):
                runtime_manifest.load_modules()
        finally:
            runtime_manifest.MODULES = original_modules

    def test_register_all_rejects_incomplete_set(self):
        modules = runtime_manifest.load_modules()
        with pytest.raises(RuntimeError, match="incomplete"):
            runtime_manifest.register_all(None, modules[:-1])
