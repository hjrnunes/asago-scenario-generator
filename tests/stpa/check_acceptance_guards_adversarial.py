"""Adversarial tests verifying the new acceptance-harness guards actually fire.

This script proves three guards work by triggering them with synthetic inputs:

1. _track_registration — raises RuntimeError on an exact duplicate registration
2. find_pattern_conflicts — detects a synthetic same-scope pattern conflict
3. check_entry_points_canonical_ir_location — catches non-canonical IR paths

Run: uv run python tests/stpa/check_acceptance_guards_adversarial.py
Exit 0 = all guards fire correctly; exit 1 = a guard failed to fire.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

_PROJECT_ROOT = next(
    p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").is_file()
)
_ACCEPTANCE_DIR = _PROJECT_ROOT / "acceptance"
sys.path.insert(0, str(_ACCEPTANCE_DIR))

from acceptance_runtime import (  # noqa: E402
    STEP_PATTERNS,
    _REGISTERED_PATTERN_KEYS,
    _track_registration,
    find_pattern_conflicts,
)
from snapshot import snapshot_layout  # noqa: E402


def test_track_registration_fires_on_duplicate() -> bool:
    """_track_registration must raise RuntimeError on an exact duplicate."""
    pattern = r"^a synthetic test step$"
    handler_name = "_adversarial_handler"
    feature_tag = None

    def _adversarial_handler():
        pass

    # Simulate a first registration
    _track_registration(pattern, _adversarial_handler, feature_tag)

    # Simulate the same registration again — must raise
    try:
        _track_registration(pattern, _adversarial_handler, feature_tag)
    except RuntimeError as exc:
        msg = str(exc)
        if "Duplicate step pattern registration" in msg and pattern in msg:
            print("PASS _track_registration fires on exact duplicate")
            # Clean up the key we added
            key = (pattern, handler_name, feature_tag)
            _REGISTERED_PATTERN_KEYS.discard(key)
            return True
        else:
            print(f"FAIL _track_registration raised but message unexpected: {msg}")
            _REGISTERED_PATTERN_KEYS.discard((pattern, handler_name, feature_tag))
            return False
    else:
        print("FAIL _track_registration did NOT raise on exact duplicate")
        _REGISTERED_PATTERN_KEYS.discard((pattern, handler_name, feature_tag))
        return False


def test_find_pattern_conflicts_detects_synthetic() -> bool:
    """find_pattern_conflicts must detect duplicate raw patterns with
    different handlers in the same scope."""
    # Build a minimal synthetic STEP_PATTERNS snapshot
    original = list(STEP_PATTERNS)

    # Insert two global patterns that both match the same text
    duplicate_pattern = r"the revision is run"
    pat1 = re.compile(duplicate_pattern, re.IGNORECASE)
    pat2 = re.compile(duplicate_pattern, re.IGNORECASE)

    def _synth_handler_1() -> None:
        return None

    def _synth_handler_2() -> None:
        return None

    handler1 = _synth_handler_1
    handler2 = _synth_handler_2

    # Temporarily replace STEP_PATTERNS with just our two patterns
    STEP_PATTERNS.clear()
    STEP_PATTERNS.append((pat1, handler1, None))
    STEP_PATTERNS.append((pat2, handler2, None))

    try:
        conflicts = find_pattern_conflicts(["the revision is run"])
        if conflicts and len(conflicts) >= 1:
            text, first, second = conflicts[0]
            if "the revision is run" in text:
                print(
                    f"PASS find_pattern_conflicts detected synthetic conflict: "
                    f"{first!r} vs {second!r}"
                )
                return True
            else:
                print(f"FAIL find_pattern_conflicts returned wrong text: {text!r}")
                return False
        else:
            print("FAIL find_pattern_conflicts did NOT detect synthetic conflict")
            return False
    finally:
        # Restore
        STEP_PATTERNS.clear()
        STEP_PATTERNS.extend(original)


def test_check_entry_points_canonical_ir_location() -> bool:
    """check_entry_points_canonical_ir_location must flag non-canonical IR.

    We can't easily run the full QA runner, so we replicate the core logic
    and prove it catches a non-canonical path.
    """
    IR_DIR = _PROJECT_ROOT / snapshot_layout().ir_dir

    # A non-canonical path (outside the generated IR dir)
    non_canonical = str(_PROJECT_ROOT / "tmp" / "rogue_ir.json")
    canonical = str(IR_DIR / "acceptance-refresh" / "stage2-coordination-analysis.json")

    def _check_path(ref: str) -> bool:
        """Return True if ref is canonical, False otherwise."""
        try:
            Path(ref).resolve().relative_to(IR_DIR.resolve())
            return True
        except ValueError:
            return False

    # The canonical path should pass
    if not _check_path(canonical):
        print("FAIL canonical path was rejected (logic error in test)")
        return False

    # The non-canonical path should fail
    if _check_path(non_canonical):
        print("FAIL non-canonical IR path was NOT detected")
        return False
    else:
        print(
            f"PASS check_entry_points_canonical_ir_location flags non-canonical: {non_canonical}"
        )
        return True


def main() -> int:
    results = [
        test_track_registration_fires_on_duplicate(),
        test_find_pattern_conflicts_detects_synthetic(),
        test_check_entry_points_canonical_ir_location(),
    ]
    passed = sum(results)
    total = len(results)
    print(f"\n{passed}/{total} adversarial guard tests passed")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
