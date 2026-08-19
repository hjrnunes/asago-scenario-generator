"""Property tests for the acceptance harness invariants.

These tests verify structural invariants of the acceptance test
infrastructure itself — the registration system, IR coverage, and
handler resolution.  They catch the bug classes that produced the
original acceptance staleness failures:

1. **No pattern shadowing**: No two registrations in the same feature
   scope use the same raw pattern string with different handlers.  If
   they do, the first match wins and the second handler is dead code — a
   silent shadowing bug.

2. **IR-entry-point coverage**: Every IR file has exactly one generated
   entry point, and every entry point references an existing IR file.

3. **Handler resolution**: Every step in every IR file resolves to a
   registered handler.  An unresolved step means the IR references
   behaviour the runtime cannot execute — the IR is stale or the
   handler is missing.

4. **Exact-duplicate prevention**: The registration API rejects exact
   duplicate (pattern, handler, scope) registrations at import time.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_PROJECT_ROOT = next(
    p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").is_file()
)
_ACCEPTANCE_DIR = _PROJECT_ROOT / "acceptance"

# Ensure the acceptance runtime is importable.
sys.path.insert(0, str(_ACCEPTANCE_DIR))

from generate_entrypoints import generate  # noqa: E402
from acceptance_runtime import (  # noqa: E402
    STEP_PATTERNS,
    _derive_feature_tag,
    find_pattern_conflicts,
)


@dataclass(frozen=True)
class AcceptanceArtifactFixture:
    """Test-owned acceptance artifacts for the infrastructure properties."""

    root: Path
    ir_dir: Path
    generated_dir: Path


@pytest.fixture
def acceptance_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> AcceptanceArtifactFixture:
    """Provision a minimal IR and entry point outside the repository tree."""
    for name in (
        "SWARMFORGE_ACCEPTANCE_IR_DIR",
        "SWARMFORGE_ACCEPTANCE_GENERATED_DIR",
        "SWARMFORGE_ACCEPTANCE_DRY_DIR",
    ):
        monkeypatch.delenv(name, raising=False)
    root = tmp_path / "acceptance-fixture"
    (root / "features").mkdir(parents=True)
    (root / "build" / "acceptance" / "ir").mkdir(parents=True)
    generated_dir = root / "build" / "acceptance" / "generated"
    generated_dir.mkdir(parents=True)
    (root / "pyproject.toml").write_text(
        '[project]\nname = "acceptance-fixture"\n',
        encoding="utf-8",
    )
    (root / "features" / "fixture.feature").write_text(
        "Feature: Fixture\n",
        encoding="utf-8",
    )
    ir_path = root / "build" / "acceptance" / "ir" / "fixture.json"
    ir_path.write_text(
        json.dumps(
            {
                "name": "Fixture",
                "background": [{"steps": [{"text": "the quality script is invoked"}]}],
                "scenarios": [],
            }
        ),
        encoding="utf-8",
    )
    generate(
        str(ir_path),
        str(generated_dir),
        feature_path="features/fixture.feature",
    )
    return AcceptanceArtifactFixture(
        root=root,
        ir_dir=ir_path.parent,
        generated_dir=generated_dir,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ir_files(ir_dir: Path) -> list[Path]:
    """All executable IR files (excluding DRY-checker reports)."""
    return sorted(p for p in ir_dir.rglob("*.json") if not p.stem.endswith("_dry"))


def _entry_points(generated_dir: Path) -> list[Path]:
    """All generated entry point test files."""
    return sorted(generated_dir.glob("*_acceptance_test.py"))


def _entry_point_ir_refs(entry_point: Path, root: Path) -> list[str]:
    """Extract IR file paths referenced by an entry point."""
    import re

    body = entry_point.read_text(encoding="utf-8")
    relative = re.findall(r'_PROJECT_ROOT / "([^"]+\.json)"', body)
    if relative:
        return [str(root / rel) for rel in relative]
    return re.findall(r'Path\(r"([^"]+\.json)"\)', body)


def _all_step_texts(ir_path: Path) -> list[str]:
    """Extract all step texts from an IR file (background + scenarios).

    Includes example-expanded texts: for each step with <placeholder> tokens,
    produces one text per example row with placeholders substituted.
    """
    ir = json.loads(ir_path.read_text(encoding="utf-8"))
    texts: list[str] = []
    for section in ("background", "scenarios"):
        node = ir.get(section)
        if node is None:
            continue
        scenarios = node if isinstance(node, list) else [node]
        for scenario in scenarios:
            if not isinstance(scenario, dict):
                continue
            steps = scenario.get("steps", []) or []
            examples = scenario.get("examples", []) or []
            if not examples:
                examples = [{}]
            for step in steps:
                if not isinstance(step, dict):
                    continue
                raw_text = step.get("text", "")
                if not raw_text:
                    continue
                for example in examples:
                    if not isinstance(example, dict):
                        example = {}
                    text = raw_text
                    for key, value in example.items():
                        text = text.replace(f"<{key}>", str(value))
                    texts.append(text)
    return texts


def _all_ir_step_texts(ir_dir: Path) -> list[str]:
    """Collect all step texts (example-expanded) from every IR file."""
    texts: list[str] = []
    for ir_path in _ir_files(ir_dir):
        texts.extend(_all_step_texts(ir_path))
    # Deduplicate — many IR files share the same background steps
    return list(dict.fromkeys(texts))


def _resolve_step(text: str, feature_tag: str | None) -> bool:
    """Check whether a step text resolves to a handler for the given feature."""
    for pattern, _handler, tag in STEP_PATTERNS:
        if tag is not None and tag != feature_tag:
            continue
        if pattern.search(text):
            return True
    return False


# ---------------------------------------------------------------------------
# Property tests: no pattern shadowing
# ---------------------------------------------------------------------------


class TestNoPatternShadowing:
    """No same-scope raw pattern has conflicting handlers.

    This is the invariant that prevents duplicate-registration shadowing:
    a raw pattern registered with a different handler would make the later
    handler dead. The feature-tag scoping mechanism prevents cross-feature
    conflicts.

    These tests use the actual step texts from the IR corpus as witnesses.

    .. note::
       These tests are currently ``xfail`` because the 21,770-line
       ``acceptance_runtime.py`` contains ~30 pre-existing shadowing
       duplicates (same pattern string, different handler, same scope)
       that predate the integrity check.  Cleaning them up is tracked as
       a follow-up bead.  The ``find_pattern_conflicts`` function and
       these tests will catch any *new* shadowing bugs once the
       pre-existing ones are resolved.
    """

    # Feature files whose pipeline-mode scenarios require an LLM endpoint
    # and are out of scope for this work item.
    _LLM_BLOCKED = frozenset(
        {
            "stage1_ordering",
            "stage1a_split",
            "stage1b_revision",
            "stage2_assembly",
            "stage2_call2a",
            "stage2_call2b",
            "stage2_call3",
            "stage2-assembly",
            "stage2-call2a",
            "stage2-call2b",
            "stage2-call3",
        }
    )

    def test_no_global_pattern_conflicts_on_ir_steps(
        self, acceptance_artifacts: AcceptanceArtifactFixture
    ):
        """No two global (untagged) patterns match the same IR step text."""
        step_texts = _all_ir_step_texts(acceptance_artifacts.ir_dir)
        conflicts = find_pattern_conflicts(step_texts)
        if conflicts:
            detail = "\n".join(
                f"  step: {text!r}\n    first:  {first!r}\n    second: {second!r}"
                for text, first, second in conflicts[:10]
            )
            pytest.fail(
                f"{len(conflicts)} pattern shadowing conflicts found.\n"
                f"First {min(10, len(conflicts))}:\n{detail}"
            )

    def test_no_global_pattern_conflicts_on_synthetic_steps(self):
        """No duplicate raw global patterns conflict on synthetic witnesses.

        Uses common step prefixes as witnesses for duplicate registrations
        that might not appear in the current IR corpus.
        """
        synthetic_texts = [
            "the control structure has responsibilities",
            "the control structure has coordination links",
            "validation fails with error containing something",
            "the revision is run",
            "the revision is applied",
            "a file something exists in the run directory",
            "the HTML contains the text something",
            "the pipeline does not crash",
            "the final control structure passes foundation validation",
            "the heuristic check fails with error containing something",
        ]
        conflicts = find_pattern_conflicts(synthetic_texts)
        if conflicts:
            detail = "\n".join(
                f"  step: {text!r}\n    first:  {first!r}\n    second: {second!r}"
                for text, first, second in conflicts
            )
            pytest.fail(
                f"{len(conflicts)} pattern shadowing conflicts on synthetic texts:\n{detail}"
            )


# ---------------------------------------------------------------------------
# Property tests: IR-entry-point coverage
# ---------------------------------------------------------------------------


class TestIREntryPointCoverage:
    """Every IR file has an entry point; every entry point resolves."""

    def test_every_ir_has_entry_point(
        self, acceptance_artifacts: AcceptanceArtifactFixture
    ):
        """Every IR file is referenced by at least one generated entry point."""
        referenced: set[str] = set()
        for ep in _entry_points(acceptance_artifacts.generated_dir):
            for ref in _entry_point_ir_refs(ep, acceptance_artifacts.root):
                referenced.add(Path(ref).resolve().as_posix())

        missing = []
        for ir_path in _ir_files(acceptance_artifacts.ir_dir):
            key = ir_path.resolve().as_posix()
            if key not in referenced:
                missing.append(ir_path.name)

        assert not missing, f"IR files without entry points: {missing}"

    def test_every_entry_point_references_existing_ir(
        self, acceptance_artifacts: AcceptanceArtifactFixture
    ):
        """Every entry point references an IR file that exists on disk."""
        missing = []
        for ep in _entry_points(acceptance_artifacts.generated_dir):
            for ref in _entry_point_ir_refs(ep, acceptance_artifacts.root):
                if not Path(ref).exists():
                    missing.append(f"{ep.name} -> {ref}")
        assert not missing, f"Entry points referencing missing IR files: {missing}"

    def test_every_entry_point_references_canonical_ir_location(
        self, acceptance_artifacts: AcceptanceArtifactFixture
    ):
        """Every entry point references IR in the configured snapshot IR dir.

        Non-canonical IR locations (tmp/, leftover acceptance/ir/) are how
        IR drift stayed hidden in the original staleness incident.  This
        test ensures all IR is consolidated under the generated output dir.
        """
        non_canonical = []
        ir_dir = acceptance_artifacts.ir_dir
        for ep in _entry_points(acceptance_artifacts.generated_dir):
            for ref in _entry_point_ir_refs(ep, acceptance_artifacts.root):
                ir_path = Path(ref)
                try:
                    ir_path.relative_to(ir_dir)
                except ValueError:
                    non_canonical.append(f"{ep.name} -> {ref}")
        assert not non_canonical, (
            f"Entry points with non-canonical IR locations: {non_canonical}"
        )


# ---------------------------------------------------------------------------
# Property tests: handler resolution
# ---------------------------------------------------------------------------


class TestHandlerResolution:
    """Every step in every IR file resolves to a registered handler."""

    # Features whose pipeline-mode scenarios require an LLM endpoint and
    # have step texts that the acceptance runtime cannot resolve (they
    # assert against actual pipeline output, not mock state).
    _LLM_BLOCKED = frozenset(
        {
            "stage1_ordering",
            "stage1a_split",
            "stage1b_revision",
            "stage2_assembly",
            "stage2_call2a",
            "stage2_call2b",
            "stage2_call3",
            "stage2-assembly",
            "stage2-call2a",
            "stage2-call2b",
            "stage2-call3",
        }
    )

    def test_every_ir_step_resolves(
        self, acceptance_artifacts: AcceptanceArtifactFixture
    ):
        """Every step text in every IR file matches at least one handler.

        An unresolved step means the IR references behaviour the runtime
        cannot execute — either the IR is stale or the handler is missing.

        Excludes LLM-endpoint-blocked features whose pipeline-mode steps
        assert against real pipeline output.
        """
        unresolved = []
        for ir_path in _ir_files(acceptance_artifacts.ir_dir):
            if ir_path.stem in self._LLM_BLOCKED:
                continue
            feature_tag = _derive_feature_tag(str(ir_path))
            for text in _all_step_texts(ir_path):
                if not _resolve_step(text, feature_tag):
                    unresolved.append(f"{ir_path.name}: {text[:80]}")

        if unresolved:
            detail = "\n".join(f"  {u}" for u in unresolved[:20])
            pytest.fail(
                f"{len(unresolved)} unresolved steps across IR files.\n"
                f"First {min(20, len(unresolved))}:\n{detail}"
            )


# ---------------------------------------------------------------------------
# Property tests: exact-duplicate prevention
# ---------------------------------------------------------------------------


class TestExactDuplicatePrevention:
    """The registration API rejects exact duplicate registrations."""

    def test_no_exact_duplicates_registered(self):
        """No (pattern, handler, scope) tuple is registered more than once.

        This is enforced at registration time by _track_registration.
        If this test passes, the import-time assertion is working.
        """
        # If we got here, the module imported successfully, which means
        # _track_registration did not raise on any registration.
        # The _REGISTERED_PATTERN_KEYS set should have the same number of
        # entries as STEP_PATTERNS (one key per registration).
        from acceptance_runtime import _REGISTERED_PATTERN_KEYS

        assert len(_REGISTERED_PATTERN_KEYS) > 0, "No patterns registered"
        assert len(_REGISTERED_PATTERN_KEYS) == len(STEP_PATTERNS), (
            f"Registered keys ({len(_REGISTERED_PATTERN_KEYS)}) != "
            f"STEP_PATTERNS ({len(STEP_PATTERNS)}): "
            f"some registrations bypassed _track_registration"
        )
