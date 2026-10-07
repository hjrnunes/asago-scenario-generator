"""Surfaces the product removed must stay removed.

Each case observes one public surface and names what it must no longer carry.
Add a case here instead of a new compatibility file when you remove a flag, a
payload field, or a catalog record.

The five historical T7 records (AP-T7-01..05) left the live catalog for good:
AP-T7-01 is deferred and AP-T7-02..05 are retired, with an empty authoritative
resulting-ID set. No T7 source has a defensible exact ATLAS identity, so
``catalog-lineage.yaml`` records the dispositions and the live side pins only
that the merged catalog carries none of them.
"""

from __future__ import annotations

from collections.abc import Callable, Collection
from pathlib import Path

import pytest

from asago_scenario_generator.cli import app
from asago_scenario_generator.data.loaders import load_attack_patterns
from tests.cli_helpers import PlainCliRunner
from tests.helpers.obligation_factory import make_plan

T7_FILE = (
    Path(__file__).resolve().parents[1]
    / "data"
    / "taxonomies"
    / "attack-patterns"
    / "attack-patterns.yaml"
)


def _generate_help() -> str:
    result = PlainCliRunner().invoke(app, ["generate", "--help"])
    assert result.exit_code == 0
    return result.stdout.lower()


def _plan_payload_keys() -> Collection[str]:
    return make_plan().model_dump(mode="json")


def _merged_pattern_ids() -> Collection[str]:
    return load_attack_patterns()


def _merged_threat_ids() -> Collection[str]:
    return {pattern["threat_id"] for pattern in load_attack_patterns().values()}


def _stage5_wire_names() -> Collection[str]:
    from asago_scenario_generator.stpa.scenario_prod.stage5 import wire

    return dir(wire)


# (surface, observation, names that must be absent from the observation)
REMOVED_SURFACES: list[
    tuple[str, Callable[[], Collection[str] | str], tuple[str, ...]]
] = [
    (
        "generate --help: manual resource-map flags",
        _generate_help,
        ("resource-map",),
    ),
    (
        "standalone plan payload: provider and generation counters",
        _plan_payload_keys,
        ("network_calls", "model_calls", "generation_inputs_digest"),
    ),
    (
        "merged catalog: T7 pattern ids",
        _merged_pattern_ids,
        ("AP-T7-01", "AP-T7-02", "AP-T7-03", "AP-T7-04", "AP-T7-05"),
    ),
    (
        "merged catalog: T7 threat id",
        _merged_threat_ids,
        ("T7",),
    ),
    (
        "stage 5 wire: the execution-route factor base",
        _stage5_wire_names,
        ("_ContextCausalFactorWireBase",),
    ),
]


@pytest.mark.parametrize(
    ("observe", "absent"),
    [
        pytest.param(observe, absent, id=surface)
        for surface, observe, absent in REMOVED_SURFACES
    ],
)
def test_removed_surface_stays_removed(
    observe: Callable[[], Collection[str] | str], absent: tuple[str, ...]
) -> None:
    observed = observe()
    reintroduced = [name for name in absent if name in observed]
    assert not reintroduced, f"removed surface is back: {reintroduced}"


def test_t7_file_stays_loader_valid_with_zero_live_records() -> None:
    """The historical file stays on disk and yields no patterns."""
    assert T7_FILE.is_file(), "the historical T7 file must not be deleted"
    assert load_attack_patterns(path=T7_FILE) == {}
