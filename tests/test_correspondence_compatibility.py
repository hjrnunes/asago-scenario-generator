"""Unit tests verifying backward compatibility when correspondence is introduced."""

from __future__ import annotations

from asago_scenario_generator.models.system_resource_map import (
    ControlActionEntry,
    SystemResourceEntry,
    SystemResourceMap,
)
from asago_scenario_generator.pipeline.correspondence import (
    propose_correspondence,
    reconcile_correspondence,
)


def test_correspondence_does_not_mutate_inputs() -> None:
    srm = SystemResourceMap(
        schema_version="1",
        stpa_version="stpa-v1",
        taxonomy_version="atlas-2026.05",
        system_resources=[
            SystemResourceEntry(
                element_id="SR-1",
                taxonomy_ref="ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
        ],
        control_actions=[
            ControlActionEntry(
                element_id="CA-1-1",
                controller_id="RESP-1",
                process_id="CP-2",
                action_name="Issue Payment",
            )
        ],
    )
    initial_yaml = srm.to_yaml()

    source_artifacts = {
        "control_structure": {"key": "val"},
        "attack_patterns": "raw tsv data",
    }
    initial_cs = dict(source_artifacts["control_structure"])
    initial_ap = str(source_artifacts["attack_patterns"])

    pset = propose_correspondence(srm, source_artifacts=source_artifacts)
    res = reconcile_correspondence(srm, pset)

    assert res.is_valid
    # SRM unchanged
    assert srm.to_yaml() == initial_yaml
    # Source artifacts unchanged
    assert source_artifacts["control_structure"] == initial_cs
    assert source_artifacts["attack_patterns"] == initial_ap
