"""Persistence for the shared capability-profile input artifact."""

from __future__ import annotations

from pathlib import Path

import yaml

from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    inject_kc_subcodes_display,
)


def write_capability_profile(profile: CapabilityProfile, output_dir: Path) -> Path:
    """Write the canonical capability profile used by STPA preparation."""
    path = output_dir / "capability-profile.yaml"
    data = inject_kc_subcodes_display(
        profile.model_dump(mode="json", exclude_none=True)
    )
    path.write_text(
        yaml.dump(
            data,
            default_flow_style=False,
            sort_keys=False,
            allow_unicode=True,
        ),
        encoding="utf-8",
    )
    return path


__all__ = ["write_capability_profile"]
