"""Small in-memory authorities shared by qualification-focused tests."""

from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any

from asago_scenario_generator.manifest import ArtifactRole
from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    ConfidenceLevel,
    EntryPoint,
    InventoryCompleteness,
)
from asago_scenario_generator.pipeline.persistence import (
    CoveragePlanV2,
    FinalizationInventoryV1,
)


@dataclass
class _Entry:
    role: ArtifactRole
    path: str
    scenario_id: str | None = None


class QualificationResolver:
    """Minimal resolver authority for deterministic qualification tests."""

    def __init__(self, *, confirmed: bool = False) -> None:
        self.manifest = SimpleNamespace(
            manifest_version="3",
            run_id="20260101T000000_abcdef0123456789abcdef0123456789",
        )
        self.plan = CoveragePlanV2(
            schema_version="2",
            completeness="confirmed_complete" if confirmed else "not_applicable",
            evidence_refs=["operator-review:test"] if confirmed else [],
            targets=[],
            selection_limitation_target_ids=[],
        )
        self.final = FinalizationInventoryV1(
            schema_version="1",
            run_id=self.manifest.run_id,
            coverage_plan_sha256="a" * 64,
            candidate_attempts=[],
            stage_attempts=[],
            transitions=[],
            repairs=[],
            admission_decisions=[],
            admitted_inventory=[],
            quarantine_inventory=[],
        )
        self.profile = CapabilityProfile(
            zones_active=["input"],
            entry_points=[EntryPoint(name="prompt", direction="input")],
            confidence=ConfidenceLevel.medium,
            kc_subcodes=["KC1.1"],
            entry_point_completeness=(
                InventoryCompleteness.operator_confirmed_complete
                if confirmed
                else InventoryCompleteness.inferred_partial
            ),
            entry_point_evidence=["operator-review:test"] if confirmed else [],
        )
        self.entries = {
            ArtifactRole.COVERAGE_PLAN: _Entry(
                ArtifactRole.COVERAGE_PLAN, "coverage-plan.json"
            ),
            ArtifactRole.FINALIZATION_INVENTORY: _Entry(
                ArtifactRole.FINALIZATION_INVENTORY, "finalization-inventory.json"
            ),
            ArtifactRole.CAPABILITY_PROFILE: _Entry(
                ArtifactRole.CAPABILITY_PROFILE, "capability-profile.yaml"
            ),
        }

    def entry_by_role(self, role: ArtifactRole) -> _Entry | None:
        return self.entries.get(role)

    def read_text(self, entry: _Entry) -> str:
        value = self.plan if entry.role is ArtifactRole.COVERAGE_PLAN else self.final
        return value.model_dump_json()

    def read_yaml(self, entry: _Entry) -> dict[str, Any]:
        assert entry.role is ArtifactRole.CAPABILITY_PROFILE
        return self.profile.model_dump(mode="json")

    def scenario_yaml_entries(self) -> list[_Entry]:
        return []

    def scenario_feature_entries(self) -> list[_Entry]:
        return []


_Resolver = QualificationResolver

__all__ = ["QualificationResolver", "_Resolver"]
