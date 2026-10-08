"""A scenario context carries the threat's catalog mappings as catalog context."""

from __future__ import annotations

from asago_scenario_generator.stpa.models.enriched_threat_set import CatalogMapping
from asago_scenario_generator.stpa.scenario_prod.context import (
    build_scenario_generation_context,
)
from tests.helpers.sp3_scenario_continuity import (
    _control_structure,
    _loss_analysis,
    _threat,
)


def test_catalog_mappings_become_ordered_catalog_context() -> None:
    threat = _threat().model_copy(
        update={
            "catalog_mappings": [
                CatalogMapping(
                    catalog="OWASP_AGENTIC",
                    id="T1",
                    name="Prompt Injection",
                    confidence="low",
                ),
                CatalogMapping(
                    catalog="MITRE_ATLAS",
                    id="AML.T0051",
                    name="LLM Prompt Injection",
                    confidence="high",
                ),
            ]
        }
    )

    context = build_scenario_generation_context(
        threat, _control_structure(), _loss_analysis(), scenario_id="SCN-001"
    )

    assert [
        (item.catalog, item.entry_id, item.name, item.confidence)
        for item in context.catalog_context
    ] == [
        ("OWASP_AGENTIC", "T1", "Prompt Injection", "low"),
        ("MITRE_ATLAS", "AML.T0051", "LLM Prompt Injection", "high"),
    ]
