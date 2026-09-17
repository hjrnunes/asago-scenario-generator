"""R6 field-level inventory checks."""

from __future__ import annotations

import json
from pathlib import Path

from scripts.qualification.audit_scenario_fidelity_evidence import (
    build_field_inventory,
    write_field_inventory,
)


def test_inventory_covers_both_products_and_all_eight_variants(tmp_path: Path) -> None:
    inventory = build_field_inventory()
    fields = {item["field"] for item in inventory["fields"]}

    assert "adversary.kind" in fields
    assert "unsafe_outcome.semantic_proposition" in fields
    assert "stimulus_text" in fields
    assert "argument_values" in fields
    assert len(inventory["rendered_input_variants"]) == 8
    assert inventory["unused_demands"] == []
    assert inventory["contradictions"] == []

    path = write_field_inventory(tmp_path)
    assert json.loads(path.read_text()) == inventory


def test_inventory_fields_reconcile_to_prompt_and_schema_authorities() -> None:
    inventory = build_field_inventory()

    for field in inventory["fields"]:
        assert field["prompt"]
        assert field["schema"]
        assert field["downstream_use"]
