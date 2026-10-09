"""Tests for STPA infra YAML I/O (InfraYAML-01 through InfraYAML-04)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from asago_scenario_generator.stpa.infra.yaml_io import (
    read_yaml,
    write_yaml,
    yaml_text,
)
from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.models.ica_enumeration import ICAEnumeration
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from tests.stpa.helpers import (
    make_ica_slot,
    make_minimal_control_structure,
    make_minimal_loss_analysis,
)


class TestInfraYAML:
    """YAML read/write helpers."""

    def test_yaml_01_write_yaml_serializes_model(self, tmp_path):
        """InfraYAML-01: write_yaml produces a YAML file with model data."""
        model = make_minimal_loss_analysis()
        path = tmp_path / "loss_analysis.yaml"
        write_yaml(model, path)
        assert path.exists()
        text = path.read_text()
        assert "L-1" in text

    def test_yaml_02_read_yaml_loads_into_model(self, tmp_path):
        """InfraYAML-02: read_yaml loads YAML into a Pydantic model."""
        model = make_minimal_loss_analysis()
        path = tmp_path / "loss_analysis.yaml"
        write_yaml(model, path)
        loaded = read_yaml(path, LossAnalysis)
        assert isinstance(loaded, LossAnalysis)
        all_losses = loaded.risk_card_losses + loaded.use_case_losses
        assert all_losses[0].loss_id == "L-1"

    def test_yaml_03_round_trip_preserves_data(self, tmp_path):
        """InfraYAML-03: YAML round-trip preserves model data."""
        original = make_minimal_control_structure()
        path = tmp_path / "control_structure.yaml"
        write_yaml(original, path)
        loaded = read_yaml(path, ControlStructure)
        assert loaded.responsibilities[0].resp_id == "RESP-1"
        assert loaded.responsibilities[0].process_model_parts[0].pm_id == "PM-1-1"

    def test_yaml_04_read_yaml_on_invalid_data_raises(self, tmp_path):
        """InfraYAML-04: read_yaml on invalid data raises validation error."""
        invalid_yaml = """
risk_card_losses: []
use_case_losses:
  - loss_id: L-1
    description: Loss
    provenance: use_case
hazards:
  - hazard_id: H-1
    description: Hazard
    related_losses: ["L-99"]
security_constraints: []
"""
        path = tmp_path / "invalid.yaml"
        path.write_text(invalid_yaml)
        with pytest.raises(ValidationError):
            read_yaml(path, LossAnalysis)

    def test_yaml_05_creates_nested_parent_dirs(self, tmp_path):
        """InfraYAML-05: write_yaml creates nested parent directories."""
        model = make_minimal_loss_analysis()
        path = tmp_path / "nested" / "sub" / "dir" / "output.yaml"
        write_yaml(model, path)
        assert path.exists()

    def test_yaml_06_excludes_none_fields_from_yaml(self, tmp_path):
        """InfraYAML-06: write_yaml excludes None-valued fields from output."""
        # ICASlot has coordination_link=None and na_justification=None
        model = ICAEnumeration(slots=[make_ica_slot()])
        path = tmp_path / "ica.yaml"
        write_yaml(model, path)
        text = path.read_text()
        # With exclude_none=True, None fields should not appear in the YAML
        assert "coordination_link" not in text
        assert "na_justification" not in text

    def test_yaml_07_yaml_text_keeps_explicit_nulls_on_request(self):
        """InfraYAML-07: yaml_text(exclude_none=False) keeps None fields as null."""
        model = ICAEnumeration(slots=[make_ica_slot()])

        kept = yaml_text(model, exclude_none=False)

        assert "coordination_link: null" in kept
        assert "na_justification: null" in kept

    def test_yaml_08_yaml_text_is_what_write_yaml_persists(self, tmp_path):
        """InfraYAML-08: write_yaml writes exactly the yaml_text of the model."""
        model = ICAEnumeration(slots=[make_ica_slot()])
        path = tmp_path / "ica.yaml"

        write_yaml(model, path)

        assert path.read_text(encoding="utf-8") == yaml_text(model)
