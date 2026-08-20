"""ScenarioSpec boundary schema (Section 4.5 of the STPA-Sec foundation spec).

SP3 internal, produced by Stage 5.

Cross-artifact validation against ControlStructure requires the
referencing model to have access to the referenced model. This is
handled by the ``validate_against`` method.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, Field

from asago_scenario_generator.stpa.models.causal_factor import (
    CausalFactor,
    validate_factor_sources,
)
from asago_scenario_generator.stpa.models.enriched_threat_set import CatalogMapping
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType

if TYPE_CHECKING:
    from asago_scenario_generator.stpa.models.control_structure import ControlStructure


class DefenderBelief(BaseModel):
    """A defender belief referencing a process model part."""

    pm_id: str  # references ControlStructure PM
    content: str
    vulnerability: str  # LLM-added annotation


class DefenderDesire(BaseModel):
    """A defender desire referencing a responsibility."""

    resp_id: str  # references ControlStructure RESP
    content: str


class DefenderIntention(BaseModel):
    """A defender intention referencing a control action."""

    ca_id: str  # references ControlStructure CA
    content: str


class DefenderBDI(BaseModel):
    """Defender Belief-Desire-Intention model."""

    beliefs: list[DefenderBelief]
    desires: list[DefenderDesire]
    intentions: list[DefenderIntention]


class AttackerBDI(BaseModel):
    """Attacker Belief-Desire-Intention model (free-form strings)."""

    beliefs: list[str]
    desires: list[str]
    intentions: list[str]


class ThreatSource(BaseModel):
    """The source threat for a scenario."""

    ica_slot_id: str  # RESP-X:CA-Y:TYPE-Z or CL-X:CM-Y:TYPE-Z
    provenance: Literal["structural", "catalog_only"]
    ica_id: str | None = None


class ScenarioSpec(BaseModel):
    """A scenario specification produced by Stage 5."""

    scenario_id: str  # SCN-001, ...
    threat_source: ThreatSource
    target_controller: str  # resp_id
    target_control_action: str  # ca_id
    ica_type: UCAType
    defender_bdi: DefenderBDI
    attacker_bdi: AttackerBDI
    catalog_context: list[CatalogMapping] = Field(default_factory=list)
    loss_scenario: str  # carried from Stage 3
    # Stage 5 declared, evidence-backed causal factors in declared order.
    # Only factors the LLM explicitly declared with evidence are stored;
    # structural presence alone never invents a factor.  Empty is valid
    # and means "no declared factors".
    causal_factors: list[CausalFactor] = Field(default_factory=list)

    def validate_against(self, control_structure: ControlStructure) -> None:
        """Validate scenario spec references against a ControlStructure.

        Checks:
        - Every DefenderBelief.pm_id references a valid PM.
        - Every DefenderDesire.resp_id references a valid RESP.
        - Every DefenderIntention.ca_id references a valid CA.
        - target_controller references a valid RESP.
        - target_control_action references a valid CA belonging to
          target_controller.
        - Every causal-factor reference resolves to its PM/FB/CA
          namespace in the control structure.

        Args:
            control_structure: The control structure to validate against.

        Raises:
            ValueError: If any reference is invalid.
        """
        resp_ids, all_pm_ids, all_ca_ids, ca_to_resp = _build_lookup_maps(
            control_structure
        )

        _validate_target(
            self.target_controller,
            self.target_control_action,
            resp_ids,
            all_ca_ids,
            ca_to_resp,
        )
        _validate_defender_bdi(self.defender_bdi, all_pm_ids, resp_ids, all_ca_ids)
        validate_factor_sources(control_structure, self.causal_factors)


def _build_lookup_maps(
    cs: ControlStructure,
) -> tuple[set[str], set[str], set[str], dict[str, str]]:
    """Build lookup maps from a control structure's responsibilities.

    Returns:
        A tuple of (resp_ids, all_pm_ids, all_ca_ids, ca_to_resp).
    """
    resp_ids: set[str] = set()
    all_pm_ids: set[str] = set()
    all_ca_ids: set[str] = set()
    ca_to_resp: dict[str, str] = {}

    for resp in cs.responsibilities:
        resp_ids.add(resp.resp_id)
        for pm in resp.process_model_parts:
            all_pm_ids.add(pm.pm_id)
        for ca in resp.control_actions:
            all_ca_ids.add(ca.ca_id)
            ca_to_resp[ca.ca_id] = resp.resp_id

    return resp_ids, all_pm_ids, all_ca_ids, ca_to_resp


def _validate_target(
    target_controller: str,
    target_control_action: str,
    resp_ids: set[str],
    all_ca_ids: set[str],
    ca_to_resp: dict[str, str],
) -> None:
    """Validate target_controller and target_control_action references."""
    if target_controller not in resp_ids:
        raise ValueError(
            f"target_controller '{target_controller}' is not a valid responsibility ID."
        )
    if target_control_action not in all_ca_ids:
        raise ValueError(
            f"target_control_action '{target_control_action}' is not a "
            f"valid control action ID."
        )
    if ca_to_resp.get(target_control_action) != target_controller:
        raise ValueError(
            f"target_control_action '{target_control_action}' does not "
            f"belong to target_controller '{target_controller}'."
        )


def _validate_defender_bdi(
    defender_bdi: DefenderBDI,
    all_pm_ids: set[str],
    resp_ids: set[str],
    all_ca_ids: set[str],
) -> None:
    """Validate defender BDI references against control structure lookups."""
    _validate_ref_items(defender_bdi.beliefs, "pm_id", all_pm_ids, "DefenderBelief")
    _validate_ref_items(defender_bdi.desires, "resp_id", resp_ids, "DefenderDesire")
    _validate_ref_items(
        defender_bdi.intentions, "ca_id", all_ca_ids, "DefenderIntention"
    )


def _validate_ref_items(
    items: list,
    attr_name: str,
    valid_ids: set[str],
    model_name: str,
) -> None:
    """Validate that each item's *attr_name* references a valid ID."""
    for item in items:
        ref_value = getattr(item, attr_name)
        if ref_value not in valid_ids:
            raise ValueError(
                f"{model_name} references non-existent {attr_name} '{ref_value}'."
            )


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-08T23:13:34Z","module_hash":"bacc4f02e593f9ea7c19867c78c89252298d61f761c197f1c5e6e1abc094ab6f","functions":[{"id":"func/ScenarioSpec.validate_against","name":"validate_against","line":82,"end_line":112,"hash":"b5f3b0fff2dade0010ce3d68b761fe6f173237300c4c658255b955186ce3c081"},{"id":"func/_build_lookup_maps","name":"_build_lookup_maps","line":115,"end_line":136,"hash":"b114dd4e0d6acbec60c82defef2d8b4170618b683673aa2bceb71f9343dda7b0"},{"id":"func/_validate_target","name":"_validate_target","line":139,"end_line":161,"hash":"d40818f06ac8a94db8511b0199b91691dd8cf0c82e374686938ff7075d7b0d2d"},{"id":"func/_validate_defender_bdi","name":"_validate_defender_bdi","line":164,"end_line":179,"hash":"cd5f60176463094dee673af1db7275677030c230ba9265974fc12f268d4bd5ae"},{"id":"func/_validate_ref_items","name":"_validate_ref_items","line":182,"end_line":195,"hash":"4122803ce918efdb06fd1da19cc87ccc13e6a70333dd4b6e59d08591543481ae"}]}
# mutate4py-manifest-end
