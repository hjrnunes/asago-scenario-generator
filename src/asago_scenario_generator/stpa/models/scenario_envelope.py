"""ScenarioEnvelope boundary schema (Section 4.6 of the STPA-Sec foundation spec).

SP3 final output. Wraps Stage 6 artifacts (narrative, attack tree, Gherkin)
plus the ScenarioSpec and faceting metadata.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, model_validator

from asago_scenario_generator.stpa.models.enriched_threat_set import CatalogMapping
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.models.scenario_spec import ScenarioSpec


class GherkinSpec(BaseModel):
    """Structured Gherkin behavior specification (Stage 6 Call C output).

    The fields capture the should/but structure:
    - ``given`` — Given steps (process model state references).
    - ``when`` — When steps (triggering event).
    - ``then_expected`` — Then ... should ... steps (expected safe behavior).
    - ``then_actual`` — unsafe-alternative metadata retained outside the
      executable expected sequence.
    """

    feature: str
    scenario: str
    given: list[str]
    when: list[str]
    then_expected: list[str]
    then_actual: list[str]

    def to_feature_text(self) -> str:
        """Render the structured spec to declarative Gherkin feature text.

        ``then_actual`` is retained as structured unsafe-alternative metadata
        for the handoff and validators.  It is deliberately rendered as a
        comment so the real Gherkin parser exposes only the safe executable
        sequence to downstream adapters.
        """
        lines: list[str] = [f"Feature: {self.feature}"]
        lines.append(f"Scenario: {self.scenario}")
        for step in self.given:
            lines.append(f"  {step}")
        for step in self.when:
            lines.append(f"  {step}")
        for step in self.then_expected:
            lines.append(f"  {step}")
        for step in self.then_actual:
            lines.append(f"  # Unsafe alternative (non-executable): {step}")
        return "\n".join(lines) + "\n"


class SystemContext(BaseModel):
    """Inline SP1 system context block for the scenario envelope.

    Populated deterministically during assembly from the capability
    profile and control structure — no LLM calls.  Lets adapters
    interpret scenarios without separate SP1 artifacts.
    """

    target_responsibility_description: str
    target_control_action_description: str
    tool_inventory: list[str]  # tool names
    active_zones: list[str]
    multi_agent: bool
    has_persistent_memory: bool


class ConsumerHints(BaseModel):
    """Deterministic consumer hints for adapter filtering.

    Populated in a post-generation enrichment pass from the capability
    profile, attack tree, and narrative — no LLM calls.  Lets adapters
    self-select scenarios without LLM inference.
    """

    primary_attack_zone: str
    requires_tool_execution: bool
    requires_multi_turn: bool
    requires_multi_agent: bool
    requires_persistent_state: bool
    garak_testability: Literal["high", "medium", "low"]
    midojo_testability: Literal["high", "medium", "low"]


class ScenarioEnvelope(BaseModel):
    """Scenario envelope wrapping Stage 6 artifacts and faceting metadata."""

    scenario_id: str
    scenario_spec: ScenarioSpec
    narrative: str  # Stage 6 Call A output
    attack_tree: dict  # Stage 6 Call B output (YAML-serializable tree)
    gherkin_spec: GherkinSpec  # Stage 6 Call C output (structured)
    gherkin_raw: str = ""  # Raw LLM text for .feature file generation
    # Faceting metadata for querying/filtering
    target_responsibility: str
    ica_type: UCAType
    catalog_mappings: list[CatalogMapping] = Field(default_factory=list)
    provenance: str  # "structural" or "catalog_only"
    # Enrichment blocks (optional, backward compat)
    system_context: SystemContext | None = None
    consumer_hints: ConsumerHints | None = None

    @model_validator(mode="after")
    def validate_scenario_id_match(self) -> ScenarioEnvelope:
        if self.scenario_id != self.scenario_spec.scenario_id:
            raise ValueError(
                f"ScenarioEnvelope scenario_id '{self.scenario_id}' does not "
                f"match scenario_spec scenario_id "
                f"'{self.scenario_spec.scenario_id}'."
            )
        return self
