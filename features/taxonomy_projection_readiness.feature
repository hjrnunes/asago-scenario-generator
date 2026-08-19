Feature: Taxonomy projection architecture readiness
  Taxonomy generation checks the selected authoritative patterns against the
  supplied capability profile and qualification facts before projection.
  Missing architecture evidence stops the run with guidance instead of being
  mistaken for an ordinary zero-candidate result.

  Background:
    Given taxonomy generation uses selected authoritative attack patterns
    And Stage 1 inference remains limited to Stage 1 capability fields

  # Taxonomy projection architecture readiness 01 proceeds when required evidence is available
  Scenario: Taxonomy projection architecture readiness 01 proceeds when required evidence is available
    Given the profile supplies every architecture resource category required by the selected patterns
    And the qualification facts resolve every required authoritative fact
    When projection readiness is checked
    Then projection begins
    And no architecture-readiness error is reported

  # Taxonomy projection architecture readiness 02 stops before projection when architecture resources are absent
  Scenario: Taxonomy projection architecture readiness 02 stops before projection when architecture resources are absent
    Given the selected patterns require resource categories "external_integrations,trust_boundaries"
    And the inferred profile supplies neither required resource category
    When projection readiness is checked
    Then projection does not begin
    And no scenario-generation call begins
    And the run does not report normal completion
    And the user-visible error lists missing resource categories "external_integrations,trust_boundaries"
    And the user-visible error directs the user to supply a reviewed architecture with "--profile"
    And no architecture enrichment workflow is launched

  # Taxonomy projection architecture readiness 03 identifies missing qualification evidence
  Scenario: Taxonomy projection architecture readiness 03 identifies missing qualification evidence
    Given a selected pattern requires qualification fact "deployment.attacker_code_execution_on_agent_host"
    And that fact has no authoritative reading
    When projection readiness is checked
    Then projection does not begin
    And the run does not report normal completion
    And the user-visible error identifies missing fact "deployment.attacker_code_execution_on_agent_host"
    And the user-visible error directs the user to supply "--qualification-facts"
    And no architecture enrichment workflow is launched
