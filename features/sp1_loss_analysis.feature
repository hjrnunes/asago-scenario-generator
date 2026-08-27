# mutation-stamp: sha256=34dba8d0a0a254c5f9d8d9edd1b00cb5404e1a20c9bc5d488b88c5472d340bac
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-08T14:51:59.093449Z","feature_name":"SP1 Stage 1a \u2014 Loss Analysis derivation","feature_path":"features/sp1_loss_analysis.feature","background_hash":"308166141490735c84fabbe40c5c62f66592cf62e157ebf616cb79c3a16638c0","implementation_hash":"unknown","scenarios":[{"index":3,"name":"SP1-LA-04 LLM response with invalid cross-reference fails post-call validation","scenario_hash":"7271079a390b8cc8619e9f4eae194cfd1c45947411cfc9696bdc660a5ca08a71","mutation_count":6,"result":{"Total":6,"Killed":6,"Survived":0,"Errors":0},"tested_at":"2026-08-08T14:51:59.093449Z"}]}
# acceptance-mutation-manifest-end

Feature: SP1 Stage 1a — Loss Analysis derivation
  Stage 1a derives losses, hazards, and security constraints from use-case
  text and risk cards via a single LLM call. Output is a valid LossAnalysis
  with dual-source provenance: risk-card-derived losses (provenance=risk_card,
  non-empty source_risk_cards) and use-case-derived losses (provenance=use_case,
  empty source_risk_cards). Post-call validation enforces the same rules as
  the foundation LossAnalysis schema.

  Background:
    Given the STPA system model module is importable
    And a use-case description and risk cards are available as input

  # SP1-LA-01
  Scenario: SP1-LA-01 valid LLM response produces a valid LossAnalysis
    Given an LLM that returns a valid loss analysis JSON with risk-card losses and use-case losses
    When Stage 1a loss analysis is run
    Then a LossAnalysis model is produced
    And the loss analysis passes foundation validation

  # SP1-LA-02
  Scenario: SP1-LA-02 risk-card-derived losses have correct provenance
    Given an LLM that returns losses L-1 and L-2 with provenance risk_card and source_risk_cards atlas-001 and atlas-002
    When Stage 1a loss analysis is run
    Then the risk_card_losses contain L-1 and L-2 with provenance risk_card
    And each risk_card_loss has non-empty source_risk_cards

  # SP1-LA-03
  Scenario: SP1-LA-03 use-case-derived losses have correct provenance
    Given an LLM that returns loss L-3 with provenance use_case and empty source_risk_cards
    When Stage 1a loss analysis is run
    Then the use_case_losses contain L-3 with provenance use_case
    And each use_case_loss has empty source_risk_cards

  # SP1-LA-04
  Scenario Outline: SP1-LA-04 LLM response with invalid cross-reference fails post-call validation
    Given an LLM that returns a loss analysis where <entity> references non-existent <ref_target>
    When Stage 1a loss analysis is run
    Then post-call validation fails with error containing <error_fragment>

    Examples:
      | entity           | ref_target | error_fragment     |
      | hazard           | loss L-99  | related_losses     |
      | constraint       | hazard H-99| related_hazards    |

  # SP1-LA-05
  Scenario: SP1-LA-05 LLM response with risk-card loss missing source_risk_cards fails
    Given an LLM that returns a risk-card loss L-1 with empty source_risk_cards
    When Stage 1a loss analysis is run
    Then post-call validation fails with error containing source_risk_cards

  # SP1-LA-06
  Scenario: SP1-LA-06 LLM response with use-case loss having source_risk_cards fails
    Given an LLM that returns a use-case loss L-3 with source_risk_cards atlas-001
    When Stage 1a loss analysis is run
    Then post-call validation fails with error containing source_risk_cards

  # SP1-LA-07
  Scenario: SP1-LA-07 LLM response with duplicate loss IDs fails
    Given an LLM that returns a loss analysis with duplicate loss_id L-1
    When Stage 1a loss analysis is run
    Then post-call validation fails with error containing duplicate

  # SP1-LA-08
  Scenario: SP1-LA-08 LLM call is logged with stage stage_1a
    Given an LLM that returns a valid loss analysis JSON
    And a run directory for call logging
    When Stage 1a loss analysis is run
    Then a call log entry is appended with stage stage_1a
    And the call log entry step is loss_analysis

  # SP1-LA-09
  Scenario: SP1-LA-09 loss analysis is written to loss-analysis.yaml
    Given an LLM that returns a valid loss analysis JSON
    And a run directory for output
    When Stage 1a loss analysis is run
    Then a file loss-analysis.yaml exists in the run directory
    And the file contains a valid LossAnalysis model when read back

  # SP1-LA-10
  Scenario: SP1-LA-10 both risk-card and use-case losses can coexist
    Given an LLM that returns risk-card losses L-1 and L-2 and use-case losses L-3 and L-4
    When Stage 1a loss analysis is run
    Then the risk_card_losses contain L-1 and L-2
    And the use_case_losses contain L-3 and L-4
    And the loss analysis passes foundation validation

  # SP1-LA-11
  Scenario: SP1-LA-11 every hazard links to at least one loss
    Given an LLM that returns a loss analysis with hazard H-1 referencing L-1 and hazard H-2 referencing L-2
    When Stage 1a loss analysis is run
    Then the loss analysis passes foundation validation

  # SP1-LA-12
  Scenario: SP1-LA-12 every security constraint links to at least one hazard
    Given an LLM that returns a loss analysis with constraint SC-1 referencing H-1 and constraint SC-2 referencing H-2
    When Stage 1a loss analysis is run
    Then the loss analysis passes foundation validation

  # SP1-LA-13
  Scenario: SP1-LA-13 dangling Stage 1a reference is repaired with one retry
    Given an LLM that returns a Stage 1a draft with a dangling reference followed by a corrected draft
    When Stage 1a loss analysis is run
    Then Stage 1a loss analysis succeeds after one reference retry
    And the Stage 1a retry includes validation feedback
    And the Stage 1a attempts are logged with one failure and two successes

  # SP1-LA-14
  Scenario: SP1-LA-14 repeated dangling Stage 1a reference fails after one retry
    Given an LLM that returns a Stage 1a draft with the same dangling reference twice
    When Stage 1a loss analysis is run
    Then Stage 1a validation fails after one reference retry
    And the Stage 1a attempts are logged as two failures
