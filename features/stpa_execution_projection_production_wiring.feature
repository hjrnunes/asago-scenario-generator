# STPA-PROD-WIRING-01, STPA-PROD-WIRING-02, STPA-PROD-WIRING-03, STPA-PROD-WIRING-04, STPA-PROD-WIRING-05, STPA-PROD-WIRING-06
Feature: STPA post-SP3 execution projection production wiring
  Stage 5 selects declared, evidence-backed STPA causal factors and Stage 6
  projects those factors without inference.  The same projection constrains
  all Stage 6 calls and is persisted beside the existing scenario artifacts.

  Background:
    Given the STPA production projection workflow is available
    And a control structure contains RESP-1, PM-1-1, FB-1-1, and CA-1-1
    And the structural unsafe control action has ICA ID "RESP-1:CA-1-1:WRONG_TIMING:1"
    And the structural unsafe control action has scenario ID "SCN-001"

  # STPA-PROD-WIRING-01
  Scenario: STPA-PROD-WIRING-01 Stage 5 preserves evidence-backed causal factors
    Given Stage 5 returns ordered evidence for a process-model flaw at PM-1-1 and a feedback delay at FB-1-1
    When the production STPA run performs Stage 5 assembly
    Then the ScenarioSpec contains causal factors "PM-1-1,FB-1-1" in declared order
    And each stored causal factor has its declared kind, source ID, and evidence description
    And the ScenarioSpec validates every causal-factor reference against the control structure
    And no causal factor is selected from structural presence alone

  # STPA-PROD-WIRING-02
  Scenario Outline: STPA-PROD-WIRING-02 invalid causal-factor references stop projection
    Given Stage 5 returns evidence for a "<kind>" at unknown "<source_id>"
    When the production STPA run performs Stage 5 assembly
    Then Stage 5 fails with a causal-factor reference validation error
    And no Stage 6 narrative, attack-tree, or Gherkin call is made for the invalid ScenarioSpec
    And no projection artifact is written for the invalid scenario

    Examples:
      | kind               | source_id |
      | process-model flaw | PM-99-1   |
      | feedback delay     | FB-99-1   |
      | actuator anomaly   | CA-99-1   |

  # STPA-PROD-WIRING-03
  Scenario Outline: STPA-PROD-WIRING-03 project_execution is deterministic and inference-free
    Given the Stage 5 evidence declares causal factors "<factors>"
    When project_execution is applied to the ScenarioSpec and control structure twice
    Then both candidate execution envelopes are byte-equivalent
    And the envelope candidate identifier is "EXEC:RESP-1:CA-1-1:WRONG_TIMING"
    And the envelope causal factors are "<factor_ids>" in declared order
    And the envelope contains no causal factor or temporal behavior not declared by Stage 5

    Examples:
      | factors                                                      | factor_ids     |
      | a process-model flaw for PM-1-1 and a feedback delay for FB-1-1 | PM-1-1,FB-1-1 |
      | a feedback delay for FB-1-1 and an actuator anomaly for CA-1-1   | FB-1-1,CA-1-1 |

  # STPA-PROD-WIRING-04
  Scenario: STPA-PROD-WIRING-04 explicit empty factors remain present and empty
    Given Stage 5 explicitly returns an empty causal-factor list
    When the production STPA run performs Stage 5 assembly
    And the production STPA run derives the projection and writes artifacts
    Then the ScenarioSpec has a present causal_factors field containing an empty list
    And the projection has present causal_factors, assertions, and steps fields containing empty lists
    And the temporal action vector has no assertions and no steps
    And no behavior is invented from RESP-1, PM-1-1, FB-1-1, or CA-1-1 being present in the control structure

  # STPA-PROD-WIRING-05
  Scenario: STPA-PROD-WIRING-05 one validated alignment reaches every Stage 6 call
    Given the validated Stage 5 factor set contains PM-1-1 followed by FB-1-1
    When Stage 6 derives one projection alignment from that validated projection
    Then the narrative, attack-tree, and Gherkin calls each receive the same alignment table
    And the table has one row for PM-1-1, one row for FB-1-1, and one final row for CA-1-1
    And the rows preserve declared factor order and place the unsafe-control-action row last
    And every Stage 6 prompt forbids inventing causal factors, assertions, or steps
    And the prompt references semantic structural IDs rather than positional labels

  # STPA-PROD-WIRING-06
  Scenario: STPA-PROD-WIRING-06 canonical projection is written beside legacy artifacts
    Given Stage 5 returns one evidence-backed process-model factor at PM-1-1
    When the production STPA run completes the scenario
    Then the scenario directory contains the legacy scenario YAML and Gherkin feature
    And the scenario directory contains canonical JSON and YAML projection artifacts
    And each canonical projection artifact declares schema version "stpa-execution-projection-v1"
    And the canonical projection artifacts identify ICA "RESP-1:CA-1-1:WRONG_TIMING:1" and scenario "SCN-001" separately
    And parsing either canonical projection artifact with a standard reader does not require project imports
