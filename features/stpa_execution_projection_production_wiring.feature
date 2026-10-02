# STPA-PROD-WIRING-01, STPA-PROD-WIRING-02, STPA-PROD-WIRING-04
Feature: STPA post-SP3 execution projection production wiring
  Stage 5 selects declared, evidence-backed STPA causal factors, and an
  invalid causal-factor declaration stops the scenario before Stage 6.

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
    And no projection artifact is written for the invalid scenario

    Examples:
      | kind               | source_id |
      | process-model flaw | PM-99-1   |
      | feedback delay     | FB-99-1   |
      | actuator anomaly   | CA-99-1   |

  # STPA-PROD-WIRING-04
  Scenario: STPA-PROD-WIRING-04 successful Stage 5 output requires a causal factor
    Given Stage 5 explicitly returns an empty causal-factor list
    When the production STPA run performs Stage 5 assembly
    Then Stage 5 fails with a non-empty causal_factors validation error
    And no projection artifact is written for the invalid scenario
