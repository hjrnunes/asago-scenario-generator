Feature: Post-SP3 STPA execution projection
  STPA structural findings become platform-neutral candidate execution
  envelopes. Controller flaws, feedback timing, and sensor or actuator
  anomalies are retained as deterministic temporal assertions and executable
  scenario steps.

  Background:
    Given the STPA execution projection models are importable
    And a control structure with RESP-1, PM-1-1, FB-1-1, and CA-1-1 is available
    And a WRONG_TIMING unsafe control action targets CA-1-1

  # STPA-EXEC-01
  Scenario: STPA-EXEC-01 maps structural findings into a candidate envelope
    Given causal factors PM-1-1 and FB-1-1 explain the unsafe control action
    When the candidate execution envelope is assembled
    Then the envelope identifies controller RESP-1 and control action CA-1-1
    And the envelope retains UCA type WRONG_TIMING
    And the envelope maps causal factors PM-1-1 and FB-1-1
    And the envelope is platform-neutral

  # STPA-EXEC-02
  Scenario: STPA-EXEC-02 preserves canonical traceability for a candidate
    Given causal factor PM-1-1 explains the unsafe control action
    When the candidate execution envelope is assembled
    Then the envelope has a canonical candidate identifier
    And every mapped causal factor has a source identifier
    And the envelope links the UCA to its control action

  # STPA-EXEC-03
  Scenario: STPA-EXEC-03 formalizes controller flaws as temporal assertions
    Given causal factors include a process-model flaw for PM-1-1 and a feedback delay for FB-1-1
    When the temporal action vector is derived
    Then it contains 2 temporal assertions
    And the temporal assertions are executable
    And the vector contains scenario steps in causal-factor order
    And a scenario step references PM-1-1 before CA-1-1
    And a scenario step references FB-1-1 before CA-1-1

  # STPA-EXEC-04
  Scenario: STPA-EXEC-04 formalizes sensor and actuator anomalies
    Given causal factors include a sensor anomaly for FB-1-1 and an actuator anomaly for CA-1-1
    When the temporal action vector is derived
    Then it contains 2 temporal assertions
    And the vector contains a sensor anomaly step for FB-1-1
    And the vector contains an actuator anomaly step for CA-1-1
    And every scenario step has a deterministic order

  # STPA-EXEC-05
  Scenario: STPA-EXEC-05 assembles a candidate with its temporal vector
    Given causal factors include a process-model flaw for PM-1-1 and an actuator anomaly for CA-1-1
    When the candidate execution envelope is assembled with temporal assertions
    Then the envelope contains a temporal action vector
    And the temporal vector is linked to the envelope candidate identifier
    And the envelope retains the canonical control action description

  # STPA-EXEC-06
  Scenario: STPA-EXEC-06 does not invent temporal behavior
    Given no causal factors explain the unsafe control action
    When the temporal action vector is derived
    Then it contains no temporal assertions
    And it contains no scenario steps
