# STPA-TEMPORAL-01, STPA-TEMPORAL-02, STPA-TEMPORAL-03, STPA-TEMPORAL-04, STPA-TEMPORAL-05
Feature: STPA typed temporal execution constraints
  Temporal assertions carry a typed, discriminated constraint only when the
  declared evidence supplies timing.  Constraint construction is
  deterministic and never turns runtime observations into projection input.

  Background:
    Given the STPA temporal projection models are available
    And a control structure contains RESP-1, PM-1-1, FB-1-1, and CA-1-1
    And a WRONG_TIMING unsafe control action targets CA-1-1

  # STPA-TEMPORAL-01
  Scenario Outline: STPA-TEMPORAL-01 declared timing selects one typed constraint variant
    Given "<source_id>" has declared timing "<timing>"
    When the temporal action vector is derived
    Then its assertion has constraint variant "<variant>"
    And the constraint uses canonical unit "<unit>"
    And the constraint contains the declared numeric value "<value>"
    And the constraint references only "<reference>"
    And the constraint contains no fields belonging to another variant

    Examples:
      | source_id | timing                                  | variant           | unit | value | reference |
      | PM-1-1    | ordering before S-2                     | OrderingConstraint |      |       | S-2       |
      | FB-1-1    | delay 250 milliseconds                  | DelayConstraint    | ms   | 250   | FB-1-1    |
      | CA-1-1    | duration 2 seconds                      | DurationConstraint | s    | 2     | CA-1-1    |
      | FB-1-1    | window from 100 to 500 milliseconds     | WindowConstraint   | ms   | 100-500 | FB-1-1  |
      | CA-1-1    | absence until S-2                      | AbsenceConstraint  |      |       | S-2       |

  # STPA-TEMPORAL-02
  Scenario: STPA-TEMPORAL-02 canonical units normalize numeric timing
    Given declared timing uses "1000 milliseconds" and "2 seconds" for two factors
    When the temporal action vector is derived
    Then each numeric timing value uses only canonical unit "ms" or "s"
    And repeated derivation preserves the numeric values, units, and constraint discriminators byte-for-byte
    And no free-form timing text is used as an executable constraint

  # STPA-TEMPORAL-03
  Scenario: STPA-TEMPORAL-03 unknown timing requires explicit binding
    Given a feedback-delay factor for FB-1-1 has unknown timing
    When the temporal action vector is derived
    Then its assertion has constraint null
    And its assertion has requires_binding true
    And the assertion still preserves the canonical feedback-delay predicate and source ID
    And the projection does not invent a duration, delay, window, or runtime observation

  # STPA-TEMPORAL-04
  Scenario Outline: STPA-TEMPORAL-04 constraint references are namespace-bound
    Given a candidate constraint names structural reference "<reference>"
    When the temporal assertion is validated
    Then validation "<result>"
    And any accepted reference resolves to a PM-, FB-, CA-, or S-* structural ID

    Examples:
      | reference | result  |
      | PM-1-1    | succeeds |
      | FB-1-1    | succeeds |
      | CA-1-1    | succeeds |
      | S-2       | succeeds |
      | H-1       | fails   |
      | runtime-1 | fails   |

  # STPA-TEMPORAL-05
  Scenario: STPA-TEMPORAL-05 UCA outcome mapping is explicit and observations stay in evaluation
    Given causal factors include a process-model flaw for PM-1-1 and a feedback delay for FB-1-1
    When the temporal action vector is derived
    Then the vector has a uca_constraint for the final unsafe-control-action outcome
    And the uca_constraint identifies CA-1-1 and WRONG_TIMING
    And the final scenario step remains the unsafe-control-action step for CA-1-1
    And runtime observations are absent from the projection and available only to evaluation
