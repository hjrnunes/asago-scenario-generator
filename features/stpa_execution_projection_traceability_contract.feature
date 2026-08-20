# STPA-TRACEABILITY-01, STPA-TRACEABILITY-02, STPA-TRACEABILITY-03, STPA-TRACEABILITY-04, STPA-TRACEABILITY-05
Feature: STPA execution projection traceability and identity contract
  Canonical projection validation is fail-closed for malformed plain
  documents, while explicit present-empty vectors remain valid.  Structural
  candidate identity, ICA identity, and scenario identity are distinct.

  Background:
    Given a valid canonical STPA projection with candidate "EXEC:RESP-1:CA-1-1:WRONG_TIMING"
    And its UCA reference is "RESP-1:CA-1-1:WRONG_TIMING"

  # STPA-TRACEABILITY-01
  Scenario: STPA-TRACEABILITY-01 absent projection vectors fail closed
    Given the canonical projection is missing the "<key>" key
    When STPA projection traceability is validated
    Then traceability is invalid
    And the result contains typed violation code "<violation_code>"
    And the violation identifies projection element "<key>"

    Examples:
      | key             | violation_code        |
      | causal_factors  | causal_factors_missing |
      | assertions      | assertions_missing     |
      | steps           | steps_missing          |

  # STPA-TRACEABILITY-02
  Scenario: STPA-TRACEABILITY-02 present-empty vectors are valid
    Given the canonical projection explicitly contains causal_factors, assertions, and steps as empty lists
    When STPA projection traceability is validated
    Then traceability is valid
    And the result contains no violations
    And no causal-factor, assertion, or step provenance is invented

  # STPA-TRACEABILITY-03
  Scenario Outline: STPA-TRACEABILITY-03 typed validation rejects forged links
    Given the valid canonical projection is mutated by changing "<field>" to "<value>"
    When STPA projection traceability is validated
    Then traceability is invalid
    And the result contains typed violation code "<violation_code>"
    And validation identifies the earliest affected projection element

    Examples:
      | field                    | value                     | violation_code               |
      | candidate_id             | EXEC:RESP-9:CA-1-1:WRONG_TIMING | candidate_identity_mismatch |
      | assertion source_id      | PM-9-9                   | assertion_source_mismatch   |
      | step source_id           | CA-9-9                   | uca_step_mismatch            |
      | assertion source_kind    | unsafe_control_action    | typed_provenance_mismatch   |
      | schema_version           | absent                   | schema_version_missing       |

  # STPA-TRACEABILITY-04
  Scenario Outline: STPA-TRACEABILITY-04 canonical export separates candidate, ICA, and scenario identities
    Given the projection carries ICA ID "RESP-1:CA-1-1:WRONG_TIMING:1" and scenario ID "SCN-001"
    And the projection is exported as canonical JSON and YAML
    When both exports are parsed with standard readers
    Then both exports retain candidate "EXEC:RESP-1:CA-1-1:WRONG_TIMING"
    And both exports contain ICA ID "RESP-1:CA-1-1:WRONG_TIMING:1" in its own field
    And both exports contain scenario ID "SCN-001" in its own field
    And changing "<identity>" does not change structural candidate ID

    Examples:
      | identity    |
      | scenario ID |
      | ICA ID      |

  # STPA-TRACEABILITY-05
  Scenario: STPA-TRACEABILITY-05 canonical projection round-trips without project objects
    Given the projection contains two causal factors in declared order
    When canonical JSON and YAML are produced twice
    Then the repeated JSON and YAML outputs are each byte-identical
    And JSON and YAML preserve causal-factor, assertion, and step order
    And parsing either export requires only a standard JSON or YAML reader
    And validating either parsed export applies the same typed traceability rules
