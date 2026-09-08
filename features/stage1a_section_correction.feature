Feature: Stage 1a section-aware correction
  Stage 1a corrections preserve omitted sections, replace supplied sections as
  complete collections, and fail closed on conflicting authoritative records.

  Scenario: empty sections retain prior records and populated sections replace them
    Given a neutral Stage 1a correction fixture "section_patch"
    When the public Stage 1a loss-analysis seam is called
    Then the Stage 1a wire contract requires exactly five collections
    And the corrected analysis retains the prior risk-derived loss
    And the corrected analysis retains the prior use-case loss
    And the corrected analysis contains the replacement hazard
    And the corrected analysis omits the obsolete hazard
    And the corrected analysis retains the prior security constraint
    And the corrected analysis contains the replacement security constraint
    And the corrected analysis omits the obsolete security constraint
    And the Stage 1a run makes at most one correction attempt
    And the rejected gap response remains in call evidence

  Scenario: exact repeated risk-base records are deduplicated
    Given a neutral Stage 1a correction fixture "duplicate"
    When the public Stage 1a loss-analysis seam is called
    Then the final analysis has exactly one risk-derived loss
    And the final analysis has no use-case losses
    And the Stage 1a run makes no correction attempt

  Scenario: conflicting reused authoritative IDs are rejected
    Given a neutral Stage 1a correction fixture "conflict"
    When the public Stage 1a loss-analysis seam is called
    Then Stage 1a derivation fails with a conflicting authoritative ID
    And the conflicting correction remains in call evidence
    And the Stage 1a run makes at most one correction attempt
