Feature: Stage 1a section-aware correction
  Stage 1a corrections preserve omitted sections, replace supplied sections as
  complete collections, and fail closed on malformed authoritative handles.

  Scenario: offline section merge retains empty sections
    Given a neutral Stage 1a correction fixture "empty_sections"
    When the offline Stage 1a section-merge seam is called
    Then the corrected analysis retains the prior risk-derived loss
    And the corrected analysis retains the prior use-case loss
    And the corrected analysis retains the prior hazard
    And the corrected analysis retains the prior security constraint
    And the section merge makes no provider call

  Scenario: offline section merge replaces populated sections completely
    Given a neutral Stage 1a correction fixture "section_patch"
    When the offline Stage 1a section-merge seam is called
    Then the corrected analysis retains the prior risk-derived loss
    And the corrected analysis retains the prior use-case loss
    And the corrected analysis contains the replacement hazard
    And the corrected analysis omits the obsolete hazard
    And the corrected analysis contains the replacement security constraint
    And the corrected analysis omits the obsolete security constraint
    And the section merge makes no provider call

  Scenario: the public Stage 1a wire keeps all five risk collections explicit
    Given a neutral Stage 1a correction fixture "wire"
    When the public Stage 1a loss-analysis seam is called
    Then the Stage 1a wire contract requires exactly five collections
    And the Stage 1a run makes no correction attempt

  Scenario: duplicate request-local handles fail closed
    Given a neutral Stage 1a correction fixture "duplicate"
    When the public Stage 1a loss-analysis seam is called
    Then Stage 1a derivation rejects the duplicate local handle
    And the duplicate risk response remains in call evidence
    And the Stage 1a run makes no repair attempt

  Scenario: reserved canonical handles are rejected
    Given a neutral Stage 1a correction fixture "conflict"
    When the public Stage 1a loss-analysis seam is called
    Then Stage 1a derivation fails with a reserved canonical handle
    And the malformed gap response remains in call evidence
    And the Stage 1a run makes no repair attempt
