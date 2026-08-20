Feature: Taxonomy step-ID transport normalization
  Projection-aware model responses may echo canonical step IDs in a small set
  of transport shapes, which are normalized before strict validation.

  Background:
    Given taxonomy generation selects canonical step IDs "step.1,attacker.prepare,system.transform"

  # Taxonomy step-ID transport normalization 01 normalizes each accepted echo shape
  Scenario Outline: Taxonomy step-ID transport normalization 01 normalizes each accepted echo shape
    Given a projection-aware response has one projected_step_ids item "<echo_item>"
    When projected step-ID transport is normalized
    Then the normalized projected step IDs are "<canonical_step_id>"
    And their order is unchanged

    Examples:
      | echo_item                         | canonical_step_id |
      | attacker.prepare                  | attacker.prepare  |
      | {"step_id": "attacker.prepare"}   | attacker.prepare  |
      | step_id: attacker.prepare         | attacker.prepare  |
      | step.attacker.prepare             | attacker.prepare  |
      | step.1                            | step.1            |
      | step.step.1                       | step.1            |

  # Taxonomy step-ID transport normalization 02 preserves mixed-shape order
  Scenario: Taxonomy step-ID transport normalization 02 preserves mixed-shape order
    Given projected_step_ids items are "step.system.transform,step_id: attacker.prepare,step.1"
    When projected step-ID transport is normalized
    Then the normalized projected step IDs are "system.transform,attacker.prepare,step.1"
    And their order is unchanged

  # Taxonomy step-ID transport normalization 03 rejects duplicate canonical identities
  Scenario Outline: Taxonomy step-ID transport normalization 03 rejects duplicate canonical identities
    Given projected_step_ids items are "<echo_items>"
    When projected step-ID transport is normalized
    Then normalization raises a stable ValueError for duplicate canonical step ID "attacker.prepare"
    And normalization does not raise TypeError
    And no finalized artifact is published

    Examples:
      | echo_items                                       |
      | attacker.prepare,{"step_id": "attacker.prepare"} |
      | step.attacker.prepare,step_id: attacker.prepare  |

  # Taxonomy step-ID transport normalization 04 rejects unknown or ambiguous echo shapes
  Scenario Outline: Taxonomy step-ID transport normalization 04 rejects unknown or ambiguous echo shapes
    Given a projection-aware response has one projected_step_ids item "<echo_item>"
    When projected step-ID transport is normalized
    Then normalization raises a stable ValueError identifying "<rejection>"
    And normalization does not raise TypeError
    And no finalized artifact is published

    Examples:
      | echo_item                         | rejection             |
      | unknown.step                      | unknown canonical ID   |
      | step.unknown.step                 | unknown canonical ID   |
      | step_id: step.attacker.prepare    | ambiguous prefix shape |
      | {"step_id": 7}                    | non-string step_id     |
      | {"id": "attacker.prepare"}        | unknown object shape   |
      | ["attacker.prepare"]              | nested sequence shape  |
      | 7                                 | non-string item        |

  # Taxonomy step-ID transport normalization 05 applies the same transport contract to narrative steps and tree leaves
  Scenario Outline: Taxonomy step-ID transport normalization 05 applies the same transport contract to narrative steps and tree leaves
    Given a valid "<artifact_stage>" response echoes projected step ID "step.attacker.prepare"
    When the response transport is normalized and strictly validated
    Then the finalized "<artifact_stage>" artifact contains projected step ID "attacker.prepare"
    And its canonical realization is derived from "attacker.prepare"

    Examples:
      | artifact_stage |
      | narrative      |
      | attack tree    |

  # Taxonomy step-ID transport normalization 06 prompts render plain canonical ID lists
  Scenario Outline: Taxonomy step-ID transport normalization 06 prompts render plain canonical ID lists
    When the taxonomy "<call>" user prompt is rendered
    Then selected projected step IDs are rendered as the plain quoted list "step.1,attacker.prepare,system.transform"
    And the selected projected step ID list does not use the "- step_id:" record shape
    And the prompt requires the exact canonical ID values in projected_step_ids

    Examples:
      | call             |
      | narrative call   |
      | attack-tree call |
