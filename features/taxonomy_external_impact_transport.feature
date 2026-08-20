Feature: Taxonomy external impact transport
  Attack-tree transport clears Schneider zones from external impacts before
  strict model validation while retaining projection semantic enforcement.

  Background:
    Given taxonomy generation has an immutable canonical projection

  # Taxonomy external impact transport 01 normalizes accepted impact zones by action boundary
  Scenario Outline: Taxonomy external impact transport 01 normalizes accepted impact zones by action boundary
    Given projection selects impact step "<step_id>" at boundary position "<projection_boundary>"
    And an attack-tree leaf at placement "<placement>" maps that step with action kind "impact", action boundary "<action_boundary>", and zone "reasoning"
    When the attack-tree response is normalized and strictly validated
    Then the impact leaf zone is "<normalized_zone>"
    And the impact leaf preserves projected step ID "<step_id>"
    And the impact leaf has the canonical realization for "<step_id>"
    And the normalized attack tree passes strict validation

    Examples:
      | step_id                  | projection_boundary | placement | action_boundary | normalized_zone |
      | attacker.external_impact | outside             | nested    | external        | null            |
      | system.internal_impact   | inside              | direct    | internal        | reasoning       |

  # Taxonomy external impact transport 02 fails closed when external impact maps a non-outside projected step
  Scenario Outline: Taxonomy external impact transport 02 fails closed when external impact maps a non-outside projected step
    Given projection selects impact step "system.impact" at boundary position "<projection_boundary>"
    And an attack-tree leaf at placement "direct" maps that step with action kind "impact", action boundary "external", and zone "<transport_zone>"
    When the attack-tree response is normalized and strictly validated
    Then the impact leaf zone is normalized to null before strict model validation
    And strict projection validation rejects the external impact mapping as a boundary semantic violation
    And projected step ID "system.impact" is not silently removed or remapped
    And no finalized attack tree is published

    Examples:
      | projection_boundary | transport_zone |
      | inside              | reasoning      |
      | crossing            | input          |

  # Taxonomy external impact transport 03 keeps external precondition normalization unchanged
  Scenario: Taxonomy external impact transport 03 keeps external precondition normalization unchanged
    Given projection selects outside-boundary step "attacker.prepare"
    And an attack-tree leaf maps that step with action kind "external_precondition" and zone "input"
    When the attack-tree response is normalized and strictly validated
    Then the external_precondition leaf zone is null
    And the external_precondition leaf preserves projected step ID "attacker.prepare"
