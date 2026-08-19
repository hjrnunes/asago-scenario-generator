Feature: Taxonomy projection prompt alignment
  Narrative and attack-tree prompts identify canonical steps by semantic ID and
  present the same compact alignment rules used by projection validation.

  Background:
    Given taxonomy generation has canonical steps "attacker.observe,operator.impact"

  # Taxonomy projection prompt alignment 01 aligns each projection-aware user prompt
  Scenario Outline: Taxonomy projection prompt alignment 01 aligns each projection-aware user prompt
    When the taxonomy "<call>" user prompt is rendered
    Then canonical step IDs "attacker.observe,operator.impact" are each rendered with the "- step_id:" prefix
    And no canonical step is rendered with a numeric positional label
    And the prompt warns that step IDs are semantic names rather than positional labels
    And its projection alignment rules include action-kind mappings "observe:external_precondition,prepare:external_precondition"
    And its projection alignment rules include executor-role mapping "operator:impact"
    And its projection alignment rules state that compatible action-kind and executor-role sets must intersect
    And its projection alignment rules require an external_precondition leaf to have no zone
    And its projection alignment rules permit that leaf to map only an outside-boundary canonical step
    And its projection alignment rules leave inside-boundary and crossing-boundary external_precondition leaves unmapped
    And its projection alignment rules require resource bindings from the mapped canonical step
    And its projection alignment rules permit only ATLAS or LAAF technique ID formats

    Examples:
      | call               |
      | narrative call     |
      | attack-tree call   |
