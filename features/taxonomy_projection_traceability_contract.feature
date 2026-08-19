Feature: Taxonomy projection traceability contract
  Taxonomy generation aligns canonical steps with compatible attack-tree leaves.
  Outside-boundary preconditions remain traceable, while incompatible mappings
  and unknown semantic step identities cannot enter an admitted scenario.

  Background:
    Given taxonomy generation has an immutable canonical projection
    And attack-tree transport is normalized before projection traceability validation

  # Taxonomy projection traceability contract 01 resolves non-empty leaf compatibility
  Scenario Outline: Taxonomy projection traceability contract 01 resolves non-empty leaf compatibility
    Given projected step "<step_id>" has action kind "<action_kind>", executor role "<executor_role>", and boundary position "<boundary_position>"
    When compatible attack-tree leaf kinds are resolved
    Then action-kind compatibility includes "<leaf_kind>"
    And executor-role compatibility includes "<leaf_kind>"
    And the combined compatibility intersection is non-empty

    Examples:
      | step_id          | action_kind | executor_role | boundary_position | leaf_kind             |
      | attacker.observe | observe     | attacker      | outside           | external_precondition |
      | attacker.prepare | prepare     | attacker      | outside           | external_precondition |
      | operator.impact  | impact      | operator      | inside            | impact                |

  # Taxonomy projection traceability contract 02 canonicalizes and maps an outside external precondition
  Scenario: Taxonomy projection traceability contract 02 canonicalizes and maps an outside external precondition
    Given projection selects outside-boundary step "attacker.observe"
    And an external_precondition transport leaf references projected step ID "attacker.observe"
    And that leaf supplies zone "input" and technique ID "not-a-technique"
    When the attack-tree response is normalized and strictly validated
    Then the normalized leaf zone is null
    And the normalized leaf technique ID is null
    And the normalized leaf preserves projected step ID "attacker.observe"
    And the normalized leaf has the canonical realization for "attacker.observe"
    And complete attack-tree coverage passes

  # Taxonomy projection traceability contract 03 leaves non-outside external preconditions unmapped
  Scenario Outline: Taxonomy projection traceability contract 03 leaves non-outside external preconditions unmapped
    Given projection selects step "system.observe" at boundary position "<boundary_position>"
    And an external_precondition transport leaf references projected step ID "system.observe"
    When the attack-tree response is normalized
    Then the external_precondition leaf has no projected step IDs
    And the external_precondition leaf has no realizations

    Examples:
      | boundary_position |
      | inside            |
      | crossing          |

  # Taxonomy projection traceability contract 04 preserves valid technique identities
  Scenario Outline: Taxonomy projection traceability contract 04 preserves valid technique identities
    Given an attack-tree transport leaf supplies technique ID "<technique_id>"
    When the attack-tree response is normalized
    Then the normalized leaf preserves technique ID "<technique_id>"

    Examples:
      | technique_id  |
      | AML.T0051     |
      | AML.T0051.001 |
      | S1            |
      | M2            |
      | L3            |

  # Taxonomy projection traceability contract 05 keeps canonical step identity validation closed
  Scenario: Taxonomy projection traceability contract 05 keeps canonical step identity validation closed
    Given projection selects outside-boundary step "attacker.observe"
    And an external_precondition transport leaf references projected step ID "step.unknown"
    When the attack-tree response is normalized
    Then normalization rejects unknown projected step ID "step.unknown"
    And no finalized attack tree is published

  # Taxonomy projection traceability contract 06 admits aligned outside and operator chains
  Scenario: Taxonomy projection traceability contract 06 admits aligned outside and operator chains
    Given projection selects the ordered canonical chain "attacker.observe,attacker.prepare,operator.impact"
    And the attacker steps are outside-boundary external_precondition leaves
    And the operator step is an inside-boundary impact leaf
    When the projection is realized as an attack tree and admission is evaluated
    Then every selected step has a compatible mapped leaf
    And the attack tree has complete projection coverage in canonical order
    And projection traceability reports no violation
    And the candidate is admitted
