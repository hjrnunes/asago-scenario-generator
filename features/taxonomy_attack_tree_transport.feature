Feature: Taxonomy attack-tree transport normalization
  Attack-tree model output is decoded as transport data before strict domain
  validation. Canonical realizations come only from projected step identities
  and the immutable projection context, never from model-supplied semantics.

  Background:
    Given taxonomy generation has an immutable projection context with selected step IDs "step.1,step.2"
    And each selected step has canonical realization semantics

  # Taxonomy attack-tree transport normalization 01 derives omitted realizations before strict validation
  Scenario: Taxonomy attack-tree transport normalization 01 derives omitted realizations before strict validation
    Given an attack-tree transport response maps security leaves to projected step IDs "step.1,step.2"
    And the response omits every realizations field
    When the attack-tree response is normalized
    Then each mapped leaf has exactly one canonical realization per projected step ID
    And each canonical realization matches the immutable projection context
    And the normalized attack tree passes strict validation
    And no retry is caused by the omitted realizations fields

  # Taxonomy attack-tree transport normalization 02 replaces model-supplied realization semantics
  Scenario: Taxonomy attack-tree transport normalization 02 replaces model-supplied realization semantics
    Given an attack-tree transport response maps a security leaf to projected step ID "step.1"
    And the response supplies realization semantics inconsistent with "step.1"
    When the attack-tree response is normalized
    Then the model-supplied realization semantics are discarded
    And the leaf has the canonical realization for "step.1"
    And the normalized attack tree passes strict validation

  # Taxonomy attack-tree transport normalization 03 rejects an unknown projected step
  Scenario: Taxonomy attack-tree transport normalization 03 rejects an unknown projected step
    Given an attack-tree transport response maps a security leaf to projected step ID "step.unknown"
    When the attack-tree response is normalized
    Then strict validation rejects projected step ID "step.unknown"
    And no finalized attack tree is published

  # Taxonomy attack-tree transport normalization 04 preserves strict finalized-tree validation
  Scenario Outline: Taxonomy attack-tree transport normalization 04 preserves strict finalized-tree validation
    Given a finalized attack tree has <realization_defect> for projected step ID "step.1"
    When the finalized attack tree is strictly validated
    Then strict validation rejects the finalized attack tree

    Examples:
      | realization_defect          |
      | a missing realization       |
      | an extra realization        |
      | duplicate realizations      |
      | an inconsistent realization |
