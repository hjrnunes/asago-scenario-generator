Feature: Taxonomy projection prompt alignment
  Narrative and attack-tree prompts identify canonical steps by semantic ID and
  present a compact per-step table derived from projection validation rules.

  Background:
    Given taxonomy generation selects canonical steps "attacker.observe,attacker.deliver,operator.impact"

  # Taxonomy projection prompt alignment 01 renders one derived row per selected step
  Scenario Outline: Taxonomy projection prompt alignment 01 renders one derived row per selected step
    When the taxonomy "<call>" user prompt is rendered
    Then the projection alignment table has columns "canonical ID,action,executor,boundary,allowed narrative zone,allowed tree kinds,tree zone,bound resources"
    And it has exactly one row for each selected canonical step
    And its canonical ID column preserves selected-step order "attacker.observe,attacker.deliver,operator.impact"
    And no canonical step is rendered with a numeric positional ID
    And the prompt warns that step IDs are semantic names rather than positional labels

    Examples:
      | call               |
      | narrative call     |
      | attack-tree call   |

  # Taxonomy projection prompt alignment 02 derives row values from validator rules
  Scenario Outline: Taxonomy projection prompt alignment 02 derives row values from validator rules
    Given canonical step "<canonical_id>" has action "<action>", executor "<executor>", boundary "<boundary>", and bound resources "<bound_resources>"
    When the projection alignment row is derived
    Then its allowed narrative zone is "<allowed_narrative_zone>"
    And its allowed tree kinds are the intersection "<allowed_tree_kinds>"
    And its tree zone is "<tree_zone>"
    And its bound resources are "<bound_resources>"

    Examples:
      | canonical_id       | action  | executor | boundary | allowed_narrative_zone | allowed_tree_kinds    | tree_zone              | bound_resources           |
      | attacker.observe   | observe | attacker | outside  | outside                | external_precondition | null                   | none                      |
      | attacker.deliver   | deliver | attacker | crossing | active Schneider zone  | initial_ingress       | active Schneider zone | entry_point/chat-interface |
      | operator.impact    | impact  | operator | inside   | active Schneider zone  | impact                | active Schneider zone | effect/blocked-operation  |
      | operator.deliver   | deliver | operator | crossing | active Schneider zone  | empty set             | active Schneider zone | entry_point/chat-interface |

  # Taxonomy projection prompt alignment 03 stays synchronized with validator functions
  Scenario: Taxonomy projection prompt alignment 03 stays synchronized with validator functions
    When projection alignment rows are derived for every supported action, executor, and boundary combination
    Then each allowed tree-kind set equals canonical ownership-aware validator compatibility
    And narrative-zone and tree-zone values equal their stage-specific boundary validator rules
    And each bound-resources value comes from that canonical step
    And an empty compatibility intersection is rendered as an empty set
    And no duplicated hand-authored compatibility prose is rendered
