Feature: SP3 agentic attack-tree guidance
  The Stage 6 attack-tree taxonomy offers AI-surface realizations for logical
  feedback and control paths. Infrastructure leaves are not mandatory and may
  be used only when the architecture explicitly declares the relevant surface
  attacker-accessible.

  Background:
    Given the SP3 attack tree prompt is available

  # SP3-AAT-01
  Scenario Outline: SP3-AAT-01 the hard template contains each evidence-gated causal leaf
    When the Stage 6 attack tree system prompt is rendered
    Then the hard template contains evidence-gated causal leaf <leaf>
    And the prompt permits an infrastructure leaf only with explicit attacker-accessible architecture evidence

    Examples:
      | leaf                                                                          |
      | Process-model state is stale or inaccurate [PM-*]                              |
      | Feedback is missing, late, stale, or inaccurate [FB-*]                         |
      | Evidence-backed active change (only with exact capability/access evidence)     |

  Scenario Outline: SP3-AAT-01 the hard template has no mandatory infrastructure leaf
    When the Stage 6 attack tree system prompt is rendered
    Then the hard template does not contain mandatory infrastructure leaf <leaf>

    Examples:
      | leaf                                   |
      | Delay/block feedback                   |
      | Forge feedback                         |
      | Action intercepted/modified in transit |

  # SP3-AAT-02
  Scenario: SP3-AAT-02 a logical-only architecture produces agentic attack-tree leaves
    Given an architecture where FB-1-1 updates PM-1-1 from a tool result
    And the architecture declares no attacker-accessible transport or session surface
    And a deterministic instruction-following LLM
    When SP3 generates the attack tree
    Then the tree realizes FB-1-1 by fabricating the tool result
    And the tree contains no invented infrastructure or session leaf

  # SP3-AAT-03
  Scenario: SP3-AAT-03 an infrastructure leaf requires architecture evidence
    Given an architecture where FB-1-1 updates PM-1-1 through transport webhook-1
    And transport webhook-1 is explicitly declared attacker-accessible
    And a deterministic instruction-following LLM
    When SP3 generates an attack tree with a transport-interception leaf
    Then that leaf identifies webhook-1 as the architecture evidence
