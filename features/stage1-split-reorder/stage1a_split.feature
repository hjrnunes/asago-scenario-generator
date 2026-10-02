# stage1a-split
Feature: Stage 1a Loss Analysis Split
  The current single-call Stage 1a (loss analysis) is split into two
  sequential LLM calls:
    - Call 1 (risk-grounded): derives losses, hazards, and security
      constraints from organizational risks.
    - Call 2 (gap analysis): reviews the use-case description against
      Call 1's output to find missing adversary-actionable losses.
  The old templates stage1a_system.j2 / stage1a_user.j2 are replaced by
  stage1a_risk_system.j2 / stage1a_risk_user.j2 and
  stage1a_gap_system.j2 / stage1a_gap_user.j2.

  Background:
    Given a use-case file and a risk-extraction file are available
    And an LLM endpoint is configured

  # stage1a-split-old-templates-removed
  Scenario: Old stage1a templates are absent
    Then the prompts directory does not contain `stage1a_system.j2`
    And the prompts directory does not contain `stage1a_user.j2`

  # stage1a-split-new-templates-present
  Scenario: New stage1a templates are present
    Then the prompts directory contains `stage1a_risk_system.j2`
    And the prompts directory contains `stage1a_risk_user.j2`
    And the prompts directory contains `stage1a_gap_system.j2`
    And the prompts directory contains `stage1a_gap_user.j2`
