# mutation-stamp: sha256=4829187a10d092ef1836f0c311c28312d3698865db0dd6af3d79329feaa415ac
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-12T10:32:47.004436Z","feature_name":"SP1 \u2014 Prevent RevisionDelta runaway output","feature_path":"features/sp1_revision_runaway_output.feature","background_hash":"d2c1bb399d1f338a359aea1d66186f71082f313642a60b85f65f7cf0ce4affd3","implementation_hash":"sha256:7732738e87189a6cf0181c6570b6ab8b407f1098e6bcac546760c9fb40310ce3","scenarios":[{"index":0,"name":"RevRunaway-01 revision_system.j2 instructs modified_responsibilities contains only changes","scenario_hash":"7b8f2922875595d960ddbe6c003a94a12eadbe16d878020af6eb713aed707ecd","mutation_count":3,"result":{"Total":3,"Killed":3,"Survived":0,"Errors":0},"tested_at":"2026-08-12T10:32:47.004436Z"},{"index":2,"name":"RevRunaway-03 revision_system.j2 contains control structure listing, not revision_user.j2","scenario_hash":"d62444dc049d950476776718ce98f58f610febfce7ef66a7ec9699d4488c44bc","mutation_count":4,"result":{"Total":4,"Killed":4,"Survived":0,"Errors":0},"tested_at":"2026-08-12T10:32:47.004436Z"},{"index":6,"name":"RevRunaway-07 run_revision passes max_completion_tokens 8192","scenario_hash":"d3b105144d401bfd6f242f0a7084ba1095e1f874d1ea6f4a05a49c1dad536346","mutation_count":1,"result":{"Total":1,"Killed":1,"Survived":0,"Errors":0},"tested_at":"2026-08-12T10:32:47.004436Z"}]}
# acceptance-mutation-manifest-end

Feature: SP1 — Prevent RevisionDelta runaway output
  Gemma 4 generates 16384 tokens for revision runs despite the prompt saying
  "Do NOT restate the entire control structure". A valid delta is ~800
  tokens. Root causes: (1) the model puts existing responsibilities into
  modified_responsibilities; (2) the revision user prompt includes
  use_case_text which inflates context; (3) no per-step
  max_completion_tokens cap on the revision LLM call; (4) no post-parse
  validation rejecting duplicate resp_ids in new_responsibilities. The fix
  addresses all four causes.

  Background:
    Given the STPA system model revision module is importable
    And the STPA system model llm_helpers module is importable
    And a control structure with responsibilities RESP-1 and RESP-2 is available
    And CriticFindings with unjustified gaps are available
    And a run directory for call logging

  # RevRunaway-01
  Scenario Outline: RevRunaway-01 revision_system.j2 instructs modified_responsibilities contains only changes
    Given the template revision_system.j2 is loaded
    Then the template text contains "<fragment>"

    Examples:
      | fragment                                                                      |
      | modified_responsibilities list must contain ONLY responsibilities you are CHANGING |
      | Do NOT restate the entire control structure                                    |
      | only new and modified elements                                                 |

  # RevRunaway-02
  Scenario: RevRunaway-02 revision_user.j2 does not include use_case_text
    Given the template revision_user.j2 is loaded
    Then the template text does not contain "use_case_text"
    And the template text does not contain "{{ use_case_text }}"

  # RevRunaway-03
  Scenario Outline: RevRunaway-03 revision_system.j2 contains control structure listing, not revision_user.j2
    Given the template <template> is loaded
    Then the template text contains "<fragment>"
    And the template revision_user.j2 is loaded
    And the template text does not contain "Current Control Structure"
    And the template text contains "Critic Findings"

    Examples:
      | template           | fragment                    |
      | revision_system.j2 | Existing Control Structure  |
      | revision_system.j2 | Responsibilities             |

  # RevRunaway-04
  Scenario: RevRunaway-04 call_with_policy accepts a max_completion_tokens parameter
    Given the call_with_policy function signature is inspected
    Then the function accepts a max_completion_tokens parameter with default None

  # RevRunaway-05
  Scenario: RevRunaway-05 call_with_policy passes max_completion_tokens to complete
    Given an LLM client with a mocked complete method
    When call_with_policy is called with max_completion_tokens 4096
    Then the complete method is called with max_completion_tokens 4096

  # RevRunaway-06
  Scenario: RevRunaway-06 call_with_policy without max_completion_tokens does not override client default
    Given an LLM client with a mocked complete method
    When call_with_policy is called without max_completion_tokens
    Then the complete method is called with max_completion_tokens None

  # RevRunaway-07
  Scenario Outline: RevRunaway-07 run_revision passes max_completion_tokens 8192
    Given an LLM that returns a valid RevisionDelta
    When the revision is run
    Then the LLM complete call is made with max_completion_tokens <max_tokens>

    Examples:
      | max_tokens |
      | 8192       |

  # RevRunaway-08
  Scenario: RevRunaway-08 new_responsibilities with existing resp_id is rejected
    Given an LLM that returns a RevisionDelta with new_responsibilities containing RESP-1
    When the revision is run
    Then the final control structure does not contain a duplicate RESP-1
    And a warning is logged about the rejected duplicate resp_id RESP-1

  # RevRunaway-09
  Scenario: RevRunaway-09 new_responsibilities with genuinely new resp_id is accepted
    Given an LLM that returns a RevisionDelta with new_responsibilities containing RESP-3 with valid PM, CA, and FB elements
    When the revision is run
    Then the final control structure contains RESP-3

  # RevRunaway-10
  Scenario: RevRunaway-10 duplicate rejection does not affect modified_responsibilities replacement
    Given an LLM that returns a RevisionDelta with modified_responsibilities containing RESP-1 with an updated description
    And the RevisionDelta also has new_responsibilities containing RESP-2
    When the revision is run
    Then the final control structure contains RESP-1 with the updated description
    And a warning is logged about the rejected duplicate resp_id RESP-2
    And the final control structure does not contain a duplicate RESP-2

  # RevRunaway-11
  Scenario: RevRunaway-11 revision_system.j2 preserves existing delta and ID rules
    Given the template revision_system.j2 is loaded
    Then the template text contains "Do NOT restate the entire control structure"
    And the template text contains "ID format rules"
    And the template text contains "solution-neutrality"

  # RevRunaway-12
  Scenario: RevRunaway-12 revision_system.j2 renders successfully with the new instruction
    Given the template revision_system.j2 is loaded
    When the template is rendered with control_structure and next_ids
    Then the rendered text contains "modified_responsibilities list must contain ONLY"
    And the rendered text does not contain "{{"
