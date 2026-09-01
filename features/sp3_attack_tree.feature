# mutation-stamp: sha256=e0f7feddd6539dfa75861f3a7c565fc1376942aac34fdfe5fec1783a1924a1a3
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-10T10:49:25.739395Z","feature_name":"SP3 Stage 6 Call B \u2014 Attack tree","feature_path":"features/sp3_attack_tree.feature","background_hash":"51ef595ce212d9b5440fcaf572995eec3ed642faaab4697994f0ff764100a0da","implementation_hash":"unknown","scenarios":[{"index":3,"name":"SP3-TREE-04 hard template includes sub-branches under each category","scenario_hash":"d95adf540956b05b5d49d8e1065ca2e1514e6deed869fe512248adf78d48973e","mutation_count":18,"result":{"Total":18,"Killed":18,"Survived":0,"Errors":0},"tested_at":"2026-08-10T10:49:25.739395Z"}]}
# acceptance-mutation-manifest-end

Feature: SP3 Stage 6 Call B — Attack tree
  The attack tree uses a hard STPA two-level causal taxonomy with 3 branch
  categories: controller-side causes, path-side causes, and coordination gap.
  The LLM instantiates relevant branches and prunes irrelevant ones. The tree
  must use at least 2 of the 3 categories. Branch references to PM, FB, CA,
  and RESP IDs must be valid.

  Background:
    Given the SP3 attack tree module is importable
    And a ScenarioSpec with defender BDI and attacker BDI for scenario SCN-001
    And a control structure with responsibility RESP-1, PM-1-1, CA-1-1, and FB-1-1

  # SP3-TREE-01
  Scenario: SP3-TREE-01 one LLM call produces a YAML-serializable attack tree
    Given an LLM that returns a YAML attack tree with root, branches, and leaves
    When the attack tree LLM call is executed
    Then exactly 1 LLM call is made
    And the call is labeled with stage stage_6
    And the call step is attack_tree
    And the result is a dict with root, branches, and leaves keys

  # SP3-TREE-02
  Scenario: SP3-TREE-02 tree root matches the ICA objective
    Given a ScenarioSpec with ica_type NOT_PROVIDED and target_control_action CA-1-1
    When the attack tree LLM call is executed
    Then the tree root references the ICA type NOT_PROVIDED
    And the tree root references the control action CA-1-1

  # SP3-TREE-03
  Scenario: SP3-TREE-03 hard template defines 3 branch categories
    When the attack tree LLM call is executed
    Then the system prompt contains the branch category controller_side
    And the system prompt contains the branch category path_side
    And the system prompt contains the branch category coordination_gap

  # SP3-TREE-04
  Scenario Outline: SP3-TREE-04 hard template includes sub-branches under each category
    When the attack tree LLM call is executed
    Then the system prompt contains the sub-branch <sub_branch> under <category>

    Examples:
      | category           | sub_branch                     |
      | controller_side    | Process-model divergence       |
      | controller_side    | Inadequate control algorithm   |
      | controller_side    | Feedback-path condition        |
      | controller_side    | Unsafe control input           |
      | path_side          | Actuator/executor failure      |
      | path_side          | Control-path condition         |
      | path_side          | Controlled process behavior    |
      | coordination_gap   | Shared PM differs              |
      | coordination_gap   | Controllers issue conflicting control actions |

  # SP3-TREE-05
  Scenario: SP3-TREE-05 LLM prunes irrelevant branches
    Given an LLM that returns a tree with only controller_side and path_side branches
    When the attack tree LLM call is executed
    Then the tree has 2 branch categories
    And the tree does not contain a coordination_gap branch

  # SP3-TREE-06
  Scenario: SP3-TREE-06 post-call validation requires at least 2 of 3 branch categories
    Given an LLM that returns a tree with only 1 branch category
    When attack tree branch coverage validation is performed
    Then validation fails with error containing branch

  # SP3-TREE-07
  Scenario: SP3-TREE-07 post-call validation passes with 2 branch categories
    Given an LLM that returns a tree with controller_side and path_side branches
    When attack tree branch coverage validation is performed
    Then validation succeeds

  # SP3-TREE-08
  Scenario: SP3-TREE-08 post-call validation passes with 3 branch categories
    Given an LLM that returns a tree with all 3 branch categories
    When attack tree branch coverage validation is performed
    Then validation succeeds

  # SP3-TREE-09
  Scenario: SP3-TREE-09 branch references to PM IDs must be valid
    Given an LLM that returns a tree branch referencing PM-99-1
    When attack tree ID reference validation is performed against the control structure
    Then validation fails with error containing PM-99-1

  # SP3-TREE-10
  Scenario: SP3-TREE-10 branch references to FB IDs must be valid
    Given an LLM that returns a tree branch referencing FB-99-1
    When attack tree ID reference validation is performed against the control structure
    Then validation fails with error containing FB-99-1

  # SP3-TREE-11
  Scenario: SP3-TREE-11 valid branch references pass ID reference validation
    Given an LLM that returns a tree with branches referencing PM-1-1 and FB-1-1 and CA-1-1
    When attack tree ID reference validation is performed against the control structure
    Then validation succeeds

  # SP3-TREE-12
  Scenario: SP3-TREE-12 user prompt includes ScenarioSpec and control structure context
    Given an LLM that records the user prompt
    When the attack tree LLM call is executed
    Then the user prompt contains the ScenarioSpec
    And the user prompt contains the control structure context

  # SP3-TREE-13
  Scenario: SP3-TREE-13 system prompt includes the full hard template and pruning instructions
    When the attack tree LLM call is executed
    Then the system prompt contains the full two-level causal taxonomy template
    And the system prompt contains instructions to prune irrelevant branches

  # SP3-TREE-14
  Scenario: SP3-TREE-14 all LLM calls are logged to calls.jsonl
    Given a run directory for output
    When the attack tree LLM call is executed
    Then a file calls.jsonl exists in the run directory
    And the file contains entries with stage stage_6 and step attack_tree
