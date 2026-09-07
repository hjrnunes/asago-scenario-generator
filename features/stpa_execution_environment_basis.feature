# STPA-EXEC-BASIS-01 through STPA-EXEC-BASIS-16
Feature: STPA execution environment-basis default correction
  Omission is an honest unresolved environment choice.  Only genuinely
  resource-free model behavior is target-agnostic; internal messages and
  domain actions retain their semantic resource requirements for a later,
  explicit target or simulation selection.

  Background:
    Given the execution environment-basis acceptance context is available

  # STPA-EXEC-BASIS-01
  Scenario Outline: the producer resolves environment requests after requirements
    Given a "<requirements>" domain requirement set
    When the contract environment request resolves a "<requested>" request
    Then the resolved contract environment request is "<basis>"

    Examples:
      | requirements | requested          | basis              |
      | none         | omitted            | target_agnostic     |
      | none         | target_profile     | target_agnostic     |
      | none         | simulation_profile | target_agnostic     |
      | domain       | omitted            | omitted             |
      | domain       | target_profile     | target_profile      |
      | domain       | simulation_profile | simulation_profile  |

  # STPA-EXEC-BASIS-02
  Scenario: target-agnostic is rejected when a domain resource is required
    Given a "domain" domain requirement set
    When the contract environment request resolves a "target_agnostic" request
    Then resolving the contract environment request is rejected

  # STPA-EXEC-BASIS-03
  Scenario: an unresolved resource-bearing contract retains omission
    Given a resource-bearing agent-message contract with an omitted environment request
    When the unresolved contract is validated and classified without a profile
    Then the contract requested environment basis is null
    And the classification axes are "parameterized/none/needs_binding/no_execution_claim"
    And the classification diagnostic is "environment_profile_not_supplied"

  # STPA-EXEC-BASIS-04 and STPA-EXEC-BASIS-05
  Scenario Outline: Stage 5 preserves the distinction between model output and agent messages
    Given an offline Stage 5 "<delivery>" route with action "<action>"
    When Stage 5 materializes the route with an omitted basis
    Then the Stage 5 execution contract basis is "<basis>"
    And the Stage 5 contract has domain requirements "<requirements>"

    Examples:
      | delivery             | action        | basis          | requirements  |
      | direct_prompt        | model_output  | target_agnostic | none          |
      | conversation_context | agent_message | omitted        | agent_channel |

  # STPA-EXEC-BASIS-06 through STPA-EXEC-BASIS-09
  Scenario Outline: domain resources remain parameterized without a profile
    Given an executable "<kind>" contract with one domain requirement
    When the contract is classified without a profile
    Then the classification axes are "parameterized/none/needs_binding/no_execution_claim"
    And the classification diagnostic is "environment_profile_not_supplied"

    Examples:
      | kind             |
      | tool_call        |
      | state_change     |
      | environment_action |
      | indirect_content |

  # STPA-EXEC-BASIS-10
  Scenario Outline: explicit environment requests retain their exact missing-profile diagnostic
    Given an executable agent-message contract requesting "<requested>"
    When the contract is classified without a profile
    Then the classification diagnostic is "<diagnostic>"

    Examples:
      | requested          | diagnostic                    |
      | target_profile     | target_profile_not_supplied   |
      | simulation_profile | simulation_contract_missing   |

  # STPA-EXEC-BASIS-11
  Scenario Outline: a selected profile binds an otherwise pending contract
    Given an executable agent-message contract with an omitted environment request
    When the contract is classified with a reviewed "<profile>" profile
    Then the classification axes are "concrete/<basis>/matched/<claim>"
    And the selected profile digest is pinned in the classification

    Examples:
      | profile    | basis              | claim                                  |
      | target     | target_profile     | target_specific_intent                |
      | simulation | simulation_profile | agent_behavior_with_simulated_tools   |

  # STPA-EXEC-BASIS-12
  Scenario: a resource-free model-output case stays target-agnostic with a global profile
    Given a resource-free model-output contract
    When the contract is classified with a reviewed target profile
    Then the classification axes are "concrete/target_agnostic/not_required/model_behavior_only"
    And the supplied profile is retained only as lineage without resource bindings

  # STPA-EXEC-BASIS-13
  Scenario: Stage 2 defines typed action semantics and domain-neutral contrasts
    Given the Stage 2 action-semantics prompts and critic prompt are inspected
    Then Stage 2 defines all five action kinds by typed meaning
    And Stage 2 gives domain-neutral examples for all five action kinds
    And the critic prompt names a typed action-effect conflict as an explicit gap

  # STPA-EXEC-BASIS-14
  Scenario: prose never relabels an explicitly typed action kind
    Given a control action whose description says "Return advice to a user"
    And whose typed effect kind is "environment_action"
    When the control action semantics are validated
    Then its typed effect kind remains "environment_action"

  # STPA-EXEC-BASIS-15
  Scenario: the unresolved contract is portable across the repository boundary
    Given a resource-bearing agent-message contract with an omitted environment request
    When the unresolved contract is serialized as canonical JSON
    Then standard JSON tooling parses a null requested environment basis
    And the portable contract retains the "agent_channel" requirement

  # STPA-EXEC-BASIS-16
  Scenario: multi-turn conversation mechanics do not create a domain dependency
    Given an offline Stage 5 "conversation_context" route with action "model_output"
    When Stage 5 materializes the route with an omitted basis
    Then the Stage 5 execution contract basis is "target_agnostic"
    And the Stage 5 contract has domain requirements "none"
