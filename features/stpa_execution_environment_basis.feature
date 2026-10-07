# STPA-EXEC-BASIS-01, -02, -13, -14 and -15
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
