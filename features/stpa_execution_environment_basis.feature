# STPA-EXEC-BASIS-13 and -14
Feature: STPA control-action effect semantics
  Stage 2 states typed action semantics with domain-neutral contrasts, and
  prose never relabels an explicitly typed action kind.

  Background:
    Given the execution environment-basis acceptance context is available

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
