# STPA-EXEC-ROUTE-01 through STPA-EXEC-ROUTE-08
Feature: STPA Stage 5 execution-route selection
  Stage 5 describes the test stimulus and binds it to one declared causal factor.
  Deterministic assembly derives delivery, resource roles and attacker influence
  without inventing a target or making a second causal-factor choice.

  Background:
    Given a corrected Stage 5 route context is available

  Scenario Outline: STPA-EXEC-ROUTE-01 executable route choices are materialized
    Given the provider describes stimulus "<stimulus>" with action "<action>" and binds its declared causal factor
    When corrected Stage 5 materializes the route
    Then the materialized execution contract is "executable_route"
    And the contract uses delivery "<delivery>" and action "<action>"
    And the contract has domain requirements "<requirements>"

    Examples:
      | stimulus         | delivery             | action       | requirements     |
      | user_message     | direct_prompt        | model_output | none             |
      | conversation     | conversation_context | model_output | none             |
      | retrieved_content| indirect_content     | model_output | stimulus_carrier |
      | user_message     | direct_prompt        | tool_call    | target_action    |

  Scenario: STPA-EXEC-ROUTE-05 analytical-only is explicit
    Given the provider selects an explicit analytical-only route
    When corrected Stage 5 materializes the route
    Then the materialized execution contract is "analytical_only"
    And the contract has domain requirements "none"

  Scenario: STPA-EXEC-ROUTE-06 missing route fails closed
    Given the provider response omits execution_route
    When corrected Stage 5 materializes the route
    Then the materialization fails with an execution route error

  Scenario: STPA-EXEC-ROUTE-07 direct prompt cannot stand in for feedback failure
    Given the provider selects direct prompt for feedback factor "cause_3"
    When corrected Stage 5 materializes the route
    Then materialization says the delivery cannot exercise the selected factor

  Scenario: STPA-EXEC-ROUTE-08 prompt explains semantic output judgments
    When the corrected Stage 5 route prompt is rendered
    Then it requires a literal semantic proposition for model output
    And it explains the delivery and causal-factor compatibility table

  Scenario Outline: STPA-EXEC-ROUTE-09 route binding is explicit and singular
    Given the provider binds "<count>" declared factors to its executable stimulus
    When corrected Stage 5 materializes the route
    Then materialization requires exactly one declared causal factor binding

    Examples:
      | count |
      | 0     |
      | 2     |
