# STPA-EXEC-ROUTE-01 through STPA-EXEC-ROUTE-08
Feature: STPA Stage 5 execution-route selection
  Stage 5 chooses a request-local route from the supplied evidence. Deterministic
  assembly maps that choice to a semantic contract without inventing a target.

  Background:
    Given a corrected Stage 5 route context is available

  Scenario Outline: STPA-EXEC-ROUTE-01 executable route choices are materialized
    Given the provider selects "<delivery>" with action "<action>" roles "<roles>" and influence "<influence>"
    When corrected Stage 5 materializes the route
    Then the materialized execution contract is "executable_route"
    And the contract uses delivery "<delivery>" and action "<action>"
    And the contract has domain requirements "<requirements>"

    Examples:
      | delivery            | action          | roles                   | influence | requirements    |
      | direct_prompt       | model_output    | none                    | none      | none            |
      | conversation_context| model_output    | none                    | none      | none            |
      | indirect_content    | model_output    | role_stimulus_carrier   | direct    | stimulus_carrier|
      | direct_prompt       | tool_call       | role_target_action      | none      | target_action   |

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
