# mutation-stamp: sha256=4589b76773c1978b03e405d2e79a4966baf69a98ce0ff53dc5bce067cfd4eab4
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-26T17:45:02.810441Z","feature_name":"Acceptance live LLM opt-in","feature_path":"features/acceptance_live_llm_opt_in.feature","background_hash":"2df76b13a166b0749a5c50310574c706464ff8f8b75b483f522da6da676ed971","implementation_hash":"unknown","scenarios":[{"index":2,"name":"Acceptance live LLM opt-in ALO-03 other values do not authorize live work","scenario_hash":"f7951a148df076feaacde894beeb0fba46a9be531783eeb9285ebffb9bd0b743","mutation_count":6,"result":{"Total":6,"Killed":6,"Survived":0,"Errors":0},"tested_at":"2026-08-26T17:45:02.810441Z"}]}
# acceptance-mutation-manifest-end

Feature: Acceptance live LLM opt-in
  Full-pipeline acceptance scenarios can spend money and require a configured
  live LLM endpoint. They are not authorized merely because endpoint
  credentials exist. Deterministic scenarios continue to run by default,
  while live-LLM scenarios run only when ASAGO_SCENARIO_GENERATOR_QA_PIPELINE is exactly
  "1". Skipped scenarios remain visibly distinguishable from passed scenarios.

  Background:
    Given an isolated acceptance fixture with one deterministic scenario and one live-LLM scenario

  # Acceptance live LLM opt-in ALO-01 default execution skips live work
  Scenario: Acceptance live LLM opt-in ALO-01 default execution skips live work
    Given ASAGO_SCENARIO_GENERATOR_QA_PIPELINE is unset
    And live LLM endpoint variables are configured
    When the isolated acceptance fixture is executed
    Then the deterministic scenario is executed
    And the live-LLM scenario is not executed
    And the live-LLM scenario is reported as skipped because ASAGO_SCENARIO_GENERATOR_QA_PIPELINE is not "1"
    And the acceptance result succeeds

  # Acceptance live LLM opt-in ALO-02 explicit opt-in executes live work
  Scenario: Acceptance live LLM opt-in ALO-02 explicit opt-in executes live work
    Given ASAGO_SCENARIO_GENERATOR_QA_PIPELINE is "1"
    And live LLM endpoint variables are configured
    When the isolated acceptance fixture is executed
    Then the deterministic scenario is executed
    And the live-LLM scenario is executed
    And the live-LLM scenario is reported as passed
    And the acceptance result succeeds

  # Acceptance live LLM opt-in ALO-03 other values do not authorize live work
  Scenario Outline: Acceptance live LLM opt-in ALO-03 other values do not authorize live work
    Given ASAGO_SCENARIO_GENERATOR_QA_PIPELINE is "<value>"
    And the live-LLM opt-in value is observed as "<expected_value>"
    And live LLM endpoint variables are configured
    When the isolated acceptance fixture is executed
    Then the live-LLM scenario is not executed
    And the live-LLM scenario is reported as skipped because ASAGO_SCENARIO_GENERATOR_QA_PIPELINE is not "1"

    Examples:
      | value | expected_value |
      | 0     | 0              |
      | true  | true           |
      | yes   | yes            |

  # Acceptance live LLM opt-in ALO-04 opt-in without an endpoint fails visibly
  Scenario: Acceptance live LLM opt-in ALO-04 opt-in without an endpoint fails visibly
    Given ASAGO_SCENARIO_GENERATOR_QA_PIPELINE is "1"
    And live LLM endpoint variables are unset
    When the isolated acceptance fixture is executed
    Then the live-LLM scenario is attempted
    And the live-LLM scenario fails with an endpoint-not-configured message
    And the acceptance result fails

  # Acceptance live LLM opt-in ALO-05 scenario state remains isolated
  Scenario: Acceptance live LLM opt-in ALO-05 scenario state remains isolated
    Given ASAGO_SCENARIO_GENERATOR_QA_PIPELINE is "1"
    And live LLM endpoint variables are configured
    And the isolated acceptance fixture contains two live-LLM scenarios
    When the isolated acceptance fixture is executed
    Then each scenario receives the original process environment
    And each scenario uses a distinct temporary fixture directory
    And neither scenario can observe the other scenario's output files
