# mutation-stamp: sha256=0d24c9c66594547d4e61831382be624708a61a830c69d5290b3286623bec0b2b
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-31T10:01:57.676392Z","feature_name":"Opt-in STPA obligation challenge analysis","feature_path":"features/stpa_challenge_analysis.feature","background_hash":"f3f0b13ca93cb976fc816e4211b6cef4b504d5f1d5119ce67c19036b959c6b1f","implementation_hash":"sha256:c790b0507ff236cd74319890f1ffcff132f0e97a73e4f2131296d353422d0923","scenarios":[{"index":0,"name":"one opted-in attempt returns one closed STPA result","scenario_hash":"c354040c72a7ee26d2fc359b94a4ae86ab31ae69b114e056d8073ce7d201563a","mutation_count":18,"result":{"Total":18,"Killed":18,"Survived":0,"Errors":0},"tested_at":"2026-08-31T10:01:57.676392Z"}]}
# acceptance-mutation-manifest-end

Feature: Opt-in STPA obligation challenge analysis
  A selected exact pair may receive one bounded STPA reconsideration while
  the original decision and Phase 2 assessment remain historical evidence.

  Background:
    Given an exact selected Phase 3 challenge target

  Scenario Outline: one opted-in attempt returns one closed STPA result
    Given closed-loop analysis is explicitly opted in
    And the fake STPA adapter returns "<adapter_result>"
    When the selected target is reconsidered once
    Then the analysis status is "<analysis_status>"
    And the completed challenge disposition is "<challenge_disposition>"
    And the original STPA decision remains byte-equivalent
    And the adapter reports <adapter_attempts> attempt and <provider_calls> provider calls
    And correspondence and coverage changes are both <coverage_changes>

    Examples:
      | adapter_result | analysis_status | challenge_disposition | adapter_attempts | provider_calls | coverage_changes |
      | ica            | completed       | ica                   | 1                | 0              | 0                |
      | justified_na   | completed       | justified_na          | 1                | 0              | 0                |
      | unresolved     | completed       | unresolved            | 1                | 0              | 0                |

  Scenario: opt-out stops before adapter construction
    Given closed-loop analysis is not opted in
    When the selected target is reconsidered once
    Then no challenge analysis result is produced
    And the adapter was constructed 0 times

  Scenario: invalid ICA identity remains a technical failure
    Given closed-loop analysis is explicitly opted in
    And the fake STPA adapter returns "invalid_ica"
    When the selected target is reconsidered once
    Then the analysis status is "technical_failure"
    And the technical failure kind is "identity_validation_failed"
    And no completed challenge disposition is recorded
    And the original STPA decision remains byte-equivalent

  Scenario: the exact target is attempted at most once
    Given closed-loop analysis is explicitly opted in
    And the fake STPA adapter returns "unresolved"
    When the selected target is reconsidered once
    And the same target is reconsidered with its prior result
    Then the second attempt is rejected as "already attempted"
    And the adapter was constructed 1 times

  Scenario: Phase 2 and ordinary STPA remain unchanged
    Given closed-loop analysis is explicitly opted in
    And the fake STPA adapter returns "ica"
    When the selected target is reconsidered once
    Then the Phase 2 assessment remains byte-equivalent
    And hybrid generation remains "not_attempted"
    And hybrid admission remains "not_assessed"
    And ordinary stpa-run has no Phase 3 analysis dependency
