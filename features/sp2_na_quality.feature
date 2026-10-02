# mutation-stamp: sha256=77dc422d4d39002bb3bc71acb2fbc98f589c182f318be9ded13c99dfc196f44f
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-10T07:32:42.966531Z","feature_name":"SP2 Stage 3 \u2014 N/A quality gates","feature_path":"features/sp2_na_quality.feature","background_hash":"81d51fbec80937836da350943ee2623afbd4332f366e0c0e5bb4ccc4b52aa25d","implementation_hash":"unknown","scenarios":[{"index":0,"name":"SP2-NA-01 N/A justification with structural keyword passes","scenario_hash":"747e40d6c5535b4f31d4d8db2ca6705985701fcd2504201c92b1cc8f0adf2cfe","mutation_count":6,"result":{"Total":6,"Killed":6,"Survived":0,"Errors":0},"tested_at":"2026-08-10T00:47:08.602640Z"}]}
# acceptance-mutation-manifest-end

Feature: SP2 Stage 3 — N/A quality gates
  N/A quality gates are deterministic post-fill checks that catch LLM laziness
  in declaring slots not applicable. N/A justifications must reference a
  specific structural property. No LLM calls.

  Background:
    Given the SP2 N/A quality module is importable

  # SP2-NA-01
  Scenario Outline: SP2-NA-01 N/A justification with structural keyword passes
    Given an N/A slot with na_justification containing the word <keyword>
    When the structural N/A quality check is run
    Then the slot passes the structural check

    Examples:
      | keyword        |
      | discrete       |
      | continuous     |
      | stateless      |
      | stateful       |
      | atomic         |
      | one-shot       |

  # SP2-NA-02
  Scenario: SP2-NA-02 N/A justification without structural keyword is flagged
    Given an N/A slot with na_justification this control action has no hazardous context
    When the structural N/A quality check is run
    Then the slot is flagged for missing structural keyword

  # SP2-NA-03
  Scenario: SP2-NA-03 N/A justification with no duration keyword passes
    Given an N/A slot with na_justification the action has no duration component
    When the structural N/A quality check is run
    Then the slot passes the structural check
