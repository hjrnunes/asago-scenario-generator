# mutation-stamp: sha256=eaab3790a394e667506f8c2dec40342fd7d18aacd8cbe68be9f0f3a23de2a53b
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-11T21:22:56.518920Z","feature_name":"SP3 \u2014 Run orchestration","feature_path":"features/sp3_run_orchestration.feature","background_hash":"b3d17b98f7fe97dbc2e371f25e10e49cd0c68d2bc051be7b494a5f806a0d57b1","implementation_hash":"sha256:15cd226aba77fda094a97620b718c9114a17855004646e8c38f67f33cabec5de","scenarios":[{"index":8,"name":"SP3-RUN-09 prompt templates exist for all stages","scenario_hash":"c6268e7f28641f6063d437e0782cb831813ead1cdaa33e3ff6f16491e617ff6c","mutation_count":8,"result":{"Total":8,"Killed":8,"Survived":0,"Errors":0},"tested_at":"2026-08-11T21:22:56.518920Z"}]}
# acceptance-mutation-manifest-end

Feature: SP3 — Run orchestration
  The SP3 run orchestrates Stage 5 (BDI generation), Stage 6 (narrative,
  attack tree, Gherkin), and Stage 7 (validators, eval metrics, coverage
  gaps) in sequence. Stage 5 produces ScenarioSpec instances. Stage 6
  concretizes each into a ScenarioEnvelope. Stage 7 validates and scores.
  All LLM calls are logged to calls.jsonl and a run manifest is written.

  Background:
    Given the SP3 run module is importable
    And an enriched threat set fixture for Klarna is available
    And a control structure fixture for Klarna is available
    And a loss analysis fixture for Klarna is available

  # SP3-RUN-01
  Scenario: SP3-RUN-01 full run produces scenario envelopes and eval scorecard
    Given an LLM that returns valid BDI generation, narrative, attack tree, and Gherkin results
    And a run directory for output
    When the full SP3 run is executed
    Then a directory scenarios exists in the run directory
    And at least one file *.yaml exists in the scenarios directory
    And at least one file *.feature exists in the scenarios directory
    And a file eval-scorecard.yaml exists in the run directory

  # SP3-RUN-02
  Scenario: SP3-RUN-02 stages execute in order Stage 5 then Stage 6 then Stage 7
    Given an LLM that returns valid results for all stages
    When the full SP3 run is executed
    Then Stage 5 BDI generation is produced first
    And Stage 6 concretization is produced second
    And Stage 7 validation and eval is produced last

  # SP3-RUN-03
  Scenario: SP3-RUN-03 all LLM calls are logged to calls.jsonl
    Given an LLM that returns valid results for all stages
    And a run directory for output
    When the full SP3 run is executed
    Then a file calls.jsonl exists in the run directory
    And the file contains entries with stage stage_5
    And the file contains entries with stage stage_6

  # SP3-RUN-04
  Scenario: SP3-RUN-04 Stage 7 makes no LLM calls
    Given an LLM that returns valid results for all stages
    When the full SP3 run is executed
    Then no call log entries have stage stage_7

  # SP3-RUN-05
  Scenario: SP3-RUN-05 run manifest is written at run end
    Given an LLM that returns valid results for all stages
    And a run directory for output
    When the full SP3 run is executed
    Then a file run-manifest.yaml exists in the run directory

  # SP3-RUN-06
  Scenario: SP3-RUN-06 run manifest records stage summary
    Given an LLM that returns valid results for all stages
    When the full SP3 run is executed
    Then the run manifest has stage_summary with call counts for stage_5
    And the run manifest has stage_summary with call counts for stage_6

  # SP3-RUN-07
  Scenario: SP3-RUN-07 run manifest records input hashes
    Given an LLM that returns valid results for all stages
    When the full SP3 run is executed
    Then the run manifest input_hashes contains a hash for the enriched threat set
    And the run manifest input_hashes contains a hash for the control structure
    And the run manifest input_hashes contains a hash for the loss analysis

  # SP3-RUN-08
  Scenario: SP3-RUN-08 run manifest records prompt hashes
    Given an LLM that returns valid results for all stages
    When the full SP3 run is executed
    Then the run manifest prompt_hashes contains SHA-256 hashes for stage5_system.j2
    And the run manifest prompt_hashes contains SHA-256 hashes for stage5_user.j2
    And the run manifest prompt_hashes contains SHA-256 hashes for stage6a_narrative_system.j2
    And the run manifest prompt_hashes contains SHA-256 hashes for stage6b_tree_system.j2
    And the run manifest prompt_hashes contains SHA-256 hashes for stage6c_gherkin_system.j2

  # SP3-RUN-09
  Scenario Outline: SP3-RUN-09 prompt templates exist for all stages
    Given the SP3 prompt templates directory
    Then the SP3 prompts directory contains `<template>`

    Examples:
      | template                    |
      | stage5_system.j2            |
      | stage5_user.j2              |
      | stage6a_narrative_system.j2 |
      | stage6a_narrative_user.j2   |
      | stage6b_tree_system.j2      |
      | stage6b_tree_user.j2        |
      | stage6c_gherkin_system.j2   |
      | stage6c_gherkin_user.j2     |

  # SP3-RUN-10
  Scenario Outline: SP3-RUN-10 module layout matches spec
    Given the SP3 scenario production module
    Then the module `<module>` exists and is importable

    Examples:
      | module            |
      | bdi_generation.py |
      | narrative.py      |
      | attack_tree.py    |
      | gherkin.py        |
      | validators.py     |
      | eval_metrics.py   |
      | coverage.py       |
      | assembly.py       |
      | run.py            |

  # SP3-RUN-11
  Scenario: SP3-RUN-11 SP1 and SP2 artifacts are consumed as input
    Given an LLM that returns valid results for all stages
    When the full SP3 run is executed
    Then the scenario specs are validated against the control structure
    And the eval metrics consume the enriched threat set coverage analysis
    And the traceability validation consumes the loss analysis

  # SP3-RUN-12
  Scenario: SP3-RUN-12 run_sp3.py CLI script exists and accepts arguments
    Given the scripts directory
    Then a file run_sp3.py exists in the scripts directory
    And run_sp3.py accepts an enriched-threats argument
    And run_sp3.py accepts a control-structure argument
    And run_sp3.py accepts a loss-analysis argument
    And run_sp3.py accepts an output-dir argument

  # SP3-RUN-13
  Scenario: SP3-RUN-13 max-workers flag controls parallelism for Stage 6 calls
    Given an LLM that returns valid results for all stages
    And a max_workers value of 2
    When the full SP3 run is executed with max_workers 2
    Then Stage 6 calls are parallelized across scenarios

  # SP3-RUN-21
  Scenario: SP3-RUN-21 exhausted structured length retry aborts remaining threats
    Given three structural threats are queued for Stage 5
    And an LLM whose Stage 5 normal and concise attempts both reach completion length
    When the full SP3 run is executed
    Then exactly 2 Stage 5 completion attempts are recorded
    And the Stage 5 diagnostics say 2 remaining threats were aborted

  # SP3-RUN-14
  Scenario: SP3-RUN-14 coverage gaps are written to coverage-gaps.json
    Given an LLM that returns valid results for all stages
    And a run directory for output
    When the full SP3 run is executed
    Then a file coverage-gaps.json exists in the run directory

  # SP3-RUN-15
  Scenario: SP3-RUN-15 scenario envelope files validate against ScenarioEnvelope schema
    Given an LLM that returns valid results for all stages
    When the full SP3 run is executed
    Then every scenario YAML file in the scenarios directory loads as a valid ScenarioEnvelope

  # SP3-RUN-16
  Scenario: SP3-RUN-16 scenario count equals the number of structural threats
    Given an enriched threat set with 10 structural threats
    And an LLM that returns valid results for all stages
    When the full SP3 run is executed
    Then 10 scenario envelopes are produced

  # SP3-RUN-17
  Scenario: SP3-RUN-17 eval scorecard includes coverage gaps
    Given an LLM that returns valid results for all stages
    When the full SP3 run is executed
    Then the eval scorecard contains coverage_gaps

  # SP3-RUN-18
  Scenario: SP3-RUN-18 existing pipeline tests are unaffected
    Given the SP3 scenario production module is implemented
    When the existing test suite is run
    Then no new failures are introduced

  # SP3-RUN-19
  Scenario: SP3-RUN-19 run manifest records scenario count and validation status
    Given an LLM that returns valid results for all stages
    When the full SP3 run is executed
    Then the run manifest records the total scenario count
    And the run manifest records the number of validation errors

  # SP3-RUN-20
  Scenario: SP3-RUN-20 Stage 6 calls are parallelizable across the 3 call types per scenario
    Given a ScenarioSpec and 3 LLM call specifications for narrative, attack_tree, and gherkin
    When the 3 calls are executed in parallel for the scenario
    Then results are returned in the same order as the input specifications
    And the number of LLM calls equals 3
