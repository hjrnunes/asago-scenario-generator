# mutation-stamp: sha256=670f138d024e351c2236e8cbb26cf88f14d73c7cdbc0a2bf0a33430f0b8f921d
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-11T21:23:10.394462Z","feature_name":"SP2 \u2014 Run orchestration","feature_path":"features/sp2_run_orchestration.feature","background_hash":"1563755e4e2524464cf2f71f549f69d5210644131eb79fec82e3484105e20250","implementation_hash":"sha256:51baa3854bde6dc41bcc77049674483ee5e9c4aa2dad678e95e04b8467e6b21a","scenarios":[{"index":8,"name":"SP2-RUN-09 prompt templates exist for Stage 3","scenario_hash":"2659a384fff158c94a29d226003aa64331eed190d5bab62413743caa6faeabf2","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-11T21:23:10.394462Z"}]}
# acceptance-mutation-manifest-end

Feature: SP2 — Run orchestration
  The SP2 run orchestrates Stage 3 (ICA enumeration) and Stage 4 (catalog
  enrichment) in sequence. Stage 3 produces ICAEnumeration via deterministic
  slot creation, LLM slot-filling, and N/A quality gates. Stage 4 produces
  EnrichedThreatSet via deterministic catalog matching and coverage analysis.
  All LLM calls are logged to calls.jsonl and a run manifest is written.

  Background:
    Given the SP2 run module is importable
    And a control structure fixture for Klarna is available
    And a capability profile fixture for Klarna is available
    And a loss analysis fixture for Klarna is available

  # SP2-RUN-01
  Scenario: SP2-RUN-01 full run produces both output artifacts
    Given an LLM that returns valid slot fill results for all responsibilities
    And a run directory for output
    When the full SP2 run is executed
    Then a file ica-enumeration.yaml exists in the run directory
    And a file enriched-threats.yaml exists in the run directory

  # SP2-RUN-02
  Scenario: SP2-RUN-02 stages execute in order Stage 3 then Stage 4
    Given an LLM that returns valid slot fill results for all responsibilities
    When the full SP2 run is executed
    Then Stage 3 ICA enumeration is produced first
    And Stage 4 catalog enrichment is produced second

  # SP2-RUN-03
  Scenario: SP2-RUN-03 all LLM calls are logged to calls.jsonl
    Given an LLM that returns valid slot fill results for all responsibilities
    And a run directory for output
    When the full SP2 run is executed
    Then a file calls.jsonl exists in the run directory
    And the file contains entries with stage stage_3

  # SP2-RUN-04
  Scenario: SP2-RUN-04 Stage 4 makes no LLM calls
    Given an LLM that returns valid slot fill results for all responsibilities
    When the full SP2 run is executed
    Then no call log entries have stage stage_4

  # SP2-RUN-05
  Scenario: SP2-RUN-05 run manifest is written at run end
    Given an LLM that returns valid slot fill results for all responsibilities
    And a run directory for output
    When the full SP2 run is executed
    Then a run manifest is written to the run directory

  # SP2-RUN-06
  Scenario: SP2-RUN-06 run manifest records stage summary
    Given an LLM that returns valid slot fill results for all responsibilities
    When the full SP2 run is executed
    Then the run manifest has stage_summary with call counts for stage_3

  # SP2-RUN-07
  Scenario: SP2-RUN-07 run manifest records N/A quality flags
    Given an LLM that returns slot fill results with some N/A slots exceeding the ratio threshold
    When the full SP2 run is executed
    Then the run manifest records N/A ratio flags
    And the run manifest records structural N/A check results

  # SP2-RUN-08
  Scenario: SP2-RUN-08 run manifest records coverage analysis
    Given an LLM that returns valid slot fill results for all responsibilities
    When the full SP2 run is executed
    Then the run manifest records coverage analysis metrics
    And the run manifest records catalog correspondence

  # SP2-RUN-09
  Scenario Outline: SP2-RUN-09 prompt templates exist for Stage 3
    Given the SP2 prompt templates directory
    Then the SP2 prompts directory contains `<template>`

    Examples:
      | template         |
      | stage3_system.j2 |
      | stage3_user.j2   |

  # SP2-RUN-10
  Scenario Outline: SP2-RUN-10 module layout matches spec
    Given the SP2 threat enumeration module
    Then the module `<module>` exists and is importable

    Examples:
      | module                |
      | slot_creation.py      |
      | technology_context.py |
      | slot_filling.py       |
      | na_quality.py         |
      | catalog_enrichment.py |
      | catalog_data.py       |
      | coverage.py           |
      | run.py                |

  # SP2-RUN-11
  Scenario: SP2-RUN-11 SP1 artifacts are consumed as input
    Given an LLM that returns valid slot fill results for all responsibilities
    When the full SP2 run is executed
    Then the ICA enumeration is validated against the loss analysis and control structure
    And the technology context block is built from the capability profile

  # SP2-RUN-13
  Scenario: SP2-RUN-13 max-workers flag controls parallelism
    Given an LLM that returns valid slot fill results for all responsibilities
    And a max_workers value of 2
    When the full SP2 run is executed with max_workers 2
    Then slot-filling calls are parallelized across responsibilities

  # SP2-RUN-14
  Scenario: SP2-RUN-14 N/A quality gates run after slot filling and before catalog enrichment
    Given an LLM that returns slot fill results with some N/A slots
    When the full SP2 run is executed
    Then N/A structural keyword check runs after slot filling
    And N/A ratio monitoring runs after slot filling
    And catalog enrichment runs after N/A quality gates

  # SP2-RUN-15
  Scenario: SP2-RUN-15 run manifest records input hashes
    Given an LLM that returns valid slot fill results for all responsibilities
    When the full SP2 run is executed
    Then the run manifest input_hashes contains a hash for the control structure
    And the run manifest input_hashes contains a hash for the capability profile
    And the run manifest input_hashes contains a hash for the loss analysis

  # SP2-RUN-16
  Scenario: SP2-RUN-16 run manifest records prompt hashes
    Given an LLM that returns valid slot fill results for all responsibilities
    When the full SP2 run is executed
    Then the run manifest prompt_hashes contains SHA-256 hashes for stage3_system.j2
    And the run manifest prompt_hashes contains SHA-256 hashes for stage3_user.j2

  # SP2-RUN-17
  Scenario: SP2-RUN-17 slot count in output matches the formula
    Given a control structure with 4 responsibilities having 2 control actions each and 2 coordination links
    And an LLM that returns valid slot fill results for all responsibilities
    When the full SP2 run is executed
    Then the ICA enumeration has 40 total slots

  # SP2-RUN-18
  Scenario: SP2-RUN-18 existing pipeline tests are unaffected
    Given the SP2 threat enumeration module is implemented
    When the existing test suite is run
    Then no new failures are introduced
