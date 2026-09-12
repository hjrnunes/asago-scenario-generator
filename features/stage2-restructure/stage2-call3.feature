# mutation-stamp: sha256=6a68f0fe4173fc2043610adb9ef1ab865fdbc3f0d8fab67776b7838f5ac4ab89
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-11T16:22:07.478226Z","feature_name":"Stage 2 Call 3 Coordination and Integrity","feature_path":"features/stage2-restructure/stage2-call3.feature","background_hash":"3ce4ce047c4808724701c3d5045ba13b821552e7e8a42e47ce48aacf8a16b50b","implementation_hash":"unknown","scenarios":[]}
# acceptance-mutation-manifest-end

# stage2-call3
Feature: Stage 2 Call 3 Coordination and Integrity
  Call 3 is redefined as coordination-only plus integrity verification.
  It receives the full assembled control structure from Call 2a + Call 2b
  and identifies coordination links between responsibilities that share
  state. Code verifies connection integrity and supplies findings as context;
  the model reviews semantic meaning and does not rewrite those findings. The old
  connection-assignment mechanism (ConnectionSet with connection_assignments)
  is removed. The call-log step name changes from call_3_connections to
  call_3_coordination.

  Background:
    Given a use-case file and a risk-extraction file are available
    And an LLM endpoint is configured

  # stage2-call3-call-log-entry
  Scenario: Call 3 produces a call-log entry with step call_3_coordination
    Given live LLM acceptance is enabled with ASAGO_SCENARIO_GENERATOR_QA_PIPELINE "1"
    When I run `asago-scenario-generator stpa-run --use-case <use_case> --risk-extraction <risk_file> --output-dir <dir>`
    Then the command exits with code 0
    And `calls.jsonl` contains a call entry with `stage` `stage_2` and `step` `call_3_coordination`

  # stage2-call3-old-step-name-absent
  Scenario: Old call_3_connections step name is absent from the call log
    Given live LLM acceptance is enabled with ASAGO_SCENARIO_GENERATOR_QA_PIPELINE "1"
    When I run `asago-scenario-generator stpa-run --use-case <use_case> --risk-extraction <risk_file> --output-dir <dir>`
    Then the command exits with code 0
    And `calls.jsonl` does not contain a call entry with `stage` `stage_2` and `step` `call_3_connections`

  # stage2-call3-flag-not-fix-in-prompt
  Scenario: Call 3 system prompt separates deterministic findings from semantic review
    Then the prompt template `stage2_call3_system.j2` contains `Deterministic code has already checked`
    And the prompt template `stage2_call3_system.j2` contains `Do not return an`

  # stage2-call3-no-connection-assignments-in-prompt
  Scenario: Call 3 system prompt does not mention connection assignments
    Then the prompt template `stage2_call3_system.j2` does not contain `connection_assignments`
    And the prompt template `stage2_call3_system.j2` does not contain `ConnectionSet`

  # stage2-call3-integrity-findings-in-prompt
  Scenario: Call 3 system prompt mentions integrity findings
    Then the prompt template `stage2_call3_system.j2` contains `integrity_findings`

  # stage2-call3-user-prompt-uses-control-structure
  Scenario: Call 3 user prompt receives the full control structure
    Then the prompt template `stage2_call3_user.j2` contains `control_structure`
    And the prompt template `stage2_call3_user.j2` does not contain `responsibility_set`

  # stage2-call3-coordination-links-present
  Scenario: Control structure contains a coordination links list
    Given live LLM acceptance is enabled with ASAGO_SCENARIO_GENERATOR_QA_PIPELINE "1"
    When I run `asago-scenario-generator stpa-run --use-case <use_case> --risk-extraction <risk_file> --output-dir <dir>`
    Then the command exits with code 0
    And `control-structure.yaml` contains a `coordination_links` list
