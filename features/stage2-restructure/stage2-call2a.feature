# mutation-stamp: sha256=44b8261b1841d9937206a9f501e1ebaf2848493fbd7034488e2bb03c50d13762
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-11T16:22:06.376388Z","feature_name":"Stage 2 Call 2a Responsibilities and Process Model","feature_path":"features/stage2-restructure/stage2-call2a.feature","background_hash":"3ce4ce047c4808724701c3d5045ba13b821552e7e8a42e47ce48aacf8a16b50b","implementation_hash":"unknown","scenarios":[{"index":0,"name":"Old stage2_call2 templates are absent","scenario_hash":"e5a30f8a4cf1d86175a6dbe3de0c292c38104bb95ce6bb28f1788e515eea3d74","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-11T16:22:06.376388Z"},{"index":1,"name":"New stage2_call2a templates are present","scenario_hash":"0c3fbf96993f4da93e5dc0608ff1b8c9c431104a511eb4db0fe4753ff28a59ea","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-11T16:22:06.376388Z"}]}
# acceptance-mutation-manifest-end

# stage2-call2a
Feature: Stage 2 Call 2a Responsibilities and Process Model
  The current single Call 2 (responsibilities + PM + CA + FB + CP) is split
  into Call 2a (responsibilities + responsibility constraints + process
  model parts) and Call 2b (control actions + feedback channels + controlled
  processes). Call 2a receives the requirements from Call 1 and the
  capability profile, and produces responsibilities with RCs and PM parts
  only — no control actions, feedback channels, or controlled processes.
  The old templates stage2_call2_system.j2 / stage2_call2_user.j2 are
  replaced by stage2_call2a_system.j2 / stage2_call2a_user.j2 and
  stage2_call2b_system.j2 / stage2_call2b_user.j2.

  Background:
    Given a use-case file and a risk-extraction file are available
    And an LLM endpoint is configured

  # stage2-call2a-old-templates-removed
  Scenario Outline: Old stage2_call2 templates are absent
    Then the prompts directory does not contain `<template>`
    Examples:
      | template |
      | stage2_call2_system.j2 |
      | stage2_call2_user.j2 |

  # stage2-call2a-new-templates-present
  Scenario Outline: New stage2_call2a templates are present
    Then the prompts directory contains `<template>`
    Examples:
      | template |
      | stage2_call2a_system.j2 |
      | stage2_call2a_user.j2 |

  # stage2-call2a-rc-pm-distinction-in-prompt
  Scenario: Call 2a system prompt distinguishes RCs from PMs
    Then the prompt template `stage2_call2a_system.j2` contains `RC-X-Y`
    And the prompt template `stage2_call2a_system.j2` contains `PM-X-Y`
    And the prompt template `stage2_call2a_system.j2` contains `Do NOT copy PM entries as RCs`

  # stage2-call2a-zone-driven-in-prompt
  Scenario: Call 2a system prompt includes zone-driven responsibility rules
    Then the prompt template `stage2_call2a_system.j2` contains `tool_execution`
    And the prompt template `stage2_call2a_system.j2` contains `memory`
    And the prompt template `stage2_call2a_system.j2` contains `hitl`
    And the prompt template `stage2_call2a_system.j2` contains `inter_agent`

  # stage2-call2a-capability-profile-in-user-prompt
  Scenario: Call 2a user prompt includes capability profile context
    Then the prompt template `stage2_call2a_user.j2` contains `capability_profile`
    And the prompt template `stage2_call2a_user.j2` contains `zones_active`

  # stage2-call2a-feedback-source-null-in-prompt
  Scenario: Call 2a instructs leaving feedback_source null on PM parts
    Then the prompt template `stage2_call2a_user.j2` contains `feedback_source null`

  # stage2-call2a-no-control-elements-in-prompt
  Scenario: Call 2a system prompt does not request control actions or feedback channels
    Then the prompt template `stage2_call2a_system.j2` does not contain `Control Actions`
    And the prompt template `stage2_call2a_system.j2` does not contain `Feedback Channels`
