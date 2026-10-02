# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-10T15:37:04.011563Z","feature_name":"Envelope consumer_hints filtering metadata (8b06)","feature_path":"features/envelope_8b06_consumer_hints.feature","background_hash":"f0f9074ca8df46fcace42eb51905a1f263cc0f996230c7a0b7e87abf27ca6cab","implementation_hash":"unknown","scenarios":[{"index":0,"name":"8B06-01 ConsumerHints model has required fields","scenario_hash":"112ec72f12be62ee6308d408ff06fcde85807f06a8e1af5188e62b93df6f86cd","mutation_count":14,"result":{"Total":14,"Killed":14,"Survived":0,"Errors":0},"tested_at":"2026-08-10T15:36:45.661633Z"}]}
# acceptance-mutation-manifest-end

Feature: Envelope consumer_hints filtering metadata (8b06)
  The ScenarioEnvelope gains an optional consumer_hints block with
  deterministic, rule-based fields that let adapters self-select
  scenarios without LLM inference. Fields are computed in a
  post-generation enrichment pass from the capability profile, attack
  tree, and narrative — no LLM calls.

  Background:
    Given the STPA boundary schema module is importable
    And a valid scenario spec SCN-001 with target_controller RESP-1 and target_control_action CA-1-1
    And a capability profile with active_zones ["input", "reasoning", "tool_execution"]
    And the capability profile has multi_agent False
    And the capability profile has has_persistent_memory False
    And an attack tree with root "Exploit input validation" and leaves mentioning tool execution
    And a narrative describing a single-turn attack

  # 8B06-01
  Scenario Outline: 8B06-01 ConsumerHints model has required fields
    Given the ConsumerHints model is defined
    Then it has a <field> field of type <type>

    Examples:
      | field                       | type  |
      | primary_attack_zone         | str   |
      | requires_tool_execution     | bool  |
      | requires_multi_turn         | bool  |
      | requires_multi_agent        | bool  |
      | requires_persistent_state   | bool  |
      | garak_testability           | str   |
      | midojo_testability          | str   |

  # 8B06-02
  Scenario: 8B06-02 ScenarioEnvelope has optional consumer_hints field
    Given the ScenarioEnvelope model is defined
    Then the consumer_hints field is optional with a default of None

  # 8B06-03
  Scenario: 8B06-03 consumer_hints computed deterministically without LLM calls
    When consumer_hints are computed from the capability profile, attack tree, and narrative
    Then the computation involves no LLM calls
    And the consumer_hints block is not None

  # 8B06-04
  Scenario Outline: 8B06-04 primary_attack_zone derived from scenario zone information
    Given a scenario whose primary attack zone is <zone>
    When consumer_hints are computed
    Then the primary_attack_zone is <zone>

    Examples:
      | zone             |
      | input            |
      | reasoning        |
      | tool_execution   |
      | memory           |
      | inter_agent      |

  # 8B06-05
  Scenario: 8B06-05 requires_tool_execution True when attack tree leaves mention tool execution
    Given an attack tree with leaves mentioning tool execution
    When consumer_hints are computed
    Then requires_tool_execution is True

  # 8B06-06
  Scenario: 8B06-06 requires_tool_execution False when attack tree leaves do not mention tools
    Given an attack tree with leaves that do not mention tool execution
    When consumer_hints are computed
    Then requires_tool_execution is False

  # 8B06-07
  Scenario: 8B06-07 requires_multi_turn True when narrative indicates multi-turn interaction
    Given a narrative describing a multi-turn attack with phrases indicating repeated interaction
    When consumer_hints are computed
    Then requires_multi_turn is True

  # 8B06-08
  Scenario: 8B06-08 requires_multi_turn False when narrative describes single-turn attack
    Given a narrative describing a single-turn attack
    When consumer_hints are computed
    Then requires_multi_turn is False

  # 8B06-09
  Scenario: 8B06-09 requires_multi_agent derived from capability profile multi_agent flag
    Given the capability profile has multi_agent True
    When consumer_hints are computed
    Then requires_multi_agent is True

  # 8B06-10
  Scenario: 8B06-10 requires_persistent_state derived from capability profile has_persistent_memory flag
    Given the capability profile has has_persistent_memory True
    When consumer_hints are computed
    Then requires_persistent_state is True

  # 8B06-11
  Scenario Outline: 8B06-11 garak_testability rule-based from primary_attack_zone
    Given a scenario whose primary attack zone is <zone>
    When consumer_hints are computed
    Then garak_testability is <garak_level>

    Examples:
      | zone            | garak_level |
      | input           | high        |
      | reasoning       | medium      |
      | tool_execution  | low         |
      | memory          | low         |
      | inter_agent     | low         |

  # 8B06-12
  Scenario Outline: 8B06-12 midojo_testability rule-based from zone, tree, and profile
    Given a scenario whose primary attack zone is <zone>
    And the attack tree <tree_characteristic>
    And the capability profile has <profile_characteristic>
    When consumer_hints are computed
    Then midojo_testability is <midojo_level>

    Examples:
      | zone            | tree_characteristic                  | profile_characteristic           | midojo_level |
      | tool_execution  | leaves mention tool execution        | multi_agent False                | high         |
      | input           | leaves do not mention tool execution | multi_agent True                 | medium       |
      | input           | leaves do not mention tool execution | has_persistent_memory True       | medium       |
      | input           | leaves do not mention tool execution | multi_agent False                | low          |

  # 8B06-13
  Scenario: 8B06-13 envelope without consumer_hints still parses
    Given a scenario envelope wrapping SCN-001 with no consumer_hints provided
    When the scenario envelope is validated
    Then validation succeeds
    And the consumer_hints is None

  # 8B06-14
  Scenario: 8B06-14 consumer_hints serialized in scenario YAML
    When consumer_hints are computed and the envelope is serialized to YAML
    Then the YAML contains a consumer_hints key
    And the YAML contains garak_testability
    And the YAML contains midojo_testability

  # 8B06-15
  Scenario: 8B06-15 assemble_envelope populates consumer_hints when enrichment data is provided
    When assemble_envelope is called with the capability profile, control structure, attack tree, and narrative
    Then the resulting ScenarioEnvelope.consumer_hints is not None
    And the consumer_hints.garak_testability is a non-empty string
    And the consumer_hints.midojo_testability is a non-empty string

  # 8B06-16
  Scenario: 8B06-16 run_sp3 populates consumer_hints during assembly
    Given a capability profile is available during SP3 execution
    When run_sp3 assembles an envelope
    Then the resulting ScenarioEnvelope.consumer_hints is not None

  # 8B06-18
  Scenario: 8B06-18 enrichment computation is in a dedicated module
    Given the scenario_prod enrichment module is importable
    Then it exposes a function to compute consumer_hints from profile, tree, and narrative
    And it exposes a function to compute system_context from profile and control structure
