# mutation-stamp: sha256=4959a3a794f009be490eab0895aa2eaca94307a0f5fa1d211536e02441f8266b
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-10T15:36:17.490382Z","feature_name":"Envelope system_context block (umcf)","feature_path":"features/envelope_umcf_system_context.feature","background_hash":"75d296120ab18c01c871945301a352361787bffd456b3d2f285be4d8b769f3f1","implementation_hash":"unknown","scenarios":[{"index":0,"name":"UMCF-01 SystemContext model has required fields","scenario_hash":"4092ea928d9ee0ea151920bfab1bbcce6e706987cb54c15f565779d450080390","mutation_count":12,"result":{"Total":12,"Killed":12,"Survived":0,"Errors":0},"tested_at":"2026-08-10T15:36:17.490382Z"},{"index":6,"name":"UMCF-07 system_context inlines active_zones from capability profile","scenario_hash":"9f77b2539403b10df41ebf15c2f192c61d19a5e62397ce6ee62e90e4c04cb5e8","mutation_count":3,"result":{"Total":3,"Killed":3,"Survived":0,"Errors":0},"tested_at":"2026-08-10T15:36:17.490382Z"},{"index":7,"name":"UMCF-08 system_context inlines boolean flags from capability profile","scenario_hash":"42c7b4f4dbff48f5af44c947d1e864f441fee21df9bdc2a26897e1f979fe7846","mutation_count":4,"result":{"Total":4,"Killed":4,"Survived":0,"Errors":0},"tested_at":"2026-08-10T15:36:17.490382Z"}]}
# acceptance-mutation-manifest-end

Feature: Envelope system_context block (umcf)
  The ScenarioEnvelope gains an optional system_context block that inlines
  SP1 data so adapters can interpret scenarios without separate SP1
  artifacts. The block is populated deterministically during assembly
  from the capability profile and control structure — no LLM calls.

  Background:
    Given the STPA boundary schema module is importable
    And a control structure with responsibility RESP-1 having description "Orchestrate tool calls safely"
    And a control action CA-1-1 under RESP-1 having description "Execute requested tool"
    And a capability profile with tool_inventory having tool "database_query"
    And the capability profile has active_zones ["input", "reasoning", "tool_execution"]
    And the capability profile has multi_agent False
    And the capability profile has has_persistent_memory False
    And a valid scenario spec SCN-001 with target_controller RESP-1 and target_control_action CA-1-1

  # UMCF-01
  Scenario Outline: UMCF-01 SystemContext model has required fields
    Given the SystemContext model is defined
    Then it has a <field> field of type <type>

    Examples:
      | field                                  | type             |
      | target_responsibility_description      | str              |
      | target_control_action_description      | str              |
      | tool_inventory                          | list             |
      | active_zones                            | list of str      |
      | multi_agent                             | bool             |
      | has_persistent_memory                   | bool             |

  # UMCF-02
  Scenario: UMCF-02 ScenarioEnvelope has optional system_context field
    Given the ScenarioEnvelope model is defined
    Then the system_context field is optional with a default of None

  # UMCF-03
  Scenario: UMCF-03 assemble_envelope accepts capability profile and control structure
    When assemble_envelope is called with the capability profile and control structure
    Then the resulting ScenarioEnvelope.system_context is not None

  # UMCF-04
  Scenario: UMCF-04 system_context resolves target_responsibility_description from RESP-ID
    When assemble_envelope is called with the capability profile and control structure
    Then the system_context.target_responsibility_description is "Orchestrate tool calls safely"

  # UMCF-05
  Scenario: UMCF-05 system_context resolves target_control_action_description from CA-ID
    When assemble_envelope is called with the capability profile and control structure
    Then the system_context.target_control_action_description is "Execute requested tool"

  # UMCF-06
  Scenario: UMCF-06 system_context inlines tool_inventory from capability profile
    When assemble_envelope is called with the capability profile and control structure
    Then the system_context.tool_inventory contains a tool named "database_query"

  # UMCF-07
  Scenario Outline: UMCF-07 system_context inlines active_zones from capability profile
    When assemble_envelope is called with the capability profile and control structure
    Then the system_context.active_zones contains <zone>

    Examples:
      | zone             |
      | "input"          |
      | "reasoning"      |
      | "tool_execution" |

  # UMCF-08
  Scenario Outline: UMCF-08 system_context inlines boolean flags from capability profile
    When assemble_envelope is called with the capability profile and control structure
    Then the system_context.<field> is <value>

    Examples:
      | field                  | value  |
      | multi_agent            | False  |
      | has_persistent_memory  | False  |

  # UMCF-09
  Scenario: UMCF-09 envelope without system_context still parses
    Given a scenario envelope wrapping SCN-001 with no system_context provided
    When the scenario envelope is validated
    Then validation succeeds
    And the system_context is None

  # UMCF-10
  Scenario: UMCF-10 system_context is serialized in scenario YAML
    When assemble_envelope is called with the capability profile and control structure
    And the envelope is serialized to YAML
    Then the YAML contains a system_context key
    And the YAML contains target_responsibility_description

  # UMCF-11
  Scenario: UMCF-11 run_sp3 passes capability profile to assemble_envelope
    Given a capability profile is available during SP3 execution
    When run_sp3 assembles an envelope
    Then the resulting ScenarioEnvelope.system_context is not None

  # UMCF-12
  Scenario: UMCF-12 system_context with multi_agent True from capability profile
    Given the capability profile has multi_agent True
    When assemble_envelope is called with the capability profile and control structure
    Then the system_context.multi_agent is True

  # UMCF-13
  Scenario: UMCF-13 system_context with has_persistent_memory True from capability profile
    Given the capability profile has has_persistent_memory True
    When assemble_envelope is called with the capability profile and control structure
    Then the system_context.has_persistent_memory is True

  # UMCF-14
  Scenario: UMCF-14 system_context with empty tool_inventory when no tools
    Given the capability profile has tool_inventory empty
    When assemble_envelope is called with the capability profile and control structure
    Then the system_context.tool_inventory is an empty list
