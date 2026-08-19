Feature: STPA tolerant reference normalization
  Tolerantly decoded STPA control-structure responses are normalized before
  typed serialization and validation. Recognized transport-only reference
  shapes become canonical scalar or typed references. Unsupported or
  ambiguous shapes reach controlled validation instead of serializer warnings
  or unhashable-value failures.

  Background:
    Given a tolerantly decoded SP1 control-structure response
    And every control-structure field not varied by the scenario is valid
    And source IDs are assigned canonical IDs by final list position

  # STPA-TOLERANT-REFERENCE-NORMALIZATION-01
  Scenario: STPA-TOLERANT-REFERENCE-NORMALIZATION-01 normalizes the observed object-shaped feedback update
    Given responsibility 1 process model part 1 has source ID PM-9-7
    And responsibility 1 feedback channel 1 updates is {"type":"process_model_part","id":"PM-9-7"}
    When the response is normalized before typed serialization and validation
    Then responsibility 1 feedback channel 1 updates is the scalar ID PM-1-1
    And the normalized response validates as a ControlStructure
    And normalization emits no Pydantic serializer warning
    And normalization raises no unhashable-value error

  # STPA-TOLERANT-REFERENCE-NORMALIZATION-02
  Scenario Outline: STPA-TOLERANT-REFERENCE-NORMALIZATION-02 resolves ID-shaped ElementRef types from the referenced namespace
    Given <namespace_element> 2 has source ID <source_id>
    And <reference_location> has type <source_id> and ID <source_id>
    When the response is normalized before typed serialization and validation
    Then <reference_location> has type <reference_type> and ID <canonical_id>
    And the normalized response validates as a ControlStructure
    And normalization emits no Pydantic serializer warning

    Examples:
      | namespace_element  | source_id | reference_location                                    | reference_type     | canonical_id |
      | controlled process | CP-9      | responsibility 1 control action 1 target              | controlled_process | CP-2         |
      | responsibility     | RESP-9    | responsibility 1 process model part 1 feedback_source | responsibility     | RESP-2       |

  # STPA-TOLERANT-REFERENCE-NORMALIZATION-03
  Scenario: STPA-TOLERANT-REFERENCE-NORMALIZATION-03 rejects an ambiguous object-shaped feedback update through validation
    Given responsibility 1 process model parts 1 and 2 both have source ID PM-LEGACY
    And responsibility 1 feedback channel 1 updates is {"type":"process_model_part","id":"PM-LEGACY"}
    When the response is normalized before typed serialization and validation
    Then validation fails with an error identifying feedback channel 1 updates
    And the failure is not an unhashable-value error

  # STPA-TOLERANT-REFERENCE-NORMALIZATION-04
  Scenario Outline: STPA-TOLERANT-REFERENCE-NORMALIZATION-04 rejects unknown reference shapes through validation
    Given <reference_location> is <reference_value>
    When the response is normalized before typed serialization and validation
    Then validation fails with an error identifying <invalid_field>
    And the failure is not an unhashable-value error

    Examples:
      | reference_location                                    | reference_value                                            | invalid_field |
      | responsibility 1 feedback channel 1 updates           | {"type":"process_model_part","id":"PM-UNKNOWN"}             | updates       |
      | responsibility 1 feedback channel 1 updates           | {"type":"control_action","id":"CA-9-1"}                     | updates       |
      | responsibility 1 control action 1 target              | {"type":"NODE-9","id":"NODE-9"}                             | target type   |
