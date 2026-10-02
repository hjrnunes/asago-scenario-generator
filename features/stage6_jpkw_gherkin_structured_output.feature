# mutation-stamp: sha256=bec9be5a911feb898ed16ca0953aeca2fb22e1db8df6e349ef87ed84012f779c
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-10T14:37:44.421593Z","feature_name":"Stage 6 Gherkin structured output (jpkw)","feature_path":"features/stage6_jpkw_gherkin_structured_output.feature","background_hash":"129b1d790458ad365674cab88d35d5c7a126ab63b4c4004c7f5a42132ce2fc8c","implementation_hash":"unknown","scenarios":[{"index":0,"name":"JPKW-01 GherkinSpec model has structured fields","scenario_hash":"721569ee06938a4f6775f186645c3ac40a986f2f24fec2024d98605f47112e53","mutation_count":12,"result":{"Total":12,"Killed":12,"Survived":0,"Errors":0},"tested_at":"2026-08-10T14:37:44.421593Z"},{"index":7,"name":"JPKW-08 structured validation catches missing required GherkinSpec content","scenario_hash":"1e0fcf76e1c5cc563e9f609c6978745d620c73324f3020157f1710d4660c2f79","mutation_count":6,"result":{"Total":6,"Killed":6,"Survived":0,"Errors":0},"tested_at":"2026-08-10T14:37:44.421593Z"}]}
# acceptance-mutation-manifest-end

Feature: Stage 6 Gherkin structured output (jpkw)
  The Gherkin spec on ScenarioEnvelope changes from a raw string to a
  structured GherkinSpec model with parsed components. A gherkin_raw field
  preserves the raw text for backward compatibility and artifact-writing
  fallback. The Stage 6c prompt requests structured YAML output. The
  assembly, artifact writing, and report rendering all adapt to the new
  structured form.

  Background:
    Given the SP3 Gherkin module is importable
    And a ScenarioSpec with defender BDI for scenario SCN-001
    And a security constraint SC-1 related to hazard H-1
    And a loss analysis with losses L-1 and L-2 and hazards H-1 and H-2

  # JPKW-01
  Scenario Outline: JPKW-01 GherkinSpec model has structured fields
    Given the GherkinSpec model is defined
    Then it has a <field> field of type <type>

    Examples:
      | field          | type          |
      | feature        | str           |
      | scenario       | str           |
      | given          | list of str   |
      | when           | list of str   |
      | then_expected  | list of str   |
      | then_actual    | list of str   |

  # JPKW-02
  Scenario: JPKW-02 ScenarioEnvelope has gherkin_spec of type GherkinSpec and gherkin_raw of type str
    Given the ScenarioEnvelope model is defined
    Then the gherkin_spec field is of type GherkinSpec
    And the gherkin_raw field is of type str

  # JPKW-03
  Scenario: JPKW-03 Stage 6c system prompt requests structured YAML output
    When the Gherkin system prompt is rendered
    Then the system prompt instructs the LLM to return a YAML object
    And the system prompt defines the fields feature, scenario, given, when, then_expected, then_actual

  # JPKW-04
  Scenario: JPKW-04 generate_gherkin returns a GherkinSpec and raw text
    Given an LLM that returns structured YAML with fields feature, scenario, given, when, then_expected, then_actual
    When the Gherkin LLM call is executed
    Then the result includes a GherkinSpec object
    And the result includes a raw text string

  # JPKW-05
  Scenario: JPKW-05 generate_gherkin parses YAML response into structured fields
    Given an LLM that returns YAML with given steps "Given PM-1-1 is active" and "And the system is online"
    When the Gherkin LLM call is executed
    Then the GherkinSpec.given list contains "Given PM-1-1 is active"
    And the GherkinSpec.given list contains "And the system is online"

  # JPKW-06
  Scenario: JPKW-06 assemble_envelope accepts a GherkinSpec and gherkin_raw
    Given a GherkinSpec with feature "Safe orchestration" and scenario "SCN-001"
    And a gherkin_raw string containing the full Feature block
    When assemble_envelope is called with the GherkinSpec and gherkin_raw
    Then the resulting ScenarioEnvelope.gherkin_spec equals the GherkinSpec
    And the resulting ScenarioEnvelope.gherkin_raw equals the gherkin_raw string

  # JPKW-08
  Scenario Outline: JPKW-08 structured validation catches missing required GherkinSpec content
    Given a GherkinSpec with <deficiency>
    When Gherkin structure validation is performed on the GherkinSpec
    Then validation fails with error containing <error_keyword>

    Examples:
      | deficiency                                  | error_keyword   |
      | empty then_expected list                    | should          |
      | empty then_actual list                      | but             |
      | given list with no PM reference             | process model   |

  # JPKW-09
  Scenario: JPKW-09 valid structured GherkinSpec passes validation
    Given a GherkinSpec with then_expected containing should, then_actual containing but, and given referencing PM-1-1
    When Gherkin structure validation is performed on the GherkinSpec
    Then validation succeeds

  # JPKW-10
  Scenario: JPKW-10 raw Gherkin text is reconstructable from structured fields
    Given a GherkinSpec with feature "Safe orchestration" and scenario "SCN-001" and given "Given PM-1-1 is active" and when "When a revoked user requests access" and then_expected "Then the system should reject the request"
    When the GherkinSpec is rendered to feature text
    Then the rendered text contains the Feature line
    And the rendered text contains the Scenario line
    And the rendered text contains the Given step
    And the rendered text contains the When step
    And the rendered text contains the Then step

  # JPKW-11
  Scenario: JPKW-11 Stage 7 envelope validation uses GherkinSpec fields
    Given a ScenarioEnvelope with a GherkinSpec that has empty then_expected
    When Stage 7 envelope validation is performed
    Then validation fails with error containing should

  # JPKW-12
  Scenario: JPKW-12 backward compatibility gherkin_raw preserves full Feature text
    Given an LLM that returns structured YAML with feature "Safe orchestration" and scenario "SCN-001"
    When the Gherkin LLM call is executed
    Then the gherkin_raw contains the Feature line
    And the gherkin_raw contains the Scenario line
