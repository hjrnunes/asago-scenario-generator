# mutation-stamp: sha256=0029aea101d9e8af5d4212bf03ee30de24c1277f029f1e26c9fbd0f49f10e183
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-21T13:09:02.254130Z","feature_name":"Taxonomy structured-response schema contract closure","feature_path":"features/taxonomy_structured_response_schema_contract.feature","background_hash":"74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b","implementation_hash":"unknown","scenarios":[{"index":1,"name":"Taxonomy structured-response schema contract closure 02 bounds generated items across response DTOs","scenario_hash":"09880ea29d660356874b30a51dc314586bfa5857ddb053a803e5b9b4697d3540","mutation_count":64,"result":{"Total":64,"Killed":64,"Survived":0,"Errors":0},"tested_at":"2026-08-21T13:09:02.254130Z"},{"index":4,"name":"Taxonomy structured-response schema contract closure 05 fails closed for realization resolution defects","scenario_hash":"24757e04bfab46dec6290b457255d51c5cd99283fe54ea1da0b309b871646c7f","mutation_count":4,"result":{"Total":4,"Killed":4,"Survived":0,"Errors":0},"tested_at":"2026-08-21T13:09:02.254130Z"},{"index":5,"name":"Taxonomy structured-response schema contract closure 06 sends candidate-specific step bounds","scenario_hash":"263c0c4805c9627a9522036fb9b41c0665fc4efd9d960d1c4335004a58489ea6","mutation_count":4,"result":{"Total":4,"Killed":4,"Survived":0,"Errors":0},"tested_at":"2026-08-21T13:09:02.254130Z"},{"index":6,"name":"Taxonomy structured-response schema contract closure 07 preserves the consistency helper import contract","scenario_hash":"45ac72e28ebce2dc6b9533905eb52ee1cda26969674ebbf62409fae1dcfac2f9","mutation_count":4,"result":{"Total":4,"Killed":4,"Survived":0,"Errors":0},"tested_at":"2026-08-21T13:09:02.254130Z"}]}
# acceptance-mutation-manifest-end

Feature: Taxonomy structured-response schema contract closure
  Provider-facing taxonomy response schemas bound every generated string and
  array recursively. Call 1 asks the provider only for model-owned narrative
  fields; canonical realizations are derived from immutable projection data
  after parsing, and candidate-specific step limits are sent to the provider.

  # Taxonomy structured-response schema contract closure 01 recursively audits emitted provider schemas
  Scenario: Taxonomy structured-response schema contract closure 01 recursively audits emitted provider schemas
    Given the exact provider response_format schemas for Call 0, Call 1, and Call 3 are captured
    When the emitted JSON schemas are recursively audited
    Then every reachable generated string has finite maxLength and every generated array has finite maxItems
    And the audit resolves $ref targets, anyOf branches, array items, and nested models
    And the audit reports no unbounded generated-schema path

  # Taxonomy structured-response schema contract closure 02 bounds generated items across response DTOs
  Scenario Outline: Taxonomy structured-response schema contract closure 02 bounds generated items across response DTOs
    Given a valid "<response_model>" response has a "<field>" item with <length> characters
    When the "<response_model>" response is validated by Pydantic
    Then "<response_model>" validation <outcome>

    Examples:
      | response_model | field                       | length | outcome  |
      | Call 0        | beliefs                     | 200    | succeeds |
      | Call 0        | beliefs                     | 201    | rejects  |
      | Call 0        | desires                     | 200    | succeeds |
      | Call 0        | desires                     | 201    | rejects  |
      | Call 0        | intentions                  | 200    | succeeds |
      | Call 0        | intentions                  | 201    | rejects  |
      | Call 0        | resources                   | 200    | succeeds |
      | Call 0        | resources                   | 201    | rejects  |
      | Call 1        | zone_sequence               | 64     | succeeds |
      | Call 1        | zone_sequence               | 65     | rejects  |
      | Call 1        | projected_step_ids          | 200    | succeeds |
      | Call 1        | projected_step_ids          | 201    | rejects  |
      | Call 3        | source_step_ids             | 200    | succeeds |
      | Call 3        | source_step_ids             | 201    | rejects  |
      | Call 3        | projected_postcondition_ids | 200    | succeeds |
      | Call 3        | projected_postcondition_ids | 201    | rejects  |

  # Taxonomy structured-response schema contract closure 03 bounds realization ID collections
  Scenario: Taxonomy structured-response schema contract closure 03 bounds realization ID collections
    Given a canonical projected-step realization has bounded ID-list fields "resource_ref_ids,consumed_ref_ids,produced_ref_ids,produced_effect_ids,outcome_link_pc_ids,postcondition_ids"
    When each ID-list item is validated at its declared boundary and one item is made one character longer
    Then every boundary-length realization is accepted
    And every over-limit realization is rejected by Pydantic

  # Taxonomy structured-response schema contract closure 04 derives narrative realizations after parsing
  Scenario: Taxonomy structured-response schema contract closure 04 derives narrative realizations after parsing
    Given immutable projection context contains selected canonical steps "step.1,step.2"
    And the Call 1 response supplies only step_number, zone, action, effect, control_point, and projected_step_ids
    When the Call 1 request and finalized narrative are produced
    Then the provider Call 1 step schema contains only those model-owned fields
    And the provider Call 1 step schema does not contain a realizations property
    And the finalized narrative contains exactly one canonical realization for each resolved projected step ID
    And every finalized realization exactly matches the immutable projection context
    And no provider-supplied realization record is published

  # Taxonomy structured-response schema contract closure 05 fails closed for realization resolution defects
  Scenario Outline: Taxonomy structured-response schema contract closure 05 fails closed for realization resolution defects
    Given immutable projection context contains selected canonical steps "step.1,step.2"
    And the Call 1 response has projected-step resolution defect "<defect>"
    When the narrative is finalized
    Then finalization rejects the response with a diagnostic identifying "<defect>"
    And no finalized narrative artifact is published

    Examples:
      | defect                          |
      | an unknown projected step ID    |
      | a duplicate projected step ID  |
      | an omitted projected step ID   |
      | semantically incompatible step |

  # Taxonomy structured-response schema contract closure 06 sends candidate-specific step bounds
  Scenario Outline: Taxonomy structured-response schema contract closure 06 sends candidate-specific step bounds
    Given the current candidate selects <selected_step_count> canonical projected steps
    When the Call 1 provider response_format schema is built
    Then the provider request contains steps.maxItems equal to <maximum_steps>
    And that bound is present before the provider receives the request

    Examples:
      | selected_step_count | maximum_steps |
      | 5                   | 7             |
      | 16                  | 16            |

  # Taxonomy structured-response schema contract closure 07 preserves the consistency helper import contract
  Scenario Outline: Taxonomy structured-response schema contract closure 07 preserves the consistency helper import contract
    Given the tool-execution grounding helper is imported from "asago_scenario_generator.pipeline.generate.tree"
    And a tool_execution leaf uses the "<action_kind>" typed action
    When direct tool-execution grounding consistency is checked
    Then the result is "<outcome>"

    Examples:
      | action_kind             | outcome        |
      | integration_interaction | no violation   |
      | ai_system_action        | untyped violation |
