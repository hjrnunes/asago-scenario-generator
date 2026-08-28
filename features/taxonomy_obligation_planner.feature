# mutation-stamp: sha256=dc8cfb35be0c37f619bfc24a9a2099a8ce2ffb526631adebd0432db177fea26b
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-28T17:31:31.845135Z","feature_name":"Taxonomy obligation planner","feature_path":"features/taxonomy_obligation_planner.feature","background_hash":"ba5e424d8b121ffee446ad729b24ddb2198f58c040d25b8c8438dac3de6f61ae","implementation_hash":"sha256:de8ac8cbffe243eaf86511f6406fc57cf146fa4895ece7c52f1f115465ec8b7b","scenarios":[{"index":0,"name":"Typed planner preserves distinct risk-scoped obligations","scenario_hash":"b6da4b67d91ba7165196d0090bfcaeb77af8a9ffaae60ea4241841bbd1df4255","mutation_count":7,"result":{"Total":7,"Killed":7,"Survived":0,"Errors":0},"tested_at":"2026-08-28T17:31:31.845135Z"},{"index":1,"name":"Typed planner records an authoritative capability exclusion","scenario_hash":"f069364d981407083d5a97dbf0522d9dacb6c67fe9ec583e262c3e5dbf0b57ac","mutation_count":6,"result":{"Total":6,"Killed":6,"Survived":0,"Errors":0},"tested_at":"2026-08-28T17:31:31.845135Z"},{"index":2,"name":"Typed planner retains a governance-only risk","scenario_hash":"d0cc5fbf78a9d7fa29ec396c6bede958f88f2ff0f3462bd8e55b88f3f49a6724","mutation_count":4,"result":{"Total":4,"Killed":4,"Survived":0,"Errors":0},"tested_at":"2026-08-28T17:31:31.845135Z"},{"index":3,"name":"Typed planner derives a candidate from authoritative resources","scenario_hash":"6d00249d86c3f27c6cdffe1eb112e2925f93d69fc34f0a3a889371ab2f6c6cef","mutation_count":5,"result":{"Total":5,"Killed":5,"Survived":0,"Errors":0},"tested_at":"2026-08-28T17:31:31.845135Z"},{"index":4,"name":"Typed planner retains authoritative projection evidence","scenario_hash":"3b029422d75d7d939453721c424484f2b1b2dc0f8f5ded1bf5d4bad5f478c693","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-28T17:31:31.845135Z"},{"index":6,"name":"Typed planner rejects unknown input fields before planning","scenario_hash":"adc2bf78ca0c686b3cd9efed01e13c525f2d33caf4301bd97c3c7f386332e462","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-28T17:31:31.845135Z"},{"index":7,"name":"Typed planner rejects a stale qualification facts digest","scenario_hash":"e1bf366a4115eafddddb9911cd8a220364ca2c74c1550ae7c6c963ccfce1f51a","mutation_count":1,"result":{"Total":1,"Killed":1,"Survived":0,"Errors":0},"tested_at":"2026-08-28T17:31:31.845135Z"},{"index":8,"name":"Typed planner retains a risk when qualification facts are missing","scenario_hash":"b81ebcadd7056db9eb0aed252cb764e2c8192531e4f4e49c3eaa6ef0037d5220","mutation_count":4,"result":{"Total":4,"Killed":4,"Survived":0,"Errors":0},"tested_at":"2026-08-28T17:31:31.845135Z"},{"index":9,"name":"Typed planner retains contradictory qualification evidence","scenario_hash":"3b9014577eed10bc69dc80f183eb245a7b2c5b32504e82b8a9a34726c66d5acd","mutation_count":3,"result":{"Total":3,"Killed":3,"Survived":0,"Errors":0},"tested_at":"2026-08-28T17:31:31.845135Z"},{"index":10,"name":"Typed planner retains projection infeasibility","scenario_hash":"a57d787ec3af1ff42da65a071644a69c723d6bf5688b33654d314fdbf5efe6db","mutation_count":4,"result":{"Total":4,"Killed":4,"Survived":0,"Errors":0},"tested_at":"2026-08-28T17:31:31.845135Z"},{"index":11,"name":"Typed planner atomically publishes a round-trippable YAML plan","scenario_hash":"006fff8bdc5221a51c428b56255dfd2620345e4146035c009b86a35d1a1dc745","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-28T17:31:31.845135Z"},{"index":12,"name":"Normative typed planning canonicalizes semantically identical normalized inputs","scenario_hash":"483470935b694bd5a3b8752444423cc2876d32649c3409556a49e7e67fe0059d","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-28T17:31:31.845135Z"},{"index":13,"name":"Normative typed planning ignores ICA and scenario keyword prose","scenario_hash":"02bedd23f4ca3291807f10057da533fb492d939f3099b87a97e39252c2eb0f95","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-28T17:31:31.845135Z"},{"index":14,"name":"Normative typed planning constructs no provider client or endpoint connection","scenario_hash":"86be39aeafc6e7c7a779ed2efe798fefc2c806971ac62c67f3788d8098ed673d","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-28T17:31:31.845135Z"}]}
# acceptance-mutation-manifest-end

Feature: Taxonomy obligation planner
  A deterministic typed planner turns reviewed risks, authoritative taxonomy
  mappings, capability facts, and pinned resources into a closed obligation
  ledger. Every reviewed risk remains visible, and candidate records are
  derived from authoritative projection rather than supplied by callers.

  Background:
    Given a typed taxonomy obligation input fixture is available
    And typed obligation planning makes no network or model calls

  Scenario Outline: Typed planner preserves distinct risk-scoped obligations
    Given typed planner inputs include reviewed risks "<risk_a>" and "<risk_b>" mapped to attack pattern "<pattern_id>"
    When typed obligation planning runs
    Then typed plan contains <row_count> obligation rows
    And typed rows retain risk identities "<expected_risk_a>" and "<expected_risk_b>" for attack pattern "<expected_pattern_id>"

    Examples:
      | risk_a | risk_b | pattern_id | row_count | expected_risk_a | expected_risk_b | expected_pattern_id |
      | risk-a | risk-b | AP-T1-01   | 2         | risk-a          | risk-b          | AP-T1-01            |

  Scenario Outline: Typed planner records an authoritative capability exclusion
    Given typed planner inputs include risk "<risk_id>" mapped to attack pattern "<pattern_id>" whose authoritative profile gate is unmet
    When typed obligation planning runs
    Then typed plan contains <row_count> obligation row
    And typed row has risk "<expected_risk_id>" and attack pattern "<expected_pattern_id>" with scope disposition "<scope_disposition>"

    Examples:
      | risk_id     | pattern_id | row_count | expected_risk_id | expected_pattern_id | scope_disposition  |
      | risk-gated  | AP-T1-01   | 1         | risk-gated       | AP-T1-01           | capability_excluded |

  Scenario Outline: Typed planner retains a governance-only risk
    Given the normative typed planner inputs contain only reviewed risk "<input_risk_id>" with no pattern
    When typed obligation planning runs
    Then the typed plan contains <row_count> obligation row
    And the typed row retains risk_ref "<expected_risk_id>" with "<scope_disposition>" scope

    Examples:
      | input_risk_id         | row_count | expected_risk_id       | scope_disposition |
      | risk-governance-only  | 1         | risk-governance-only  | governance_only   |

  Scenario Outline: Typed planner derives a candidate from authoritative resources
    Given the normative typed planner inputs include risk "<risk_id>" mapped to attack pattern "<pattern_id>" with the canonical resources
    When typed obligation planning runs
    Then the typed plan contains <row_count> obligation row
    And the typed obligation row has exactly the normative closed fields
    And the typed candidate row retains risk "<expected_risk_id>" and attack pattern "<expected_pattern_id>"
    And the typed candidate identity and resource bindings are retained
    And the typed summary reconciles from typed obligation rows

    Examples:
      | risk_id | pattern_id | row_count | expected_risk_id | expected_pattern_id |
      | risk-a  | AP-T1-01   | 1         | risk-a           | AP-T1-01            |

  Scenario Outline: Typed planner retains authoritative projection evidence
    Given the default normative typed planner inputs are ready
    When typed obligation planning runs
    Then typed plan contains <row_count> obligation row
    And typed row retains projection evidence from "<evidence_source>"

    Examples:
      | row_count | evidence_source                  |
      | 1         | unsupported_requirement_derivation |

  Scenario: Typed planner binds identity to every required input
    Given normative typed planner identity inputs vary independently
    When typed identity planning runs
    Then every changed risk, pattern, capability snapshot, catalog pin, and mapping pin changes the obligation identity

  Scenario Outline: Typed planner rejects unknown input fields before planning
    Given the normative typed planner inputs contain unknown field "<unknown_field>"
    When typed input validation runs
    Then typed input validation is rejected
    And typed input validation identifies unknown field "<expected_unknown_field>"
    And no partial typed plan is returned

    Examples:
      | unknown_field    | expected_unknown_field |
      | unsupported_field | unsupported_field      |

  Scenario Outline: Typed planner rejects a stale qualification facts digest
    Given the normative typed planner inputs contain a "<digest_state>" qualification facts digest
    When typed input validation runs
    Then typed input validation is rejected
    And no partial typed plan is returned

    Examples:
      | digest_state |
      | false        |

  Scenario Outline: Typed planner retains a risk when qualification facts are missing
    Given normative typed planner inputs contain no "<fact_source>" qualification facts
    When typed obligation planning runs
    Then typed plan contains <row_count> obligation row
    And typed row has qualification disposition "<qualification_disposition>"
    And typed row retains projection evidence from "<projection_reason>"
    And typed row has no candidate records

    Examples:
      | fact_source                    | row_count | qualification_disposition | projection_reason   |
      | authoritative-capability-snapshot | 1         | missing_evidence          | unresolved_condition |

  Scenario Outline: Typed planner retains contradictory qualification evidence
    Given normative typed planner inputs contain a contradictory "<fact_source>" qualification fact
    When typed obligation planning runs
    Then typed plan contains <row_count> obligation row
    And typed row has qualification disposition "<qualification_disposition>"
    And typed row retains contradictory qualification evidence
    And typed row has no candidate records

    Examples:
      | fact_source                    | row_count | qualification_disposition |
      | authoritative-qualification-input | 1         | contradictory_evidence    |

  Scenario Outline: Typed planner retains projection infeasibility
    Given normative typed planner inputs use an authoritative profile with no compatible "<resource_kind>" resource
    When typed obligation planning runs
    Then typed plan contains <row_count> obligation row
    And typed row has qualification disposition "<qualification_disposition>" and projection-infeasible candidate records
    And typed row retains projection evidence from "<projection_reason>"

    Examples:
      | resource_kind | row_count | qualification_disposition | projection_reason      |
      | entry_point   | 1         | structurally_infeasible  | missing_compatible_resource |

  Scenario Outline: Typed planner atomically publishes a round-trippable YAML plan
    Given the default normative typed planner inputs are ready
    When the typed plan is published atomically as "<publication_format>"
    Then the typed publication is named "<artifact_name>"
    And the typed publication round-trips without semantic loss
    And no typed partial plan file remains

    Examples:
      | publication_format | artifact_name                   |
      | YAML                | taxonomy-obligation-plan.yaml   |

  Scenario Outline: Normative typed planning canonicalizes semantically identical normalized inputs
    Given typed planner inputs use semantically equivalent "<left_form>" and "<right_form>" normalized representations
    When typed normalized-input planning runs
    Then normalized typed plan contents are byte-equivalent
    And normalized typed obligation IDs are identical

    Examples:
      | left_form | right_form |
      | composed  | decomposed |

  Scenario Outline: Normative typed planning ignores ICA and scenario keyword prose
    Given typed planner has ICA keyword prose fixture "<ica_prose>" and scenario keyword prose fixture "<scenario_prose>"
    When typed keyword-prose planning runs
    Then changing ICA or scenario keyword prose leaves the typed plan unchanged

    Examples:
      | ica_prose             | scenario_prose             |
      | ica-keyword-baseline  | scenario-keyword-baseline |

  Scenario Outline: Normative typed planning constructs no provider client or endpoint connection
    Given the default normative typed planner inputs are ready
    When typed planning runs under provider and endpoint guards
    Then typed obligation planning constructs <provider_client_count> provider clients and contacts <endpoint_count> endpoints

    Examples:
      | provider_client_count | endpoint_count |
      | 0                     | 0              |
