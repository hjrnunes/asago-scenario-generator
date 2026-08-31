# mutation-stamp: sha256=967821eee81f331d60fee47aac0ddad4eebace97df9063e76bc693c2a67cbc11
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-31T11:09:17.818243Z","feature_name":"bounded closed-loop STPA composition","feature_path":"features/closed_loop_stpa.feature","background_hash":"6db85b0262229456e205e7842a707daddf712185a1219cd43b18d177a6683eb5","implementation_hash":"sha256:55068daf7e4f2e1b999f92a7c4afeeda9d72c3215480f2d5f8b9489d85c05763","scenarios":[{"index":0,"name":"one opted-in run retains each typed STPA outcome","scenario_hash":"33bb5dbbf0887c159ceddd6a1c94837f4dc9a0d62640a3c1f38df19973a7ec59","mutation_count":27,"result":{"Total":27,"Killed":27,"Survived":0,"Errors":0},"tested_at":"2026-08-31T11:09:17.818243Z"},{"index":1,"name":"opt-out retains selection without invoking analysis","scenario_hash":"365dd27f46907d87779ff2016644e0a963c618ae71676189c03db6a9d81f72c9","mutation_count":5,"result":{"Total":5,"Killed":5,"Survived":0,"Errors":0},"tested_at":"2026-08-31T11:09:17.818243Z"},{"index":2,"name":"an exact rerun reuses its one prior attempt","scenario_hash":"a154f8ebc258699af8b2dafe5eed6d01e6120f7563e3ae5e28318bf3f223efa3","mutation_count":4,"result":{"Total":4,"Killed":4,"Survived":0,"Errors":0},"tested_at":"2026-08-31T11:09:17.818243Z"},{"index":3,"name":"stale Phase 2 input fails before analysis","scenario_hash":"d47b70f453632410486af57d8abec29b60de7c4f5000bd9792b4e3e0485046ea","mutation_count":4,"result":{"Total":4,"Killed":4,"Survived":0,"Errors":0},"tested_at":"2026-08-31T11:09:17.818243Z"},{"index":4,"name":"audited lineage remains evidence rather than eligibility","scenario_hash":"38eb24b005b5c0459d3b4228f5ca578e4229cd7fbf119556f6967e4cec986186","mutation_count":16,"result":{"Total":16,"Killed":16,"Survived":0,"Errors":0},"tested_at":"2026-08-31T11:09:17.818243Z"},{"index":5,"name":"ordinary STPA has no closed-loop dependency","scenario_hash":"e2aec6aec99dd1ee7040159a223b27357d5addc1e229f4d521f87de26049604c","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-31T11:09:17.818243Z"}]}
# acceptance-mutation-manifest-end

Feature: bounded closed-loop STPA composition
  Explicitly approved obligation and STPA-slot pairs may be reconsidered once
  without rewriting Phase 2 or changing ordinary scenario generation.

  Background:
    Given an exact Phase 2 assessment and one explicit closed-loop target

  Scenario Outline: one opted-in run retains each typed STPA outcome
    Given closed-loop composition is explicitly opted in
    And its fake adapter returns "<adapter_result>"
    When the bounded closed-loop run is composed with budget <budget>
    Then the run retains explicit budget <expected_budget>
    And it records <attempted> attempted target and "<disposition>"
    And it reports <correspondence_changes> correspondence and <coverage_changes> coverage changes
    And hybrid generation is "<generation_status>" and admission is "<admission_status>"
    And its Phase 2 assessment remains byte-equivalent

    Examples:
      | adapter_result | budget | expected_budget | attempted | disposition | correspondence_changes | coverage_changes | generation_status | admission_status |
      | ica            | 1      | 1               | 1         | ica         | 0                      | 0                | not_attempted     | not_assessed     |
      | justified_na   | 1      | 1               | 1         | justified_na | 0                     | 0                | not_attempted     | not_assessed     |
      | unresolved     | 1      | 1               | 1         | unresolved  | 0                      | 0                | not_attempted     | not_assessed     |

  Scenario Outline: opt-out retains selection without invoking analysis
    Given closed-loop composition is not opted in
    When the bounded closed-loop run is composed with budget <budget>
    Then it retains <selected> selected and <pending> pending targets
    And it records <attempted> attempted targets
    And its adapter is constructed <adapter_constructions> times

    Examples:
      | budget | selected | pending | attempted | adapter_constructions |
      | 1      | 1        | 1       | 0         | 0                     |

  Scenario Outline: an exact rerun reuses its one prior attempt
    Given closed-loop composition is explicitly opted in
    And its fake adapter returns "<adapter_result>"
    When the bounded closed-loop run is composed with budget <budget>
    Then the run retains explicit budget <expected_budget>
    And the exact run is persisted and resumed
    And the two persisted run records are byte-equivalent
    And its adapter is constructed <adapter_constructions> times

    Examples:
      | adapter_result | budget | expected_budget | adapter_constructions |
      | unresolved     | 1      | 1               | 1                     |

  Scenario Outline: stale Phase 2 input fails before analysis
    Given the Phase 2 assessment digest is substituted with "<bad_digest>"
    And the substituted digest must equal "<expected_bad_digest>"
    When closed-loop composition is attempted with budget 1
    Then composition fails with "<error_fragment>"
    And its adapter is constructed <adapter_constructions> times

    Examples:
      | bad_digest                                                       | expected_bad_digest                                              | error_fragment             | adapter_constructions |
      | ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff | ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff | assessment digest mismatch | 0                     |

  Scenario Outline: audited lineage remains evidence rather than eligibility
    Given the completed Phase 3 lineage audit
    When I inspect audited use case "<use_case>"
    Then it records <taxonomy_total> taxonomy envelopes, <inconsistent> inconsistent planning inputs, and <extra> expected extra candidates
    And it records <stpa_joined> of <stpa_total> exact STPA joins with <lineage_bugs> lineage bugs
    And it infers <inferred_targets> closed-loop eligibility targets

    Examples:
      | use_case | taxonomy_total | inconsistent | extra | stpa_joined | stpa_total | lineage_bugs | inferred_targets |
      | klarna   | 94             | 77           | 17    | 16          | 16         | 0            | 0                |
      | nhs      | 27             | 13           | 14    | 18          | 18         | 0            | 0                |

  Scenario Outline: ordinary STPA has no closed-loop dependency
    When ordinary stpa-run is inspected without Phase 3 opt-in
    Then it imports <closed_loop_imports> closed-loop modules
    And it requires <required_phase3_artifacts> Phase 3 artifacts

    Examples:
      | closed_loop_imports | required_phase3_artifacts |
      | 0                   | 0                         |
