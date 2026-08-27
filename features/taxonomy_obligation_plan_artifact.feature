# mutation-stamp: sha256=9231912afc5cd7d64874710a0fe97764a2679b754df1b21422325bfb17df778a
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-27T17:14:27.448662Z","feature_name":"Taxonomy obligation plan artifact","feature_path":"features/taxonomy_obligation_plan_artifact.feature","background_hash":"404ec7aa5df544172f5d7bba33f66ab007a962f33538ef45f7b38cb73129ab7b","implementation_hash":"unknown","scenarios":[{"index":0,"name":"Taxonomy obligation plan artifact 01 copies pinned snapshot versions into the plan","scenario_hash":"4ba23d6cf8f5391c7a0f2867a8b72984827c455afa6c3b3ca230e86d969ee8e3","mutation_count":5,"result":{"Total":5,"Killed":5,"Survived":0,"Errors":0},"tested_at":"2026-08-27T17:14:27.448662Z"},{"index":1,"name":"Taxonomy obligation plan artifact 02 keeps identifiers and order independent of presentation order","scenario_hash":"98764ac154ca3922fa5458816e5e8a2104ed635d2809613aa7d20b248e2ea542","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-27T17:14:27.448662Z"},{"index":2,"name":"Taxonomy obligation plan artifact 03 round-trips without semantic loss","scenario_hash":"876f03e0ed42f5186611804b97f71eb645916db7a126a29f5bb15731577a840b","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-27T17:14:27.448662Z"},{"index":3,"name":"Taxonomy obligation plan artifact 04 is byte-stable for identical inputs","scenario_hash":"c85325c3b98e55a1c342d68078e028b81208ca681fb7ba1f74a4f1aa2ec8b54c","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-27T17:14:27.448662Z"}]}
# acceptance-mutation-manifest-end

Feature: Taxonomy obligation plan artifact
  The obligation plan is a versioned YAML and JSON artifact. Identifiers
  and ordering come from semantic identity, and round-trip persistence
  preserves pinned versions, dispositions, and evidence.

  Background:
    Given a pinned taxonomy obligation snapshot is available
    And obligation planning makes no network or model calls

  # Taxonomy obligation plan artifact 01 copies pinned snapshot versions into the plan
  Scenario Outline: Taxonomy obligation plan artifact 01 copies pinned snapshot versions into the plan
    Given the snapshot pins taxonomy version "<taxonomy_version>", mapping version "<mapping_version>", qualification ruleset version "<ruleset_version>", template version "<template_version>", and digest "<digest>"
    When the obligation plan is produced
    Then the plan records taxonomy version "<taxonomy_version>"
    And the plan records mapping version "<mapping_version>"
    And the plan records qualification ruleset version "<ruleset_version>"
    And the plan records template version "<template_version>"
    And the plan records digest "<digest>"

    Examples:
      | taxonomy_version | mapping_version | ruleset_version            | template_version      | digest                                                           |
      | atlas-2026.05    | sssom-v1        | catalog-qualification-v1   | scenario-envelope-v1  | aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa |

  # Taxonomy obligation plan artifact 02 keeps identifiers and order independent of presentation order
  Scenario Outline: Taxonomy obligation plan artifact 02 keeps identifiers and order independent of presentation order
    Given one snapshot presents relationships in order "<order_a>"
    And another snapshot presents the same relationships in order "<order_b>"
    When an obligation plan is produced from each presentation
    Then both plans have identical obligation identifiers
    And both plans have identical canonical ledger order
    And both serialized artifacts are canonically equivalent

    Examples:
      | order_a                                          | order_b                                          |
      | atlas-prompt-injection:AP-T6-01,atlas-memory-poisoning:AP-T1-01 | atlas-memory-poisoning:AP-T1-01,atlas-prompt-injection:AP-T6-01 |

  # Taxonomy obligation plan artifact 03 round-trips without semantic loss
  Scenario Outline: Taxonomy obligation plan artifact 03 round-trips without semantic loss
    Given the snapshot produces a plan with pinned versions, dispositions, and evidence
    When the plan is serialized as "<format>" and deserialized
    Then obligation identities are preserved
    And pinned versions are preserved
    And terminal dispositions are preserved
    And qualification traces and candidate evidence are preserved

    Examples:
      | format |
      | YAML   |
      | JSON   |

  # Taxonomy obligation plan artifact 04 is byte-stable for identical inputs
  Scenario Outline: Taxonomy obligation plan artifact 04 is byte-stable for identical inputs
    Given the snapshot produces a plan with pinned versions, dispositions, and evidence
    When the plan is serialized as "<format>" twice
    Then the two artifacts are byte-identical

    Examples:
      | format |
      | YAML   |
      | JSON   |
