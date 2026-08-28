# mutation-stamp: sha256=8b996067f2c955218f31a205ac383fc7ad90506f785a5f40c7c39b38fcde4c45
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-28T10:48:48.625089Z","feature_name":"Taxonomy obligation plan artifact","feature_path":"features/taxonomy_obligation_plan_artifact.feature","background_hash":"404ec7aa5df544172f5d7bba33f66ab007a962f33538ef45f7b38cb73129ab7b","implementation_hash":"unknown","scenarios":[{"index":5,"name":"Taxonomy obligation plan artifact 06a rejects the unknown field extra_score","scenario_hash":"4b547086a3560ef89da217920ab06296219e477c20d528c73a6a40270ed5071a","mutation_count":1,"result":{"Total":1,"Killed":1,"Survived":0,"Errors":0},"tested_at":"2026-08-28T10:48:48.625089Z"},{"index":6,"name":"Taxonomy obligation plan artifact 06b rejects the unknown field covered_rate","scenario_hash":"745b2465f529c111d4d93ac72a228c72a8139d9bedb155488cae164366348a89","mutation_count":1,"result":{"Total":1,"Killed":1,"Survived":0,"Errors":0},"tested_at":"2026-08-28T10:48:48.625089Z"},{"index":7,"name":"Taxonomy obligation plan artifact 07a rejects the unsupported schema version v0","scenario_hash":"4444666edd2a64fdce2f6039e9fe9c8e10ddefca6c60a3690e395876cbca241c","mutation_count":1,"result":{"Total":1,"Killed":1,"Survived":0,"Errors":0},"tested_at":"2026-08-28T10:48:48.625089Z"},{"index":8,"name":"Taxonomy obligation plan artifact 07b rejects the unsupported schema version v2","scenario_hash":"62da876738243b0fd389b26176e08e1e022f1bc2e92e703813b6ac1eec6fd961","mutation_count":1,"result":{"Total":1,"Killed":1,"Survived":0,"Errors":0},"tested_at":"2026-08-28T10:48:48.625089Z"},{"index":12,"name":"Taxonomy obligation plan artifact 09 publishes the YAML plan atomically","scenario_hash":"6b633963d66a874d930e683d59492718b5363cbcbc37352dca79822c13e2ccad","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-28T10:48:48.625089Z"},{"index":13,"name":"Taxonomy obligation plan artifact 10a rejects the covered correspondence claim","scenario_hash":"0410c1bd03e2612924017e5e097f1976e12bf462dfe0c4f27a555face9f08837","mutation_count":1,"result":{"Total":1,"Killed":1,"Survived":0,"Errors":0},"tested_at":"2026-08-28T10:48:48.625089Z"},{"index":14,"name":"Taxonomy obligation plan artifact 10b rejects the matched correspondence claim","scenario_hash":"3f60ca673234a41b12e2e83375f7d54932943414739986307d8b9780917f45e6","mutation_count":1,"result":{"Total":1,"Killed":1,"Survived":0,"Errors":0},"tested_at":"2026-08-28T10:48:48.625089Z"},{"index":15,"name":"Taxonomy obligation plan artifact 10c rejects the satisfied correspondence claim","scenario_hash":"90de5a8266503557c38a1c49a11af1d446901882481aeb822a849a06bcff0dc4","mutation_count":1,"result":{"Total":1,"Killed":1,"Survived":0,"Errors":0},"tested_at":"2026-08-28T10:48:48.625089Z"},{"index":0,"name":"Taxonomy obligation plan artifact 01 records closed schema metadata from canonical content","scenario_hash":"60b31418b6fad6ac7a947a9298ae73f334e74a47fb285712774b4469b2912e97","mutation_count":4,"result":{"Total":4,"Killed":4,"Survived":0,"Errors":0},"tested_at":"2026-08-28T10:43:39.312819Z"},{"index":1,"name":"Taxonomy obligation plan artifact 02 keeps identifiers and digests independent of presentation order","scenario_hash":"0e1589433043650a648ed3bc60f1cd9b89b5db475378bab9f06e7b68ebeeb1f1","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-28T10:43:39.312819Z"},{"index":2,"name":"Taxonomy obligation plan artifact 03 round-trips without semantic loss","scenario_hash":"ff2bb5095d57e2e4b68716dfd1cd389f5f395fb3c888b0e0979d23fd03de60a1","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-28T10:43:39.312819Z"},{"index":3,"name":"Taxonomy obligation plan artifact 04 is byte-stable for identical inputs","scenario_hash":"c0c7220e2b5e0e6af9e1b9c6458bf74f8f3de573ce2a9e70bb4f9f8c46bb6cd1","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-28T10:43:39.312819Z"},{"index":4,"name":"Taxonomy obligation plan artifact 05 rejects tampered persisted content","scenario_hash":"1f595d1181c7e6df74e7602be8afab2de86a754ed6160c05ce7dbbc36d5b0f29","mutation_count":6,"result":{"Total":6,"Killed":6,"Survived":0,"Errors":0},"tested_at":"2026-08-28T10:43:39.312819Z"}]}
# acceptance-mutation-manifest-end

Feature: Taxonomy obligation plan artifact
  The obligation plan is a closed, versioned YAML and JSON artifact.
  Identifiers and digests come from canonical content, unknown fields
  and unsupported versions are rejected, and round-trip persistence
  preserves pins, dispositions, and evidence.

  Background:
    Given a pinned taxonomy obligation snapshot is available
    And obligation planning makes no network or model calls

  # Taxonomy obligation plan artifact 01 records closed schema metadata from canonical content
  Scenario Outline: Taxonomy obligation plan artifact 01 records closed schema metadata from canonical content
    Given the snapshot pins catalog pin "<catalog_pin>", mapping pin "<mapping_pin>", capability snapshot content "<capability_content>", and qualification facts "<qualification_facts>"
    When the obligation plan is produced
    Then the plan records schema version "taxonomy-obligation-plan-v1"
    And the plan records catalog pin "atlas-2026.05"
    And the plan records mapping pin "sssom-v1"
    And the plan records the capability snapshot digest of "profile-v1"
    And the plan records the qualification facts digest of "facts-v1"
    And the plan records computed digests for capability snapshot, qualification facts, generation inputs, and semantic content

    Examples:
      | catalog_pin   | mapping_pin | capability_content | qualification_facts |
      | atlas-2026.05 | sssom-v1    | profile-v1         | facts-v1            |

  # Taxonomy obligation plan artifact 02 keeps identifiers and digests independent of presentation order
  Scenario Outline: Taxonomy obligation plan artifact 02 keeps identifiers and digests independent of presentation order
    Given one snapshot presents relationships in order "<order_a>"
    And another snapshot presents the same relationships in order "<order_b>"
    When an obligation plan is produced from each presentation
    Then both plans have identical obligation identifiers
    And both plans have identical semantic digests
    And both plans have identical canonical ledger order
    And both serialized artifacts are canonically equivalent

    Examples:
      | order_a                                                       | order_b                                                       |
      | atlas-prompt-injection:AP-T6-01,atlas-memory-poisoning:AP-T1-01 | atlas-memory-poisoning:AP-T1-01,atlas-prompt-injection:AP-T6-01 |

  # Taxonomy obligation plan artifact 03 round-trips without semantic loss
  Scenario Outline: Taxonomy obligation plan artifact 03 round-trips without semantic loss
    Given the snapshot produces a plan with pins, dispositions, digests, and evidence
    When the plan is serialized as "<format>" and deserialized
    Then obligation identities are preserved
    And schema version, pins, and computed digests are preserved
    And scope, qualification, projection, and correspondence dispositions are preserved
    And qualification traces, candidate records, and summary counts are preserved

    Examples:
      | format |
      | YAML   |
      | JSON   |

  # Taxonomy obligation plan artifact 04 is byte-stable for identical inputs
  Scenario Outline: Taxonomy obligation plan artifact 04 is byte-stable for identical inputs
    Given the snapshot produces a plan with pins, dispositions, digests, and evidence
    When the plan is serialized as "<format>" twice
    Then the two artifacts are byte-identical

    Examples:
      | format |
      | YAML   |
      | JSON   |

  # Taxonomy obligation plan artifact 05 rejects tampered persisted content
  Scenario Outline: Taxonomy obligation plan artifact 05 rejects tampered persisted content
    Given a published plan artifact in "<format>"
    And the persisted content is tampered in field "<field>" without updating the semantic digest
    When the plan is loaded
    Then loading is rejected
    And the result identifies a digest mismatch

    Examples:
      | format | field        |
      | YAML   | catalog_pins |
      | JSON   | mapping_pins |
      | YAML   | obligations  |

  # Taxonomy obligation plan artifact 06a rejects the unknown field extra_score
  Scenario Outline: Taxonomy obligation plan artifact 06a rejects the unknown field extra_score
    Given a persisted plan includes unknown field "<field>"
    When the plan is loaded
    Then loading is rejected
    And the result identifies unknown field "extra_score"

    Examples:
      | field       |
      | extra_score |

  # Taxonomy obligation plan artifact 06b rejects the unknown field covered_rate
  Scenario Outline: Taxonomy obligation plan artifact 06b rejects the unknown field covered_rate
    Given a persisted plan includes unknown field "<field>"
    When the plan is loaded
    Then loading is rejected
    And the result identifies unknown field "covered_rate"

    Examples:
      | field        |
      | covered_rate |

  # Taxonomy obligation plan artifact 07a rejects the unsupported schema version v0
  Scenario Outline: Taxonomy obligation plan artifact 07a rejects the unsupported schema version v0
    Given a persisted plan declares schema version "<schema_version>"
    When the plan is loaded
    Then loading is rejected
    And the result identifies schema version "taxonomy-obligation-plan-v0" as unsupported

    Examples:
      | schema_version              |
      | taxonomy-obligation-plan-v0 |

  # Taxonomy obligation plan artifact 07b rejects the unsupported schema version v2
  Scenario Outline: Taxonomy obligation plan artifact 07b rejects the unsupported schema version v2
    Given a persisted plan declares schema version "<schema_version>"
    When the plan is loaded
    Then loading is rejected
    And the result identifies schema version "taxonomy-obligation-plan-v2" as unsupported

    Examples:
      | schema_version              |
      | taxonomy-obligation-plan-v2 |

  # Taxonomy obligation plan artifact 08a ignores a caller-supplied false capability snapshot digest
  Scenario: Taxonomy obligation plan artifact 08a ignores a caller-supplied false capability snapshot digest
    Given the snapshot supplies "capability_snapshot_digest" with false value "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    And the canonical content does not match "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    When the obligation plan is produced
    Then the plan does not record "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef" as the "capability_snapshot_digest"
    And the plan records the "capability_snapshot_digest" computed from canonical content

  # Taxonomy obligation plan artifact 08b ignores a caller-supplied false semantic digest
  Scenario: Taxonomy obligation plan artifact 08b ignores a caller-supplied false semantic digest
    Given the snapshot supplies "semantic_digest" with false value "cafebebecafebebecafebebecafebebecafebebecafebebecafebebecafebebe"
    And the canonical content does not match "cafebebecafebebecafebebecafebebecafebebecafebebecafebebecafebebe"
    When the obligation plan is produced
    Then the plan does not record "cafebebecafebebecafebebecafebebecafebebecafebebecafebebecafebebe" as the "semantic_digest"
    And the plan records the "semantic_digest" computed from canonical content

  # Taxonomy obligation plan artifact 08c ignores a caller-supplied false qualification facts digest
  Scenario: Taxonomy obligation plan artifact 08c ignores a caller-supplied false qualification facts digest
    Given the snapshot supplies "qualification_facts_digest" with false value "0000000000000000000000000000000000000000000000000000000000000000"
    And the canonical content does not match "0000000000000000000000000000000000000000000000000000000000000000"
    When the obligation plan is produced
    Then the plan does not record "0000000000000000000000000000000000000000000000000000000000000000" as the "qualification_facts_digest"
    And the plan records the "qualification_facts_digest" computed from canonical content

  # Taxonomy obligation plan artifact 09 publishes the YAML plan atomically
  Scenario Outline: Taxonomy obligation plan artifact 09 publishes the YAML plan atomically
    When the plan is published as "<format>"
    Then the published artifact is named "<artifact_name>"
    And the published artifact loads as a complete closed plan
    And no partial plan file remains

    Examples:
      | format | artifact_name                 |
      | YAML   | taxonomy-obligation-plan.yaml |

  # Taxonomy obligation plan artifact 10a rejects the covered correspondence claim
  Scenario Outline: Taxonomy obligation plan artifact 10a rejects the covered correspondence claim
    Given a persisted plan sets correspondence disposition to "<invalid_disposition>"
    When the plan is loaded
    Then loading is rejected
    And the result identifies correspondence disposition "covered" as invalid

    Examples:
      | invalid_disposition |
      | covered             |

  # Taxonomy obligation plan artifact 10b rejects the matched correspondence claim
  Scenario Outline: Taxonomy obligation plan artifact 10b rejects the matched correspondence claim
    Given a persisted plan sets correspondence disposition to "<invalid_disposition>"
    When the plan is loaded
    Then loading is rejected
    And the result identifies correspondence disposition "matched" as invalid

    Examples:
      | invalid_disposition |
      | matched             |

  # Taxonomy obligation plan artifact 10c rejects the satisfied correspondence claim
  Scenario Outline: Taxonomy obligation plan artifact 10c rejects the satisfied correspondence claim
    Given a persisted plan sets correspondence disposition to "<invalid_disposition>"
    When the plan is loaded
    Then loading is rejected
    And the result identifies correspondence disposition "satisfied" as invalid

    Examples:
      | invalid_disposition |
      | satisfied           |
