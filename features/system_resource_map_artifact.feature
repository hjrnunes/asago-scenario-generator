# mutation-stamp: sha256=438582d85e06178735e92f0fac904a93c2a4bc4847639436c6e32145a0204e15
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-27T22:31:25.115474Z","feature_name":"System resource map artifact","feature_path":"features/system_resource_map_artifact.feature","background_hash":"0bfaf3171637b4ca3948b8e4a056b0e02fd1d186b76546533a60aaaaa0d5f76e","implementation_hash":"unknown","scenarios":[{"index":0,"name":"System resource map artifact 01 copies pinned snapshot versions into the map","scenario_hash":"a14fdff414fc89bc4804bf01a5489b096b31e232f44a36e0cd7957882f3271bb","mutation_count":3,"result":{"Total":3,"Killed":3,"Survived":0,"Errors":0},"tested_at":"2026-08-27T21:26:31.316583Z"},{"index":1,"name":"System resource map artifact 02 keeps identifiers and order independent of presentation order","scenario_hash":"42de85cbd676ace4f1383d85c3835ccf2b3775d64b04f365b574a56491b8ca2d","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-27T21:26:31.316583Z"},{"index":2,"name":"System resource map artifact 03 round-trips without semantic loss","scenario_hash":"3fb98fd9d11b7365459a22ce8545ce58ad1369a2d3d23fc8460456037af0b97e","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-27T21:26:31.316583Z"},{"index":3,"name":"System resource map artifact 04 is byte-stable for identical inputs","scenario_hash":"47999a6c9ccb15a5ba7c9d86bf323491e30c77eb467296f0e2defcecc4ecd77f","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-27T21:26:31.316583Z"},{"index":4,"name":"System resource map artifact 05 exposes the domain contract without persistence details","scenario_hash":"6c82f9eaa1a138452db983e6ec7e62c2007f20df59e40d3a798667695474dc4e","mutation_count":4,"result":{"Total":4,"Killed":4,"Survived":0,"Errors":0},"tested_at":"2026-08-27T21:26:31.316583Z"}]}
# acceptance-mutation-manifest-end

Feature: System resource map artifact
  The SystemResourceMap is a versioned YAML and JSON artifact. Identifiers
  and ordering come from semantic identity, round-trip persistence
  preserves references and provenance, and consumers read the domain
  contract without persistence details.

  Background:
    Given a pinned resource-map snapshot is available
    And resource-map validation makes no network or model calls

  # System resource map artifact 01 copies pinned snapshot versions into the map
  Scenario Outline: System resource map artifact 01 copies pinned snapshot versions into the map
    Given the snapshot pins schema version "<schema_version>", STPA version "<stpa_version>", and taxonomy version "<taxonomy_version>"
    When a valid resource map is produced
    Then the map records schema version "<schema_version>"
    And the map records STPA version "<stpa_version>"
    And the map records taxonomy version "<taxonomy_version>"

    Examples:
      | schema_version | stpa_version | taxonomy_version |
      | 1              | stpa-v1      | atlas-2026.05    |

  # System resource map artifact 02 keeps identifiers and order independent of presentation order
  Scenario Outline: System resource map artifact 02 keeps identifiers and order independent of presentation order
    Given one map presents entities in order "<order_a>"
    And another map presents the same entities in order "<order_b>"
    When each map is validated and serialized
    Then both maps have identical identifiers
    And both maps have identical canonical entity order
    And both serialized artifacts are canonically equivalent

    Examples:
      | order_a              | order_b              |
      | SR-1,RESP-1,CA-1-1   | CA-1-1,RESP-1,SR-1   |

  # System resource map artifact 03 round-trips without semantic loss
  Scenario Outline: System resource map artifact 03 round-trips without semantic loss
    Given a valid representative resource map
    When the map is serialized as "<format>" and deserialized
    Then identifiers and cross-references are preserved
    And provenance is preserved
    And unknown and absent statuses are preserved

    Examples:
      | format |
      | YAML   |
      | JSON   |

  # System resource map artifact 04 is byte-stable for identical inputs
  Scenario Outline: System resource map artifact 04 is byte-stable for identical inputs
    Given a valid representative resource map
    When the map is serialized as "<format>" twice
    Then the two artifacts are byte-identical

    Examples:
      | format |
      | YAML   |
      | JSON   |

  # System resource map artifact 05 exposes the domain contract without persistence details
  Scenario Outline: System resource map artifact 05 exposes the domain contract without persistence details
    Given a valid representative resource map serialized as "<format>"
    When a consumer reads the map through the domain contract
    Then the consumer can access entity family "<family>"
    And the consumer does not import persistence adapters

    Examples:
      | format | family            |
      | YAML   | control-action    |
      | JSON   | trust-boundary    |
