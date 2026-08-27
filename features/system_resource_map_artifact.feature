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
