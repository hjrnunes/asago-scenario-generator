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
    Then the plan records schema version "<schema_version>"
    And the plan records catalog pin "<catalog_pin>"
    And the plan records mapping pin "<mapping_pin>"
    And the plan records computed digests for capability snapshot, qualification facts, generation inputs, and semantic content

    Examples:
      | schema_version              | catalog_pin   | mapping_pin | capability_content | qualification_facts |
      | taxonomy-obligation-plan-v1 | atlas-2026.05 | sssom-v1    | profile-v1         | facts-v1            |

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

  # Taxonomy obligation plan artifact 06 rejects unknown fields
  Scenario Outline: Taxonomy obligation plan artifact 06 rejects unknown fields
    Given a persisted plan includes unknown field "<field>"
    When the plan is loaded
    Then loading is rejected
    And the result identifies unknown field "<field>"

    Examples:
      | field         |
      | extra_score   |
      | covered_rate  |

  # Taxonomy obligation plan artifact 07 rejects unsupported schema versions
  Scenario Outline: Taxonomy obligation plan artifact 07 rejects unsupported schema versions
    Given a persisted plan declares schema version "<schema_version>"
    When the plan is loaded
    Then loading is rejected
    And the result identifies schema version "<schema_version>" as unsupported

    Examples:
      | schema_version               |
      | taxonomy-obligation-plan-v0  |
      | taxonomy-obligation-plan-v2  |

  # Taxonomy obligation plan artifact 08 ignores caller-supplied false digests
  Scenario Outline: Taxonomy obligation plan artifact 08 ignores caller-supplied false digests
    Given the snapshot supplies "<digest_kind>" with false value "<false_digest>"
    And the canonical content does not match "<false_digest>"
    When the obligation plan is produced
    Then the plan does not record "<false_digest>" as the "<digest_kind>"
    And the plan records the "<digest_kind>" computed from canonical content

    Examples:
      | digest_kind                | false_digest                                                     |
      | capability_snapshot_digest | deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef |
      | semantic_digest            | cafebebecafebebecafebebecafebebecafebebecafebebecafebebecafebebe |
      | qualification_facts_digest | 0000000000000000000000000000000000000000000000000000000000000000 |

  # Taxonomy obligation plan artifact 09 publishes the YAML plan atomically
  Scenario Outline: Taxonomy obligation plan artifact 09 publishes the YAML plan atomically
    When the plan is published as "<format>"
    Then the published artifact is named "<artifact_name>"
    And the published artifact loads as a complete closed plan
    And no partial plan file remains

    Examples:
      | format | artifact_name                   |
      | YAML   | taxonomy-obligation-plan.yaml   |

  # Taxonomy obligation plan artifact 10 rejects Phase 1 correspondence claims
  Scenario Outline: Taxonomy obligation plan artifact 10 rejects Phase 1 correspondence claims
    Given a persisted plan sets correspondence disposition to "<invalid_disposition>"
    When the plan is loaded
    Then loading is rejected
    And the result identifies correspondence disposition "<invalid_disposition>" as invalid

    Examples:
      | invalid_disposition |
      | covered             |
      | matched             |
      | satisfied           |
