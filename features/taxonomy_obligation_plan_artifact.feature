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
