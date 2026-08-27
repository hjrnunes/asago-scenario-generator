Feature: Correspondence artifact
  Proposal sets and reconciliation results are versioned YAML and JSON
  artifacts. Identifiers and ordering come from semantic identity, and
  round-trip persistence preserves provenance and adjudication history.

  Background:
    Given a valid SystemResourceMap is available
    And correspondence reconciliation depends on the SystemResourceMap domain contract
    And correspondence proposal makes no network or model calls

  # Correspondence artifact 01 copies pinned source versions into proposals
  Scenario Outline: Correspondence artifact 01 copies pinned source versions into proposals
    Given the resource map pins STPA version "<stpa_version>" and taxonomy version "<taxonomy_version>"
    When correspondence proposals are produced
    Then every proposal records STPA version "<stpa_version>"
    And every proposal records taxonomy version "<taxonomy_version>"

    Examples:
      | stpa_version | taxonomy_version |
      | stpa-v1      | atlas-2026.05    |

  # Correspondence artifact 02 round-trips without semantic loss
  Scenario Outline: Correspondence artifact 02 round-trips without semantic loss
    Given a reconciliation result with confirmed, rejected, and unresolved proposals
    When the result is serialized as "<format>" and deserialized
    Then proposal identities are preserved
    And evidence provenance is preserved
    And adjudication history is preserved
    And relation types are preserved

    Examples:
      | format |
      | YAML   |
      | JSON   |

  # Correspondence artifact 03 is byte-stable for identical inputs
  Scenario Outline: Correspondence artifact 03 is byte-stable for identical inputs
    Given a reconciliation result with confirmed, rejected, and unresolved proposals
    When the result is serialized as "<format>" twice
    Then the two artifacts are byte-identical

    Examples:
      | format |
      | YAML   |
      | JSON   |

  # Correspondence artifact 04 keeps order independent of presentation
  Scenario Outline: Correspondence artifact 04 keeps order independent of presentation
    Given one proposal set presents identities in order "<order_a>"
    And another proposal set presents the same identities in order "<order_b>"
    When each set is reconciled and serialized
    Then both results have identical proposal identities
    And both results have identical canonical order
    And both serialized artifacts are canonically equivalent

    Examples:
      | order_a     | order_b     |
      | P-1,P-2,P-3 | P-3,P-2,P-1 |

  # Correspondence artifact 05 accepts a new proposer without changing reconciliation rules
  Scenario Outline: Correspondence artifact 05 accepts a new proposer without changing reconciliation rules
    Given proposer "<proposer_id>" emits the shared proposal contract
    And existing proposals "<existing_ids>" already have adjudications
    When correspondence is reconciled
    Then proposal "<new_id>" is retained with adjudication "<new_adjudication>"
    And proposals "<existing_ids>" keep their previous adjudications
    And reconciliation rules are unchanged

    Examples:
      | proposer_id     | existing_ids | new_id | new_adjudication |
      | overlap-adapter | P-1,P-2      | P-3    | unresolved       |

  # Correspondence artifact 06 omits coverage scores and blended method metrics
  Scenario Outline: Correspondence artifact 06 omits coverage scores and blended method metrics
    Given a reconciliation result with confirmed, rejected, and unresolved proposals
    When the result is serialized as "<format>"
    Then the artifact does not contain a coverage score
    And the artifact does not contain a blended method metric

    Examples:
      | format |
      | YAML   |
      | JSON   |
