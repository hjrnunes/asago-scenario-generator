Feature: Correspondence reconciliation
  Reconciliation adjudicates proposals into confirmed, rejected, or
  unresolved states. Relation type stays separate from adjudication.
  Conflicts are preserved, confirmation requires evidence, and repeated
  reconciliation is idempotent.

  Background:
    Given a valid SystemResourceMap is available
    And correspondence reconciliation depends on the SystemResourceMap domain contract
    And correspondence reconciliation makes no network or model calls

  # Correspondence reconciliation 01 retains confirmed rejected and unresolved outcomes
  Scenario Outline: Correspondence reconciliation 01 retains confirmed rejected and unresolved outcomes
    Given proposal "<proposal_id>" has relation type "<relation_type>"
    And reconciliation input assigns adjudication "<adjudication>" to "<proposal_id>"
    When correspondence is reconciled
    Then the result retains proposal "<proposal_id>"
    And the result records adjudication "<adjudication>" for "<proposal_id>"
    And the result records relation type "<relation_type>" for "<proposal_id>"

    Examples:
      | proposal_id | relation_type | adjudication |
      | P-1         | supports      | confirmed    |
      | P-2         | addresses     | rejected     |
      | P-3         | overlaps      | unresolved   |

  # Correspondence reconciliation 02 keeps relation type separate from strength and adjudication
  Scenario Outline: Correspondence reconciliation 02 keeps relation type separate from strength and adjudication
    Given proposal "<proposal_id>" has relation type "<relation_type>" and strength "<strength>"
    And reconciliation input assigns adjudication "<adjudication>" to "<proposal_id>"
    When correspondence is reconciled
    Then proposal "<proposal_id>" has relation type "<relation_type>"
    And proposal "<proposal_id>" has strength "<strength>"
    And proposal "<proposal_id>" has adjudication "<adjudication>"
    And relation type is not equal to adjudication
    And relation type is not equal to strength

    Examples:
      | proposal_id | relation_type | strength | adjudication |
      | P-1         | supports      | high     | confirmed    |
      | P-4         | contradicts   | high     | rejected     |
      | P-3         | overlaps      | weak     | unresolved   |

  # Correspondence reconciliation 03 preserves conflicting proposals as unresolved
  Scenario Outline: Correspondence reconciliation 03 preserves conflicting proposals as unresolved
    Given conflicting proposals "<proposal_a>" with type "<type_a>" and "<proposal_b>" with type "<type_b>" for "<left_ref>" and "<right_ref>"
    And the proposals are presented in order "<order>"
    When correspondence is reconciled
    Then both proposals are retained
    And the pair has adjudication "<adjudication>"
    And the pair has conflict reason "<conflict_reason>"
    And neither proposal is confirmed by iteration order

    Examples:
      | proposal_a | type_a   | proposal_b | type_b      | left_ref | right_ref                              | order   | adjudication | conflict_reason |
      | P-1        | supports | P-4        | contradicts | CA-1-1   | ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa | P-1,P-4 | unresolved   | conflict        |
      | P-1        | supports | P-4        | contradicts | CA-1-1   | ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa | P-4,P-1 | unresolved   | conflict        |

  # Correspondence reconciliation 04 rejects dangling stale and evidence-free confirmation
  Scenario Outline: Correspondence reconciliation 04 rejects dangling stale and evidence-free confirmation
    Given proposal "<proposal_id>" has confirmation defect "<defect>"
    When correspondence is reconciled
    Then reconciliation fails
    And the result contains error code "<error_code>"
    And the error identifies "<proposal_id>"
    And no confirmed relation is written for "<proposal_id>"

    Examples:
      | proposal_id | defect         | error_code              |
      | P-9         | dangling-left  | dangling_reference      |
      | P-9         | dangling-right | dangling_reference      |
      | P-9         | stale-version  | source_version_mismatch |
      | P-9         | evidence-free  | evidence_required       |

  # Correspondence reconciliation 05 is deterministic and idempotent under reordered inputs
  Scenario Outline: Correspondence reconciliation 05 is deterministic and idempotent under reordered inputs
    Given proposals "<order_a>" are reconciled to a result
    And the same proposals are presented as "<order_b>"
    When correspondence is reconciled again
    Then both results have identical proposal identities
    And both results have identical adjudications
    And repeating reconciliation on the first result does not change it

    Examples:
      | order_a     | order_b     |
      | P-1,P-2,P-3 | P-3,P-1,P-2 |

  # Correspondence reconciliation 06 infers no relation from scenario wording
  Scenario Outline: Correspondence reconciliation 06 infers no relation from scenario wording
    Given scenario prose contains "<prose>"
    And no explicit proposal cites that prose
    When correspondence is reconciled
    Then the result contains <proposal_count> proposals
    And no relation is inferred from scenario wording

    Examples:
      | prose                                   | proposal_count |
      | the assistant supports prompt injection | 0              |

  # Correspondence reconciliation 07 does not mutate source STPA or taxonomy artifacts
  Scenario Outline: Correspondence reconciliation 07 does not mutate source STPA or taxonomy artifacts
    Given source STPA artifact "<stpa_artifact>" and taxonomy artifact "<taxonomy_artifact>"
    When correspondence proposals are produced
    And correspondence is reconciled
    Then source STPA artifact "<stpa_artifact>" and taxonomy artifact "<taxonomy_artifact>" are unchanged

    Examples:
      | stpa_artifact          | taxonomy_artifact         |
      | control-structure.yaml | attack-patterns.sssom.tsv |
