# mutation-stamp: sha256=07cd4207e8f87f3a5600524b28aac66a8a1a1a9cae9bf882afb6a48bf6bd8d46
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-28T07:32:50.878618Z","feature_name":"Correspondence reconciliation","feature_path":"features/correspondence_reconciliation.feature","background_hash":"7f07c460bb9dd16d1f170c16903f35b36bbcf4d60ec3451fd35a0911d0315f6b","implementation_hash":"unknown","scenarios":[{"index":0,"name":"Correspondence reconciliation 01a retains a confirmed outcome","scenario_hash":"7f5523bd464b996be5c01ad010d4fe471f1e2d5d65ea2834e1e5d259089537f7","mutation_count":3,"result":{"Total":3,"Killed":3,"Survived":0,"Errors":0},"tested_at":"2026-08-28T07:01:41.341069Z"},{"index":1,"name":"Correspondence reconciliation 01b retains a rejected outcome","scenario_hash":"f9c4fd9306428c2986250b18c212c17fb5012fb5fa705e12542042dede12ef85","mutation_count":3,"result":{"Total":3,"Killed":3,"Survived":0,"Errors":0},"tested_at":"2026-08-28T07:01:41.341069Z"},{"index":2,"name":"Correspondence reconciliation 01c retains an unresolved outcome","scenario_hash":"209956aacf3e7bb5e7ffc4c9527c4efc826682fcd0c69842b5a341eec9ec671d","mutation_count":3,"result":{"Total":3,"Killed":3,"Survived":0,"Errors":0},"tested_at":"2026-08-28T07:01:41.341069Z"},{"index":3,"name":"Correspondence reconciliation 02a keeps relation type separate from strength and adjudication","scenario_hash":"54b7a9ee00ebde559a7dbc66256ff660a72be2a35b9902afcc22f4864992b7cd","mutation_count":4,"result":{"Total":4,"Killed":4,"Survived":0,"Errors":0},"tested_at":"2026-08-28T07:01:41.341069Z"},{"index":4,"name":"Correspondence reconciliation 02b keeps relation type separate from strength and adjudication for contradictions","scenario_hash":"7b06a209b0b6c4c53b2430139b542b02762ddc6ccbc455bff174501d05a533a0","mutation_count":4,"result":{"Total":4,"Killed":4,"Survived":0,"Errors":0},"tested_at":"2026-08-28T07:01:41.341069Z"},{"index":5,"name":"Correspondence reconciliation 02c keeps relation type separate from strength and adjudication for overlaps","scenario_hash":"1d56f35606c8623b6f5d1d161aa7a169eaf81d017a8a18b84c770a4216d5d8bc","mutation_count":4,"result":{"Total":4,"Killed":4,"Survived":0,"Errors":0},"tested_at":"2026-08-28T07:01:41.341069Z"},{"index":6,"name":"Correspondence reconciliation 03 preserves conflicting proposals as unresolved","scenario_hash":"8c11308eb1ae01390b89d0ae2666f8dd0718f6d739492f3d42005bd7f14e5e99","mutation_count":6,"result":{"Total":6,"Killed":6,"Survived":0,"Errors":0},"tested_at":"2026-08-28T07:01:41.341069Z"},{"index":7,"name":"Correspondence reconciliation 04 rejects dangling stale and evidence-free confirmation","scenario_hash":"a02e67b4dd4d8d31eecc9c8b46a7b54ea0c88c8385afa56f517a8d9e2e5b1c41","mutation_count":12,"result":{"Total":12,"Killed":12,"Survived":0,"Errors":0},"tested_at":"2026-08-28T07:01:41.341069Z"},{"index":8,"name":"Correspondence reconciliation 05 is deterministic and idempotent under reordered inputs","scenario_hash":"27e80bbfcdc50b5ae09754c08152c6a45af21edce223675e8d331843cf20bab7","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-28T07:01:41.341069Z"},{"index":9,"name":"Correspondence reconciliation 06 infers no relation from scenario wording","scenario_hash":"2cad0c4331bf1bf69b9460ddc9590ee4bbb89e0547902d0d76f43d7bb4ff4851","mutation_count":1,"result":{"Total":1,"Killed":1,"Survived":0,"Errors":0},"tested_at":"2026-08-28T07:01:41.341069Z"},{"index":10,"name":"Correspondence reconciliation 07 does not mutate source STPA or taxonomy artifacts","scenario_hash":"3ca969d2fa8670b4e16aceeb726ca0b428b3d4b1192411c3d9931212dff7461a","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-28T07:01:41.341069Z"}]}
# acceptance-mutation-manifest-end

Feature: Correspondence reconciliation
  Reconciliation adjudicates proposals into confirmed, rejected, or
  unresolved states. Relation type stays separate from adjudication.
  Conflicts are preserved, confirmation requires evidence, and repeated
  reconciliation is idempotent.

  Background:
    Given a valid SystemResourceMap is available
    And correspondence reconciliation depends on the SystemResourceMap domain contract
    And correspondence reconciliation makes no network or model calls

  # Correspondence reconciliation 01a retains a confirmed outcome
  Scenario Outline: Correspondence reconciliation 01a retains a confirmed outcome
    Given proposal "<proposal_id>" has relation type "<relation_type>"
    And reconciliation input assigns adjudication "<adjudication>" to "<proposal_id>"
    When correspondence is reconciled
    Then the result retains proposal "P-1"
    And the result records adjudication "confirmed" for "P-1"
    And the result records relation type "supports" for "P-1"

    Examples:
      | proposal_id | relation_type | adjudication |
      | P-1         | supports      | confirmed    |

  # Correspondence reconciliation 01b retains a rejected outcome
  Scenario Outline: Correspondence reconciliation 01b retains a rejected outcome
    Given proposal "<proposal_id>" has relation type "<relation_type>"
    And reconciliation input assigns adjudication "<adjudication>" to "<proposal_id>"
    When correspondence is reconciled
    Then the result retains proposal "P-2"
    And the result records adjudication "rejected" for "P-2"
    And the result records relation type "addresses" for "P-2"

    Examples:
      | proposal_id | relation_type | adjudication |
      | P-2         | addresses     | rejected     |

  # Correspondence reconciliation 01c retains an unresolved outcome
  Scenario Outline: Correspondence reconciliation 01c retains an unresolved outcome
    Given proposal "<proposal_id>" has relation type "<relation_type>"
    And reconciliation input assigns adjudication "<adjudication>" to "<proposal_id>"
    When correspondence is reconciled
    Then the result retains proposal "P-3"
    And the result records adjudication "unresolved" for "P-3"
    And the result records relation type "overlaps" for "P-3"

    Examples:
      | proposal_id | relation_type | adjudication |
      | P-3         | overlaps      | unresolved   |

  # Correspondence reconciliation 02a keeps relation type separate from strength and adjudication
  Scenario Outline: Correspondence reconciliation 02a keeps relation type separate from strength and adjudication
    Given proposal "<proposal_id>" has relation type "<relation_type>" and strength "<strength>"
    And reconciliation input assigns adjudication "<adjudication>" to "<proposal_id>"
    When correspondence is reconciled
    Then the result records relation type "supports" for "P-1"
    And proposal "P-1" has strength "high"
    And the result records adjudication "confirmed" for "P-1"
    And relation type is not equal to adjudication
    And relation type is not equal to strength

    Examples:
      | proposal_id | relation_type | strength | adjudication |
      | P-1         | supports      | high     | confirmed    |

  # Correspondence reconciliation 02b keeps relation type separate from strength and adjudication for contradictions
  Scenario Outline: Correspondence reconciliation 02b keeps relation type separate from strength and adjudication for contradictions
    Given proposal "<proposal_id>" has relation type "<relation_type>" and strength "<strength>"
    And reconciliation input assigns adjudication "<adjudication>" to "<proposal_id>"
    When correspondence is reconciled
    Then the result records relation type "contradicts" for "P-4"
    And proposal "P-4" has strength "high"
    And the result records adjudication "rejected" for "P-4"
    And relation type is not equal to adjudication
    And relation type is not equal to strength

    Examples:
      | proposal_id | relation_type | strength | adjudication |
      | P-4         | contradicts   | high     | rejected     |

  # Correspondence reconciliation 02c keeps relation type separate from strength and adjudication for overlaps
  Scenario Outline: Correspondence reconciliation 02c keeps relation type separate from strength and adjudication for overlaps
    Given proposal "<proposal_id>" has relation type "<relation_type>" and strength "<strength>"
    And reconciliation input assigns adjudication "<adjudication>" to "<proposal_id>"
    When correspondence is reconciled
    Then the result records relation type "overlaps" for "P-3"
    And proposal "P-3" has strength "weak"
    And the result records adjudication "unresolved" for "P-3"
    And relation type is not equal to adjudication
    And relation type is not equal to strength

    Examples:
      | proposal_id | relation_type | strength | adjudication |
      | P-3         | overlaps      | weak     | unresolved   |

  # Correspondence reconciliation 03 preserves conflicting proposals as unresolved
  Scenario Outline: Correspondence reconciliation 03 preserves conflicting proposals as unresolved
    Given conflicting proposals "P-1" with type "supports" and "P-4" with type "contradicts" for "CA-1-1" and "ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    And the proposals are presented in order "<order>"
    When correspondence is reconciled
    Then both proposals are retained
    And the pair has adjudication "<adjudication>"
    And the pair has conflict reason "<conflict_reason>"
    And neither proposal is confirmed by iteration order

    Examples:
      | order   | adjudication | conflict_reason |
      | P-1,P-4 | unresolved   | conflict        |
      | P-4,P-1 | unresolved   | conflict        |

  # Correspondence reconciliation 04 rejects dangling stale and evidence-free confirmation
  Scenario Outline: Correspondence reconciliation 04 rejects dangling stale and evidence-free confirmation
    Given proposal "<proposal_id>" has confirmation defect "<defect>"
    When correspondence is reconciled
    Then reconciliation fails
    And the result contains error code "<error_code>"
    And the error identifies "P-9"
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
    Given scenario prose contains "the assistant supports prompt injection"
    And no explicit proposal cites that prose
    When correspondence is reconciled
    Then the result contains <proposal_count> proposals
    And no relation is inferred from scenario wording

    Examples:
      | proposal_count |
      | 0              |

  # Correspondence reconciliation 07 does not mutate source STPA or taxonomy artifacts
  Scenario Outline: Correspondence reconciliation 07 does not mutate source STPA or taxonomy artifacts
    Given source STPA artifact "<stpa_artifact>" and taxonomy artifact "<taxonomy_artifact>"
    When correspondence proposals are produced
    And correspondence is reconciled
    Then source STPA artifact "control-structure.yaml" and taxonomy artifact "attack-patterns.sssom.tsv" are unchanged

    Examples:
      | stpa_artifact          | taxonomy_artifact         |
      | control-structure.yaml | attack-patterns.sssom.tsv |
