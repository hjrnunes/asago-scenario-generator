# mutation-stamp: sha256=314fdb8998360d1a131a3d99e03c679ce0de18ae5b7944e12c93ee1459b1fd9a
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-28T07:32:50.575966Z","feature_name":"Correspondence artifact","feature_path":"features/correspondence_artifact.feature","background_hash":"f620ce3b813733828f23955cad8fcbc2eadfc7321a1f99a85049c0bba955d166","implementation_hash":"unknown","scenarios":[{"index":0,"name":"Correspondence artifact 01 copies pinned source versions into proposals","scenario_hash":"513bdd9fb78cbfc27bf222661989dce1ca5c1572732115d0a8aa69422231a233","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-28T06:53:36.514087Z"},{"index":1,"name":"Correspondence artifact 02 round-trips without semantic loss","scenario_hash":"aa1c7b13ef33738ff759010a0f649f53d79f2c15216e38de2e40f9086b6ed2b2","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-28T06:53:36.514087Z"},{"index":2,"name":"Correspondence artifact 03 is byte-stable for identical inputs","scenario_hash":"3ba7ada12ca36be818aab400368ee888f0160faaeaecf391fd4e04011367430a","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-28T06:53:36.514087Z"},{"index":4,"name":"Correspondence artifact 05 accepts a new proposer without changing reconciliation rules","scenario_hash":"83d872431d06d8b300fd01d2ab651d3d221a90c65977a3b65b24104d69ede360","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-28T06:53:36.514087Z"},{"index":5,"name":"Correspondence artifact 06 omits coverage scores and blended method metrics","scenario_hash":"2607a59af3e258279f3d96f47fa8a52a8b00f136ef02a28982c07a580c41e2cc","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-28T06:53:36.514087Z"},{"index":3,"name":"Correspondence artifact 04 keeps order independent of presentation","scenario_hash":"5c1f97c198a62df5b204679db97d591af4b4c2301621e521ce696c00f5712aaf","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-28T06:49:57.132357Z"}]}
# acceptance-mutation-manifest-end

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
    And source artifacts contain "exact-id" evidence linking "CA-1-1" to "ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    When correspondence proposals are produced
    Then the proposal set contains proposal "P-1"
    And every proposal records STPA version "stpa-v1"
    And every proposal records taxonomy version "atlas-2026.05"

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
    Then proposal "P-3" is retained with adjudication "unresolved"
    And proposals "<existing_ids>" keep their previous adjudications
    And the result records proposer "overlap-adapter" for "P-3"
    And reconciliation rules are unchanged

    Examples:
      | proposer_id     | existing_ids |
      | overlap-adapter | P-1,P-2      |

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
