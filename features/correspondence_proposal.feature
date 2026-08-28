# mutation-stamp: sha256=80b2ed000a0e6733417a8ed7b510243c92fd4f861f85a217be2284501a5539d0
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-28T07:32:50.720910Z","feature_name":"Correspondence proposal","feature_path":"features/correspondence_proposal.feature","background_hash":"5209710c8b8b9d0a523ca0902be66cbe9254f96aefa52006fb87e726f5882a39","implementation_hash":"unknown","scenarios":[{"index":0,"name":"Correspondence proposal 01a records exact-id evidence as high-strength support","scenario_hash":"c259f77c8b897ac9b3fedd822cde5fa45ce48881136145de718e5428a34c99f5","mutation_count":4,"result":{"Total":4,"Killed":4,"Survived":0,"Errors":0},"tested_at":"2026-08-28T07:01:29.074950Z"},{"index":1,"name":"Correspondence proposal 01b records curated-map evidence as high-strength addresses","scenario_hash":"6a8b74ae7942525cbc16b450a118bbbe2f0fd4cf7000367afa1d26e6ded5e357","mutation_count":4,"result":{"Total":4,"Killed":4,"Survived":0,"Errors":0},"tested_at":"2026-08-28T07:01:29.074950Z"},{"index":2,"name":"Correspondence proposal 02a keeps weak resource overlap distinct from exact-id evidence","scenario_hash":"3dfe0b35d020db1fd99044fb35f8bcf1133116de5c3a4f94ffa4eaee901aefe8","mutation_count":4,"result":{"Total":4,"Killed":4,"Survived":0,"Errors":0},"tested_at":"2026-08-28T07:01:29.074950Z"},{"index":3,"name":"Correspondence proposal 02b keeps weak resource overlap distinct from curated-map evidence","scenario_hash":"47bea0dff88093f745a09c18d463e4dcb54a301d1c214ce86e6d0218fb708703","mutation_count":4,"result":{"Total":4,"Killed":4,"Survived":0,"Errors":0},"tested_at":"2026-08-28T07:01:29.074950Z"},{"index":4,"name":"Correspondence proposal 03 retains typed proposal provenance","scenario_hash":"9b7962fb2201af49d1926bd52282fc4b3030fa4cbb4fb4430f2d0795b25d7629","mutation_count":9,"result":{"Total":9,"Killed":9,"Survived":0,"Errors":0},"tested_at":"2026-08-28T07:01:29.074950Z"},{"index":5,"name":"Correspondence proposal 04a forbids heuristic adapters from writing confirmed relations","scenario_hash":"3d08ca264ea16f792a03b9c7ac01fcfbdbc2c13624c870958ef8c8263bd14595","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-28T07:01:29.074950Z"},{"index":6,"name":"Correspondence proposal 04b forbids model-assisted adapters from writing confirmed relations","scenario_hash":"062a858e476703ee7a58a40fbfcff5cd74f4e0b59772d145656b9c19d3218b6b","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-28T07:01:29.074950Z"}]}
# acceptance-mutation-manifest-end

Feature: Correspondence proposal
  Deterministic proposers emit typed correspondence suggestions from a
  SystemResourceMap and source artifacts. A proposal is not a confirmed
  relation. Evidence strength is retained, and heuristic adapters cannot
  write confirmed relations.

  Background:
    Given a valid SystemResourceMap is available
    And correspondence proposal makes no network or model calls

  # Correspondence proposal 01a records exact-id evidence as high-strength support
  Scenario Outline: Correspondence proposal 01a records exact-id evidence as high-strength support
    Given source artifacts contain "<evidence_source>" evidence linking "<left_ref>" to "<right_ref>"
    When correspondence proposals are produced
    Then the proposal set contains proposal "<proposal_id>"
    And proposal "P-1" has left ref "CA-1-1" and right ref "ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    And that proposal has evidence source "exact-id"
    And that proposal has strength "high"
    And that proposal has relation type "supports"
    And that proposal is not confirmed

    Examples:
      | evidence_source | left_ref | right_ref                              | proposal_id |
      | exact-id        | CA-1-1   | ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa | P-1         |

  # Correspondence proposal 01b records curated-map evidence as high-strength addresses
  Scenario Outline: Correspondence proposal 01b records curated-map evidence as high-strength addresses
    Given source artifacts contain "<evidence_source>" evidence linking "<left_ref>" to "<right_ref>"
    When correspondence proposals are produced
    Then the proposal set contains proposal "<proposal_id>"
    And proposal "P-2" has left ref "L-1" and right ref "AP-T6-01"
    And that proposal has evidence source "curated-map"
    And that proposal has strength "high"
    And that proposal has relation type "addresses"
    And that proposal is not confirmed

    Examples:
      | evidence_source | left_ref | right_ref | proposal_id |
      | curated-map     | L-1      | AP-T6-01  | P-2         |

  # Correspondence proposal 02a keeps weak resource overlap distinct from exact-id evidence
  Scenario Outline: Correspondence proposal 02a keeps weak resource overlap distinct from exact-id evidence
    Given source artifacts contain "<evidence_source>" evidence linking "<left_ref>" to "<right_ref>"
    When correspondence proposals are produced
    Then the proposal set contains proposal "<proposal_id>"
    And proposal "P-3" has left ref "CP-2" and right ref "tb:v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    And that proposal has evidence source "resource-overlap"
    And that proposal has strength "weak"
    And that proposal is not classified as evidence source "exact-id"
    And that proposal is not confirmed

    Examples:
      | evidence_source  | left_ref | right_ref                              | proposal_id |
      | resource-overlap | CP-2     | tb:v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb | P-3         |

  # Correspondence proposal 02b keeps weak resource overlap distinct from curated-map evidence
  Scenario Outline: Correspondence proposal 02b keeps weak resource overlap distinct from curated-map evidence
    Given source artifacts contain "<evidence_source>" evidence linking "<left_ref>" to "<right_ref>"
    When correspondence proposals are produced
    Then the proposal set contains proposal "<proposal_id>"
    And proposal "P-3" has left ref "CP-2" and right ref "tb:v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    And that proposal has evidence source "resource-overlap"
    And that proposal has strength "weak"
    And that proposal is not classified as evidence source "curated-map"
    And that proposal is not confirmed

    Examples:
      | evidence_source  | left_ref | right_ref                              | proposal_id |
      | resource-overlap | CP-2     | tb:v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb | P-3         |

  # Correspondence proposal 03 retains typed proposal provenance
  Scenario Outline: Correspondence proposal 03 retains typed proposal provenance
    Given proposer "<proposer_id>" version "<proposer_version>" emits a proposal for "<left_ref>" and "<right_ref>"
    And the proposal cites evidence references "<evidence_refs>"
    And the proposal pins STPA version "<stpa_version>" and taxonomy version "<taxonomy_version>"
    And the proposal rationale is "<rationale>"
    When correspondence proposals are produced
    Then proposal "P-1" has left ref "CA-1-1" and right ref "ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    And proposal "P-1" records proposer "exact-id-adapter" version "1"
    And proposal "P-1" records evidence references "CA-1-1,ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    And proposal "P-1" records STPA version "stpa-v1" and taxonomy version "atlas-2026.05"
    And proposal "P-1" records rationale "exact identifier match"

    Examples:
      | proposal_id | left_ref | right_ref                              | proposer_id      | proposer_version | evidence_refs                                  | stpa_version | taxonomy_version | rationale              |
      | P-1         | CA-1-1   | ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa | exact-id-adapter | 1                | CA-1-1,ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa | stpa-v1      | atlas-2026.05    | exact identifier match |

  # Correspondence proposal 04a forbids heuristic adapters from writing confirmed relations
  Scenario Outline: Correspondence proposal 04a forbids heuristic adapters from writing confirmed relations
    Given proposer "<proposer_id>" is a "<adapter_kind>" adapter
    When correspondence proposals are produced
    Then the proposal set contains proposal "P-heuristic-adapter"
    And every proposal from "heuristic-adapter" has evidence source "heuristic"
    And no confirmed relation is written by "heuristic-adapter"

    Examples:
      | proposer_id       | adapter_kind |
      | heuristic-adapter | heuristic    |

  # Correspondence proposal 04b forbids model-assisted adapters from writing confirmed relations
  Scenario Outline: Correspondence proposal 04b forbids model-assisted adapters from writing confirmed relations
    Given proposer "<proposer_id>" is a "<adapter_kind>" adapter
    When correspondence proposals are produced
    Then the proposal set contains proposal "P-model-assisted-adapter"
    And every proposal from "model-assisted-adapter" has evidence source "model-assisted"
    And no confirmed relation is written by "model-assisted-adapter"

    Examples:
      | proposer_id            | adapter_kind   |
      | model-assisted-adapter | model-assisted |
