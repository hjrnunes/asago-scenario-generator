Feature: Correspondence proposal
  Deterministic proposers emit typed correspondence suggestions from a
  SystemResourceMap and source artifacts. A proposal is not a confirmed
  relation. Evidence strength is retained, and heuristic adapters cannot
  write confirmed relations.

  Background:
    Given a valid SystemResourceMap is available
    And correspondence proposal makes no network or model calls

  # Correspondence proposal 01 records high-strength evidence without confirming the relation
  Scenario Outline: Correspondence proposal 01 records high-strength evidence without confirming the relation
    Given source artifacts contain "<evidence_source>" evidence linking "<left_ref>" to "<right_ref>"
    When correspondence proposals are produced
    Then the proposal set contains proposal "<proposal_id>"
    And that proposal has evidence source "<evidence_source>"
    And that proposal has strength "<strength>"
    And that proposal has relation type "<relation_type>"
    And that proposal is not confirmed

    Examples:
      | evidence_source | left_ref | right_ref                              | proposal_id | strength | relation_type |
      | exact-id        | CA-1-1   | ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa | P-1         | high     | supports      |
      | curated-map     | L-1      | AP-T6-01                               | P-2         | high     | addresses     |

  # Correspondence proposal 02 keeps weak resource overlap distinct from high-strength evidence
  Scenario Outline: Correspondence proposal 02 keeps weak resource overlap distinct from high-strength evidence
    Given source artifacts contain "<evidence_source>" evidence linking "<left_ref>" to "<right_ref>"
    When correspondence proposals are produced
    Then the proposal set contains proposal "<proposal_id>"
    And that proposal has evidence source "<evidence_source>"
    And that proposal has strength "<strength>"
    And that proposal is not classified as evidence source "<other_source>"
    And that proposal is not confirmed

    Examples:
      | evidence_source  | left_ref | right_ref                              | proposal_id | strength | other_source |
      | resource-overlap | CP-2     | tb:v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb | P-3         | weak     | exact-id     |
      | resource-overlap | CP-2     | tb:v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb | P-3         | weak     | curated-map  |

  # Correspondence proposal 03 retains typed proposal provenance
  Scenario Outline: Correspondence proposal 03 retains typed proposal provenance
    Given proposer "<proposer_id>" version "<proposer_version>" emits a proposal for "<left_ref>" and "<right_ref>"
    And the proposal cites evidence references "<evidence_refs>"
    And the proposal pins STPA version "<stpa_version>" and taxonomy version "<taxonomy_version>"
    And the proposal rationale is "<rationale>"
    When correspondence proposals are produced
    Then proposal "<proposal_id>" has left ref "<left_ref>" and right ref "<right_ref>"
    And proposal "<proposal_id>" records proposer "<proposer_id>" version "<proposer_version>"
    And proposal "<proposal_id>" records evidence references "<evidence_refs>"
    And proposal "<proposal_id>" records STPA version "<stpa_version>" and taxonomy version "<taxonomy_version>"
    And proposal "<proposal_id>" records rationale "<rationale>"

    Examples:
      | proposal_id | left_ref | right_ref                              | proposer_id      | proposer_version | evidence_refs                                  | stpa_version | taxonomy_version | rationale              |
      | P-1         | CA-1-1   | ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa | exact-id-adapter | 1                | CA-1-1,ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa | stpa-v1      | atlas-2026.05    | exact identifier match |

  # Correspondence proposal 04 forbids heuristic adapters from writing confirmed relations
  Scenario Outline: Correspondence proposal 04 forbids heuristic adapters from writing confirmed relations
    Given proposer "<proposer_id>" is a "<adapter_kind>" adapter
    When correspondence proposals are produced
    Then every proposal from "<proposer_id>" has evidence source "<evidence_source>"
    And no confirmed relation is written by "<proposer_id>"

    Examples:
      | proposer_id            | adapter_kind   | evidence_source |
      | heuristic-adapter      | heuristic      | heuristic       |
      | model-assisted-adapter | model-assisted | model-assisted  |
