# mutation-stamp: sha256=f6061857b0b2926430bc0365ef3af14d4df8f0ad65902a720262e6765e05da91
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-31T01:00:49.494021Z","feature_name":"Normative correspondence proposals","feature_path":"features/correspondence_proposal.feature","background_hash":"78aceb8c7ed78f6df84f4589ce6da7176d0565b9385733fa516f4783ad40532f","implementation_hash":"sha256:cb65ca606474103bfe2d0c0379518b34a7bc7ffe68d1a2bf6610cf175210063e","scenarios":[{"index":1,"name":"capability snapshot substitution fails closed","scenario_hash":"0219364e8827cd32b348b3e73614ddfe4450daba1df343cacc6aa7e6a9e777a3","mutation_count":1,"result":{"Total":1,"Killed":1,"Survived":0,"Errors":0},"tested_at":"2026-08-31T01:00:49.494021Z"},{"index":4,"name":"shared resource identity is not mechanism evidence","scenario_hash":"6ac29757ab2c592c071e33bbe595b7039cafb96c7b31281d098b2cbdcf19fcde","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-31T01:00:49.494021Z"},{"index":5,"name":"resource-link evidence uses an exact candidate witness and stays noncoverage","scenario_hash":"88640e89d9f7038d937f41a39ea8c42b937a238a9c9de73172b13d00d47b55c5","mutation_count":3,"result":{"Total":3,"Killed":3,"Survived":0,"Errors":0},"tested_at":"2026-08-31T01:00:49.494021Z"}]}
# acceptance-mutation-manifest-end

Feature: Normative correspondence proposals
  Deterministic evidence produces typed suggestions only. Proposals never
  become confirmed relations at proposal time.

  Background:
    Given a valid typed correspondence authority is available
    And correspondence operations make no provider calls

  Scenario: exact evidence emits a closed proposal
    Given a deterministic exact-ID proposal is prepared
    When correspondence proposals are produced
    Then the proposal set contains exactly one proposal
    And the proposal is not confirmed
    And the proposal set names the resource map capability snapshot digest

  Scenario Outline: capability snapshot substitution fails closed
    Given a deterministic exact-ID proposal is prepared
    When correspondence proposals are produced
    And proposal set "<pin_field>" is substituted
    Then the proposal artifact rejects substituted "<pin_field>"

    Examples:
      | pin_field                  |
      | capability_snapshot_digest |

  Scenario: proposal generation does not infer from prose
    Given a prose-only correspondence input is supplied
    When correspondence proposals are produced
    Then no proposal is produced from the prose-only input
    And the prose-only input is rejected with typed diagnostics

  Scenario: advisory resource evidence cannot be confirmed
    Given a deterministic advisory-only proposal is prepared
    When the advisory proposal is reconciled with explicit confirmation
    Then reconciliation rejects confirmation with code "non_authoritative_resource_link"
    And the proposal is not confirmed

  Scenario Outline: shared resource identity is not mechanism evidence
    Given accepted-resource-link evidence claims "<relation_kind>"
    When the shared-resource correspondence evidence is validated
    Then the coverage claim is rejected with diagnostic "<diagnostic>"

    Examples:
      | relation_kind  | diagnostic                                        |
      | same_mechanism | accepted resource link evidence supports noncoverage only |

  Scenario Outline: resource-link evidence uses an exact candidate witness and stays noncoverage
    Given an exact candidate and resource-link witness is prepared
    When deterministic resource-link evidence is derived
    Then one evidence item is produced for selected candidate "<candidate_id>" and resource link "<link_id>"
    And the derived evidence relation is "<relation_kind>"
    And no coverage relation is proposed by the resource-link adapter

    Examples:
      | candidate_id                              | link_id  | relation_kind          |
      | cand:v2:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa | srm:v1:1 | related_but_not_coverage |
