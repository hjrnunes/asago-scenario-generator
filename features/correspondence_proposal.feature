# mutation-stamp: sha256=d83609f81442ea76411cbe4c8f28a831a472704b7a484edb2de3c36e518df15e
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-29T14:32:25.661176Z","feature_name":"Normative correspondence proposals","feature_path":"features/correspondence_proposal.feature","background_hash":"78aceb8c7ed78f6df84f4589ce6da7176d0565b9385733fa516f4783ad40532f","implementation_hash":"sha256:cb65ca606474103bfe2d0c0379518b34a7bc7ffe68d1a2bf6610cf175210063e","scenarios":[{"index":1,"name":"capability snapshot substitution fails closed","scenario_hash":"0219364e8827cd32b348b3e73614ddfe4450daba1df343cacc6aa7e6a9e777a3","mutation_count":1,"result":{"Total":1,"Killed":1,"Survived":0,"Errors":0},"tested_at":"2026-08-29T14:32:25.661176Z"}]}
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
