# mutation-stamp: sha256=93967a56d1e487e986aca442d29faaaa3e09cd6f1fc3b2d9016b6f2b1943fe6e
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-30T00:27:18.961313Z","feature_name":"Normative correspondence reconciliation","feature_path":"features/correspondence_reconciliation.feature","background_hash":"78aceb8c7ed78f6df84f4589ce6da7176d0565b9385733fa516f4783ad40532f","implementation_hash":"sha256:907292f70ae427c170e988f371cf8ec0a0b220fe41bffb9bb5592b79b343ca81","scenarios":[{"index":9,"name":"duplicate confirmations fail closed as typed audits","scenario_hash":"8933d5f09ca26f660e579f6ed1a1a27ae7813880bce320629e24513893fc3aff","mutation_count":1,"result":{"Total":1,"Killed":1,"Survived":0,"Errors":0},"tested_at":"2026-08-30T00:27:18.961313Z"},{"index":10,"name":"reviewed calibration remains separate from coverage","scenario_hash":"ac76446a546acdac8b26ed196dc001918595c716dce84bd38e7f47d81f1dda6a","mutation_count":4,"result":{"Total":4,"Killed":4,"Survived":0,"Errors":0},"tested_at":"2026-08-30T00:27:18.961313Z"}]}
# acceptance-mutation-manifest-end

Feature: Normative correspondence reconciliation
  Reconciliation is explicit, deterministic, and fail-closed.

  Background:
    Given a valid typed correspondence authority is available
    And correspondence operations make no provider calls

  Scenario: explicit adjudication confirms a valid proposal
    Given a deterministic exact-ID proposal is prepared
    When correspondence proposals are produced
    And the proposal is reconciled with explicit confirmation
    Then one accepted relation is returned

  Scenario: no adjudication preserves uncertainty
    Given a deterministic exact-ID proposal is prepared
    When correspondence proposals are produced
    And the proposal remains unresolved without adjudication
    Then the proposal is not confirmed

  Scenario: shared resource without a proposal remains an unresolved obligation
    Given a shared resource authority has no correspondence proposal
    When correspondence is reconciled without a proposal
    Then the obligation remains an unresolved typed gap "unresolved_no_proposal"

  Scenario: many-to-many identity is retained in both directions
    Given one obligation maps to two ICAs and one ICA maps to two obligations
    When all many-to-many relations are explicitly confirmed
    Then reconciliation contains 4 distinct accepted relations
    And accepted relation identities retain both obligation and ICA identities

  Scenario: same-slot ICAs remain distinct with a shared EXEC identity
    Given two ICAs share a slot and EXEC identity
    When both same-slot ICAs are explicitly confirmed
    Then both same-slot ICAs remain distinct accepted relations

  Scenario: an unmapped ICA remains structural and scenario-eligible
    Given an unmapped ICA is in structural authority
    When correspondence is reconciled without a proposal
    Then the unmapped ICA remains structurally retained and scenario-eligible

  Scenario: an unmatched obligation is a typed dangling gap
    Given an unmatched obligation is in typed authority
    When correspondence is reconciled with explicit confirmation
    Then the unmatched obligation remains a typed gap with code "dangling_obligation"

  Scenario: related correspondence is retained without coverage credit
    Given a reviewed related-but-not-coverage proposal is prepared
    When the related-but-not-coverage proposal is explicitly confirmed
    Then the relation remains a finding and never coverage

  Scenario: rejected correspondence remains auditable
    Given a rejected correspondence proposal is prepared
    When the proposal is explicitly rejected
    Then the rejection remains retained with no accepted relation

  Scenario Outline: duplicate confirmations fail closed as typed audits
    Given two proposals imply the same semantic relation
    When both duplicate relations are explicitly confirmed
    Then both proposals are rejected with code "<validation_code>"
    And no duplicate accepted relation is returned

    Examples:
      | validation_code              |
      | duplicate_confirmed_relation |

  Scenario Outline: reviewed calibration remains separate from coverage
    Given four coverage-bearing proposals await independent review
    When calibration records one confirmed one rejected one unresolved and one unreviewed
    Then calibration precision evidence is <numerator> of <denominator> resolved coverage proposals
    And calibration retains <unresolved> unresolved and <unreviewed> unreviewed proposal

    Examples:
      | numerator | denominator | unresolved | unreviewed |
      | 1         | 2           | 1          | 1          |
