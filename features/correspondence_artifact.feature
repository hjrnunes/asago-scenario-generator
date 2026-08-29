# mutation-stamp: sha256=ec40cf4729948c48e802ba46735dec22943ae2fe2fa5549e02bab048532a108e
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-29T13:37:30.052886Z","feature_name":"Normative correspondence artifacts","feature_path":"features/correspondence_artifact.feature","background_hash":"78aceb8c7ed78f6df84f4589ce6da7176d0565b9385733fa516f4783ad40532f","implementation_hash":"sha256:08d8eff854b173d73b41b79858d18f671f1b37426e2022224ce4ae30fe0a85b5","scenarios":[]}
# acceptance-mutation-manifest-end

Feature: Normative correspondence artifacts
  Reconciliation artifacts preserve typed provenance and stable identities.

  Background:
    Given a valid typed correspondence authority is available
    And correspondence operations make no provider calls

  Scenario: reconciliation artifact round trips canonically
    Given a deterministic exact-ID proposal is prepared
    When correspondence proposals are produced
    And the proposal is reconciled with explicit confirmation
    And the reconciliation is serialized
    Then the reconciliation round-trips unchanged
