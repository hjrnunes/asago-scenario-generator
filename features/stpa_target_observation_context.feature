Feature: Target observations inform scenario details without changing the systemic baseline
  Captured target facts are a separately pinned input to Stage 5.
  Quotation establishes source presence, not policy truth or enforcement.

  Scenario: Explain target evidence without exposing capture bookkeeping
    Given a dispatch scenario with target observation mode "quoted"
    When Stage 5 renders the target observation companion
    Then the dispatch prompt explains the observations without their digest or source query

  Scenario: Reject observations captured for a different target before generation
    Given a dispatch scenario with target observation mode "quoted"
    When the dispatch observations are paired with a different target profile
    Then the product input rejects the target observation mismatch
