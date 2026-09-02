Feature: Obligation-aware synthesis run
  The product run joins the typed Phase 1 obligation ledger to STPA. STPA is
  the only scenario-generation authority.

  Background:
    Given a deterministic synthesis fixture is available

  Scenario: An applied revision rechecks the complete applicable universe once
    Given a deterministic synthesis revision is applied
    When the product run executes
    Then Phase 1 planning runs before baseline STPA
    And the synthesis recheck covers every applicable obligation exactly once
    And the synthesis writes the nine normative sidecars atomically
    And the synthesis report includes non-blocking Phase 2 verification
    And applicable and non-applicable obligations are accounted separately

  Scenario: A rejected revision retains upstream gaps without a second pass
    Given a deterministic synthesis revision is rejected
    When the product run executes
    Then Phase 1 planning runs before baseline STPA
    And the synthesis performs no recheck after a rejected revision
    And the synthesis writes the nine normative sidecars atomically

  Scenario: A clean run does not perform a revision or second pass
    Given a deterministic synthesis revision is not required
    When the product run executes
    Then the clean synthesis has no revision or recheck
    And applicable and non-applicable obligations are accounted separately

  Scenario: Scenario failure retains structural accounting
    Given a deterministic synthesis revision is not required
    And scenario generation fails after ICA
    Then applicable and non-applicable obligations are accounted separately

  Scenario Outline: STPA retains each typed route outcome as analysis evidence
    Given a deterministic synthesis route disposition "<disposition>"
    When the product run executes
    Then the synthesis returns a typed "<disposition>" route
    And the route evidence remains separate from taxonomy coverage

    Examples:
      | disposition             |
      | targeted                |
      | proposed_not_applicable |
      | upstream_gap            |
      | unresolved              |

  Scenario: An invalid revision retains the baseline and its upstream gap
    Given a deterministic synthesis revision is invalid
    When the product run executes
    Then the synthesis retains the baseline after the revision failure
    And the synthesis performs no recheck after the invalid revision
    And the invalid revision remains a typed technical diagnostic

  Scenario: A local provider failure remains visible without erasing accounting
    Given a deterministic synthesis provider fails during consideration
    When the product run executes
    Then the provider failure is retained as local unresolved evidence
    And the synthesis still writes accounting and manifest sidecars

  Scenario: The public CLI has one normal scenario-generation command
    Given a deterministic synthesis revision is not required
    Then run is the normal command and retired generation commands are absent
