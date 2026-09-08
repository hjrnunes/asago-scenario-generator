Feature: Phase 1 loss-analysis gates
  The persisted loss analysis must account for every supplied risk card and
  carry a hazard graph dense enough to distinguish scenarios.  Offline
  deterministic checks verify both properties and record their evidence.

  Scenario: every supplied risk card must be accounted for
    Given a persisted loss analysis that disposes one of two supplied risk cards
    When the deterministic risk-accounting check runs
    Then the check reports the undisposed card as unaccounted
    And the check reports the disposed card as cited

  Scenario: the five density checks flag an undifferentiated hazard graph
    Given a persisted loss analysis with gaps in its hazard graph
    When the deterministic hazard-graph density check runs
    Then the check reports each loss without a hazard
    And the check reports each constraint without a hazard
    And the check reports each hazard without a constraint
    And the check reports each constraint-hazard pair that shares no subject phrase
    And the check reports each behavior class that owns no hazard of its own
    And the check passes for the constraint-hazard pair that shares a subject phrase

  Scenario: a hazard with no constraint fails the density check and is named in the revision call
    Given a persisted loss analysis whose gap adds hazard H-2 without a constraint
    When the loss-analysis gate runs against a mock provider that covers that hazard
    Then the revision call received "hazard H-2 has no constraint" as a failed check
    And the gates artifact records the gate as passed after the revision

  Scenario: the subject rule never matches on generic vocabulary
    When the deterministic subject rule extracts phrases from constraint and hazard text
    Then texts sharing only generic actor and verb vocabulary produce no shared phrase
    And texts sharing a concrete noun phrase produce that shared phrase

  Scenario: a dense graph passes the gate without a revision call
    Given a persisted loss analysis that satisfies every gate check
    When the loss-analysis gate runs against a mock provider
    Then the gates artifact records the gate as passed with no revision
    And the gate makes no provider call
    And the gate returns the unchanged analysis

  Scenario: a revision that drops a prior record fails closed with evidence
    Given a persisted loss analysis that fails the density gate
    When the loss-analysis gate runs against a mock provider that drops a prior hazard
    Then the gate stops with the revision failure recorded as a stage error
    And the gates artifact records the attempted revision as not applied
    And the gates artifact retains the original failing checks

  Scenario: a revision that changes only a constraint's conditions records a warning
    Given a persisted loss analysis with conditional SC-2 that fails the density gate
    When the loss-analysis gate runs against a mock provider that changes those conditions
    Then the gate stops with the still-failing checks recorded as a stage error
    And the gates artifact records the changed conditions as a normalization warning
    And the gates artifact records the attempted revision as not applied

  Scenario: a revision that rewrites a constraint's rule onto new hazards records a warning
    Given a persisted loss analysis with conditional SC-2 that fails the density gate
    When the loss-analysis gate runs against a mock provider that rewrites that rule
    Then the gate stops with the rewritten rule recorded as a stage error
    And the gates artifact records the rewritten rule as a normalization warning
    And the gates artifact records the attempted revision as not applied

  Scenario: a revision that still fails the checks stops with the exact checks
    Given a persisted loss analysis that fails the density gate
    When the loss-analysis gate runs against a mock provider that changes nothing
    Then the gate stops with the still-failing checks recorded as a stage error
    And the gates artifact records the attempted revision as not applied
    And the gates artifact retains the original failing checks
