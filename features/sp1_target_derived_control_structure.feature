Feature: Phase 2 target-derived control structure
  With an observed execution target profile supplied and a capability profile
  that says the system has one controller, Stage 2 derives the control
  structure deterministically from the observed target with at most two
  model calls.  The target-blind derivation stays unchanged for every other
  case.

  Scenario: the structure is derived from the observed target
    Given an observed execution target profile for a single-controller system
    When the target-derived Stage 2 derivation runs against a mock provider
    Then the derived control structure has exactly one controller
    And the derived control structure has one action per observed tool plus a reply action
    And the derived control structure has no coordination links
    And every tool action records its exact observed operation binding
    And the target-derived sidecar pins the target profile and control structure digests

  Scenario: the derivation makes at most two model calls
    Given an observed execution target profile for a single-controller system
    When the target-derived Stage 2 derivation runs against a mock provider
    Then the derivation records exactly two model calls
    And no target-blind Stage 2 call step is recorded

  Scenario: conditional actions come from capability profile facts
    Given a capability profile declaring persistent memory and filesystem operations
    When the target-derived Stage 2 derivation runs with the declared capability facts
    Then the derived structure adds a memory_write action justified by persistent memory
    And the derived structure adds a file_output action justified by the filesystem subcode

  Scenario: the session identity comes from the observed target state
    Given a target-observations snapshot naming the authenticated customer
    When the target-derived Stage 2 derivation runs with the observed session state
    Then the session identity process model cites the observed authenticated customer

  Scenario: the relevance table applies the deterministic rules
    Given an observed execution target profile for a single-controller system
    When the target-derived Stage 2 derivation runs against a mock provider
    Then the reply action is relevant to every disclosure constraint
    And the escalation tool is named by the escalation constraint
    And the relevance artifact is pinned to the loss analysis and control structure

  Scenario: the target-blind path stays unchanged without a profile
    Given no execution target profile
    When the ordinary SP1 pipeline runs against a mock provider
    Then the manifest records no generation-mode field
    And the target-blind Stage 2 call steps are recorded
