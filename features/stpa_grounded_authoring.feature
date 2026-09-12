Feature: Phase 4 grounded authoring in target-derived mode
  With an observed execution target profile and paired target observations,
  one grounded authoring model call per (constraint, action) candidate
  replaces ICA enumeration, ICA verification and correction, and Stage 5 BDI
  generation.  Deterministic code owns validation, the deviation category,
  identifiers, lineage, the oracle templates, and contract assembly.  The
  target-blind path is unchanged.

  Scenario: the authoring call validates its scenarios deterministically
    Given a target-derived structure with one relevant constraint-action candidate
    And a mock provider returning one valid draft and one draft naming an unobserved tool
    When the grounded authoring call runs for the candidate
    Then exactly one model call is recorded for the candidate
    And the valid scenario is accepted with the synthesized deviation category
    And the invalid scenario is rejected with a typed reason and no repair call

  Scenario: the oracle templates render deterministic text and fail closed
    Given the committed oracle template table
    When the oracle text renders for every supported kind
    Then each kind renders one deterministic sentence from its validated values
    And an unknown oracle kind fails closed

  Scenario: the synthesized enumeration keeps the exact slot identities
    Given one accepted authored scenario for the refund action
    When the ICA enumeration synthesizes from the accepted scenarios
    Then the accepted scenario occupies the process_refund INCORRECT slot
    And every other slot in the deterministic universe stays typed-unresolved

  Scenario: assembly produces a projection-valid scenario without a Stage 5 BDI call
    Given one accepted tool_argument authored scenario
    When the deterministic assembly builds the contextual scenario spec
    Then the unsafe condition pins the exact argument and expected value
    And the adversary reaches the target via the user message
    And the v2 execution projection validates offline with a tool_call action kind

  Scenario: the system prompt stays inside its bounded budget
    Given the committed authoring prompt templates
    When the authoring system prompt renders
    Then the rendered system prompt is at most 3000 characters
    And the prompt schema names only the four supported oracle kinds

  Scenario: omission triggers cite an exact user source and stay conditional
    Given a synthetic reviewed handoff obligation and its bound action
    When a user trigger is cited with its exact prepared turn
    Then the omission draft is accepted with a conditional semantic proposition
    And the assembled spec retains the exact trigger evidence
    And the accepted source does not claim that the obligation is applicable
    And the prepared stimulus contains user turns only

  Scenario: omission trigger evidence covers state, observation, and persistence
    Given a synthetic reviewed handoff obligation and its bound action
    When exact state and observation trigger sources are validated
    Then each exact source citation is accepted
    And the trigger evidence survives authored-record persistence
    And a conversation citation uses its exact one-based turn identity

  Scenario: omission trigger evidence rejects missing and fabricated sources
    Given a synthetic reviewed handoff obligation and its bound action
    When malformed, absent, foreign, ambiguous, and fabricated trigger evidence is validated
    Then every invalid omission draft has a typed trigger-evidence rejection

  Scenario: omission trigger evidence cannot replace a reviewed binding
    Given a synthetic reviewed handoff obligation and its bound action
    When valid source evidence is supplied without the reviewed action binding
    Then the omission draft remains held for an unreviewed binding
    And an unknown binding does not bypass the reviewed-binding hold

  Scenario: non-omission authoring keeps its existing validation path
    Given a synthetic reviewed handoff obligation and its bound action
    When a tool argument draft has no omission trigger evidence
    Then the non-omission draft is accepted without trigger evidence
