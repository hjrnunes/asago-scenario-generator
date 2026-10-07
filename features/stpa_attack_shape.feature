Feature: Attack shape on every adversarial scenario
  After Stage 5 compiles an adversarial scenario, the shape step asks the model
  one closed-vocabulary question about how the attack reaches the agent: the
  channel, the planned turns and, for an attack through content, the carrier.
  Code validates the reply and replaces any failure with a single direct
  request. A functional scenario gets no shape and no request. The published
  handoff is scenario-handoff-v4 and carries no attack text.

  Scenario: a valid shape reply is published on the handoff
    Given a shape run whose Stage 5 response declares adversary kind "malicious_customer"
    And the shape reply is a two-turn direct plan
    When the shape run publishes its scenarios
    Then the published handoff schema is "scenario-handoff-v4"
    And the published attack shape comes from "stage5_validated" with 2 planned turns
    And the shape step made 1 request

  Scenario: a failing shape request publishes the single-turn direct default
    Given a shape run whose Stage 5 response declares adversary kind "malicious_customer"
    And the shape request fails with a transport error
    When the shape run publishes its scenarios
    Then the published attack shape comes from "code_default" with 1 planned turns
    And the published attack shape records the downgrade "shape_call_failed"
    And the shape step made 1 request

  Scenario: a functional scenario publishes a null shape and makes no request
    Given a shape run whose Stage 5 response declares adversary kind "none"
    When the shape run publishes its scenarios
    Then the published handoff schema is "scenario-handoff-v4"
    And the published handoff carries a null attack shape
    And the shape step made 0 requests

  Scenario: a shape reply with free text is refused
    Given a shape run whose Stage 5 response declares adversary kind "malicious_customer"
    And the shape reply adds a free-text field
    When the shape run publishes its scenarios
    Then the published attack shape records the downgrade "shape_call_failed"

  Scenario: the shape prompt explains every field and keeps the forged channel off
    Given a shape prompt rendered for a malicious customer scenario
    Then the shape prompt explains each response field
    And the shape prompt does not offer the forged channel
