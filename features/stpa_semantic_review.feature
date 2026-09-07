Feature: Grounded constraint ownership and observable outcomes
  The systemic review fixes ownership and observation labels before target realization.
  Comparison values need supplied evidence, not merely a compatible JSON type.

  Scenario: The coordination provider is asked for the complete required review
    Given a semantic-review fixture with constraint decision "SC-1" and effect "agent_message"
    When the coordination call requests its systemic semantic review
    Then its provider schema rejects an omitted or incomplete semantic review

  Scenario Outline: Reconcile the action owner without changing the draft
    Given a semantic-review fixture with constraint decision "<constraints>" and effect "<effect>"
    When the complete systemic semantic review is applied
    Then the semantic-review result retains "<constraints>" and "<effect>" without changing its draft

    Examples:
      | constraints | effect        |
      | SC-1        | agent_message |
      | none        | unknown       |

  Scenario: Narrow a response-data rule using an explicitly allowed function
    Given a disclosure semantic-review fixture with quoted allowed function "Authenticated members may retrieve their own financial details."
    When the complete disclosure semantic review is applied
    Then the disclosure review preserves loss lineage and identities while correcting response ownership

  Scenario Outline: Disclosure revisions require exact source evidence
    Given a disclosure semantic-review fixture with source evidence "<evidence>"
    When the disclosure semantic review is attempted
    Then the disclosure semantic review is rejected for "<reason>"

    Examples:
      | evidence       | reason    |
      | near_quote     | quotation |
      | missing_source | source    |

  Scenario Outline: Preserve grounded comparisons and expose missing reference values
    Given a semantic-review comparison with value evidence "<evidence>"
    When the comparison value is grounded against supplied rules
    Then its semantic-review value disposition is "<disposition>"

    Examples:
      | evidence           | disposition   |
      | quoted_reference   | literal       |
      | absent             | parameterized |
      | semantic_boolean   | literal       |

  Scenario Outline: A hazard match cannot override an action or category mismatch
    Given independent ICA checks for action "<action>", category "<category>" and harm "<harm>"
    When the ICA provider result is compiled without another judgement call
    Then the compiled ICA verdict is "<verdict>" with exactly one provider call

    Examples:
      | action           | category       | harm                  | verdict               |
      | performed_unsafe | INCORRECT      | supported             | supported             |
      | different_action | NOT_PROVIDED   | supported             | contradictory         |
      | absent           | INCORRECT      | supported             | contradictory         |
      | performed_unsafe | INCORRECT      | insufficient_evidence | insufficient_evidence |
      | undetermined     | INCORRECT      | contradictory         | contradictory         |
      | absent           | NOT_PROVIDED   | supported             | supported             |
      | absent           | NOT_PROVIDED   | contradictory         | contradictory         |
      | absent           | NOT_PROVIDED   | insufficient_evidence | insufficient_evidence |
      | wrong_timing     | WRONG_TIMING   | supported             | supported             |
      | wrong_duration   | WRONG_DURATION | supported             | supported             |
