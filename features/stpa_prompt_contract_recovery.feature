Feature: Recover actionable STPA prompts and truthful candidate outcomes
  The normal public boundaries must recover the captured failure patterns
  without a live endpoint, invented system facts, or extra unbounded attempts.

  Scenario Outline: A malformed revision link is handled before merging
    Given a recovery revision provider in "<mode>" mode
    When the public revision boundary is exercised
    Then revision recovery uses <attempts> responses and retains the baseline
    And revision recovery reports no missing-mechanism crash

    Examples:
      | mode    | attempts |
      | correct | 2        |
      | exhaust | 2        |

  Scenario Outline: ICA inputs expose the timing facts required by their instructions
    Given a recovery control action with temporality "<temporality>"
    When the public synthesis ICA prompt is rendered
    Then its supplied timing value is "<temporality>"
    And its causal example contains no placeholder loss consequence

    Examples:
      | temporality |
      | instantaneous |
      | continuous    |

  Scenario: SDK response parsing cannot erase provider receipt
    When a recovery SDK response has malformed structured content
    Then recovery call evidence retains the body and usage with response received

  Scenario: Candidate failures are not diagnostic-message counts
    When recovery synthesis has one published, two failed and one skipped candidates with four diagnostics
    Then recovery synthesis reports generated 1, failed 2, requested 4, attempted 3, skipped 1, functional_test 0 and diagnostics 4
