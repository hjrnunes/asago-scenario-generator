# mutation-stamp: sha256=2c5e6f7d2e83009fafc3109f78ef4dee491ee7a7ea0cb51542c7ff4f5373f6f1
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-23T12:21:25.881468Z","feature_name":"Taxonomy/risk HTML report rendering","feature_path":"features/taxonomy_report_rendering.feature","background_hash":"0dbc163f19739f08e8832540280b53894b88d0c11dca41acea7c8919b1a41523","implementation_hash":"unknown","scenarios":[{"index":2,"name":"Taxonomy report rendering 03 shows a placeholder for empty ID lists","scenario_hash":"ae630288719d572bba29f1f2d36ccbbb61944cae6489d24426b5af4f29d20435","mutation_count":6,"result":{"Total":6,"Killed":6,"Survived":0,"Errors":0},"tested_at":"2026-08-23T12:21:25.881468Z"},{"index":4,"name":"Taxonomy report rendering 05 truncates overlong attack pattern descriptions at 300 characters","scenario_hash":"c17e33ec80b3059c30f22be67415251861c885f9227f6aabdd0a8c3f67b8c19d","mutation_count":4,"result":{"Total":4,"Killed":4,"Survived":0,"Errors":0},"tested_at":"2026-08-23T12:21:25.881468Z"},{"index":8,"name":"Taxonomy report rendering 09 colors metric badges by the 90-percent and 70-percent thresholds","scenario_hash":"a2bd2984eee0d28088024f02d728a105789f1f050a4c474d88a4f1619ba27be3","mutation_count":12,"result":{"Total":12,"Killed":12,"Survived":0,"Errors":0},"tested_at":"2026-08-23T12:21:25.881468Z"},{"index":9,"name":"Taxonomy report rendering 10 colors inverted count badges green at zero and red above zero","scenario_hash":"04b4154827f6cd9d010b5c4d0c0dc13b96c22cbb641cc76ac8584bfc0c2df0ae","mutation_count":6,"result":{"Total":6,"Killed":6,"Survived":0,"Errors":0},"tested_at":"2026-08-23T12:21:25.881468Z"},{"index":10,"name":"Taxonomy report rendering 11 renders schema v1 scorecards with status-colored badges","scenario_hash":"129cc3a8efc2d470ee07a5f85ae29175826669c71bf0bd77909df47130ce2e22","mutation_count":9,"result":{"Total":9,"Killed":9,"Survived":0,"Errors":0},"tested_at":"2026-08-23T12:21:25.881468Z"},{"index":11,"name":"Taxonomy report rendering 12 renders the Scenario Seed block only when seed metadata is present and complete","scenario_hash":"012d49488a287af907a19a2f75157df2b0f1e7f143e3d3f1706c657e67cae3a6","mutation_count":6,"result":{"Total":6,"Killed":6,"Survived":0,"Errors":0},"tested_at":"2026-08-23T12:21:25.881468Z"}]}
# acceptance-mutation-manifest-end

Feature: Taxonomy/risk HTML report rendering
  The taxonomy-and-risk report renders a per-scenario provenance chain
  and the evaluation scorecard from an offline completed run. Provenance
  traces the risk card through OWASP LLM IDs and agentic threats to the
  selected attack pattern, attack goal, ATLAS classification, entry
  point, and zone sequence. The scorecard reports summary statistics,
  metric groups, colored badges, and quality outliers. Optional inputs
  degrade honestly: empty ID lists render a muted "none" placeholder,
  absent seed metadata is omitted, and a missing scorecard removes the
  section entirely.

  Background:
    Given an offline completed taxonomy-and-risk run fixture

  # Taxonomy report rendering 01 renders the full provenance chain with all inputs
  Scenario: Taxonomy report rendering 01 renders the full provenance chain with all inputs
    Given the run fixture contains scenario "scn-01"
    And scenario "scn-01" carries risk card "atlas-phishing" with risk name "Spear phishing", taxonomy "ibm-risk-atlas", and confidence 0.85
    And scenario "scn-01" lists OWASP LLM IDs "LLM01,LLM06" and agentic threats "T6,T11"
    And the threat surface entry for risk card "atlas-phishing" lists attack patterns "AP-T11-01,AP-T6-01" and ATLAS techniques "AML.T0015,AML.T0053"
    And scenario "scn-01" carries seed metadata with seed "AP-T6-01", attack pattern name "Prompt injection with hidden intent", description "A short attack pattern description.", threat "T6", threat name "Social engineering", and origin "LLM01"
    And the capability profile lists entry points "ze-query,ze-rag" and scenario "scn-01" selects "ze-rag"
    And scenario "scn-01" traverses zones "Z1,Z2"
    When the HTML report is generated
    Then the scenario card for "scn-01" contains a Provenance tab
    And the provenance chain shows the step labels "Risk Card", "OWASP LLM IDs", "Agentic Threats", "Attack Pattern", "Attack Goal", "Scenario classifications", "Entry Point", and "Zone Sequence" in order
    And the provenance chain shows risk card "atlas-phishing" with risk name "Spear phishing" and confidence value "0.85"
    And the provenance chain shows the OWASP LLM badges "LLM01,LLM06" and the agentic threat badges "T6,T11" in order
    And the provenance chain highlights seed "AP-T6-01" as the selected attack pattern
    And the provenance chain shows the ATLAS techniques "AML.T0015,AML.T0053" as unpinned classification candidates
    And the provenance chain highlights entry point "ze-rag" and shows zone crumbs "Z1,Z2" in order

  # Taxonomy report rendering 02 degrades the risk card step when no risk card exists
  Scenario: Taxonomy report rendering 02 degrades the risk card step when no risk card exists
    Given the run fixture contains scenario "scn-01" without a risk card
    And scenario "scn-01" lists OWASP LLM IDs "LLM01" and agentic threats "T6"
    When the HTML report is generated
    Then the scenario card for "scn-01" still contains a Provenance tab
    And the provenance chain shows an empty risk ID and risk name with confidence value "0.00"
    And the provenance chain shows no taxonomy badge in the risk card step

  # Taxonomy report rendering 03 shows a placeholder for empty ID lists
  Scenario Outline: Taxonomy report rendering 03 shows a placeholder for empty ID lists
    Given the run fixture contains scenario "scn-01"
    And scenario "scn-01" lists OWASP LLM IDs "LLM01" and agentic threats "T6" except the <empty_list> is empty
    When the HTML report is generated
    Then the provenance chain shows the placeholder "none" in the <empty_step> step
    And the provenance chain still shows the "<remaining_badge>" badge in the other step

    Examples:
      | empty_list      | empty_step      | remaining_badge |
      | OWASP LLM IDs   | OWASP LLM IDs   | T6              |
      | agentic threats | Agentic Threats | LLM01           |

  # Taxonomy report rendering 04 renders the provenance steps without seed metadata
  Scenario: Taxonomy report rendering 04 renders the provenance steps without seed metadata
    Given the run fixture contains scenario "scn-01" with no seed metadata but an attack goal and one traversed zone
    When the HTML report is generated
    Then the scenario card for "scn-01" still contains a Provenance tab
    And the provenance chain shows an empty seed ID, attack pattern name, and threat in the attack pattern step
    And the provenance chain shows no description in the attack pattern step
    And the provenance chain still shows the "Attack Goal", "Entry Point", and "Zone Sequence" steps

  # Taxonomy report rendering 05 truncates overlong attack pattern descriptions at 300 characters
  Scenario Outline: Taxonomy report rendering 05 truncates overlong attack pattern descriptions at 300 characters
    Given the run fixture contains scenario "scn-01"
    And the seed metadata description of scenario "scn-01" is <description_case>
    When the HTML report is generated
    Then the provenance chain shows the attack pattern description <rendering>

    Examples:
      | description_case                                                                 | rendering                                    |
      | a 400-character run-on string with no sentence break in the first 300 characters | truncated to 300 characters followed by "..." |
      | a 120-character description with a terminal period                               | in full                                       |

  # Taxonomy report rendering 06 renders the scorecard with every metric group when all metrics are present
  Scenario: Taxonomy report rendering 06 renders the scorecard with every metric group when all metrics are present
    Given the run fixture carries an evaluation scorecard with consistency, gherkin, grounding, technique-agreement, diversity, and plausibility metrics
    When the HTML report is generated
    Then the report contains an "Eval Scorecard" section
    And the scorecard summary shows scenario count 3 and feature file count 2
    And the scorecard shows the groups "Consistency", "Gherkin Quality", "Grounding", "Projected-step Mapping Agreement", "Diversity", and "Plausibility"
    And the scorecard shows the badge "Mean Technique Agreement: 0.92"

  # Taxonomy report rendering 07 shows a clean outliers panel when every metric is in range
  Scenario: Taxonomy report rendering 07 shows a clean outliers panel when every metric is in range
    Given the run fixture carries an evaluation scorecard whose consistency, agreement, diversity, and plausibility metrics are all in range
    When the HTML report is generated
    Then the scorecard shows the text "All scenarios pass quality checks"
    And the scorecard shows no "Quality Outliers" panel

  # Taxonomy report rendering 08 lists red-tier outliers before yellow-tier outliers
  Scenario: Taxonomy report rendering 08 lists red-tier outliers before yellow-tier outliers
    Given the run fixture carries an evaluation scorecard where scenario "scn-a" has zone alignment 0.65 and scenario "scn-b" has zone alignment 0.80
    And the same scorecard records 2 capability-complexity violations
    When the HTML report is generated
    Then the scorecard shows a "Quality Outliers" panel
    And the outlier rows list "(aggregate)" with metric "Capability Violations" and value "2"
    And the outlier rows list "scn-a" with metric "Zone Alignment" and value "0.65"
    And the outlier rows list "scn-b" with metric "Zone Alignment" and value "0.80"
    And the outlier rows appear in the order "(aggregate)", "scn-a", then "scn-b"

  # Taxonomy report rendering 09 colors metric badges by the 90-percent and 70-percent thresholds
  Scenario Outline: Taxonomy report rendering 09 colors metric badges by the 90-percent and 70-percent thresholds
    Given the run fixture carries an evaluation scorecard whose only consistency metric is the mean <mean_value>
    When the HTML report is generated
    Then the scorecard shows a <badge_color> badge with label "Mean" and value <display_value>

    Examples:
      | mean_value | badge_color | display_value |
      | 0.95       | green       | 0.95          |
      | 0.75       | yellow      | 0.75          |
      | 0.55       | red         | 0.55          |
      | 1.0        | green       | 1             |

  # Taxonomy report rendering 10 colors inverted count badges green at zero and red above zero
  Scenario Outline: Taxonomy report rendering 10 colors inverted count badges green at zero and red above zero
    Given the run fixture carries an evaluation scorecard whose only plausibility metric is <violation_count> capability-complexity violations
    When the HTML report is generated
    Then the scorecard shows a <badge_color> badge with label "Capability Violations" and value <display_value>

    Examples:
      | violation_count | badge_color | display_value |
      | 0               | green       | 0             |
      | 2               | red         | 2             |

  # Taxonomy report rendering 11 renders schema v1 scorecards with status-colored badges
  Scenario Outline: Taxonomy report rendering 11 renders schema v1 scorecards with status-colored badges
    Given the run fixture carries a schema v1 scorecard with one metric in status <status> under the <group> group
    When the HTML report is generated
    Then the report contains a "Versioned Eval Scorecard" section with the schema badge "Schema v1"
    And the scorecard shows the <group> group with the metric's status badge in <badge_color>

    Examples:
      | status         | group                  | badge_color |
      | pass           | Presence / Coverage    | green       |
      | fail           | Validity / Grounding   | red         |
      | not_applicable | Release Qualification | yellow      |

  # Taxonomy report rendering 12 renders the Scenario Seed block only when seed metadata is present and complete
  Scenario Outline: Taxonomy report rendering 12 renders the Scenario Seed block only when seed metadata is present and complete
    Given the run fixture contains scenario "scn-01" whose seed metadata is <metadata_case>
    When the HTML report is generated
    Then the report <rendering> a "Scenario Seed" section

    Examples:
      | metadata_case                                  | rendering       |
      | absent                                         | does not render |
      | present with attack pattern name and seed ID   | renders         |
      | present without attack pattern name or seed ID | does not render |

  # Taxonomy report rendering 13 shows the seed fields inside the Scenario Seed block
  Scenario: Taxonomy report rendering 13 shows the seed fields inside the Scenario Seed block
    Given the run fixture contains scenario "scn-01" with seed metadata carrying seed "AP-T6-01", attack pattern name "Prompt injection with hidden intent", description "A short attack pattern description.", threat "T6", threat name "Social engineering", and origin "LLM01"
    When the HTML report is generated
    Then the report contains a "Scenario Seed" section
    And the Scenario Seed section shows the attack pattern name "Prompt injection with hidden intent"
    And the Scenario Seed section shows the description "A short attack pattern description."
    And the Scenario Seed section shows threat "T6" with threat name "Social engineering"
    And the Scenario Seed section shows origin "LLM01" and seed "AP-T6-01"

  # Taxonomy report rendering 14 omits the scorecard section and sidebar link without scorecard data
  Scenario: Taxonomy report rendering 14 omits the scorecard section and sidebar link without scorecard data
    Given the run fixture carries no eval scorecard
    When the HTML report is generated
    Then the report contains no "Eval Scorecard" section
    And the report contains no scorecard sidebar link
