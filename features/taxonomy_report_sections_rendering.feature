# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-24T23:53:08.999595Z","feature_name":"Taxonomy/risk HTML report section rendering","feature_path":"features/taxonomy_report_sections_rendering.feature","background_hash":"0dbc163f19739f08e8832540280b53894b88d0c11dca41acea7c8919b1a41523","implementation_hash":"unknown","scenarios":[]}
# acceptance-mutation-manifest-end

Feature: Taxonomy/risk HTML report section rendering
  The taxonomy-and-risk report renders the remaining section builders
  that still live in report/template.py: the capability profile, threat
  surface, coverage analysis, threat-technique matrix, actor profile
  distribution, scenario cards (priority signals, actor profile, attack
  tree, generation inputs, behavior spec, ATLAS techniques, attack
  complexity), the run summary, pipeline call logs, and raw-data syntax
  highlighting. Sections built from structured inputs degrade honestly:
  empty inventories and ID lists show muted placeholders, an absent
  manifest removes the run summary, and a missing attack tree renders no
  node markup. All fixtures are offline; no LLM endpoint is involved.

  Background:
    Given an offline completed taxonomy-and-risk run fixture

  # Taxonomy report section rendering 01 renders the capability profile with zones, flags, entry points, inventories, evidence, and KC sub-codes
  Scenario: Taxonomy report section rendering 01 renders the capability profile with zones, flags, entry points, inventories, evidence, and KC sub-codes
    Given the capability profile declares active zones "input,tool_execution"
    And the capability profile declares the flag "memory" on and the flag "multi-agent" off with confidence "high"
    And the capability profile lists entry point "ze-query" with direction "input" and entry point "ze-rag" with direction "bidirectional"
    And the capability profile lists the tool "Web search" with tool id "tool-web"
    And the capability profile lists the integration "OAuth IdP" with integration id "int-oidc"
    And the capability profile records entry point completeness "confirmed" with evidence "use-case.md"
    And the capability profile records tool inventory completeness "partial" with no evidence
    And the capability profile declares the KC sub-code "KC6.1.1"
    When the HTML report is generated
    Then the report contains a "Capability Profile" section with the badge "Schneider 5-Zone"
    And the capability profile shows an active zone chip "Input Surfaces" and an inactive zone chip "Planning & Reasoning"
    And the capability profile shows the flag "Memory" on, the flag "Multi-Agent" off, and confidence "High"
    And the capability profile shows entry point "ze-query" with input direction and entry point "ze-rag" with bidirectional direction
    And the capability profile shows tool "Web search" with tool id "tool-web" and integration "OAuth IdP" with integration id "int-oidc"
    And the capability profile shows entry point completeness "Confirmed" with the evidence "use-case.md"
    And the capability profile shows tool inventory completeness "Partial" and the message "No evidence sources recorded"
    And the capability profile shows the KC sub-code badge "KC6.1.1"

  # Taxonomy report section rendering 02 degrades the capability profile when inventories and evidence are empty
  Scenario: Taxonomy report section rendering 02 degrades the capability profile when inventories and evidence are empty
    Given the capability profile declares active zone "input" with no tool inventory, no external integrations, and no evidence
    When the HTML report is generated
    Then the capability profile shows the message "No tools inventoried"
    And the capability profile shows the message "No external integrations inventoried"
    And the capability profile shows the message "No evidence sources recorded"
    And the capability profile renders no entry point row

  # Taxonomy report section rendering 03 renders actionable and governance-only threat surface entries distinctly
  Scenario: Taxonomy report section rendering 03 renders actionable and governance-only threat surface entries distinctly
    Given the threat surface lists the actionable entry for risk card "atlas-phishing" with risk name "Spear phishing", confidence 0.85, OWASP LLM IDs "LLM01", agentic threats "T6", and attack patterns "AP-T6-01"
    And the threat surface lists the governance-only entry for risk card "atlas-copyright" with risk name "Copyright compliance" and no mappings
    When the HTML report is generated
    Then the report contains a "Threat Surface" section with the badge "1 actionable / 1 governance"
    And the threat surface entry for "atlas-phishing" shows the status badge "ACT" and the row values "Spear phishing", "0.85", "LLM01", "T6", and "AP-T6-01"
    And the threat surface entry for "atlas-copyright" shows the status badge "GOV"
    And the governance-only entry shows the placeholder "-" for the OWASP LLM IDs, agentic threats, and attack patterns
    And the threat surface flow diagram node for "atlas-phishing" carries the tip "atlas-phishing: Spear phishing"

  # Taxonomy report section rendering 04 degrades an empty threat surface to placeholders
  Scenario: Taxonomy report section rendering 04 degrades an empty threat surface to placeholders
    Given the threat surface lists no actionable entries and no governance-only entries
    When the HTML report is generated
    Then the report contains a "Threat Surface" section with the badge "0 actionable / 0 governance"
    And the threat surface shows the message "No actionable entries to visualize."

  # Taxonomy report section rendering 05 shows the threat surface outcomes column with scenario priority chips
  Scenario: Taxonomy report section rendering 05 shows the threat surface outcomes column with scenario priority chips
    Given the run fixture contains scenario "scn-a"
    And scenario "scn-a" lists OWASP LLM IDs "LLM01" and agentic threats "T6"
    And scenario "scn-a" carries priority composite 0.85
    And the threat surface lists the actionable entry for risk card "atlas-phishing" with agentic threats "T6"
    When the HTML report is generated
    Then the threat surface table shows the "Outcomes" column
    And the threat surface entry for "atlas-phishing" shows the outcomes "1 scenarios" with the chip "1 high"

  # Taxonomy report section rendering 06 renders the coverage analysis with every target covered and the sidebar link
  Scenario: Taxonomy report section rendering 06 renders the coverage analysis with every target covered and the sidebar link
    Given the coverage data confirms a complete inventory with no uncovered entry points, zones, threats, or attack patterns
    And the coverage universe records the evidence reference "operator-confirmation.md"
    When the HTML report is generated
    Then the report contains a "Coverage Analysis" section with the badge "Full Coverage"
    And the coverage cards "Entry Points", "Active Zones", "In-Scope Threats", and "Attack Patterns" each show the status "Covered"
    And the coverage section shows the messages "All confirmed entry points have scenario coverage.", "All active zones are traversed by scenarios.", "All in-scope threats have scenario coverage.", and "All in-scope attack patterns have scenario coverage."
    And the coverage universe card shows inventory completeness "Confirmed Complete" with the evidence "operator-confirmation.md"
    And the sidebar shows a link to the "Coverage Analysis" section

  # Taxonomy report section rendering 07 renders coverage gaps with counts, tiers, and attributions
  Scenario: Taxonomy report section rendering 07 renders coverage gaps with counts, tiers, and attributions
    Given the coverage data reports 3 uncovered entry points, 1 uncovered zone, and 2 uncovered threats
    And the coverage data records no uncovered attack patterns
    And the coverage data attributes the uncovered entry point "ze-query" to "deterministic_rule_rejection"
    And the coverage data records a coverage universe with 2 feasible targets and 1 excluded target
    When the HTML report is generated
    Then the report contains a "Coverage Analysis" section with the badge "6 gaps"
    And the coverage card "Entry Points" shows the status "3 gaps" and the uncovered entry point "ze-query" with the attribution "rejected by deterministic rules"
    And the coverage card "Active Zones" shows the status "1 gap"
    And the coverage card "In-Scope Threats" shows the status "2 gaps"
    And the coverage section shows the "Feasible Targets (2)" and "Excluded Targets (1)" cards

  # Taxonomy report section rendering 08 renders the threat-technique matrix and scenario roster
  Scenario: Taxonomy report section rendering 08 renders the threat-technique matrix and scenario roster
    Given the run fixture contains scenario "scn-a" and scenario "scn-b"
    And scenario "scn-a" lists OWASP LLM IDs "LLM01" and agentic threats "T6"
    And scenario "scn-b" lists OWASP LLM IDs "LLM02" and agentic threats "T11"
    And scenario "scn-a" carries the attack pattern seed "AP-T6-01" with ATLAS techniques "AML.T0015"
    And scenario "scn-b" carries the attack pattern seed "AP-T11-01" with ATLAS techniques "AML.T0015,AML.T0040"
    And scenario "scn-a" pins the technique "AML.T0015" with the name "Phishing"
    And scenario "scn-b" pins the technique "AML.T0040" with the name "LLM Data Leakage"
    And scenario "scn-a" has actor type "cybercriminal" with capability level "advanced"
    And scenario "scn-b" has actor type "nation-state" with capability level "expert"
    When the HTML report is generated
    Then the report contains a "Threat–Technique Matrix" section with the badge "2/17 threats", "2 techniques", and "2 scenarios"
    And the matrix shows for threat "T6" a count of 1 for technique "AML.T0015" linking to scenario "scn-a"
    And the matrix shows for threat "T11" a count of 1 for technique "AML.T0040" linking to scenario "scn-b"
    And the roster row for "scn-a" shows threat "T6", attack pattern "AP-T6-01", technique "AML.T0015", actor type "Cybercriminal", and capability "Advanced"
    And the roster row for "scn-b" shows threat "T11", attack pattern "AP-T11-01", technique "AML.T0040", actor type "Nation State", and capability "Expert"

  # Taxonomy report section rendering 09 degrades the threat-technique matrix when scenarios carry no techniques
  Scenario: Taxonomy report section rendering 09 degrades the threat-technique matrix when scenarios carry no techniques
    Given the run fixture contains scenario "scn-a"
    And scenario "scn-a" lists OWASP LLM IDs "LLM01" and agentic threats "T6"
    And scenario "scn-a" carries the attack pattern seed "AP-T6-01" with no ATLAS techniques
    When the HTML report is generated
    Then the report contains a "Threat–Technique Matrix" section with the badge "1/17 threats", "0 techniques", and "1 scenarios"
    And the matrix shows no technique column headers
    And the roster row for "scn-a" shows the attack pattern "AP-T6-01" with no technique value

  # Taxonomy report section rendering 10 renders actor profile distribution with a monotone warning and goal categories
  Scenario: Taxonomy report section rendering 10 renders actor profile distribution with a monotone warning and goal categories
    Given the run fixture contains scenario "scn-a", "scn-b", and "scn-c"
    And each scenario has actor type "cybercriminal" with capability level "advanced" and goal category "integrity"
    When the HTML report is generated
    Then the report contains an "Actor Profile Distribution" section with the badge "1 type"
    And the distribution shows the actor type "Cybercriminal" with the count 3 and 100 percent
    And the distribution shows the warning "Low actor diversity: 100% of scenarios use the Cybercriminal actor type."
    And the distribution shows the goal category "Integrity" with the count 3

  # Taxonomy report section rendering 11 renders the priority signals grid with all six signal values
  Scenario: Taxonomy report section rendering 11 renders the priority signals grid with all six signal values
    Given the run fixture contains scenario "scn-a"
    And scenario "scn-a" carries priority composite 0.72 with the signals "realized", "critical", "high", "medium", "explicit", and "elevated"
    When the HTML report is generated
    Then the scenario card for "scn-a" shows a priority signals grid
    And the priority signals grid shows the labels "Technique Maturity", "Risk Impact", "Risk Likelihood", "Attack Complexity", "Architecture Match", and "Structural Exposure"
    And the priority signals grid shows the value "Realized" for "Technique Maturity" and "Critical" for "Risk Impact"

  # Taxonomy report section rendering 12 omits the priority signals grid when the scenario has no signals
  Scenario: Taxonomy report section rendering 12 omits the priority signals grid when the scenario has no signals
    Given the run fixture contains scenario "scn-a" with no priority signals
    When the HTML report is generated
    Then the scenario card for "scn-a" shows no priority signals grid

  # Taxonomy report section rendering 13 renders the actor profile block with BDI lists and access provenance
  Scenario: Taxonomy report section rendering 13 renders the actor profile block with BDI lists and access provenance
    Given the run fixture contains scenario "scn-a"
    And scenario "scn-a" has an actor profile of type "malicious-insider" with capability "advanced" and goal "Sell stolen data"
    And the actor profile records the beliefs "Data is not monitored", the desires "Exfiltrate the billing database", the intentions "Move laterally to the data store", and the resources "Incident response creds"
    And the actor profile records access with ingress mode "network", initial entry point ID "ze-query", and influence source "helpdesk"
    When the HTML report is generated
    Then the scenario card for "scn-a" shows the actor type chip "Malicious Insider", the capability chip "Advanced", and the goal chip "Sell Stolen Data"
    And the actor profile block shows the belief "Data is not monitored", the desire "Exfiltrate the billing database", the intention "Move laterally to the data store", and the resource "Incident response creds"
    And the actor profile block shows the access provenance with ingress "network" and entry point "ze-query"

  # Taxonomy report section rendering 14 omits the actor profile block when the scenario has no actor profile
  Scenario: Taxonomy report section rendering 14 omits the actor profile block when the scenario has no actor profile
    Given the run fixture contains scenario "scn-b" with no actor profile
    When the HTML report is generated
    Then the scenario card for "scn-b" shows no actor profile block

  # Taxonomy report section rendering 15 renders attack tree nodes with and without children and omits an absent tree
  Scenario Outline: Taxonomy report section rendering 15 renders attack tree nodes with and without children and omits an absent tree
    Given the run fixture contains scenario "scn-a"
    And scenario "scn-a" carries an attack tree with <tree_case>
    When the HTML report is generated
    Then the Attack Tree tab of scenario "scn-a" <tree_rendering>

    Examples:
      | tree_case                                                                                                            | tree_rendering                                    |
      | an OR root labeled "Gain access" with two leaf children carrying the techniques "AML.T0015" and "AML.T0040"         | renders an OR gate summary containing two leaf nodes with both technique badges |
      | an AND root labeled "Open safe" with two leaf children carrying the techniques "AML.T0015" and "AML.T0040"         | renders an AND gate summary containing two leaf nodes with both technique badges |
      | a single leaf node labeled "Exfiltrate data" with no children                                                       | renders exactly one leaf node and no gate summary |
      | no root                                                                                                              | renders no tree node markup                       |

  # Taxonomy report section rendering 16 renders unresolved attack tree resource IDs honestly
  Scenario: Taxonomy report section rendering 16 renders unresolved attack tree resource IDs honestly
    Given the run fixture contains scenario "scn-a"
    And scenario "scn-a" carries an attack tree with a leaf node labeled "Run the tool" whose action invokes tool "tool-code" with integration "int-oidc" and a leaf node labeled "Enter the portal" whose action performs initial ingress through entry point "ze-gone" in zone "input"
    When the HTML report is generated
    Then the Attack Tree tab shows the leaf node meta "Tool: Unresolved" with code "tool-code"
    And the leaf node meta shows "Integration: Unresolved" with code "int-oidc"
    And the leaf node meta shows "Entry Point: Unresolved" with code "ze-gone"

  # Taxonomy report section rendering 17 renders the scenarios dashboard and a card per scenario
  Scenario: Taxonomy report section rendering 17 renders the scenarios dashboard and a card per scenario
    Given the run fixture contains scenario "scn-a" and scenario "scn-b"
    And scenario "scn-a" carries priority composite 0.85 with narrative title "Phishing the support desk"
    And scenario "scn-b" carries priority composite 0.35 with narrative title "Exfiltrate via RAG"
    When the HTML report is generated
    Then the Scenarios section shows the dashboard stats "2" In Report, "1" High Priority, "0" Medium Priority, and "1" Low Priority
    And the Scenarios section shows "0" Coverage Gaps
    And the report contains a scenario card for "scn-a" with the title "Phishing the support desk"
    And the report contains a scenario card for "scn-b" with the title "Exfiltrate via RAG"

  # Taxonomy report section rendering 18 renders a scenario card for a scenario missing optional fields
  Scenario: Taxonomy report section rendering 18 renders a scenario card for a scenario missing optional fields
    Given the run fixture contains scenario "scn-min" with only its scenario ID
    When the HTML report is generated
    Then the report contains a scenario card for "scn-min"
    And the card shows the priority badge "LOW" with the score "0.00"
    And the card shows all nine tab labels "Provenance", "Generation Inputs", "Actor Profile", "ATLAS Techniques", "Narrative", "Attack Tree", "Behavior Spec", "Priority Signals", and "LLM Calls"
    And the card shows no zone crumbs

  # Taxonomy report section rendering 19 renders a placeholder when the fixture has no scenarios
  Scenario: Taxonomy report section rendering 19 renders a placeholder when the fixture has no scenarios
    Given the run fixture contains no scenarios
    When the HTML report is generated
    Then the report contains a Scenarios section showing "No scenarios generated."
    And the report contains no "Threat–Technique Matrix" section
    And the report contains no "Actor Profile Distribution" section
    And the sidebar shows a link to the "Capability Profile" section
    And the sidebar shows a link to the "Threat Surface" section
    And the sidebar shows a link to the "Scenarios" section
    And the sidebar shows a link to the "Raw Data" section
    And the sidebar shows a link to the "Glossary & Methodology" section

  # Taxonomy report section rendering 20 renders the run summary funnel, outcomes, and configuration
  Scenario: Taxonomy report section rendering 20 renders the run summary funnel, outcomes, and configuration
    Given the run fixture contains scenario "scn-a"
    And the run manifest records seeds generated 12, candidates expanded 10 with 6 submitted and 3 accepted, 4 scenarios generated, and 1 failed
    And the run manifest records model "gemma-3-27b" with temperature 0.7 and timestamps "2026-08-24T10:00:00" to "2026-08-24T10:05:30"
    When the HTML report is generated
    Then the report contains a "Run Summary" section
    And the funnel shows "12" Seeds Generated, "10" Candidates Expanded, "3" Candidates Accepted, "4" Scenarios Generated, and "1" In Report
    And the run summary shows "1" Failed, "3" Rejected, and the rejection rate "30.0%"
    And the run summary shows the duration "5m 30s"
    And the run summary shows model "gemma-3-27b", temperature "0.7", start "2026-08-24T10:00:00", and end "2026-08-24T10:05:30"

  # Taxonomy report section rendering 21 omits the run summary when no manifest is available
  Scenario: Taxonomy report section rendering 21 omits the run summary when no manifest is available
    Given the run fixture contains no run manifest
    When the HTML report is generated
    Then the report contains no "Run Summary" section
    And the sidebar shows no link to the "Run Summary" section

  # Taxonomy report section rendering 22 shows honest absence in the run summary when fields are missing
  Scenario: Taxonomy report section rendering 22 shows honest absence in the run summary when fields are missing
    Given the run manifest records zero candidates expanded and no timestamps and no model
    When the HTML report is generated
    Then the report contains a "Run Summary" section
    And the run summary shows the rejection rate "N/A"
    And the run summary shows model "unknown", temperature "N/A", start "N/A", and end "N/A"

  # Taxonomy report section rendering 23 highlights raw YAML and Gherkin content in the Raw Data section
  Scenario: Taxonomy report section rendering 23 highlights raw YAML and Gherkin content in the Raw Data section
    Given the run fixture carries raw files including a YAML file and a Gherkin file
    When the HTML report is generated
    Then the report contains a "Raw Data" section with the badge "2 files"
    And the YAML panel shows a highlighted comment, key "completeness", number value 3, boolean value true, and null value
    And the YAML panel renders the quoted string "confirmed" without a highlight class
    And the Gherkin panel shows a highlighted comment, tag "smoke", and the keywords "Feature:", "Background:", "Given", "When", "And", and "But"

  # Taxonomy report section rendering 24 renders the generation inputs block with values and em dashes for gaps
  Scenario: Taxonomy report section rendering 24 renders the generation inputs block with values and em dashes for gaps
    Given the run fixture contains scenario "scn-a"
    And scenario "scn-a" carries seed metadata with the attack pattern name "Prompt injection", threat "T6" with name "Social engineering", and the taxonomy chain ATLAS techniques "AML.T0015"
    And scenario "scn-a" has a narrative with title "Phish the desk" and no summary
    When the HTML report is generated
    Then the Generation Inputs tab of scenario "scn-a" shows the call headers "Call 0: Actor Profile" and "Call 3: Behavior Spec"
    And the Generation Inputs tab shows the row "Attack pattern" with the value "Prompt injection"
    And the Generation Inputs tab shows the row "Threat" with the value "T6 — Social engineering"
    And the Generation Inputs tab shows the row "ATLAS techniques" with the value "AML.T0015"
    And the Generation Inputs tab shows the row "Narrative summary" with the em dash "—"

  # Taxonomy report section rendering 25 renders the behavior spec and degrades without a feature file
  Scenario: Taxonomy report section rendering 25 renders the behavior spec and degrades without a feature file
    Given the run fixture contains scenario "scn-a" with a behavior feature file containing the steps "Given a precondition", "When the event occurs", and "Then the outcome holds"
    And the run fixture contains scenario "scn-b" with no behavior feature file
    When the HTML report is generated
    Then the Behavior Spec tab of scenario "scn-a" shows the step keywords "Given", "When", and "Then" with the texts "a precondition", "the event occurs", and "the outcome holds"
    And the Behavior Spec tab of scenario "scn-b" shows the message "No behavior specification available."

  # Taxonomy report section rendering 26 renders scenario and projected-step ATLAS techniques and the none placeholder
  Scenario: Taxonomy report section rendering 26 renders scenario and projected-step ATLAS techniques and the none placeholder
    Given the run fixture contains scenario "scn-a"
    And scenario "scn-a" lists ATLAS techniques "AML.T0015" in its taxonomy chain
    And scenario "scn-a" records technique scope evidence with scenario classifications "AML.T0015" and no projected-step mappings
    When the HTML report is generated
    Then the ATLAS Techniques tab of scenario "scn-a" shows the heading "Scenario classifications" with the badge "AML.T0015"
    And the ATLAS Techniques tab shows the heading "Projected-step mappings" with the placeholder "none"

  # Taxonomy report section rendering 27 renders the attack complexity assessment with bounds and reasons
  Scenario: Taxonomy report section rendering 27 renders the attack complexity assessment with bounds and reasons
    Given the run fixture contains scenario "scn-a"
    And scenario "scn-a" carries an attack complexity assessment at rule version "3" with candidate lower bound "advanced", final required level "expert", and the reason "R-7" of detail "requires chaining three tools" citing evidence "projection:R7"
    When the HTML report is generated
    Then the Actor Profile tab of scenario "scn-a" shows the heading "ATTACK COMPLEXITY (RULE V3):"
    And the attack complexity block shows "Candidate lower bound" as "Advanced" and "Final required level" as "Expert"
    And the attack complexity block shows the reason line "R-7 → expert: requires chaining three tools [projection:R7]"

  # Taxonomy report section rendering 28 omits the attack complexity block when the scenario has no assessment
  Scenario: Taxonomy report section rendering 28 omits the attack complexity block when the scenario has no assessment
    Given the run fixture contains scenario "scn-b" with no attack complexity assessment
    When the HTML report is generated
    Then the Actor Profile tab of scenario "scn-b" shows no attack complexity block

  # Taxonomy report section rendering 29 renders pipeline call logs with usage totals and semantic status
  Scenario: Taxonomy report section rendering 29 renders pipeline call logs with usage totals and semantic status
    Given the pipeline call log contains the accepted "candidate_filter" call with 100 prompt tokens and the rejected "capability_profile" call with 50 prompt tokens
    When the HTML report is generated
    Then the report contains a "Pipeline LLM Calls" section
    And the pipeline calls summary shows "2 call(s)" with "150 prompt tokens", "60 completion tokens", and "40ms total"
    And the pipeline calls summary shows the semantic status "Candidate Filter semantic draft: Accepted provider semantics"
    And the pipeline calls summary shows the semantic status "Capability Profile semantic draft: Rejected: invalid"
    And the pipeline calls summary shows the semantic warning "raw JSON payload"

  # Taxonomy report section rendering 30 renders count badges when an entry maps to many threats and patterns
  Scenario: Taxonomy report section rendering 30 renders count badges when an entry maps to many threats and patterns
    Given the threat surface lists the actionable entry for risk card "atlas-phishing" with risk name "Spear phishing", confidence 0.85, OWASP LLM IDs "LLM01", agentic threats "T6,T7,T8", and attack patterns "AP-T6-01,AP-T7-01,AP-T8-01"
    When the HTML report is generated
    Then the report contains a "Threat Surface" section with the badge "1 actionable / 0 governance"
    And the threat surface entry for "atlas-phishing" shows the count badge "3 threats"
    And the threat surface entry for "atlas-phishing" shows the count badge "3 patterns"

  # Taxonomy report section rendering 31 renders the behavior spec headers, tags, docstrings, And steps, and zone badges
  Scenario: Taxonomy report section rendering 31 renders the behavior spec headers, tags, docstrings, And steps, and zone badges
    Given the run fixture contains scenario "scn-a" with a behavior feature file containing the tag "smoke", the section "Feature" titled "Phish suite", the section "Scenario" titled "Phish the desk", the "And" step "escalate privileges", the "Given" step "access through (Zone input)", the "But" step "hold the session", a continuation line "the platform times out", and the docstring "requires a compromised credential"
    When the HTML report is generated
    Then the Behavior Spec tab of scenario "scn-a" renders the keyword "Feature:" with the text "Phish suite"
    And the Behavior Spec tab of scenario "scn-a" renders the keyword "Scenario:" with the text "Phish the desk"
    And the Behavior Spec tab shows the step "And" with the text "escalate privileges"
    And the Behavior Spec tab shows the step "Given" with the text "access through (Zone input)" and the zone badge "Input Surfaces"
    And the Behavior Spec tab shows the step "But" with the text "hold the session"
    And the Behavior Spec tab shows the continuation line "the platform times out"
    And the Behavior Spec tab shows the docstring "requires a compromised credential"
    And the Behavior Spec tab does not render the tag "smoke"

  # Taxonomy report section rendering 32 renders per-scenario LLM call entries with usage and failure markers
  Scenario: Taxonomy report section rendering 32 renders per-scenario LLM call entries with usage and failure markers
    Given the run fixture contains scenario "scn-a"
    And scenario "scn-a" records the call "actor_profile" with 100 prompt tokens, 40 completion tokens, duration 250ms, the system prompt "Assess the profile", the user prompt "Profile the capability", and success
    And scenario "scn-a" records the call "behavior_spec" with 30 prompt tokens, 10 completion tokens, duration 80ms, the system prompt "Generate the feature", the user prompt "Write the behavior", failing with the error "timeout"
    When the HTML report is generated
    Then the LLM Calls tab of scenario "scn-a" shows the entry "Call 0: Actor Profile (100 prompt / 40 completion tokens, 250ms)"
    And the LLM Calls tab of scenario "scn-a" shows the entry "Call 1: Behavior Spec (30 prompt / 10 completion tokens, 80ms) FAILED: timeout"
    And the LLM Calls tab of scenario "scn-a" renders the system prompt "Assess the profile" and the user prompt "Profile the capability"

  # Taxonomy report section rendering 33 renders the categorized coverage summary and plan with a not-confirmed universe
  Scenario: Taxonomy report section rendering 33 renders the categorized coverage summary and plan with a not-confirmed universe
    Given the coverage data records no uncovered entry points, zones, threats, or attack patterns with an inventory completeness not confirmed
    And the coverage data records a summary with the covered feasible target "AP-T6-01", a selection limitation for entry point "ze-query" with reason "selection_limitation", detail "candidate queue saturated", and candidate "cand-42", and a policy exclusion for entry point "ze-license" with reason "out_of_scope"
    And the coverage data records a coverage plan targeting entry point "ze-query" with primary candidate "cand-42", state "planned", and ordered choices "cand-42,cand-7"
    When the HTML report is generated
    Then the report contains a "Coverage Analysis" section with the badge "Known Targets Covered"
    And the coverage section shows the messages "All identified feasible entry points have scenario coverage; inventory completeness is not confirmed.", "All active zones are traversed by scenarios.", "All in-scope threats have scenario coverage.", and "All in-scope attack patterns have scenario coverage."
    And the coverage section shows the "Covered Feasible Targets" card containing "AP-T6-01"
    And the coverage section shows the "Selection Limitations" card with the entry "ze-query", the reason "cap overflow (coverage preserved)", the detail "candidate queue saturated", and the candidate "cand-42"
    And the coverage section shows the "Policy Exclusions" card with the entry "ze-license" and the reason "out of scope"
    And the coverage section shows a "Coverage Plan" row for "ze-query" with primary candidate "cand-42" and state "planned"
    And the coverage universe card shows inventory completeness "Not Applicable (Inferred Partial)"
    And the coverage universe card shows the message "No operator-confirmed evidence"

  # Taxonomy report section rendering 34 renders the run summary outcome counts and coverage gaps card
  Scenario: Taxonomy report section rendering 34 renders the run summary outcome counts and coverage gaps card
    Given the run fixture contains scenario "scn-a" and scenario "scn-b"
    And scenario "scn-a" carries priority composite 0.85
    And scenario "scn-b" carries priority composite 0.35
    And the run manifest records seeds generated 12, candidates expanded 10 with 6 submitted and 3 accepted, 4 scenarios generated, and 1 failed
    And the coverage data reports 1 uncovered entry point, 1 uncovered zone, and 2 uncovered threats
    And the coverage data records no uncovered attack patterns
    When the HTML report is generated
    Then the report contains a "Run Summary" section
    And the run summary outcome summary shows "1" High Priority, "0" Medium Priority, and "1" Low Priority
    And the run summary shows the coverage card "4" Coverage Gaps

  # Taxonomy report section rendering 35 renders the signal decomposition, threat-by-zone matrix, entry point distribution, and filter chips
  Scenario: Taxonomy report section rendering 35 renders the signal decomposition, threat-by-zone matrix, entry point distribution, and filter chips
    Given the run fixture contains scenario "scn-a" and scenario "scn-b"
    And scenario "scn-a" lists OWASP LLM IDs "LLM01" and agentic threats "T6"
    And scenario "scn-b" lists OWASP LLM IDs "LLM02" and agentic threats "T6"
    And scenario "scn-a" traverses zones "input,tool_execution"
    And scenario "scn-b" traverses zones "input"
    And scenario "scn-a" carries a narrative entry point "ze-query"
    And scenario "scn-b" carries a narrative entry point "ze-rag"
    And scenario "scn-a" carries priority composite 0.72 with the signals "realized", "critical", "high", "medium", "explicit", and "elevated"
    And scenario "scn-b" carries priority composite 0.35 with the signals "realized", "critical", "high", "medium", "explicit", and "elevated"
    And the run manifest records seeds generated 12, candidates expanded 10 with 6 submitted and 3 accepted, 4 scenarios generated, and 1 failed
    When the HTML report is generated
    Then the Scenarios section shows the "Priority Signal Decomposition" chart with the segment "Risk Impact: critical"
    And the Scenarios section shows the "Threat x Zone Coverage" matrix with the cell "T6" x "Input Surfaces" counting "2"
    And the Scenarios section shows the "Entry Point Distribution" listing "ze-query" with count 1 and "ze-rag" with count 1
    And the Scenarios section shows the filter chips "Threats" containing "T6", "Zones" containing "Input Surfaces" and "Tool Execution", and "Priority" containing "High", "Medium", and "Low"
    And the Scenarios section shows the stat "2" In Report with the sublabel "of 4 generated"
    And the scenario card for "scn-a" shows the zone crumbs "input" and "tool_execution"

  # Taxonomy report section rendering 36 renders actor diversity without a monotone warning and plural goal categories
  Scenario: Taxonomy report section rendering 36 renders actor diversity without a monotone warning and plural goal categories
    Given the run fixture contains scenario "scn-a", "scn-b", and "scn-c"
    And scenario "scn-a" has actor type "cybercriminal" with capability level "advanced" and goal category "integrity"
    And scenario "scn-b" has actor type "nation-state" with capability level "expert" and goal category "privacy"
    And scenario "scn-c" has actor type "hacktivist" with capability level "intermediate" and goal category "availability"
    When the HTML report is generated
    Then the report contains an "Actor Profile Distribution" section with the badge "3 types"
    And the distribution shows the actor type "Cybercriminal" with the count 1 and 33 percent
    And the distribution shows no low-diversity warning
    And the distribution shows the goal category "Integrity" with the count 1
    And the distribution shows the "Goal Category Distribution" block with the badge "3 categories"

  # Taxonomy report section rendering 37 renders the roster technique fallback when no technique is pinned
  Scenario: Taxonomy report section rendering 37 renders the roster technique fallback when no technique is pinned
    Given the run fixture contains scenario "scn-a"
    And scenario "scn-a" lists OWASP LLM IDs "LLM01" and agentic threats "T6"
    And scenario "scn-a" carries the attack pattern seed "AP-T6-01" with ATLAS techniques "AML.T0015,AML.T0040"
    And scenario "scn-a" has actor type "cybercriminal" with capability level "advanced"
    When the HTML report is generated
    Then the report contains a "Threat–Technique Matrix" section with the badge "1/17 threats", "2 techniques", and "1 scenarios"
    And the matrix shows technique column headers for "AML.T0015" and "AML.T0040"
    And the matrix shows for threat "T6" a count of 1 for technique "AML.T0015" linking to scenario "scn-a"
    And the roster row for "scn-a" shows threat "T6", attack pattern "AP-T6-01", technique "AML.T0015, AML.T0040", actor type "Cybercriminal", and capability "Advanced"

  # Taxonomy report section rendering 38 renders the remaining categorized coverage summary cards
  Scenario: Taxonomy report section rendering 38 renders the remaining categorized coverage summary cards
    Given the coverage data records no uncovered entry points, zones, threats, or attack patterns with an inventory completeness not confirmed
    And the coverage data records a summary with a structural gap for entry point "ze-query" with reason "projection_limitation", a runtime generation gap for entry point "ze-rag" with reason "generation_exhaustion", a quarantine admission failure for entry point "ze-scan" with reason "admission_failure", and a projection limitation for entry point "ze-parse" with reason "projection_limitation"
    When the HTML report is generated
    Then the report contains a "Coverage Analysis" section with the badge "Known Targets Covered"
    And the coverage section shows the "Structural / Projection Gaps" card containing "ze-query"
    And the coverage section shows the "Runtime Generation Gaps" card containing "ze-rag"
    And the coverage section shows the "Quarantine / Admission Failures" card containing "ze-scan"
    And the coverage section shows the "Projection Limitations" card containing "ze-parse"

  # Taxonomy report section rendering 39 renders nonzero scenario coverage gaps and empty threat-by-zone cells
  Scenario: Taxonomy report section rendering 39 renders nonzero scenario coverage gaps and empty threat-by-zone cells
    Given the run fixture contains scenario "scn-a" and scenario "scn-b"
    And scenario "scn-a" lists OWASP LLM IDs "LLM01" and agentic threats "T6"
    And scenario "scn-b" lists OWASP LLM IDs "LLM02" and agentic threats "T11"
    And scenario "scn-a" traverses zones "input"
    And scenario "scn-b" traverses zones "tool_execution"
    When the HTML report is generated
    Then the Scenarios section shows "2" Coverage Gaps
    And the Scenarios section shows the "Threat x Zone Coverage" matrix with the cell "T6" x "Input Surfaces" counting "1"
    And the Scenarios section shows the "Threat x Zone Coverage" matrix with the empty cell "T11" x "Input Surfaces"

  # Taxonomy report section rendering 40 renders usage warnings and unavailable-metrics summaries for partial telemetry
  Scenario: Taxonomy report section rendering 40 renders usage warnings and unavailable-metrics summaries for partial telemetry
    Given the pipeline call log contains the accepted "candidate_filter" call with 100 prompt tokens, the rejected "capability_profile" call with 50 prompt tokens, and a "behavior" call with no duration telemetry
    When the HTML report is generated
    Then the report contains a "Pipeline LLM Calls" section
    And the pipeline calls summary shows "3 call(s)" with "150 prompt tokens", "60 completion tokens", and "40ms total"
    And the pipeline calls summary shows the unavailable-metrics warning for call "behavior"
    And the pipeline calls summary shows the entry "Call 2: behavior (prompt_tokens=0, completion_tokens=0, duration_ms=unavailable)"
