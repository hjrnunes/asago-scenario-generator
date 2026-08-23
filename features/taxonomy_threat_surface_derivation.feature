# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-23T04:28:23.492057Z","feature_name":"Taxonomy threat-surface derivation","feature_path":"features/taxonomy_threat_surface_derivation.feature","background_hash":"e8ad8418d2689dba0956477a8b3f95906bacb424431f103e4cb098212251aabb","implementation_hash":"unknown","scenarios":[{"index":0,"name":"Taxonomy threat-surface derivation 01 resolves the three-hop chain in first-seen order","scenario_hash":"877b0addf118711f8e12c4f96a889db2fbc95097c85bc51075414117ce4f5373","mutation_count":4,"result":{"Total":4,"Killed":4,"Survived":0,"Errors":0},"tested_at":"2026-08-23T04:28:23.492057Z"},{"index":5,"name":"Taxonomy threat-surface derivation 06 applies the KC6 gate to ATLAS techniques","scenario_hash":"f7a6d6009164d38a68e56af93ed559b35e4740d8c6218e44b485c37cad2b86d2","mutation_count":4,"result":{"Total":4,"Killed":4,"Survived":0,"Errors":0},"tested_at":"2026-08-23T04:28:23.492057Z"}]}
# acceptance-mutation-manifest-end

Feature: Taxonomy threat-surface derivation
  Threat-surface derivation walks each Risk Atlas card through its OWASP
  LLM Top 10 entries to in-scope agentic T-threats, then joins
  direct-path T-threats only when they share an ATLAS technique with the
  card's three-hop threats. Cards that reach no in-scope T-threat become
  governance-only entries.

  Background:
    Given the risk-extraction, SSSOM, cross-taxonomy, and capability-profile inputs are available

  # Taxonomy threat-surface derivation 01 resolves the three-hop chain in first-seen order
  Scenario Outline: Taxonomy threat-surface derivation 01 resolves the three-hop chain in first-seen order
    Given the SSSOM mapping links risk card "atlas-prompt-injection" to OWASP LLM entries "LLM01,LLM06"
    And the cross-taxonomy mapping links OWASP LLM entry "LLM01" to T-threats "T6,T11"
    And the cross-taxonomy mapping links OWASP LLM entry "LLM06" to T-threats "T2,T13"
    And the cross-taxonomy mapping links no ATLAS techniques from any T-threat
    And the capability profile gates T-threats "<scoped_t>" in scope
    When the threat surface is derived
    Then the surface contains 1 actionable entry and 0 governance-only entries
    And the actionable entry for risk card "atlas-prompt-injection" lists OWASP LLM IDs "LLM01,LLM06"
    And the actionable entry for risk card "atlas-prompt-injection" lists T-threats "<expected_t>" in first-seen order
    And the actionable entry for risk card "atlas-prompt-injection" lists no ATLAS techniques

    Examples:
      | scoped_t      | expected_t    |
      | T2,T6,T11,T13 | T6,T11,T2,T13 |
      | T6,T11        | T6,T11        |

  # Taxonomy threat-surface derivation 02 marks cards without an LLM mapping as governance-only
  Scenario: Taxonomy threat-surface derivation 02 marks cards without an LLM mapping as governance-only
    Given the risk-extraction file contains risk card "atlas-orphan-risk" with risk name "Orphaned risk signal"
    And the SSSOM mapping has no entry for risk card "atlas-orphan-risk"
    And the risk card "atlas-orphan-risk" carries causal-chain threat, vulnerability, consequence, and impact text
    When the threat surface is derived
    Then the surface contains 0 actionable entries and 1 governance-only entry
    And the governance-only entry references risk card "atlas-orphan-risk" with risk name "Orphaned risk signal"
    And the governance-only entry lists no OWASP LLM IDs, no T-threats, and no attack-pattern IDs
    And the governance-only entry retains the causal-chain text of its risk card

  # Taxonomy threat-surface derivation 03 keeps cards with only out-of-scope LLM mappings governance-only with their LLM IDs
  Scenario: Taxonomy threat-surface derivation 03 keeps cards with only out-of-scope LLM mappings governance-only with their LLM IDs
    Given the SSSOM mapping links risk card "atlas-prompt-injection" to OWASP LLM entries "LLM01"
    And the cross-taxonomy mapping links OWASP LLM entry "LLM01" to T-threats "T11"
    And the capability profile gates T-threats "T7,T9,T10" in scope
    When the threat surface is derived
    Then the surface contains 0 actionable entries and 1 governance-only entry
    And the governance-only entry for risk card "atlas-prompt-injection" lists OWASP LLM IDs "LLM01"
    And the governance-only entry lists no T-threats, no attack-pattern IDs, no ATLAS techniques, and no ASI IDs
    And the governance-only entry lists no direct-path T-threat

  # Taxonomy threat-surface derivation 04 joins direct-path T-threats only on shared ATLAS techniques
  Scenario Outline: Taxonomy threat-surface derivation 04 joins direct-path T-threats only on shared ATLAS techniques
    Given the SSSOM mapping links risk card "atlas-prompt-injection" to OWASP LLM entries "LLM06"
    And the cross-taxonomy mapping links OWASP LLM entry "LLM06" to T-threats "T2"
    And the cross-taxonomy mapping links T-threat "T2" to ATLAS techniques "AML.T0015,AML.T0053"
    And the cross-taxonomy mapping links direct-path T-threat "<direct_t>" to ATLAS techniques "<direct_atlas>"
    And the capability profile gates T-threats "<scoped_t>" in scope
    When the threat surface is derived
    Then the surface contains 1 actionable entry and 0 governance-only entries
    And the actionable entry for risk card "atlas-prompt-injection" lists T-threats "<expected_t>" in first-seen order
    And the actionable entry for risk card "atlas-prompt-injection" lists ATLAS techniques "<expected_atlas>" in first-seen order

    Examples:
      | direct_t | direct_atlas                    | scoped_t  | expected_t | expected_atlas             |
      | T7       | AML.T0054,AML.T0015,AML.T0053   | T2,T7,T8  | T2,T7      | AML.T0015,AML.T0053,AML.T0054 |
      | T8       | AML.T0056,AML.T0057             | T2,T8     | T2         | AML.T0015,AML.T0053        |

  # Taxonomy threat-surface derivation 05 unions ID lists without duplicates in first-seen order
  Scenario: Taxonomy threat-surface derivation 05 unions ID lists without duplicates in first-seen order
    Given the SSSOM mapping links risk card "atlas-memory-poisoning" to OWASP LLM entries "LLM04,LLM08"
    And the cross-taxonomy mapping links OWASP LLM entry "LLM04" to T-threats "T1,T12"
    And the cross-taxonomy mapping links OWASP LLM entry "LLM08" to T-threats "T1,T2"
    And the cross-taxonomy mapping links T-threats "T1,T12" to ATLAS techniques "AML.T0043,AML.T0031,AML.T0020"
    And the cross-taxonomy mapping links T-threat "T1" to ASI entry "ASI06" and T-threat "T12" to ASI entry "ASI07"
    And the capability profile keeps attack patterns "AP-T1-01,AP-T1-02" for T-threat "T1" and "AP-T12-01,AP-T1-01" for T-threat "T12"
    And the capability profile gates T-threats "T1,T12" in scope
    When the threat surface is derived
    Then the surface contains 1 actionable entry and 0 governance-only entries
    And the actionable entry for risk card "atlas-memory-poisoning" lists OWASP LLM IDs "LLM04,LLM08"
    And the actionable entry for risk card "atlas-memory-poisoning" lists T-threats "T1,T12" in first-seen order
    And the actionable entry for risk card "atlas-memory-poisoning" lists attack patterns "AP-T1-01,AP-T1-02,AP-T12-01" in first-seen order
    And the actionable entry for risk card "atlas-memory-poisoning" lists ATLAS techniques "AML.T0043,AML.T0031,AML.T0020" once each in first-seen order
    And the actionable entry for risk card "atlas-memory-poisoning" lists ASI entries "ASI06,ASI07" in first-seen order

  # Taxonomy threat-surface derivation 06 applies the KC6 gate to ATLAS techniques
  Scenario Outline: Taxonomy threat-surface derivation 06 applies the KC6 gate to ATLAS techniques
    Given the SSSOM mapping links risk card "atlas-prompt-injection" to OWASP LLM entries "LLM01"
    And the cross-taxonomy mapping links OWASP LLM entry "LLM01" to T-threats "T6"
    And the cross-taxonomy mapping links T-threat "T6" to ATLAS techniques "AML.T0054,AML.T0053"
    And the cross-taxonomy mapping links direct-path T-threats "T7,T15" to ATLAS techniques "AML.T0050"
    And the capability profile gates T-threat "T6" in scope with KC sub-codes "<kc_subcodes>"
    When the threat surface is derived
    Then the surface contains 1 actionable entry and 0 governance-only entries
    And the actionable entry for risk card "atlas-prompt-injection" lists ATLAS techniques "<expected_atlas>" in first-seen order

    Examples:
      | kc_subcodes | expected_atlas      |
      | KC1.1       | AML.T0054           |
      | KC1.1,KC6.4 | AML.T0054,AML.T0053 |

  # Taxonomy threat-surface derivation 07 returns empty surfaces for empty risk cards
  Scenario: Taxonomy threat-surface derivation 07 returns empty surfaces for empty risk cards
    Given the risk-extraction file contains zero risk cards
    When the threat surface is derived
    Then the surface contains 0 actionable entries and 0 governance-only entries
