Feature: Post-SP3 STPA execution projection
  Stream B validates, aligns, and exports the deterministic STPA execution
  projection.  The projection is the structural bridge from causal factors
  and one UCA to executable temporal assertions and scenario steps.

  Background:
    Given the STPA execution projection models are importable
    And a control structure with RESP-1, PM-1-1, FB-1-1, and CA-1-1 is available
    And a WRONG_TIMING unsafe control action targets CA-1-1

  # STPA-PROJ-03-01
  Scenario: Valid projection traceability covers factors, assertions, and UCA
    Given causal factors include a process-model flaw for PM-1-1 and a feedback delay for FB-1-1
    When the candidate execution envelope is assembled with temporal assertions
    And STPA projection traceability is validated
    Then STPA projection traceability is valid
    And the traceability result has no violations
    And the projection candidate identifier is "EXEC:RESP-1:CA-1-1:WRONG_TIMING"
    And assertion sources are ordered "PM-1-1,FB-1-1"
    And factor scenario steps are ordered "PM-1-1,FB-1-1"
    And the final scenario step references control action "CA-1-1"
    And every temporal assertion has its canonical predicate and source provenance

  # STPA-PROJ-03-02
  Scenario Outline: Traceability rejects a broken factor-to-vector link
    Given causal factors include a process-model flaw for PM-1-1 and a feedback delay for FB-1-1
    When the candidate execution envelope is assembled with temporal assertions
    And the temporal projection is mutated by "<mutation>"
    And STPA projection traceability is validated
    Then STPA projection traceability is invalid
    And the traceability result contains violation code "<violation_code>"
    And the violation identifies the earliest affected projection element

    Examples:
      | mutation                                      | violation_code                  |
      | omitting the PM-1-1 assertion                 | omitted_causal_factor           |
      | reordering the PM-1-1 and FB-1-1 assertions   | reordered_causal_factor         |
      | changing TA-2 source to PM-1-1                | assertion_source_mismatch       |
      | changing S-2 source to PM-1-1                 | step_source_mismatch             |
      | changing TA-1 predicate to FEEDBACK_DELAYED  | assertion_predicate_mismatch     |
      | changing the final step source to CA-9-9      | uca_step_mismatch                |

  # STPA-PROJ-03-03
  Scenario: Traceability rejects a vector linked to another candidate
    Given causal factors include a process-model flaw for PM-1-1
    When the candidate execution envelope is assembled with temporal assertions
    And the temporal vector candidate identifier is changed to "EXEC:RESP-9:CA-1-1:WRONG_TIMING"
    And STPA projection traceability is validated
    Then STPA projection traceability is invalid
    And the traceability result contains violation code "candidate_identity_mismatch"
    And the violation identifies the temporal vector candidate identifier

  # STPA-PROJ-03-04
  Scenario: Empty causal factors remain an explicit empty projection
    Given no causal factors explain the unsafe control action
    When the candidate execution envelope is assembled with temporal assertions
    And STPA projection traceability is validated
    Then STPA projection traceability is valid
    And the temporal vector contains no assertions
    And the temporal vector contains no scenario steps
    And the traceability result has no invented causal-factor provenance

  # STPA-PROJ-03-05
  Scenario: Traceability validation is deterministic
    Given causal factors include a process-model flaw for PM-1-1 and a feedback delay for FB-1-1
    When the candidate execution envelope is assembled with temporal assertions
    And STPA projection traceability is validated twice
    Then both traceability results have the same validity
    And both traceability results have byte-identical canonical violations

  # STPA-PROJ-04-01
  Scenario: One validator-derived alignment table is rendered for every STPA Stage 6 call
    Given causal factors include a process-model flaw for PM-1-1 and a feedback delay for FB-1-1
    When the candidate execution envelope is assembled with temporal assertions
    And the STPA Stage 6 prompts are rendered from the validated projection
    Then every narrative, tree, and Gherkin Stage 6 prompt contains a projection alignment table
    And the table has columns "projection ID,source kind,source ID,assertion ID,assertion predicate,step ID,step kind,order,required reference"
    And the table has exactly one row for each temporal assertion and final UCA step
    And the table rows preserve causal-factor order and place the UCA row last
    And the table contains "PM-1-1,PROCESS_MODEL_FLAW,TA-1,MODEL_FLAWED,S-1"
    And the table contains "FB-1-1,FEEDBACK_DELAY,TA-2,FEEDBACK_DELAYED,S-2"
    And the table contains "CA-1-1,UNSAFE_CONTROL_ACTION,S-3"
    And the table contains candidate identifier "EXEC:RESP-1:CA-1-1:WRONG_TIMING"
    And the prompts identify projection IDs as semantic structural IDs rather than positional labels

  # STPA-PROJ-04-02
  Scenario: Narrative prompt constraints follow the validated temporal projection
    Given causal factors include a process-model flaw for PM-1-1 and a feedback delay for FB-1-1
    When the candidate execution envelope is assembled with temporal assertions
    And the STPA narrative prompts are rendered from the validated projection
    Then the narrative prompt requires PM-1-1 before FB-1-1 before CA-1-1
    And the narrative prompt requires the exact UCA type "WRONG_TIMING"
    And the narrative prompt forbids inventing a causal factor, assertion, or scenario step
    And the narrative prompt preserves the distinction between FB-1-1 as a logical feedback dependency and an inferred transport

  # STPA-PROJ-04-03
  Scenario: Attack-tree prompt constraints follow the validated temporal projection
    Given causal factors include a process-model flaw for PM-1-1 and an actuator anomaly for CA-1-1
    When the candidate execution envelope is assembled with temporal assertions
    And the STPA attack-tree prompts are rendered from the validated projection
    Then the attack-tree prompt requires root "Induce ICA WRONG_TIMING on CA-1-1"
    And the attack-tree prompt requires known structural references PM-1-1 and CA-1-1
    And the attack-tree prompt requires any temporal-factor leaf references to preserve projection order
    And the attack-tree prompt forbids an infrastructure or session mechanism without explicit attacker-accessible evidence

  # STPA-PROJ-04-04
  Scenario: Gherkin prompt constraints follow the validated temporal projection
    Given causal factors include a process-model flaw for PM-1-1 and a feedback delay for FB-1-1
    When the candidate execution envelope is assembled with temporal assertions
    And the STPA Gherkin prompts are rendered from the validated projection
    Then the Gherkin prompt requires a Given reference to PM-1-1
    And the Gherkin prompt requires the exact ICA type "WRONG_TIMING" and control action "CA-1-1" in the actual outcome
    And the Gherkin prompt forbids structural IDs not present in the validated projection or control structure
    And the Gherkin prompt retains independent valid Loss ID validation

  # STPA-PROJ-04-05
  Scenario: Alignment tables cannot drift from validator rules
    Given causal factors include a sensor anomaly for FB-1-1 and an actuator anomaly for CA-1-1
    When the candidate execution envelope is assembled with temporal assertions
    And the STPA alignment table is derived twice
    Then both alignment tables are byte-identical
    And each assertion row source and predicate equals the causal-factor validator mapping
    And each factor step row source and step kind equals the causal-factor validator mapping
    And the final row is the unsafe-control-action step for "CA-1-1"
    And no alignment row is hand-authored independently by a Stage 6 prompt

  # STPA-PROJ-05-01
  Scenario: Canonical JSON and YAML exports are standalone and equivalent
    Given causal factors include a process-model flaw for PM-1-1 and a feedback delay for FB-1-1
    When the candidate execution envelope is assembled with temporal assertions
    And the STPA execution projection is exported as canonical JSON and YAML
    Then both exports declare schema version "stpa-execution-projection-v1"
    And both exports identify candidate "EXEC:RESP-1:CA-1-1:WRONG_TIMING"
    And both exports identify UCA reference "RESP-1:CA-1-1:WRONG_TIMING"
    And parsing both exports with only standard JSON and YAML readers yields equivalent data
    And parsing either export does not require project imports

  # STPA-PROJ-05-02
  Scenario: Export preserves stable identifiers, order, and typed provenance
    Given causal factors include a process-model flaw for PM-1-1 and a feedback delay for FB-1-1
    When the candidate execution envelope is assembled with temporal assertions
    And the STPA execution projection is exported as canonical JSON
    Then the export contains assertion IDs "TA-1,TA-2" in order
    And the export contains step IDs "S-1,S-2,S-3" in order
    And assertion "TA-1" has typed provenance source kind "causal_factor" and source ID "PM-1-1"
    And step "S-2" has typed provenance source kind "causal_factor" and source ID "FB-1-1"
    And step "S-3" has typed provenance source kind "unsafe_control_action" and source ID "CA-1-1"
    And every exported structural reference is one of "RESP-1,PM-1-1,FB-1-1,CA-1-1"

  # STPA-PROJ-05-03
  Scenario: Canonical exports are byte-stable
    Given causal factors include a process-model flaw for PM-1-1 and a feedback delay for FB-1-1
    When the candidate execution envelope is assembled with temporal assertions
    And canonical JSON and YAML exports are produced twice
    Then the two JSON exports are byte-identical
    And the two YAML exports are byte-identical
    And JSON object keys use canonical ordering
    And YAML list ordering preserves assertions and steps without sorting by source text

  # STPA-PROJ-05-04
  Scenario: Export round-trip rejects forged identity and provenance
    Given causal factors include a process-model flaw for PM-1-1 and a feedback delay for FB-1-1
    When the candidate execution envelope is assembled with temporal assertions
    And the canonical JSON export is mutated by "<mutation>"
    And the exported projection is loaded and validated without project imports
    Then exported projection validation fails with "<error>"

    Examples:
      | mutation                                      | error                            |
      | changing candidate_id to another EXEC ID     | candidate_identity_mismatch     |
      | changing assertion TA-1 source_id             | assertion_source_mismatch       |
      | changing step S-3 source_id                   | uca_step_mismatch                |
      | changing provenance source_kind               | typed_provenance_mismatch       |
      | removing schema_version                       | schema_version_missing          |
