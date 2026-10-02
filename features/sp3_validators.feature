Feature: SP3 Stage 7 — Validators
  Stage 7 runs two layers of validation. Stage-local validators check BDI
  grounding and vulnerability completeness at each stage boundary. End-to-end traceability validation checks
  the full provenance chain: provenance root → loss → hazard → constraint →
  responsibility → CA → ICA → scenario. Foreign-key constraints are enforced
  at every link.

  Background:
    Given the SP3 validators module is importable
    And a control structure with responsibility RESP-1, PM-1-1, CA-1-1, and FB-1-1
    And a loss analysis with loss L-1, hazard H-1, and security constraint SC-1
    And an enriched threat set with a structural threat for ICA slot RESP-1:CA-1-1:NOT_PROVIDED

  # SP3-VAL-01
  Scenario: SP3-VAL-01 BDI grounding validator passes when all IDs are valid
    Given a scenario with defender beliefs referencing PM-1-1, desires referencing RESP-1, intentions referencing CA-1-1
    When BDI grounding validation is performed against the control structure
    Then validation succeeds

  # SP3-VAL-02
  Scenario: SP3-VAL-02 BDI grounding validator fails on invalid PM reference
    Given a scenario with a defender belief referencing PM-99-1
    When BDI grounding validation is performed against the control structure
    Then validation fails with error containing pm_id

  # SP3-VAL-03
  Scenario: SP3-VAL-03 BDI grounding validator fails on invalid RESP reference
    Given a scenario with a defender desire referencing RESP-99
    When BDI grounding validation is performed against the control structure
    Then validation fails with error containing resp_id

  # SP3-VAL-04
  Scenario: SP3-VAL-04 BDI grounding validator fails on invalid CA reference
    Given a scenario with a defender intention referencing CA-99-1
    When BDI grounding validation is performed against the control structure
    Then validation fails with error containing ca_id

  # SP3-VAL-05
  Scenario: SP3-VAL-05 vulnerability completeness validator fails on empty vulnerability
    Given a scenario where defender belief PM-1-1 has an empty vulnerability annotation
    When vulnerability completeness validation is performed
    Then validation fails with error containing vulnerability

  # SP3-VAL-06
  Scenario: SP3-VAL-06 vulnerability completeness validator passes when all vulnerabilities are filled
    Given a scenario where every defender belief has a non-empty vulnerability annotation
    When vulnerability completeness validation is performed
    Then validation succeeds

  # SP3-VAL-12
  Scenario: SP3-VAL-12 traceability validation passes on complete unbroken chain
    Given a scenario tracing from loss L-1 through hazard H-1, constraint SC-1, responsibility RESP-1, CA-1-1, ICA RESP-1:CA-1-1:NOT_PROVIDED:1
    When end-to-end traceability validation is performed
    Then no traceability errors are returned

  # SP3-VAL-13
  Scenario: SP3-VAL-13 traceability validation fails on broken hazard link
    Given a scenario whose ICA references hazard H-99 which does not exist in the loss analysis
    When end-to-end traceability validation is performed
    Then a traceability error is returned for the broken hazard link

  # SP3-VAL-14
  Scenario: SP3-VAL-14 traceability validation fails on broken constraint link
    Given a scenario whose ICA references constraint SC-99 which does not exist
    When end-to-end traceability validation is performed
    Then a traceability error is returned for the broken constraint link

  # SP3-VAL-15
  Scenario: SP3-VAL-15 traceability validation fails on broken responsibility link
    Given a scenario with target_controller RESP-99 which does not exist in the control structure
    When end-to-end traceability validation is performed
    Then a traceability error is returned for the broken responsibility link

  # SP3-VAL-16
  Scenario: SP3-VAL-16 traceability validation fails on broken ICA-to-scenario link
    Given an enriched threat set with ICA RESP-1:CA-1-1:NOT_PROVIDED:1
    And a scenario referencing ica_id RESP-1:CA-1-1:NOT_PROVIDED:99 which does not exist
    When end-to-end traceability validation is performed
    Then a traceability error is returned for the broken ICA link

  # SP3-VAL-17
  Scenario: SP3-VAL-17 traceability validation checks provenance root is legal
    Given a scenario with provenance root risk_card
    When end-to-end traceability validation is performed
    Then the provenance root is accepted

  # SP3-VAL-18
  Scenario: SP3-VAL-18 traceability validation rejects illegal provenance root
    Given a scenario with provenance root unknown_source
    When end-to-end traceability validation is performed
    Then a traceability error is returned for the illegal provenance root

  # SP3-VAL-19
  Scenario: SP3-VAL-19 orphan detection finds control structure elements not referenced by any ICA
    Given a control structure with PM-1-2 not referenced by any ICA
    When orphan detection is performed
    Then PM-1-2 is listed as an orphan element

  # SP3-VAL-20
  Scenario: SP3-VAL-20 orphan detection finds ICAs not concretized into scenarios
    Given an enriched threat set with 5 structural threats and only 3 scenarios produced
    When orphan detection is performed
    Then 2 orphan ICAs are listed
