# mutation-stamp: sha256=da5195ff4ec0f4022482ae39a2f4562877705d8e1b9757ff3f178a9e09151f4b
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-10T14:37:50.487109Z","feature_name":"Stage 6 Gherkin Loss/Hazard ID validation (gddi)","feature_path":"features/stage6_gddi_loss_id_validation.feature","background_hash":"782bf772d63a3b62343ddd97f68318f39df15d28ee873c9f53111b59ecc1719c","implementation_hash":"unknown","scenarios":[{"index":0,"name":"GDDI-01 user prompt includes valid Loss and Hazard IDs","scenario_hash":"c48e1e67f00a0505a2ef093ae47b59f63f89a97446d7a8f605562742b73678c9","mutation_count":10,"result":{"Total":10,"Killed":10,"Survived":0,"Errors":0},"tested_at":"2026-08-10T14:37:50.487109Z"},{"index":4,"name":"GDDI-05 validator catches hallucinated Loss or Hazard IDs","scenario_hash":"e655832d9ae98d0db66f4fc65fc2ac5f46d009e8a9e9bb2f1ca7937687c79c1c","mutation_count":4,"result":{"Total":4,"Killed":4,"Survived":0,"Errors":0},"tested_at":"2026-08-10T14:37:50.487109Z"}]}
# acceptance-mutation-manifest-end

Feature: Stage 6 Gherkin Loss/Hazard ID validation (gddi)
  Scenario Gherkin must reference only valid Loss (L-*) and Hazard (H-*) IDs.
  A validator checks all L-* and H-* references in the Gherkin text against
  the loss analysis and reports any hallucinated IDs.

  Background:
    Given the SP3 validators module is importable
    And a ScenarioSpec with defender BDI for scenario SCN-001
    And a security constraint SC-1 related to hazard H-1
    And a loss analysis with losses L-1, L-2, L-3 and hazards H-1, H-2

  # GDDI-05
  Scenario Outline: GDDI-05 validator catches hallucinated Loss or Hazard IDs
    Given a Gherkin text referencing <hallucinated_id> which is not in the loss analysis
    When Loss/Hazard ID validation is performed against the loss analysis
    Then validation fails with error containing <hallucinated_id>

    Examples:
      | hallucinated_id |
      | L-99            |
      | L-100           |
      | H-99            |
      | H-100           |

  # GDDI-06
  Scenario: GDDI-06 validator catches multiple hallucinated IDs simultaneously
    Given a Gherkin text referencing L-99 and H-88 which are not in the loss analysis
    When Loss/Hazard ID validation is performed against the loss analysis
    Then validation fails with error containing L-99
    And validation fails with error containing H-88

  # GDDI-07
  Scenario: GDDI-07 validator passes when all L-* and H-* references are valid
    Given a Gherkin text referencing L-1 and H-1 which are in the loss analysis
    When Loss/Hazard ID validation is performed against the loss analysis
    Then validation succeeds

  # GDDI-08
  Scenario: GDDI-08 validator passes when Gherkin has no L-* or H-* references
    Given a Gherkin text with no L-* or H-* references
    When Loss/Hazard ID validation is performed against the loss analysis
    Then validation succeeds

  # GDDI-10
  Scenario: GDDI-10 Loss/Hazard ID validation runs during Stage 7 envelope validation
    Given a ScenarioEnvelope with Gherkin referencing hallucinated Hazard ID H-99
    When Stage 7 envelope validation is performed
    Then validation fails with error containing H-99
