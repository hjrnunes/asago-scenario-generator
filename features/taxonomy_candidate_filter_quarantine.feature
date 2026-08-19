Feature: Taxonomy candidate-filter seed quarantine
  Candidate-filter responses are reconciled independently per seed. An
  invalid seed response is retried once, then quarantined without allowing
  any unrecognized identity to enter projection or stopping other seeds.

  Background:
    Given taxonomy generation has independent seeds "AP-T1-01" and "AP-T2-01"
    And each seed submits its exact candidate IDs to the candidate filter

  # Taxonomy candidate-filter seed quarantine 01 accepts a corrected retry
  Scenario: Taxonomy candidate-filter seed quarantine 01 accepts a corrected retry
    Given the first filter response for seed "AP-T1-01" contains unknown candidate ID "cand:v2:ffffffffffffffffffffffffffffffff"
    And its retry contains exactly the submitted candidate IDs
    When candidate filtering finishes
    Then seed "AP-T1-01" continues with only its submitted accepted candidate IDs
    And seed "AP-T1-01" is not quarantined
    And the filter made 2 attempts for seed "AP-T1-01"

  # Taxonomy candidate-filter seed quarantine 02 quarantines only an irreconcilable seed
  Scenario: Taxonomy candidate-filter seed quarantine 02 quarantines only an irreconcilable seed
    Given both filter responses for seed "AP-T1-01" contain unknown candidate ID "cand:v2:ffffffffffffffffffffffffffffffff"
    And the filter response for seed "AP-T2-01" contains exactly the submitted candidate IDs
    When taxonomy generation finishes
    Then seed "AP-T1-01" is quarantined after 2 filter attempts
    And no candidate from seed "AP-T1-01" reaches projection
    And seed "AP-T2-01" continues through projection and finalization
    And candidate ID "cand:v2:ffffffffffffffffffffffffffffffff" is not admitted
    And the run is not failed by the quarantined seed

  # Taxonomy candidate-filter seed quarantine 03 records exact reconciliation evidence
  Scenario: Taxonomy candidate-filter seed quarantine 03 records exact reconciliation evidence
    Given seed "AP-T1-01" submits candidate IDs "cand:v2:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,cand:v2:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    And its final filter response contains candidate IDs "cand:v2:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,cand:v2:ffffffffffffffffffffffffffffffff"
    When seed "AP-T1-01" is quarantined
    Then reconciliation evidence records expected IDs "cand:v2:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,cand:v2:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" and received IDs "cand:v2:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,cand:v2:ffffffffffffffffffffffffffffffff"
    And reconciliation evidence identifies missing IDs "cand:v2:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" and unknown IDs "cand:v2:ffffffffffffffffffffffffffffffff"
    And the final user summary records seed "AP-T1-01", expected IDs "cand:v2:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,cand:v2:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", and received IDs "cand:v2:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,cand:v2:ffffffffffffffffffffffffffffffff"
