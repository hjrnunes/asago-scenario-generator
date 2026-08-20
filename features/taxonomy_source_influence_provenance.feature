Feature: Taxonomy source-influence provenance
  Taxonomy scenarios preserve typed provenance from source-influence
  requirements through projected attack-tree leaves and narrative steps.
  Qualification is deterministic and fails closed when a source, mitigation,
  capability constraint, projected step, or generated artifact is orphaned or
  unreferenced.

  Background:
    Given taxonomy source-influence qualification uses deterministic offline inputs

  # Taxonomy source-influence provenance 01 records complete typed provenance
  Scenario: Taxonomy source-influence provenance 01 records complete typed provenance
    Given a source-influence projection fixture with projected step "attacker.deliver"
    And the fixture declares threat source "threat:T12", mitigation "mitigation:M12", and capability constraint "constraint:KCX-MAGENT"
    And projected leaf "n1.1" realizes projected step "attacker.deliver"
    And narrative step "1" realizes projected step "attacker.deliver"
    And both artifacts link to threat source "threat:T12", mitigation "mitigation:M12", and capability constraint "constraint:KCX-MAGENT"
    When source-influence provenance is qualified
    Then qualification passes
    And the scenario envelope metadata contains a typed source-influence provenance block
    And projected leaf "n1.1" is linked to threat source "threat:T12"
    And projected leaf "n1.1" is linked to mitigation "mitigation:M12"
    And projected leaf "n1.1" is linked to capability constraint "constraint:KCX-MAGENT"
    And narrative step "1" is linked to threat source "threat:T12"
    And narrative step "1" is linked to mitigation "mitigation:M12"
    And narrative step "1" is linked to capability constraint "constraint:KCX-MAGENT"

  # Taxonomy source-influence provenance 02 computes complete coverage metrics
  Scenario: Taxonomy source-influence provenance 02 computes complete coverage metrics
    Given a source-influence projection fixture with projected steps "attacker.observe,attacker.deliver"
    And the fixture declares threat sources "threat:T12,threat:T13", mitigations "mitigation:M12,mitigation:M13", and capability constraints "constraint:KCX-MAGENT,constraint:KCX-VSTORE"
    And projected leaves "n1.1,n1.2" realize projected steps "attacker.observe,attacker.deliver"
    And narrative steps "1,2" realize projected steps "attacker.observe,attacker.deliver"
    And every artifact link names its corresponding threat source, mitigation, and capability constraint
    When source-influence provenance is qualified
    Then qualification passes
    And metric "projected_leaf_coverage" has numerator 2 and denominator 2
    And metric "narrative_step_coverage" has numerator 2 and denominator 2
    And metric "source_reference_coverage" has numerator 6 and denominator 6
    And metric "orphaned_source_count" is 0
    And metric "unreferenced_artifact_count" is 0
    And source-influence qualification status is "pass"

  # Taxonomy source-influence provenance 03 permits shared typed source records
  Scenario: Taxonomy source-influence provenance 03 permits shared typed source records
    Given a source-influence projection fixture with projected steps "attacker.observe,attacker.deliver"
    And the fixture declares threat source "threat:T12", mitigation "mitigation:M12", and capability constraint "constraint:KCX-MAGENT"
    And projected leaves "n1.1,n1.2" realize projected steps "attacker.observe,attacker.deliver"
    And narrative steps "1,2" realize projected steps "attacker.observe,attacker.deliver"
    And every artifact link names threat source "threat:T12", mitigation "mitigation:M12", and capability constraint "constraint:KCX-MAGENT"
    When source-influence provenance is qualified
    Then qualification passes
    And each declared source record is stored once
    And every projected leaf link resolves to the shared typed source records
    And every narrative step link resolves to the shared typed source records
    And metric "source_reference_coverage" has numerator 3 and denominator 3

  # Taxonomy source-influence provenance 04 requires every source type
  Scenario Outline: Taxonomy source-influence provenance 04 requires every source type
    Given a source-influence projection fixture with projected step "attacker.deliver"
    And the fixture declares threat source "threat:T12", mitigation "mitigation:M12", and capability constraint "constraint:KCX-MAGENT"
    And projected leaf "n1.1" realizes projected step "attacker.deliver"
    And narrative step "1" realizes projected step "attacker.deliver"
    And the artifact provenance omits source type "<source_type>"
    When source-influence provenance is qualified
    Then qualification fails with violation code "missing_source_provenance"
    And the violation identifies source type "<source_type>"
    And no admitted scenario envelope is published

    Examples:
      | source_type            |
      | threat_source          |
      | mitigation             |
      | capability_constraint  |

  # Taxonomy source-influence provenance 05 rejects unknown source references
  Scenario: Taxonomy source-influence provenance 05 rejects unknown source references
    Given a source-influence projection fixture with projected step "attacker.deliver"
    And the fixture declares threat source "threat:T12", mitigation "mitigation:M12", and capability constraint "constraint:KCX-MAGENT"
    And projected leaf "n1.1" realizes projected step "attacker.deliver"
    And narrative step "1" realizes projected step "attacker.deliver"
    And the projected leaf link refers to unknown source "mitigation:M99"
    When source-influence provenance is qualified
    Then qualification fails with violation code "unknown_source_reference"
    And the violation identifies source "mitigation:M99"
    And no admitted scenario envelope is published

  # Taxonomy source-influence provenance 06 rejects mismatched projected identities
  Scenario: Taxonomy source-influence provenance 06 rejects mismatched projected identities
    Given a source-influence projection fixture with projected step "attacker.deliver"
    And the fixture declares threat source "threat:T12", mitigation "mitigation:M12", and capability constraint "constraint:KCX-MAGENT"
    And projected leaf "n1.1" realizes projected step "attacker.deliver"
    And narrative step "1" realizes projected step "attacker.deliver"
    And the projected leaf provenance link claims projected step "attacker.observe"
    When source-influence provenance is qualified
    Then qualification fails with violation code "provenance_projected_step_mismatch"
    And the violation identifies artifact "n1.1"
    And no admitted scenario envelope is published

  # Taxonomy source-influence provenance 07 rejects orphaned source records
  Scenario: Taxonomy source-influence provenance 07 rejects orphaned source records
    Given a source-influence projection fixture with projected step "attacker.deliver"
    And the fixture declares threat source "threat:T12", mitigation "mitigation:M12", and capability constraint "constraint:KCX-MAGENT"
    And the fixture also declares unused mitigation "mitigation:M99"
    And projected leaf "n1.1" realizes projected step "attacker.deliver"
    And narrative step "1" realizes projected step "attacker.deliver"
    And both artifacts link only to threat source "threat:T12", mitigation "mitigation:M12", and capability constraint "constraint:KCX-MAGENT"
    When source-influence provenance is qualified
    Then qualification fails with violation code "orphaned_source_provenance"
    And the violation identifies source "mitigation:M99"
    And metric "orphaned_source_count" is 1
    And no admitted scenario envelope is published

  # Taxonomy source-influence provenance 08 rejects unreferenced source-influence artifacts
  Scenario: Taxonomy source-influence provenance 08 rejects unreferenced source-influence artifacts
    Given a source-influence projection fixture with projected steps "attacker.observe,attacker.deliver"
    And the fixture declares threat sources "threat:T12,threat:T13", mitigations "mitigation:M12,mitigation:M13", and capability constraints "constraint:KCX-MAGENT,constraint:KCX-VSTORE"
    And projected leaves "n1.1,n1.2" realize projected steps "attacker.observe,attacker.deliver"
    And narrative steps "1,2" realize projected steps "attacker.observe,attacker.deliver"
    And only the artifacts for projected step "attacker.deliver" have provenance links
    When source-influence provenance is qualified
    Then qualification fails with violation code "unreferenced_source_influence_artifact"
    And the violation identifies projected step "attacker.observe"
    And metric "projected_leaf_coverage" has numerator 1 and denominator 2
    And metric "narrative_step_coverage" has numerator 1 and denominator 2
    And no admitted scenario envelope is published

  # Taxonomy source-influence provenance 09 serializes typed metadata and metrics
  Scenario: Taxonomy source-influence provenance 09 serializes typed metadata and metrics
    Given a source-influence projection fixture with projected step "attacker.deliver"
    And the fixture declares threat source "threat:T12", mitigation "mitigation:M12", and capability constraint "constraint:KCX-MAGENT"
    And projected leaf "n1.1" realizes projected step "attacker.deliver"
    And narrative step "1" realizes projected step "attacker.deliver"
    And both artifacts link to threat source "threat:T12", mitigation "mitigation:M12", and capability constraint "constraint:KCX-MAGENT"
    When source-influence provenance is qualified and the scenario envelope is serialized
    Then the serialized envelope contains a source-influence provenance block
    And each provenance reference contains an explicit source type and source ID
    And the serialized envelope contains source-influence qualification metrics
    And the serialized qualification status is "pass"
