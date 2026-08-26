# mutation-stamp: sha256=54ad100b3831af728b19fa91e17805f70d1d7b14ee7cceb06be948f51f498acb
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-26T17:49:51.579110Z","feature_name":"Taxonomy narrative outside boundaries","feature_path":"features/taxonomy_narrative_outside_boundaries.feature","background_hash":"3daff95561111fd4bb4a6016f7c3daf493a031162ba3b320422d2e7b4859ca4d","implementation_hash":"unknown","scenarios":[{"index":0,"name":"Taxonomy narrative outside boundaries 01 accepts each stage-specific narrative boundary rule","scenario_hash":"1a6ee5a3d98d9c87d9050c52ed0e176bfbee65905c4161500b2563aee7943ff8","mutation_count":18,"result":{"Total":18,"Killed":18,"Survived":0,"Errors":0},"tested_at":"2026-08-26T17:49:51.579110Z"},{"index":2,"name":"Taxonomy narrative outside boundaries 03 rejects boundary and active-zone mismatches without semantic repair","scenario_hash":"02de235e28fbbc2d5807b91bb759b67528ff35288adac69214fb2b322623de2d","mutation_count":48,"result":{"Total":48,"Killed":48,"Survived":0,"Errors":0},"tested_at":"2026-08-26T17:49:51.579110Z"}]}
# acceptance-mutation-manifest-end

Feature: Taxonomy narrative outside boundaries
  Taxonomy narratives represent activity outside the assessed AI boundary
  without treating that representation as an active Schneider zone.

  Background:
    Given taxonomy generation has active Schneider zones "input,reasoning,tool_execution"
    And taxonomy generation has an immutable canonical projection

  # Taxonomy narrative outside boundaries 01 accepts each stage-specific narrative boundary rule
  Scenario Outline: Taxonomy narrative outside boundaries 01 accepts each stage-specific narrative boundary rule
    Given projected step "<step_id>" has boundary position "<boundary_position>"
    And a narrative step maps projected step ID "<step_id>" with zone "<narrative_zone>"
    When narrative projection zones are enforced
    Then the narrative step is accepted without changing its zone or projected step IDs
    And the narrative mapping matches expected projected step ID "<expected_step_id>" and zone "<expected_narrative_zone>"
    And projected step "<expected_step_id>" has expected boundary position "<expected_boundary_position>"

    Examples:
      | step_id           | boundary_position | narrative_zone | expected_step_id  | expected_boundary_position | expected_narrative_zone |
      | attacker.prepare  | outside           | outside        | attacker.prepare  | outside                    | outside                |
      | attacker.deliver  | crossing          | input          | attacker.deliver  | crossing                   | input                  |
      | system.transform  | inside            | reasoning      | system.transform  | inside                     | reasoning              |

  # Taxonomy narrative outside boundaries 02 combines only outside projected steps under the outside zone
  Scenario: Taxonomy narrative outside boundaries 02 combines only outside projected steps under the outside zone
    Given projected steps "attacker.observe,attacker.prepare" each have boundary position "outside"
    And one narrative step maps projected step IDs "attacker.observe,attacker.prepare" with zone "outside"
    When narrative projection zones are enforced
    Then the narrative step is accepted without changing its zone or projected step IDs

  # Taxonomy narrative outside boundaries 03 rejects boundary and active-zone mismatches without semantic repair
  Scenario Outline: Taxonomy narrative outside boundaries 03 rejects boundary and active-zone mismatches without semantic repair
    Given projected step IDs "<projected_step_ids>" have boundary positions "<boundary_positions>"
    And one narrative step maps those projected step IDs with zone "<narrative_zone>"
    When narrative projection zones are enforced
    Then enforcement rejects the narrative with projection-zone reason "<reason>"
    And no narrative step is removed, renumbered, or remapped
    And the narrative mapping matches expected projected step IDs "<expected_projected_step_ids>" and zone "<expected_narrative_zone>"
    And projected step boundaries match expected positions "<expected_boundary_positions>"
    And enforcement reports exact projection-zone reason "<expected_reason>"

    Examples:
      | projected_step_ids                    | boundary_positions | narrative_zone | reason                  | expected_projected_step_ids             | expected_boundary_positions | expected_narrative_zone | expected_reason           |
      | attacker.prepare,system.transform     | outside,inside     | outside        | mixed boundary positions | attacker.prepare,system.transform      | outside,inside             | outside                | mixed boundary positions |
      | attacker.prepare,system.transform     | outside,inside     | input          | mixed boundary positions | attacker.prepare,system.transform      | outside,inside             | input                  | mixed boundary positions |
      | system.transform                      | inside             | outside        | inside step outside       | system.transform                       | inside                     | outside                | inside step outside       |
      | attacker.deliver                      | crossing           | outside        | crossing step outside     | attacker.deliver                       | crossing                  | outside                | crossing step outside  |
      | attacker.prepare                      | outside            | input          | outside step active zone  | attacker.prepare                       | outside                   | input                  | outside step active zone |
      | system.transform                      | inside             | memory         | inactive Schneider zone   | system.transform                       | inside                    | memory                 | inactive Schneider zone |

  # Taxonomy narrative outside boundaries 04 preserves outside traversal order
  Scenario: Taxonomy narrative outside boundaries 04 preserves outside traversal order
    Given ordered narrative step zones are "outside,outside,input,outside,reasoning"
    When the narrative zone sequence is derived
    Then the derived zone sequence is "outside,input,outside,reasoning"

  # Taxonomy narrative outside boundaries 05 excludes outside from active-zone consumers
  Scenario: Taxonomy narrative outside boundaries 05 excludes outside from active-zone consumers
    Given an accepted narrative has zone sequence "outside,input,outside,reasoning"
    When active narrative zones are consumed
    Then the ordered active narrative zones are "input,reasoning"
    And coverage credits traversed zones "input,reasoning"
    And coverage reports uncovered active zone "tool_execution"
    And priority zone signals use 2 distinct zones and traversal length 2
    And capability faceting records zones_traversed "input,reasoning"

  # Taxonomy narrative outside boundaries 06 uses the first active zone for tree skeleton fallback
  Scenario: Taxonomy narrative outside boundaries 06 uses the first active zone for tree skeleton fallback
    Given an accepted narrative has zone sequence "outside,outside,reasoning"
    And a mandatory tree leaf has no more specific zone
    When the attack-tree skeleton is built
    Then the mandatory tree leaf fallback zone is "reasoning"
    And the fallback zone is not "outside"

  # Taxonomy narrative outside boundaries 07 aligns the narrative system prompt with boundary rules
  Scenario: Taxonomy narrative outside boundaries 07 aligns the narrative system prompt with boundary rules
    When the taxonomy narrative system prompt is rendered
    Then it permits literal zone "outside" only for a narrative step whose mapped projected steps are all outside-boundary
    And it requires inside-boundary and crossing-boundary narrative steps to use active Schneider zones
    And it forbids one narrative step from combining outside-boundary and non-outside projected step IDs
    And it distinguishes literal "outside" from the capability profile active zone list
