Feature: Taxonomy source-influence relation preflight
  Authoritative projection and qualification resolve source-influence
  relations before any generated-stage provider call.  Only a valid,
  representable source-to-reviewed-boundary-to-canonical-ingress tuple may
  reach generation, and actor and narrative provenance share its typed source
  reference.

  Background:
    Given source-influence projection and qualification use deterministic offline inputs
    And generated-stage call counts are observable per candidate

  # Taxonomy source-influence relation preflight 01 rejects the reviewed Klarna mismatch before Call 0
  Scenario: Taxonomy source-influence relation preflight 01 rejects the reviewed Klarna mismatch before Call 0
    Given the reviewed Klarna profile has one trust boundary from zone "input" to zone "reasoning"
    And pinned indirect entry point "authenticated customer context injection" has effective ingress zone "input"
    And the selected source-influence relation binds source "int:v1:22222222222222222222222222222222", boundary "tb:v1:33333333333333333333333333333333", and target ingress "ep:v1:44444444444444444444444444444444"
    When authoritative candidates are projected and qualified
    Then the candidate is rejected before generated-stage Call 0
    And the candidate is quarantined with typed issue code "source_influence_relation_infeasible"
    And the typed issue identifies source "int:v1:22222222222222222222222222222222", boundary "tb:v1:33333333333333333333333333333333", target ingress "ep:v1:44444444444444444444444444444444", expected target zone "input", and actual boundary zones "input->reasoning"
    And the typed issue guidance says to review explicit "ingress_zone" or trust-boundary declaration
    And zero generated-stage provider calls are recorded for the candidate

  # Taxonomy source-influence relation preflight 02 rejects a source kind and ID mismatch without substitution
  Scenario: Taxonomy source-influence relation preflight 02 rejects a source kind and ID mismatch without substitution
    Given an indirect target ingress with effective ingress zone "reasoning"
    And a reviewed trust boundary from zone "input" to zone "reasoning"
    And the source-influence relation declares source identity kind "entry_point" but binds integration ID "int:v1:55555555555555555555555555555555"
    When authoritative candidates are projected and qualified
    Then the candidate is rejected with typed issue code "source_influence_relation_infeasible"
    And the typed issue identifies the source, boundary, target ingress, expected target zone, and actual boundary zones
    And the issue identifies expected source kind "entry_point" and actual binding kind "integration"
    And no resource binding is substituted or fuzzy-matched
    And zero generated-stage provider calls are recorded for the candidate

  # Taxonomy source-influence relation preflight 03 rejects an unreviewed boundary
  Scenario: Taxonomy source-influence relation preflight 03 rejects an unreviewed boundary
    Given an indirect target ingress with effective ingress zone "reasoning"
    And the selected source-influence relation binds a valid attacker-influenceable source and target ingress
    And its boundary ID "tb:v1:66666666666666666666666666666666" is absent from the reviewed trust-boundary declarations
    When authoritative candidates are projected and qualified
    Then the candidate is rejected with typed issue code "source_influence_relation_infeasible"
    And the typed issue identifies the source, boundary, target ingress, expected target zone, and actual boundary zones
    And the issue identifies boundary "tb:v1:66666666666666666666666666666666"
    And zero generated-stage provider calls are recorded for the candidate

  # Taxonomy source-influence relation preflight 04 rejects a non-canonical target binding
  Scenario: Taxonomy source-influence relation preflight 04 rejects a non-canonical target binding
    Given the canonical indirect ingress is "ep:v1:77777777777777777777777777777777"
    And the selected source-influence relation binds a valid source and reviewed boundary
    And the relation target binding resolves to "ep:v1:88888888888888888888888888888888" instead
    When authoritative candidates are projected and qualified
    Then the candidate is rejected with typed issue code "source_influence_relation_infeasible"
    And the typed issue identifies the source, boundary, target ingress, expected target zone, and actual boundary zones
    And the issue identifies target ingress "ep:v1:88888888888888888888888888888888" and canonical ingress "ep:v1:77777777777777777777777777777777"
    And zero generated-stage provider calls are recorded for the candidate

  # Taxonomy source-influence relation preflight 05 rejects an ineligible or self-referential entry-point source
  Scenario Outline: Taxonomy source-influence relation preflight 05 rejects an ineligible or self-referential entry-point source
    Given the canonical indirect ingress is "ep:v1:99999999999999999999999999999999"
    And the selected relation binds entry-point source "ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" with attacker influenceability "<influenceability>" and distinctness "<distinctness>" from the target
    And the relation binds a reviewed trust boundary whose to_zone matches the target effective ingress zone
    When authoritative candidates are projected and qualified
    Then the candidate is rejected with typed issue code "source_influence_relation_infeasible"
    And the typed issue identifies the source, boundary, target ingress, expected target zone, and actual boundary zones
    And zero generated-stage provider calls are recorded for the candidate

    Examples:
      | influenceability          | distinctness     |
      | not-attacker-influenceable | distinct         |
      | attacker-influenceable     | not-distinct     |

  # Taxonomy source-influence relation preflight 06 requires one representable single-path relation
  Scenario Outline: Taxonomy source-influence relation preflight 06 requires one representable single-path relation
    Given the candidate has "<path_count>" selected source-influence paths
    And the pinned ingress and reviewed profile resources are otherwise valid
    When authoritative candidates are projected and qualified
    Then the candidate is rejected with typed issue code "source_influence_relation_infeasible"
    And the issue identifies the source, boundary, target ingress, expected target zone, and actual boundary zones
    And zero generated-stage provider calls are recorded for the candidate

    Examples:
      | path_count |
      | 0          |
      | 2          |

  # Taxonomy source-influence relation preflight 07 rejects an unrepresentable provenance relation
  Scenario: Taxonomy source-influence relation preflight 07 rejects an unrepresentable provenance relation
    Given the selected source-influence relation cannot be represented by the actor and narrative typed provenance contract
    And the pinned ingress, source, boundary, and target bindings resolve individually
    When authoritative candidates are projected and qualified
    Then the candidate is rejected with typed issue code "source_influence_relation_infeasible"
    And the issue identifies the source, boundary, target ingress, expected target zone, and actual boundary zones
    And zero generated-stage provider calls are recorded for the candidate

  # Taxonomy source-influence relation preflight 08 derives null provenance for a valid direct ingress
  Scenario: Taxonomy source-influence relation preflight 08 derives null provenance for a valid direct ingress
    Given the canonical ingress is a reviewed direct entry point with effective ingress zone "input"
    And the projection contains no source-influence relation
    And deterministic generated-stage responses provide narrative evidence but no canonical source or boundary IDs
    When authoritative candidates are projected, qualified, and generated
    Then the candidate reaches generated-stage Call 0
    And actor access provenance has ingress mode "direct", influence_source_kind null, and influence_source_id null
    And narrative access realization has the same null typed source reference
    And actor and narrative provenance contain the canonical direct ingress ID

  # Taxonomy source-influence relation preflight 09 renders exactly one valid entry-point or integration tuple
  Scenario Outline: Taxonomy source-influence relation preflight 09 renders exactly one valid entry-point or integration tuple
    Given the canonical indirect ingress is "ep:v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" with effective ingress zone "reasoning"
    And the reviewed profile has a valid boundary from zone "input" to zone "reasoning" and an unrelated boundary from zone "reasoning" to zone "tool_execution"
    And one valid source-influence relation binds <source_kind> source "<source_id>" to the canonical ingress through the first boundary
    And deterministic generated-stage responses provide only access class and influence mechanism, not canonical source, boundary, or target IDs
    When authoritative candidates are projected, qualified, and generated
    Then qualification passes and the candidate reaches generated-stage Call 0
    And the rendered authoritative source-influence paths contain exactly one tuple for source "<source_id>", the first boundary, and target ingress "ep:v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    And the rendered paths do not contain the unrelated boundary
    And actor access provenance has influence_source_kind "<source_kind>" and influence_source_id "<source_id>"
    And narrative access realization has the same typed source reference
    And actor and narrative provenance have the canonical boundary and target ingress IDs
    And no canonical source, boundary, or target ID is selected by the model

    Examples:
      | source_kind | source_id                            |
      | entry_point | ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa |
      | integration  | int:v1:cccccccccccccccccccccccccccccccc |
