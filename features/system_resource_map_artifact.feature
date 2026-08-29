# mutation-stamp: sha256=ca24a9436ae6244d61a9b8d1834412798071e525589fcece7bc51d2e2fdada5e
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-29T13:37:14.583002Z","feature_name":"Normative system resource map artifact","feature_path":"features/system_resource_map_artifact.feature","background_hash":"9b06cdbe14f11ba0e074d11147f5ece5448f9c1598f5ed76047dcedb49908985","implementation_hash":"sha256:2311659be4f3033b4605b7923a27545401d47ec93054b73c7f77352796adb867","scenarios":[{"index":1,"name":"YAML and JSON preserve the closed map","scenario_hash":"08fe44d1be22db9c1f34ad40b3dfcfe52579321199210007094e0aa329360ace","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-29T13:37:14.583002Z"}]}
# acceptance-mutation-manifest-end

Feature: Normative system resource map artifact
  The system-resource-map-v1 sidecar is content-addressed, closed, and
  atomically persisted as system-resource-map.yaml.

  Background:
    Given typed capability and STPA authorities are available

  Scenario: the artifact records its versioned schema
    Given a valid typed resource map is available
    Then the map records schema version "system-resource-map-v1"

  Scenario Outline: YAML and JSON preserve the closed map
    Given a valid typed resource map is available
    When the map is serialized and deserialized as "<format>"
    Then the round-trip map is identical

    Examples:
      | format |
      | YAML   |
      | JSON   |

  Scenario: the map is atomically persisted under the normative filename
    Given a valid typed resource map is available
    When the map is atomically persisted
    Then the published filename is "system-resource-map.yaml"
