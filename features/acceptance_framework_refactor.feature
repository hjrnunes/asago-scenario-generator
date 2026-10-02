Feature: Acceptance framework refactor contracts
  The acceptance framework may be reorganized without changing its observable
  execution, registration, artifact, policy, import, or mutation-runner
  contracts. Framework-owned state is isolated per scenario example, while
  generated artifacts remain deterministic and repo-relative.

  # Acceptance framework refactor AFR-01 maps every artifact deterministically
  Scenario Outline: Acceptance framework refactor AFR-01 maps every artifact deterministically
    Given acceptance directories are configured as repo-relative paths
    When artifact paths are requested for "features/group/example.feature"
    Then the <artifact> path is "<path>"

    Examples:
      | artifact | path                                                               |
      | IR       | build/acceptance/ir/group/example.json                             |
      | dry      | build/acceptance/dry/group/example.txt                             |
      | test     | build/acceptance/generated/example_acceptance_test.py              |
      | metadata | build/acceptance/generated/metadata/example.json                   |

  # Acceptance framework refactor AFR-02 refreshes generated output deterministically
  Scenario: Acceptance framework refactor AFR-02 refreshes generated output deterministically
    Given a temporary project has nested source features in unsorted creation order
    And its configured output trees contain stale generated artifacts and an unrelated file
    When the acceptance snapshot is refreshed
    Then source features are processed in lexicographic repo-relative order
    And each source feature has one mapped IR, dry report, generated test, and metadata file
    And generated metadata contains only repo-relative source and IR paths
    And stale mapped IR, generated test, and metadata files are removed
    And the unrelated file is preserved

  # Acceptance framework refactor AFR-03 publishes registration atomically
  Scenario: Acceptance framework refactor AFR-03 publishes registration atomically
    Given an acceptance registry has already published a valid pattern and key set
    And a replacement manifest stages one valid module before a module whose registration fails
    When the replacement manifest is registered
    Then the failure identifies the failing runtime feature
    And the previously published pattern and key set remain unchanged
    And no staged replacement pattern is executable

  # Acceptance framework refactor AFR-04 resolves only patterns eligible for the current feature
  Scenario: Acceptance framework refactor AFR-04 resolves only patterns eligible for the current feature
    Given one step text matches a global pattern and patterns scoped to two different features
    When the step executes for the first feature
    Then patterns scoped to the other feature are ineligible
    And the first eligible pattern in deterministic registration priority executes exactly once
    And executing an unscoped feature cannot select either feature-scoped pattern

  # Acceptance framework refactor AFR-05 isolates scenario examples
  Scenario Outline: Acceptance framework refactor AFR-05 isolates scenario examples
    Given an IR scenario has two examples and an original process environment
    And the first example changes its world state and process environment before it <result>
    When the IR is executed for a nested feature context
    Then the second example receives a fresh world and the original process environment
    And each example shares one world between its own background and scenario steps
    And the process environment is restored after the IR execution
    And the enclosing feature context is restored after the IR execution

    Examples:
      | result |
      | passes |
      | fails  |

  # Acceptance framework refactor AFR-06 reports execution outcomes without conflation
  Scenario Outline: Acceptance framework refactor AFR-06 reports execution outcomes without conflation
    Given an isolated IR scenario named "contract" has the <condition>
    When the isolated IR is executed
    Then its result is <passed>
    And its output begins with "<status> contract/example_1"

    Examples:
      | condition                         | passed | status |
      | supported passing step            | true   | PASS   |
      | unsupported step                  | false  | FAIL   |

  # Acceptance framework refactor AFR-07 preserves namespaced manifest loading
  Scenario: Acceptance framework refactor AFR-07 preserves namespaced manifest loading
    Given the project root is the current working directory
    When the runtime manifest is loaded through the "acceptance.runtime_manifest" namespace
    Then every declared runtime feature loads in manifest order
    And every loaded feature identity matches its declared name
    And every loaded feature exposes a registration operation
    And the complete manifest registers each feature exactly once

  # Acceptance framework refactor AFR-08 maps mutation worker outcomes
  Scenario Outline: Acceptance framework refactor AFR-08 maps mutation worker outcomes
    Given the mutation worker receives job "job-1" for an IR runtime that <runtime_result>
    When the worker emits the job response
    Then the response id is "job-1"
    And the response outcome is "<outcome>"
    And the response duration is a non-negative integer of nanoseconds
    And standard output and standard error are returned in separate fields

    Examples:
      | runtime_result                      | outcome              |
      | exits with status 0                 | test_success         |
      | exits with status 1                 | test_failure         |
      | exits with another status           | infrastructure_error |
      | exceeds its requested timeout       | infrastructure_error |
      | raises a worker execution exception | infrastructure_error |

  # Acceptance framework refactor AFR-09 keeps malformed mutation requests inside the protocol
  Scenario: Acceptance framework refactor AFR-09 keeps malformed mutation requests inside the protocol
    Given the persistent mutation worker is ready
    When it receives a malformed JSON line followed by a valid job line
    Then it emits one infrastructure_error response with id "unknown" for the malformed line
    And it remains running to emit one response for the valid job
    And every response is one JSON object on one standard-output line
