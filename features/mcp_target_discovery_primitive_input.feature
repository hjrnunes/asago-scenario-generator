# MCP-TARGET-01 through MCP-TARGET-08
Feature: MCP target discovery is an optional primitive STPA input
  A target can be scanned independently without ASAGO-specific metadata.  The
  resulting profile may make later execution choices concrete, while the
  ordinary STPA baseline remains target-blind and complete.

  Background:
    Given the MCP target-discovery acceptance context is available

  # MCP-TARGET-01
  Scenario: metadata-free MCP inventory becomes a closed inferred profile
    Given a metadata-free MCP tools inventory
    When the inventory is discovered without active tool calls
    Then the profile retains exact MCP tool and operation identities
    And observed inventory authority remains separate from inferred semantic authority

  # MCP-TARGET-02
  Scenario: scanner runtime connection data never enters a published profile
    Given a metadata-free MCP tools inventory
    When the inventory is discovered with secret runtime connection data
    Then no endpoint credential or secret value appears in any discovery artifact

  # MCP-TARGET-03
  Scenario: a target profile cannot bias the systemic STPA baseline
    Given identical fixed systemic provider responses with and without a target profile
    When both synthesis runs reach the target-realization boundary
    Then every pre-realization prompt and systemic baseline artifact is identical

  # MCP-TARGET-04
  Scenario: target realization selects only an exact observed operation
    Given a target-blind systemic baseline and an observed target profile
    When target realization supports one systemic control action
    Then it selects the exact observed resource and operation
    And the target-realization artifact retains inferred semantic authority separately

  # MCP-TARGET-05
  Scenario: uncovered state-changing operations receive at most one additive extension
    Given an uncovered observed state-changing operation
    When the bounded target extension is attempted
    Then the extension adapter is called exactly once
    And the baseline records remain unchanged
    And verified target-derived ICA findings join the scenario candidate universe

  # MCP-TARGET-06
  Scenario: unresolved target relationships cannot become exact Stage 5 choices
    Given a target realization whose relationship is ambiguous
    When Stage 5 requests an exact target operation
    Then no target operation is supplied to the Stage 5 provider
