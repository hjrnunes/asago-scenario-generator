Feature: SP3 mechanism-context propagation
  Stage 5 receives a purpose-built view of one immutable scenario context,
  containing its useful meaning and copyable references but no integrity
  bookkeeping. Stage 6 receives a purpose-built view of the same selected
  evidence; content digests remain outside the reasoning prompt.

  Background:
    Given the SP3 prompt assembly modules are importable
    And optional model-authored scenario presentation is enabled
    And exact reachable capabilities for the selected control path
    And each reachable capability has explicit access evidence
    And the exact scenario generation context is built from selected authority

  # SP3-MCP-01
  Scenario Outline: SP3-MCP-01 downstream prompts include positive mechanism guidance
    When the <stage> user prompt is built with the exact scenario context
    Then the user prompt contains the stage-appropriate scenario context
    And the user prompt reachable capabilities contain mechanism <mechanism>

    Examples:
      | stage             | mechanism               |
      | Stage 5 BDI       | prompt injection        |
      | Stage 5 BDI       | tool result fabrication |
      | Stage 5 BDI       | memory poisoning        |
      | Stage 5 BDI       | agent impersonation     |
      | Stage 5 BDI       | retrieval poisoning     |
      | Stage 6 narrative | prompt injection        |
      | Stage 6 narrative | tool result fabrication |
      | Stage 6 narrative | memory poisoning        |
      | Stage 6 narrative | agent impersonation     |
      | Stage 6 narrative | retrieval poisoning     |

  # SP3-MCP-02
  Scenario: SP3-MCP-02 the full SP3 run propagates one exact scenario context downstream
    Given a recording LLM that returns valid Stage 5 and Stage 6 results
    When SP3 runs with the exact scenario context
    Then every Stage 5 BDI request contains the actionable scenario context
    And every Stage 6 narrative request contains the actionable scenario evidence without integrity bookkeeping
