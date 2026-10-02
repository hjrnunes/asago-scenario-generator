Feature: SP3 feedback-channel bridge
  An FB identifier denotes a logical information dependency that updates a
  process-model belief. The Stage 5 prompt directs the model to realize that
  dependency through a declared AI surface instead of inferring an
  attacker-accessible network or session mechanism.

  Background:
    Given the SP3 prompt templates are available

  # SP3-FCB-01
  Scenario Outline: SP3-FCB-01 generation prompts name each AI surface
    When the <stage> system prompt is rendered
    Then the prompt defines an FB identifier as a logical information dependency that updates a process-model belief
    And the prompt states that an FB identifier is not evidence of an attacker-accessible transport
    And the prompt includes the declared AI surface <surface>

    Examples:
      | stage             | surface                |
      | Stage 5 BDI       | prompt/context input   |
      | Stage 5 BDI       | retrieved content     |
      | Stage 5 BDI       | tool result            |
      | Stage 5 BDI       | memory state           |
      | Stage 5 BDI       | agent message          |
      | Stage 5 BDI       | model output           |

  Scenario Outline: SP3-FCB-01 prompts reject each inferred mechanism
    When the <stage> system prompt is rendered
    Then the prompt forbids inventing mechanism <mechanism> without explicit attacker-accessible architecture evidence

    Examples:
      | stage             | mechanism                         |
      | Stage 5 BDI       | packet interception               |
      | Stage 5 BDI       | man-in-the-middle access          |
      | Stage 5 BDI       | network delay                     |
      | Stage 5 BDI       | traffic blocking                  |
      | Stage 5 BDI       | network-signal spoofing           |
      | Stage 5 BDI       | communication-link severing       |
      | Stage 5 BDI       | credential theft                  |
      | Stage 5 BDI       | account takeover                  |
      | Stage 5 BDI       | session hijacking or fixation     |
      | Stage 5 BDI       | generic flooding or denial of service |
