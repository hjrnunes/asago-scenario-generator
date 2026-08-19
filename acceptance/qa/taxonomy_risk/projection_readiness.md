# End-to-end QA: taxonomy projection architecture readiness

Drive only `uv run asago-scenario-generator generate`. Use a deterministic
local OpenAI-compatible fixture endpoint, fresh output collections, and valid
use-case, risk-extraction, and SSSOM inputs. Inspect console output, endpoint
request logs, and published run files; do not import project modules.

## QA-TPR-01: ready architecture proceeds

1. Supply `--profile` with all resource categories required by the selected
   authoritative patterns and `--qualification-facts` with every fact those
   patterns require.
2. Run `generate` against valid fixture responses.
3. Inspect the console stage output and endpoint request log.

**Expected:** Projection starts, scenario-generation requests follow, and no
architecture-readiness error appears.

## QA-TPR-02: missing resource categories stop before projection

1. Configure Stage 1 inference to return a valid inferred-partial profile
   that omits `external_integrations` and `trust_boundaries`.
2. Select fixture inputs whose authoritative patterns require both categories.
3. Run `generate` without `--profile` and capture stdout, stderr, and exit
   status.
4. Inspect the endpoint request log and final manifest.

**Expected:** The command exits nonzero and does not report normal completion.
The diagnostic names `external_integrations` and `trust_boundaries`, directs
the user to provide a reviewed architecture with `--profile`, and states that
projection did not begin. No projection or scenario-generation request and no
automatic architecture-enrichment request occurs.

## QA-TPR-03: missing fact evidence is actionable

1. Supply architecture resources required by the selected pattern but omit
   the authoritative reading for
   `deployment.attacker_code_execution_on_agent_host`.
2. Run `generate` with the remaining valid fixture inputs.
3. Inspect stderr, exit status, endpoint requests, and the final manifest.

**Expected:** The command exits nonzero before projection. The diagnostic
names the missing fact and directs the user to `--qualification-facts`.
No enrichment or scenario-generation request occurs, and the run does not
claim normal completion.
