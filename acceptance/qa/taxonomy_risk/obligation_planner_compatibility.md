# End-to-end QA: taxonomy obligation planner compatibility

Drive only the existing public commands
`uv run asago-scenario-generator generate` and
`uv run asago-scenario-generator stpa-run`. Use deterministic local
OpenAI-compatible fixture endpoints, fresh output collections, and valid
offline inputs. Inspect console output, published run files, and request
logs. Do not import project modules. Do not add obligation-planner flags.
Never set `ASAGO_SCENARIO_GENERATOR_QA_PIPELINE` unless a live-model
suite already requires it; these cases remain offline.

Compare each run against a captured fixture of existing workflow
outputs from the same inputs.

## QA-TOPC-01: default taxonomy generate outputs are unchanged

1. Capture a deterministic offline `generate` fixture: use-case,
   risk-extraction, SSSOM, reviewed profile, qualification facts, and
   fixture endpoint responses.
2. Run `uv run asago-scenario-generator generate` without
   obligation-planner flags into a fresh output collection.
3. Compare published scenario YAML, `.feature` files, run-manifest,
   generation counts, and provider request bodies against the fixture.

**Expected:** Published scenario artifacts match the fixture.
Generation counts are unchanged. Scenario prompts in the request log
are unchanged. No obligation-plan artifact is added to the run
outputs.

## QA-TOPC-02: default STPA stpa-run outputs are unchanged

1. Capture a deterministic offline `stpa-run` fixture with valid
   use-case, risk-extraction, and stub LLM responses.
2. Run `uv run asago-scenario-generator stpa-run` without
   obligation-planner flags into a fresh output directory.
3. Compare published STPA scenario artifacts, generation counts, and
   prompts against the fixture.

**Expected:** Published scenario artifacts match the fixture.
Generation counts are unchanged. Scenario prompts are unchanged. No
obligation-plan artifact is added to the run outputs.
