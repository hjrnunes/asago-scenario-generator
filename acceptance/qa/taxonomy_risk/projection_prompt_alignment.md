# End-to-end QA: taxonomy projection prompt alignment

Drive only `uv run asago-scenario-generator generate` with a deterministic
local OpenAI-compatible fixture endpoint that records request bodies. Use a
fresh output collection and complete reviewed inputs. Inspect the fixture's
received narrative and attack-tree requests; do not import project modules or
render templates directly.

## QA-TPPA-01: prompts render one compact row per selected step

1. Select outside `attacker.observe`, crossing `attacker.deliver`, and inside
   `operator.impact` steps with representative bound resources.
2. Run `generate` through the narrative and attack-tree calls.
3. Inspect both recorded user prompts.

**Expected in both prompts:** One compact table has columns `canonical ID`,
`action`, `executor`, `boundary`, `allowed narrative zone`,
`allowed tree kinds`, `tree zone`, and `bound resources`. It has exactly one
row per selected step in canonical order, no numeric positional ID, and a
warning that IDs are semantic names.

## QA-TPPA-02: table values match observable validation

1. Configure the fixture to return leaves matching each table row and complete
   a successful run.
2. Repeat with one action-kind, executor-role, boundary/zone, or resource
   binding changed at a time through bounded retries.

**Expected:** Rows declare the action/executor intersection narrowed by the
step's explicit ingress ownership and boundary position, exactly as accepted
by validation. Outside rows use narrative zone `outside`, tree kind
`external_precondition`, and null tree zone. Inside/crossing rows use active
Schneider zones. Resource cells contain only that step's bindings. Every
single-field mismatch is rejected with the corresponding semantic diagnostic.

## QA-TPPA-03: empty compatibility is explicit

Select a crossing `operator.deliver` step and inspect both prompts.

**Expected:** Its allowed-tree-kinds cell is empty; neither prompt invents a
compatible leaf kind or repeats a conflicting hand-authored compatibility
rule elsewhere.
