# End-to-end QA: taxonomy CLI run outcome

Drive only `uv run asago-scenario-generator generate` with a deterministic
local OpenAI-compatible fixture endpoint. Use fresh output collections and
valid offline inputs. Capture stdout, stderr, exit status, and the published
`run-manifest.yaml`; do not import project modules.

For every case, verify the printed status equals the manifest status and the
printed admitted, quarantined, and failed counts reconcile with the published
finalization evidence.

## QA-TCRO-01: clean completion exits zero

1. Configure two selected candidates to pass generation, admission,
   evaluation, and report generation.
2. Run `generate`.

**Expected:** The manifest and summary report `completed`, admitted `2`,
quarantined `0`, and failed `0`. The process exits `0` and identifies the run
directory.

## QA-TCRO-02: quarantine is a nonzero completed-with-errors outcome

1. Configure one candidate to be admitted and one to exhaust bounded
   validation retries and be quarantined.
2. Run `generate`.

**Expected:** The manifest and summary report `completed_with_errors`,
admitted `1`, quarantined `1`, and failed `0`. The process exits `1`; it does
not print an unqualified success message.

## QA-TCRO-03: failed candidate is counted

1. Configure one candidate to be admitted and one candidate to exhaust a
   generation or finalization retry budget without reaching admission.
2. Run `generate`.

**Expected:** The manifest and summary report `completed_with_errors`,
admitted `1`, quarantined `0`, and failed `1`. The process exits `1`.

## QA-TCRO-04: zero admission fails by default

1. Configure valid inputs that yield no admitted candidates and no quarantine
   or failed candidate attempts.
2. Run `generate` without any outcome-policy override.

**Expected:** The summary reports admitted `0`, quarantined `0`, and failed
`0`, and prints the final manifest status. The process exits `1` even if the
manifest status is `completed`.
