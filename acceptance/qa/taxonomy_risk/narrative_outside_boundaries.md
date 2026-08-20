# End-to-end QA: taxonomy narrative outside boundaries

Drive only `uv run asago-scenario-generator generate` with a deterministic
local OpenAI-compatible fixture endpoint. Use fresh output collections and
complete reviewed inputs. Inspect recorded requests, CLI diagnostics,
manifests, reports, and published scenario YAML; do not import project modules.

## QA-TNOB-01: outside narrative steps are admitted

1. Select an ordered projection with two outside steps, a crossing step, and
   an inside step.
2. Return narrative step zones `outside`, `outside`, `input`, `outside`,
   `reasoning`, mapping the extra outside step only to outside canonical IDs.
3. Return an otherwise compatible attack tree and complete the run.

**Expected:** The narrative is admitted without changing step IDs or zones.
Its stored `zone_sequence` is `outside,input,outside,reasoning`, preserving
the return outside while collapsing the consecutive outside run.

## QA-TNOB-02: invalid boundary combinations fail closed

Repeat the run with each defect through all bounded narrative attempts:

- one `outside` narrative step combines outside and inside projected IDs;
- an inside or crossing step uses `outside`;
- an outside step uses `input`; and
- an inside step uses inactive zone `memory`.

**Expected:** Every run exits nonzero with projection-zone evidence identifying
the mismatched step and boundary. No step is deleted, renumbered, or remapped,
and no defective scenario is published.

## QA-TNOB-03: outside is not credited as an active zone

1. Complete a valid run whose stored zone sequence is
   `outside,input,outside,reasoning` and whose profile also activates
   `tool_execution`.
2. Inspect scenario faceting, coverage output, priority, and the recorded
   attack-tree prompt.
3. Repeat with extra outside-only narrative traversal but the same active
   traversal.

**Expected:** Faceting records `input,reasoning`; coverage credits those zones
and reports `tool_execution` uncovered. Zone-derived priority is unchanged by
the extra outside-only traversal. Mandatory skeleton fallback uses the first
active narrative zone, never `outside`.

## QA-TNOB-04: the narrative prompt explains outside

Inspect the recorded narrative system prompt.

**Expected:** It permits literal `outside` only when every ID mapped by that
narrative step is outside-boundary, requires inside/crossing steps to use an
active Schneider zone, forbids mixed-boundary IDs on an outside step, and does
not describe `outside` as a profile-active Schneider zone.
