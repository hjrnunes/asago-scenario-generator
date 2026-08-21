# End-to-end QA: taxonomy source-influence relation preflight

Use only the public `uv run asago-scenario-generator generate` command and a
deterministic local OpenAI-compatible fixture when generation is expected.
Use fresh output collections and the reviewed Klarna profile,
`ai/findings/capability-profile-klarna.yaml`, together with
`ai/findings/uc-klarna-customer-service-agent.md` and the repository's
reviewed risk-extraction, SSSOM, and qualification-facts fixtures. Do not
import project modules or call a project API. Keep
`ASAGO_SCENARIO_GENERATOR_QA_PIPELINE` unset.

## QA-TSIRP-01: reviewed Klarna relation fails before generation

1. Run `generate` with the reviewed Klarna profile and use-case inputs,
   pinning the indirect entry point
   `authenticated customer context injection`.
2. Use the deterministic fixture endpoint only to record requests, if the
   command requires an endpoint configuration.
3. Inspect the command's exit status, console diagnostic, run manifest, and
   fixture request log.

**Expected:** The run fails or completes with the candidate quarantined before
Call 0. Typed projection/qualification evidence names the bound source,
boundary, target ingress, expected zone `input`, and actual boundary zones
`input->reasoning`, and directs the operator to review explicit `ingress_zone`
or the trust-boundary declaration. The run does not invent or rewrite the
reviewed boundary. The fixture request log contains zero actor, narrative,
attack-tree, or behavior requests for that candidate.

## QA-TSIRP-02: invalid relation bindings fail closed

Run separate deterministic CLI cases for each condition:

1. source kind `entry_point` paired with an integration ID;
2. an unreviewed trust-boundary ID;
3. a target binding different from the canonical indirect ingress;
4. an entry-point source that is system-controlled;
5. an entry-point source equal to the target ingress;
6. zero selected source-influence paths;
7. two selected source-influence paths; and
8. a relation that the actor/narrative typed provenance contract cannot
   represent.

For every case, inspect the exit status, typed diagnostic, candidate outcome,
and fixture request log.

**Expected:** Each case emits
`source_influence_relation_infeasible`, preserves the original bindings
without fuzzy matching or substitution, and records zero generated-stage
provider calls. Relation diagnostics include source, boundary, target ingress,
expected target zone, actual boundary zones, and operator guidance to review
explicit `ingress_zone` or the trust-boundary declaration.

## QA-TSIRP-03: valid direct ingress derives null source provenance

1. Configure a reviewed direct input entry point and no
   `source_influence` relation.
2. Run `generate` against deterministic valid fixture responses.
3. Inspect the admitted scenario YAML and the fixture request payloads.

**Expected:** The candidate reaches Call 0 and is admitted. Actor and
narrative provenance contain the same canonical direct ingress ID, with
`influence_source_kind: null` and `influence_source_id: null`. The fixture
responses provide narrative evidence only, and do not provide canonical
source, boundary, or target IDs.

## QA-TSIRP-04: valid entry-point and integration sources derive identically

Run two fresh deterministic cases with the same indirect canonical ingress
and reviewed `input->reasoning` boundary:

1. bind an attacker-influenceable entry-point source
   `ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`;
2. bind a valid integration source
   `int:v1:cccccccccccccccccccccccccccccccc`.

For each case, return only access class and influence mechanism from the
fixture, then inspect the rendered authoritative prompt context, fixture
request log, and admitted scenario YAML.

**Expected:** Each candidate reaches generation. Exactly one source-boundary-
target tuple is rendered, and an unrelated reviewed boundary is absent.
Actor and narrative provenance carry the same typed source kind and canonical
source ID, plus the canonical boundary and target-ingress IDs. Canonical IDs
are deterministic projection output, not model-selected values.

## QA-TSIRP-05: authoritative paths do not expose the full boundary inventory

1. Use a valid indirect case with one selected boundary and at least one
   reviewed but unrelated boundary.
2. Run `generate` with deterministic valid fixture responses.
3. Inspect the serialized run evidence and prompts without using project
   imports.

**Expected:** Only the selected valid relation tuple appears in
source-influence context and provenance. The unrelated boundary never appears
as an eligible path, and no generated-stage retry is used to repair a
projection/access-contract infeasibility.
