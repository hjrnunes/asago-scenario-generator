# Typed facts for the tool-call condition check

Stage 5 refuses a bound tool-call condition only on proof. Three kinds of
proof need facts that a JSON Schema does not state, so the producer now reads
them from typed fields, and never from a name, a value, or a description:

| Fact | Where the producer reads it | Who supplies it |
| --- | --- | --- |
| The record kind of an operation argument (`order_id`, `customer_id`, `patient_id`, `free_text`, ...) | `value_facts.arguments` of `execution-target-profile-v1` | the target's declarations; discover passes them to the scanner |
| The record kind of a state value or of a state mapping's keys | `value_facts.state_fields` and `value_facts.state_keys` | the target's declarations |
| That an argument or state value holds a `date` or `date-time` | `format` in the same entries | the target's declarations; for an argument, also a `string` input-schema property with `format: date` or `format: date-time`, which the scanner adds (a declaration with a different format leaves no fact) |
| Whether the failure criterion is an incorrect call or a missing call, and of which operation | `semantic_failure_call` of `scenario-handoff-v5` (`unsafe_outcome.failure_call` in the Stage 5 response) | the producer (Stage 5) |

Without a fact the check reports the case undecidable, as before. With one,
it decides:

- two different declared record kinds are disjoint, so an argument of one
  kind compared for equality with a state value (or another argument) of
  another kind is refused (`discriminating_condition_record_kind_mismatch`);
  one declared kind on both sides is clean;
- an ordering (`gt`, `ge`, `lt`, `le`) on an argument declared as `date` or
  `date-time` text is refused (`discriminating_condition_ordering_not_numeric`):
  RFC 3339 text is never a number under `float()`, and
  `tool-call-condition-v1` orders numbers only, so the consumer would find the
  comparison unknown on every call;
- `not_called` on the operation of an `incorrect_call` failure call is refused
  (`discriminating_condition_polarity_inverted`) in every control-action
  category, whether or not the action maps to an operation, and whatever the
  safe outcome claims (a reply-level condition so refused is removed rather
  than corrected, as every failing reply-level condition is).

When the observation contract captures tool calls, a Stage 5 reply must
carry `unsafe_outcome.failure_call`: the object, or `null` when the failure
is not a call of one inventory operation. A reply without the key fails
validation and goes through the existing correction. The handoff's
`semantic_failure_call` stays optional and is omitted when the reply's
value is `null`, so a handoff reader must still accept its absence.

Declaring a record kind therefore asserts disjointness: a target that declares
`question` as `free_text` and `patient_id` as `patient_id` states that a
question is never exactly a patient id. Declare a kind only where that holds.

## The value-facts document

One YAML or JSON document per target, validated as `TargetValueFacts`
(`src/asago_scenario_generator/stpa/models/value_facts.py`):

```yaml
arguments:          # one entry per (operation_id, argument)
  - {operation_id: process_refund, argument: order_id, record_kind: order_id}
  - {operation_id: schedule_payment, argument: next_due, format: date}
state_fields:       # the value at a dotted TARGET-STATE path; * is any one key
  - {path: orders.*.customer_id, record_kind: customer_id}
state_keys:         # the keys of the mapping at a path
  - {path: orders, record_kind: order_id}
```

Each entry declares a `record_kind` (lower_snake), a `format` (`date` or
`date-time`), or both; the profile schema requires at least one of them to be
present and a string. Each target value is declared once. An argument entry
must name an argument of an operation the profile lists, or the profile is
rejected; the schema cannot state this rule, so a schema-only reader must
check it itself. Two state entries that match one value and disagree give no
fact.

The proposed documents for the three synthetic domains are
[`typed-condition-facts/klarna.yaml`](typed-condition-facts/klarna.yaml),
[`typed-condition-facts/occiai.yaml`](typed-condition-facts/occiai.yaml), and
[`typed-condition-facts/airbnb.yaml`](typed-condition-facts/airbnb.yaml). Each
validates against its domain's `tools-list.json` (both variants share one
tools list), checked with:

```bash
uv run asago-target-scan file \
  --tools-list <declarations>/<domain>/safe/tools-list.json \
  --target-id mini<domain> --authorization-scope local-test \
  --output-dir "$(mktemp -d)/out" \
  --value-facts docs/handoffs/typed-condition-facts/<domain>.yaml
```

Examples of what they declare:

| Domain | Arguments | State |
| --- | --- | --- |
| klarna | `process_refund.order_id: order_id`, `get_account_details.customer_id: customer_id`, `schedule_payment.next_due: date`, `retrieve_policy.query: free_text` | `orders` keys `order_id`; `orders.*.customer_id`, `authenticated_customer_id: customer_id`; `payment_plans.*.next_due: date` |
| occiai | every `patient_id: patient_id`; `ask_clinical_question.question`, `summarize_for_ehr.text`, `escalate_to_clinician.reason: free_text`; `commit_to_ehr.draft_id: ehr_draft_id` | `patients`, `ehr_records` keys `patient_id`; `referrals` keys `referral_id`; `patients.*.patient_id`, `authenticated_patient_id: patient_id` |
| airbnb | `*.reservation_id: reservation_id`, `*.listing_id: listing_id`; `modify_booking.check_in`, `modify_booking.check_out`, `check_availability.date: date` | `reservations` keys `reservation_id`; `listings` keys `listing_id`; `reservations.*.check_in`, `reservations.*.check_out: date` |

Left undeclared on purpose: free-text-like arguments whose values may be
category labels (`escalate_to_human.topic`, `escalate_trust_safety.topic`),
`authenticated_actor_id` (a guest or a host), and list-valued fields such as
`listings.*.blocked_dates`.

## Changes outside this repository

### mini-agents (owns the target declarations)

- File: `src/mini_agents/declarations/<domain>/<variant>/value-facts.yaml`,
  one per domain and variant, beside `tools-list.json` and
  `runtime-spec.yaml`. Content: the domain's document above. Both variants of
  a domain take the same document while they share a tools list.
- The declaration files are generated (`runtime-spec.yaml` says
  `Generated by scripts/gen_declarations.py`), so the generator writes
  `value-facts.yaml` too, from a per-domain table kept beside the seed slots
  and the tool access table. `runtime-spec.yaml` (`declared-runtime-v1`) is
  unchanged.
- Optional, not required by the producer: typing the date arguments as
  `datetime.date` would also put `format: date` in the input schema. The
  scanner then adds that format to `value_facts` itself; the check still
  reads only `value_facts`.

### The orchestrator (owns discover)

- `DeclaredTarget` (`src/asago_orch/declared_target.py`) gains
  `value_facts: Path | None`, the `value-facts.yaml` beside the other
  declaration files when present, and lists it in `files`.
- `run/discover.py` `_commands`: when the target's declaration has a
  value-facts file, append `--value-facts <path>` to `scan_options`, so both
  `asago-target-scan file` (declared targets) and `asago-target-scan mcp`
  (live targets) pass it.
- `fingerprint_inputs`: the file's digest joins `declared_files` (declared
  targets) and `declaration_digests()` (live targets), so changing it
  invalidates a reused discover.
- No new contract: the scanner validates the file and the profile carries
  it.

### The consumer (mirrors the producer's contracts)

- Re-mirror `data/contracts/target-profile/` (the profile schema gains the
  optional `value_facts`; the kit gains invalid vectors for a value fact
  with no declaration, with null declarations, and naming an operation or
  argument the profile does not list, coded `value_fact_without_declaration`
  and `value_fact_unknown_argument` in `expected-violations.json`;
  `scripts/gen_target_profile_kit.py` regenerates the kit) and `data/contracts/scenario-handoff/` (the handoff
  schema gains the optional `semantic_failure_call`, with
  `valid/failure-call.json` and two invalid cases). Both fields are omitted
  when absent, so existing profiles and handoffs keep their bytes and
  digests. Both schemas close their objects, so a consumer on the old mirror
  rejects a profile or handoff that carries the new field: mirror before
  discover passes value facts or Stage 5 publishes a failure call.
- `tool-call-condition-v1` is unchanged: dates stay unorderable, and the
  producer refuses an ordering on declared dates instead of the consumer
  learning to order them.

## Rollout

1. Consumer re-mirrors both kits.
2. mini-agents adds `value-facts.yaml`; the orchestrator passes it to the
   scanner. Profiles discovered afterwards carry `value_facts`; their digest
   changes, and the observations and runs pair with the new digest as usual.
3. Stage 5 requests now require `failure_call` (an object or `null`) when the
   contract captures tool calls; scenarios generated afterwards may carry
   `semantic_failure_call`. Every such Stage 5 request differs from a
   recorded one (a new prompt paragraph and a new required schema property),
   so recorded Stage 5 responses do not replay for those requests.

Saved runs carry neither fact, so the offline sweep over them reports the
same counts before and after; the decided cases are pinned in
`tests/fixtures/condition_contradictions/`. The sweep's `--value-facts
TARGET_ID=PATH` checks saved runs as if their profiles declared the proposed
documents, without changing them. Over 1,142 saved `generate` output
directories (79,924 handoffs, 25,831 bound conditions; refused counts
scenarios, undecidable counts cases):

| Run | refused a / b / c | undecidable a / b / c |
| --- | --- | --- |
| before | 148 / 40 / 4 | 2350 / 942 / 98 |
| after, saved profiles | 148 / 40 / 4 | 2350 / 942 / 98 |
| after, proposed facts overlaid | 148 / 355 / 102 | 2350 / 57 / 0 |

Rule (a) cannot move on saved runs: no saved handoff carries a failure call.
