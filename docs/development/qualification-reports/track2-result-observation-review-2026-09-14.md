# Track 2 result-observation design review (2026-09-14)

Reviewed proposal: `7c077dc`, `feature/track2-result-observation`,
`ai/findings/result-sensitive-observation-spec-2026-09-14.md` in the separate
`asago-scenario-generator-wt-track2-result-observation` worktree. This is a
read-only review, not acceptance or implementation. The sixteen prototype
fixtures demonstrate the proposed evaluator; they do not validate production
transport or the future cross-repository implementation.

## Spec corrections required before implementation

1. **Make obligation authority consistent.** The opening at line 9 authorizes
   only reviewed forbidden/result entries, but line 139 explicitly permits
   proposed authority. Choose one rule and apply it at offer, post-draft
   admission, fixtures, and examples. The opening's reviewed-only rule is
   the narrower proposed scope; a reviewed result-shape contract does not
   independently review the obligation's meaning.
2. **Preserve old profiles explicitly.** Lines 221–237 promise existing
   profiles remain valid while adding an optional field to profile-v1.
   Current `_DigestModel.semantic_payload` includes default fields, and
   `canonical_json_bytes` does too. Absent `result_contracts` must be omitted
   from both serialization and digest payload (with old-byte/digest tests
   in both repos), or choose explicit new versioning. Re-issuing profiles
   that actually add contracts does not resolve accidental changes to old
   profiles lacking the field.
3. **Distinguish absence of detection from evidence of safe refusal.** Table
   rows 5/7 at lines 307–321 classify identity-only, missing-identity, and
   empty objects as safe. Arbitrary JSON errors or partial payloads can fit
   these shapes. Specify accepted refusal/redaction shapes and field-presence
   rules in the reviewed contract, or classify unrecognized/incomplete
   shapes as inconclusive. Do not infer safe handling from any decodable
   object lacking the selected identity. Wrong-record results also remain a
   non-detection of this exact record condition, not general safety.
4. **Make the remaining checks implementable.** Line 154 requires a
   deterministic safe-behavior contrast check over general prose without
   defining evidence or an algorithm. Keep that semantic assessment in the
   independent review unless a bounded typed check is specified. Define the
   path grammar and empty/missing semantics; record the reviewed source or
   explicit attestation supporting each identity/sensitive-path relationship.
   The current generic `result: string` output schema does not verify them.

## Runtime evidence gate

The existing pinned-runtime smoke prerequisite should demonstrate repeated
matching calls and distractor calls as well as safe/unsafe output shapes.
Verify that each recorded output belongs to its particular invocation, not
merely that outputs can be decoded. No live capture was authorized or made
in this integration. Preserve the distinction between source presence,
returned-information observation, attempt proxies, and executed state effects.

## Standards and integration

Do not merge the design's ignored `ai/findings/` path as a new tracked-ignored
file. Place its durable approved copy under tracked documentation while
preserving the local proposal and prototype evidence. The current producer
and consumer integration excludes `7c077dc`; no result-observer code or
profile-v1 amendment has been applied.
