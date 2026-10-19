# attack-flow-2.0.0

`generate/output/report/attack-flow/<hazard-id>.json` holds the attack tree of
one hazard: the published scenarios that reach it, each as an ordered AND of its
conditions and attack steps, joined by an OR. The producer owns the contract;
the orchestrator mirrors this directory byte for byte, and its run reports draw
the trees from these files instead of re-deriving them. The consumer reads
none of them.

- `schema.json` is the schema. `valid/hazard.json` passes it: the bundle the
  writer produces for hazard `H-9` of the producer's `klarna-and-or` test
  fixture when only scenario `SCN-027` reaches it.
- The files follow the published Attack Flow 2.0.0 schema,
  <https://center-for-threat-informed-defense.github.io/attack-flow/stix/attack-flow-schema-2.0.0.json>,
  which the extension definition in each bundle names. That schema reaches the
  STIX common properties through remote references, so `schema.json` restates
  the subset the producer writes and validates offline. The producer depends on
  no STIX or Attack Flow package.

## Files

- One file per hazard that has a published scenario, named
  `<hazard-id>.json` with every character outside `A-Za-z0-9_.-` replaced by
  `-` (`H-9.json`). A hazard no scenario names has no file. A scenario that
  names several hazards appears in each hazard's file. A scenario can name a
  hazard that loss analysis lacks: that hazard still gets a file, but
  `policy-coverage.json` lists only loss-analysis hazards.
- A file is one STIX 2.1 `bundle`: JSON with sorted keys, two-space indent and a
  final newline. It is deterministic. Timestamps are a fixed instant, and every
  id is a version 5 UUID derived from the hazard id and the digests of its
  scenarios, so two renders of the same run are byte-identical.

## Objects

`objects` holds the Attack Flow `extension-definition` and the `identity` that
created it, the producer's `identity` (the creator of every other object),
exactly one `attack-flow`, and the tree's `attack-action`, `attack-operator`
and `attack-condition` objects. The scope is `attack-tree`. Every attack object
names the Attack Flow extension in `extensions`.

## Tree and edge directions

Edges run from child to parent.

- The hazard is the root `attack-action`. Its name is the hazard id and
  description, and it has no `effect_refs`.
- An `attack-operator` with `operator` `OR` has the root as its one effect.
- Each scenario is an `attack-action` whose `effect_refs` name the OR.
- An `attack-operator` with `operator` `AND` has the scenario's action as its
  one effect. An operator always has exactly one effect, and it is an
  `attack-action`.
- A scenario's attack steps, in order, are `attack-action` objects; each
  `effect_refs` the next, and the last, the scenario's unsafe control action,
  has the AND as its effect. A step may carry `technique_id` and `tactic_id`.
  An everyday-use check has no steps, so its unsafe control action is the whole
  chain.
- Each condition of a scenario (situation, attacker assumption, weak point) is an
  `attack-condition` whose `on_true_refs` name the scenario's action, not the
  AND: renderers fold an operator into the action it points at, and a condition
  that named the operator would render detached from the tree.
- The `attack-flow` object's `start_refs` list the leaves, the actions and
  conditions that no other object points at.

`schema.json` states the shape of each object. It cannot state that every
reference resolves to an object in the same bundle, that the tree has one root
(the one action without `effect_refs`), or that `start_refs` are exactly the
leaves. The writer guarantees them, and a reader may rely on them.
