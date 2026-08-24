"""Property tests pinning the typed access-provenance policy (cmps.6).

The deterministic actor-access policy
(``pipeline/generate/actor_access.py``) owns two contracts worth pinning
under broad input ranges:

- **Structural validation rules**: for every combination of actor type,
  ingress mode, access class, and evidence presence, exactly the rules the
  policy documents fire — access-class/ingress-mode incompatibility,
  incomplete indirect evidence, and the insider material-advantage
  requirement — and nothing else; no profile is needed for these.
- **Provenance construction**: ``build_actor_access_provenance`` derives
  ``ingress_mode`` from the canonical entry-point controllability (never
  LLM-inferred), passes LLM evidence through in the legacy path, and
  delegates typed source identity to the single authoritative
  source-influence path when the projection supplies one.

These properties are offline and deterministic; they never contact an
LLM endpoint.
"""

from __future__ import annotations

from hypothesis import given, settings, strategies as st

from asago_scenario_generator.models.scenario import (
    ActorAccessProvenance,
    ActorProfile,
)
from asago_scenario_generator.pipeline.generate.actor_access import (
    build_actor_access_provenance,
    validate_actor_access_provenance,
    Call0Response,
)
from asago_scenario_generator.pipeline.generate.constants import (
    _INSIDER_ACTOR_TYPES,
    ALL_ACTOR_TYPES,
)

_MAX_EXAMPLES = 60
_IDS = st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789-_", min_size=1, max_size=24)
_ACTOR_TYPES = tuple(sorted(ALL_ACTOR_TYPES))
_ACCESS_CLASSES = ("public", "authenticated", "privileged", "supply_chain")
_OPTIONAL_TEXT = st.one_of(st.none(), _IDS)


def _provenance(
    ingress_mode: str,
    access_class: str,
    *,
    has_source: bool,
    has_mechanism: bool,
    has_boundary: bool,
    has_material: bool,
    entry_point_id: str,
) -> ActorAccessProvenance:
    return ActorAccessProvenance(
        initial_entry_point_id=entry_point_id,
        ingress_mode=ingress_mode,  # type: ignore[arg-type]
        access_class=access_class,  # type: ignore[arg-type]
        influence_source="src-1" if has_source else None,
        influence_mechanism="staging" if has_mechanism else None,
        trust_boundary_id="tb-1" if has_boundary else None,
        material_insider_advantage="creds" if has_material else None,
    )


def _structural_expected_rules(
    actor_type: str,
    ingress_mode: str,
    access_class: str,
    *,
    has_source: bool,
    has_mechanism: bool,
    has_boundary: bool,
    has_material: bool,
) -> set[str]:
    """The documented structural rule set, computed independently."""
    expected: set[str] = set()
    if (ingress_mode == "direct" and access_class == "supply_chain") or (
        ingress_mode == "indirect" and access_class == "public"
    ):
        expected.add("access_class_ingress_mode_incompatible")
    if ingress_mode == "indirect" and not (
        has_source and has_mechanism and has_boundary
    ):
        expected.add("incomplete_indirect_evidence")
    if (
        ingress_mode == "direct"
        and actor_type in _INSIDER_ACTOR_TYPES
        and not has_material
    ):
        expected.add("missing_insider_advantage")
    return expected


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(
    actor_type=st.sampled_from(_ACTOR_TYPES),
    ingress_mode=st.sampled_from(("direct", "indirect")),
    access_class=st.sampled_from(_ACCESS_CLASSES),
    has_source=st.booleans(),
    has_mechanism=st.booleans(),
    has_boundary=st.booleans(),
    has_material=st.booleans(),
    entry_point_id=_IDS,
)
def test_validate_actor_access_provenance_structural_rules_are_exhaustive(
    actor_type: str,
    ingress_mode: str,
    access_class: str,
    has_source: bool,
    has_mechanism: bool,
    has_boundary: bool,
    has_material: bool,
    entry_point_id: str,
) -> None:
    """Exactly the documented structural rules fire — no more, no fewer."""
    profile = ActorProfile(
        actor_type=actor_type,
        capability_level="intermediate",
        beliefs=[],
        desires=[],
        intentions=[],
        resources=[],
        access=_provenance(
            ingress_mode,
            access_class,
            has_source=has_source,
            has_mechanism=has_mechanism,
            has_boundary=has_boundary,
            has_material=has_material,
            entry_point_id=entry_point_id,
        ),
    )
    expected = _structural_expected_rules(
        actor_type,
        ingress_mode,
        access_class,
        has_source=has_source,
        has_mechanism=has_mechanism,
        has_boundary=has_boundary,
        has_material=has_material,
    )

    violations = validate_actor_access_provenance(profile)

    assert {violation.rule for violation in violations} == expected
    # Deterministic validation: the same profile yields the same verdict.
    again = validate_actor_access_provenance(profile)
    assert [(v.rule, v.message) for v in again] == [
        (v.rule, v.message) for v in violations
    ]


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(actor_type=st.sampled_from(_ACTOR_TYPES))
def test_validate_actor_access_provenance_flags_missing_provenance(
    actor_type: str,
) -> None:
    """An actor profile without typed provenance fails with one rule."""
    profile = ActorProfile(
        actor_type=actor_type,
        capability_level="intermediate",
        beliefs=[],
        desires=[],
        intentions=[],
        resources=[],
        access=None,
    )

    violations = validate_actor_access_provenance(profile)

    assert [v.rule for v in violations] == ["missing_access_provenance"]


@st.composite
def builder_inputs(
    draw,
) -> tuple[
    str, str | None, Call0Response, list[dict[str, str | None]]
]:
    """Canonical EP identity, controllability, evidence, and projection paths."""
    entry_point_id = draw(_IDS)
    controllability = draw(
        st.sampled_from(("direct", "indirect", "system", None, "unexpected"))
    )
    response = Call0Response(
        actor_type=draw(st.sampled_from(_ACTOR_TYPES)),
        capability_level=draw(st.sampled_from(("novice", "advanced"))),
        beliefs=[draw(_IDS)],
        desires=[draw(_IDS)],
        intentions=[draw(_IDS)],
        resources=[],
        access_class=draw(st.sampled_from(_ACCESS_CLASSES)),
        influence_source=draw(_OPTIONAL_TEXT),
        influence_mechanism=draw(_OPTIONAL_TEXT),
        trust_boundary_id=draw(_OPTIONAL_TEXT),
        material_insider_advantage=draw(_OPTIONAL_TEXT),
    )
    path_count = draw(st.integers(min_value=0, max_value=2))
    complete = draw(st.booleans())
    paths: list[dict[str, str | None]] = []
    for index in range(path_count):
        path: dict[str, str | None] = {
            "source_id": f"src-{index}",
            "source_identity_kind": "entry_point",
            "boundary_id": f"tb-{index}",
        }
        if not complete:
            path["boundary_id"] = None
        paths.append(path)
    return entry_point_id, controllability, response, paths


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(inputs=builder_inputs())
def test_build_actor_access_provenance_delegates_canonical_identity(
    inputs: tuple[
        str, str | None, Call0Response, list[dict[str, str | None]]
    ],
) -> None:
    """Ingress mode is canonical; source identity follows the projection."""
    entry_point_id, controllability, response, paths = inputs

    def build(
        projection_context: dict[str, object] | None,
    ) -> ActorAccessProvenance:
        return build_actor_access_provenance(
            entry_point_id=entry_point_id,
            ep_controllability=controllability,
            actor_type=response.actor_type,
            resp=response,
            profile=None,
            projection_context=projection_context,
        )

    if controllability not in ("direct", "indirect"):
        for _ in (0, 1):
            try:
                build(None)
            except ValueError:
                pass
            else:
                raise AssertionError(
                    f"controllability {controllability!r} must not be ingress"
                )
        return

    complete_paths = [
        path
        for path in paths
        if all(path.get(key) is not None for key in ("source_id", "boundary_id"))
    ]
    if len(paths) > 1:
        for _ in (0, 1):
            try:
                build({"source_influence_paths": paths})
            except ValueError:
                pass
            else:
                raise AssertionError("multiple source-influence paths must fail")
        return

    if complete_paths:
        access = build({"source_influence_paths": paths})
        path = complete_paths[0]
        assert access.initial_entry_point_id == entry_point_id
        assert access.ingress_mode == controllability
        assert access.influence_source == path["source_id"]
        assert access.influence_source_kind == path["source_identity_kind"]
        assert access.influence_source_id == path["source_id"]
        assert access.trust_boundary_id == path["boundary_id"]
        assert access.influence_mechanism == response.influence_mechanism
        assert access.access_class == response.access_class
        assert build({"source_influence_paths": paths}) == access
        return

    # Legacy pass-through: no authoritative path, so LLM evidence survives.
    for projection_context in (None, {"source_influence_paths": []}):
        access = build(projection_context)
        assert access.initial_entry_point_id == entry_point_id
        assert access.ingress_mode == controllability
        assert access.access_class == response.access_class
        assert access.influence_source == response.influence_source
        assert access.influence_source_kind is None
        assert access.influence_source_id is None
        assert access.influence_mechanism == response.influence_mechanism
        assert access.trust_boundary_id == response.trust_boundary_id
        assert (
            access.material_insider_advantage
            == response.material_insider_advantage
        )
        assert build(projection_context) == access
