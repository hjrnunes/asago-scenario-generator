"""Closed ``target-subject-model-v1`` companion and check-local identity rules.

Correction spec ``correction-spec-subject-record-20260912`` (accepted
revision 2).  Three objects stay separate:

- the **session subject** (spec 1.1): an observed string in TARGET-STATE
  plus the path it was read from; never a principal, role, or permission;
- the **record index** (spec 1.2): which JSON objects can be named, under
  strict container rules; never an authorization claim;
- the **subject model** (spec 1.3): an optional companion file that declares
  argument roles and record-subject relations and is consumed only when it
  is structurally valid **and** carries a reviewer-stamped acceptance
  envelope that pins the exact observation snapshot and execution-target
  profile the reviewer saw.

A digest identifies which subject-model bytes were present; it does not
accept them.  A proposed (unstamped), edited, or mismatched file fails
closed with a typed reason and never collapses to "no model".

This module is deliberately free of ``scenario_prod`` imports so the
system-model layer can apply the same session-subject rule when it derives
the session-identity process-model record.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import Field, ValidationError, model_validator

from asago_scenario_generator.models.canonical import (
    ClosedCanonicalModel,
    compute_framed_digest,
)

TARGET_SUBJECT_MODEL_FILENAME = "target-subject-model.yaml"
TARGET_SUBJECT_MODEL_SCHEMA_VERSION = "target-subject-model-v1"
TARGET_SUBJECT_MODEL_DIGEST_DOMAIN = "asago-scenario-generator:target-subject-model:v1"

_SHA256_PATTERN = r"^[0-9a-f]{64}$"

# Typed fail-closed reasons (spec 1.3 "Proposed versus accepted").
SUBJECT_MODEL_UNREVIEWED = "subject_model_unreviewed"
SUBJECT_MODEL_INVALID = "subject_model_invalid"
SUBJECT_MODEL_CONTENT_MISMATCH = "subject_model_content_mismatch"
SUBJECT_MODEL_OBSERVATIONS_MISMATCH = "subject_model_observations_mismatch"
SUBJECT_MODEL_PROFILE_MISMATCH = "subject_model_profile_mismatch"


class SubjectModelError(ValueError):
    """A fail-closed subject-model rejection with its typed reason."""

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(f"{reason}: {detail}")
        self.reason = reason
        self.detail = detail


# ---------------------------------------------------------------------------
# The session subject (spec 1.1): observation only


@dataclass(frozen=True)
class SessionSubject:
    """An observed TARGET-STATE string and the path it was read from.

    ``observed`` carries the exact path and value; ``unobserved`` and
    ``ambiguous`` carry neither (discovery never picks one of several
    candidate keys; the matched keys are retained in ``candidates`` as
    diagnostic evidence).
    """

    status: Literal["observed", "unobserved", "ambiguous"]
    path: tuple[str, ...] | None
    value: str | None
    source: Literal["TARGET-STATE"] | None
    rule: Literal["declared", "discovered"]
    candidates: tuple[str, ...] = ()

    @property
    def observed(self) -> bool:
        """Whether a unique session-subject string was observed."""
        return self.status == "observed"


_SESSION_KEY_RE = re.compile(r"^authenticated_.+_id$")


def state_value_at_path(state: Any, path: tuple[str, ...]) -> Any:
    """Resolve one path into parsed TARGET-STATE content, or ``None``."""
    value: Any = state
    for segment in path:
        if isinstance(value, dict) and segment in value:
            value = value[segment]
        elif isinstance(value, list):
            try:
                value = value[int(segment)]
            except (ValueError, IndexError):
                return None
        else:
            return None
    return value


def resolve_session_subject(
    state: Any,
    session_path: tuple[str, ...] | None = None,
) -> SessionSubject:
    """Apply the single session-subject precedence rule (spec 1.1).

    A declared ``session_path`` is the only session subject when present:
    it resolves to a non-empty string (``observed``) or it does not
    (``unobserved``), and other ``authenticated_*_id`` keys never make a
    declared result ambiguous.  Without a declaration, top-level keys
    matching ``^authenticated_.+_id$`` with non-empty string values are
    discovered: one key is ``observed``, none is ``unobserved``, and two or
    more are ``ambiguous``.  Non-mapping state is ``unobserved`` under
    whichever rule is in force.
    """
    if session_path is not None:
        value = state_value_at_path(state, session_path)
        if isinstance(value, str) and value:
            return SessionSubject(
                status="observed",
                path=tuple(session_path),
                value=value,
                source="TARGET-STATE",
                rule="declared",
            )
        return SessionSubject(
            status="unobserved",
            path=None,
            value=None,
            source=None,
            rule="declared",
        )
    if not isinstance(state, dict):
        return SessionSubject(
            status="unobserved",
            path=None,
            value=None,
            source=None,
            rule="discovered",
        )
    matches = sorted(
        key
        for key, value in state.items()
        if _SESSION_KEY_RE.match(key) and isinstance(value, str) and value
    )
    if len(matches) == 1:
        key = matches[0]
        return SessionSubject(
            status="observed",
            path=(key,),
            value=state[key],
            source="TARGET-STATE",
            rule="discovered",
        )
    if not matches:
        return SessionSubject(
            status="unobserved",
            path=None,
            value=None,
            source=None,
            rule="discovered",
        )
    return SessionSubject(
        status="ambiguous",
        path=None,
        value=None,
        source=None,
        rule="discovered",
        candidates=tuple(matches),
    )


# ---------------------------------------------------------------------------
# The record index (spec 1.2): addressability only


@dataclass(frozen=True)
class RecordLookup:
    """One address lookup result."""

    status: Literal["found", "not_found", "ambiguous", "not_addressable"]
    record: dict[str, Any] | None = None


class RecordIndex:
    """Which TARGET-STATE objects can be named as records (spec 1.2).

    A mapping whose values are all mappings yields one record per child,
    addressed by the map key only (never by an embedded id field).  A
    sequence of mappings is addressable only when the accepted subject
    model declares ``identifier_field`` for that collection; elements whose
    identifier is missing or not a string carry no address, and duplicate
    addresses become ``ambiguous``.  Dicts of lists, lists of non-dicts,
    and scalars are not record collections.  No identifier is ever guessed.
    """

    def __init__(
        self,
        state: Any,
        model: "TargetSubjectModel | None" = None,
    ) -> None:
        self._records: dict[str, dict[str, dict[str, Any]]] = {}
        self._ambiguous: dict[str, frozenset[str]] = {}
        if not isinstance(state, dict):
            return
        identifier_fields = (
            {
                declaration.name: declaration.identifier_field
                for declaration in model.collections
                if declaration.identifier_field is not None
            }
            if model is not None
            else {}
        )
        for name, container in state.items():
            if isinstance(container, dict):
                if container and all(
                    isinstance(value, dict) for value in container.values()
                ):
                    self._records[name] = {
                        str(key): value for key, value in container.items()
                    }
            elif isinstance(container, list):
                field_name = identifier_fields.get(name)
                if field_name is None:
                    continue
                if not all(isinstance(item, dict) for item in container):
                    continue
                addresses: dict[str, dict[str, Any]] = {}
                ambiguous: set[str] = set()
                for item in container:
                    value = item.get(field_name)
                    if not isinstance(value, str) or not value:
                        continue
                    if value in addresses:
                        ambiguous.add(value)
                    else:
                        addresses[value] = item
                for duplicate in ambiguous:
                    addresses.pop(duplicate, None)
                self._records[name] = addresses
                if ambiguous:
                    self._ambiguous[name] = frozenset(ambiguous)

    @property
    def collections(self) -> tuple[str, ...]:
        """The addressable collection names, in canonical order."""
        return tuple(sorted(self._records))

    def is_addressable(self, collection: str) -> bool:
        """Whether the collection yields record addresses at all."""
        return collection in self._records

    def is_ambiguous(self, collection: str, address: str) -> bool:
        """Whether the address names two or more records in the collection."""
        return address in self._ambiguous.get(collection, frozenset())

    def lookup(self, collection: str, address: str) -> RecordLookup:
        """Resolve one address inside one named collection."""
        if collection not in self._records:
            return RecordLookup("not_addressable")
        if self.is_ambiguous(collection, address):
            return RecordLookup("ambiguous")
        record = self._records[collection].get(address)
        if record is None:
            return RecordLookup("not_found")
        return RecordLookup("found", record)


# ---------------------------------------------------------------------------
# The closed subject-model file (spec 1.3)


class SubjectModelCollection(ClosedCanonicalModel):
    """One declared TARGET-STATE collection.

    ``identifier_field`` is allowed only for a sequence-of-dicts
    collection; it names the element field whose string value is the
    record address.  Mapping collections leave it null.
    """

    name: str = Field(min_length=1)
    identifier_field: str | None = Field(default=None, min_length=1)


class SubjectArgumentRole(ClosedCanonicalModel):
    """How one tool argument participates in a subject comparison."""

    tool: str = Field(min_length=1)
    argument: str = Field(min_length=1)
    role: Literal["record_address", "session_subject"]
    # ``record_address`` looks the argument value up only in these declared
    # collections; ``session_subject`` compares the value directly and
    # carries no collections.
    collections: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_role_shape(self) -> "SubjectArgumentRole":
        if self.role == "record_address" and not self.collections:
            raise ValueError(
                f"record_address role {self.tool}.{self.argument} requires a "
                "non-empty collections list"
            )
        if self.role == "session_subject" and self.collections:
            raise ValueError(
                f"session_subject role {self.tool}.{self.argument} forbids collections"
            )
        return self


class SubjectRelation(ClosedCanonicalModel):
    """One comparable-string resolution declared for a collection.

    ``record_subject``: the named field on an indexed record is a string
    comparable to the session subject value.  ``hop``: the named field is
    an address in ``to_collection`` and the comparable string is
    ``then_field`` on that record (one hop).  ``source`` is provenance
    text: stored and shown, never evaluated, never permission.
    """

    id: str = Field(min_length=1)
    collection: str = Field(min_length=1)
    field: str = Field(min_length=1)
    kind: Literal["record_subject", "hop"]
    to_collection: str | None = Field(default=None, min_length=1)
    then_field: str | None = Field(default=None, min_length=1)
    source: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_kind_shape(self) -> "SubjectRelation":
        if self.kind == "hop":
            if self.to_collection is None or self.then_field is None:
                raise ValueError(
                    f"hop relation {self.id} requires to_collection and then_field"
                )
        elif self.to_collection is not None or self.then_field is not None:
            raise ValueError(
                f"record_subject relation {self.id} forbids to_collection and "
                "then_field"
            )
        return self


class TargetSubjectModelAcceptance(ClosedCanonicalModel):
    """The reviewer acceptance envelope for one subject-model file.

    Bindings-style ``reviewed_by`` / ``reviewed_on`` stamps plus the exact
    target-input digests the reviewer accepted and the framed content
    digest of the file excluding ``content_digest`` itself.  Both reviewer
    stamps together make the file accepted; both absent makes it proposed
    (``subject_model_unreviewed``); one without the other fails schema
    validation (``subject_model_invalid``).
    """

    reviewed_by: str | None = Field(default=None, min_length=1)
    reviewed_on: date | None = None
    observations_digest: str = Field(pattern=_SHA256_PATTERN)
    execution_target_profile_digest: str = Field(pattern=_SHA256_PATTERN)
    content_digest: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_stamps_together(self) -> "TargetSubjectModelAcceptance":
        if (self.reviewed_by is None) != (self.reviewed_on is None):
            raise ValueError(
                "reviewed_by and reviewed_on are required together: one "
                "without the other is invalid"
            )
        return self

    @property
    def reviewed(self) -> bool:
        """Whether the envelope carries both reviewer stamps."""
        return self.reviewed_by is not None and self.reviewed_on is not None


class TargetSubjectModel(ClosedCanonicalModel):
    """The closed ``target-subject-model-v1`` companion declaration."""

    schema_version: Literal[TARGET_SUBJECT_MODEL_SCHEMA_VERSION] = (
        TARGET_SUBJECT_MODEL_SCHEMA_VERSION
    )
    # Omitted session_path means discovery (spec 1.1).
    session_path: tuple[str, ...] | None = Field(default=None, min_length=1)
    # Prompt wording label only; never an authorization claim.
    subject_noun: str | None = Field(default=None, min_length=1)
    collections: tuple[SubjectModelCollection, ...] = ()
    argument_roles: tuple[SubjectArgumentRole, ...] = ()
    relations: tuple[SubjectRelation, ...] = ()
    # Omitted acceptance makes the file proposed, not accepted.
    acceptance: TargetSubjectModelAcceptance | None = None

    @model_validator(mode="after")
    def validate_structure(self) -> "TargetSubjectModel":
        names = [declaration.name for declaration in self.collections]
        if len(names) != len(set(names)):
            raise ValueError("collections must not repeat a name")
        declared = set(names)
        seen_roles: set[tuple[str, str]] = set()
        for role in self.argument_roles:
            key = (role.tool, role.argument)
            if key in seen_roles:
                raise ValueError(
                    f"argument role {role.tool}.{role.argument} is declared twice"
                )
            seen_roles.add(key)
            for collection in role.collections:
                if collection not in declared:
                    raise ValueError(
                        f"argument role {role.tool}.{role.argument} names "
                        f"undeclared collection {collection!r}"
                    )
        seen_relations: set[str] = set()
        relation_collections: set[str] = set()
        for relation in self.relations:
            if relation.id in seen_relations:
                raise ValueError(f"relation id {relation.id!r} is declared twice")
            seen_relations.add(relation.id)
            if relation.collection not in declared:
                raise ValueError(
                    f"relation {relation.id!r} names undeclared collection "
                    f"{relation.collection!r}"
                )
            if relation.collection in relation_collections:
                raise ValueError(
                    f"collection {relation.collection!r} carries competing "
                    "relations; one collection resolves at most one "
                    "comparable string"
                )
            relation_collections.add(relation.collection)
        return self

    # -- lookups used by the operator overlay and oracle resolution ---------

    def role_for(self, tool: str, argument: str) -> SubjectArgumentRole | None:
        """Return the declared role for one tool argument, if any."""
        return next(
            (
                role
                for role in self.argument_roles
                if role.tool == tool and role.argument == argument
            ),
            None,
        )

    def roles_for_tool(self, tool: str) -> tuple[SubjectArgumentRole, ...]:
        """Return every declared argument role on one tool."""
        return tuple(role for role in self.argument_roles if role.tool == tool)

    def relation_for(self, collection: str) -> SubjectRelation | None:
        """Return the one relation declared for a collection, if any."""
        return next(
            (
                relation
                for relation in self.relations
                if relation.collection == collection
            ),
            None,
        )

    def owner_field_names(self) -> frozenset[str]:
        """The record-subject fields and hop target fields (spec 4.3).

        Conversation contradicted-state checks match used paths against
        these declared leaves instead of any hardcoded field name.
        """
        return frozenset(
            [
                relation.field
                for relation in self.relations
                if relation.kind == "record_subject"
            ]
            + [
                relation.then_field
                for relation in self.relations
                if relation.kind == "hop" and relation.then_field is not None
            ]
        )

    # -- digest and target-input validation ---------------------------------

    def payload_for_digest(self) -> dict[str, Any]:
        """The file content covered by the acceptance content digest.

        Everything except ``acceptance.content_digest`` itself (the same
        self-exclusion pattern as ``TargetDerivedStructure.semantic_digest``).
        """
        payload = self.model_dump(mode="json", exclude_none=True)
        acceptance = payload.get("acceptance")
        if isinstance(acceptance, dict):
            payload["acceptance"] = {
                key: value
                for key, value in acceptance.items()
                if key != "content_digest"
            }
        return payload

    def compute_content_digest(self) -> str:
        """Compute the version-framed content identity of the file."""
        return compute_framed_digest(
            TARGET_SUBJECT_MODEL_DIGEST_DOMAIN, self.payload_for_digest()
        )

    def validate_against_target(
        self,
        state: Any,
        profile: Any,
    ) -> None:
        """Fail closed (``subject_model_invalid``) on target-input errors.

        ``state`` is the parsed TARGET-STATE mapping (``None`` when it is
        not a JSON object); ``profile`` is the run's execution target
        profile.  Collections must be top-level TARGET-STATE keys,
        ``identifier_field`` is allowed only on a sequence of dicts, every
        role names an observed tool and one of its argument names, and a
        hop's ``to_collection`` must exist in TARGET-STATE.
        """
        state_keys = set(state) if isinstance(state, dict) else set()
        for declaration in self.collections:
            if declaration.name not in state_keys:
                raise SubjectModelError(
                    SUBJECT_MODEL_INVALID,
                    f"collection {declaration.name!r} is not a top-level "
                    "TARGET-STATE key",
                )
            if declaration.identifier_field is not None:
                container = state[declaration.name]
                if not (
                    isinstance(container, list)
                    and all(isinstance(item, dict) for item in container)
                ):
                    raise SubjectModelError(
                        SUBJECT_MODEL_INVALID,
                        f"collection {declaration.name!r} declares "
                        "identifier_field but is not a sequence of records",
                    )
        for role in self.argument_roles:
            arguments = _profile_argument_names(profile, role.tool)
            if arguments is None:
                raise SubjectModelError(
                    SUBJECT_MODEL_INVALID,
                    f"argument role names unknown tool {role.tool!r}",
                )
            if role.argument not in arguments:
                raise SubjectModelError(
                    SUBJECT_MODEL_INVALID,
                    f"argument role names unknown argument {role.argument!r} "
                    f"on tool {role.tool!r}",
                )
        for relation in self.relations:
            if relation.kind == "hop" and relation.to_collection not in state_keys:
                raise SubjectModelError(
                    SUBJECT_MODEL_INVALID,
                    f"hop relation {relation.id!r} names unknown collection "
                    f"{relation.to_collection!r}",
                )

    def verify_acceptance(
        self,
        *,
        observations_digest: str,
        execution_target_profile_digest: str,
    ) -> None:
        """Fail closed unless the acceptance envelope matches this run.

        A missing envelope, or one whose reviewer stamps are both absent,
        is proposed (``subject_model_unreviewed``), not silently dropped.
        A stamped file whose content no longer matches its declared digest
        is ``subject_model_content_mismatch``; target inputs that differ
        from the reviewer's stamps are the respective mismatches.
        """
        if self.acceptance is None or not self.acceptance.reviewed:
            raise SubjectModelError(
                SUBJECT_MODEL_UNREVIEWED,
                "the target subject model carries no reviewer acceptance "
                "stamps; a proposed file does not authorize "
                "owner_differs_from_session",
            )
        if self.acceptance.content_digest != self.compute_content_digest():
            raise SubjectModelError(
                SUBJECT_MODEL_CONTENT_MISMATCH,
                "the declared acceptance content_digest no longer matches "
                "the file content; restamping is required after edits",
            )
        if self.acceptance.observations_digest != observations_digest:
            raise SubjectModelError(
                SUBJECT_MODEL_OBSERVATIONS_MISMATCH,
                "the acceptance observations_digest does not equal this "
                "run's target observation content digest",
            )
        if self.acceptance.execution_target_profile_digest != (
            execution_target_profile_digest
        ):
            raise SubjectModelError(
                SUBJECT_MODEL_PROFILE_MISMATCH,
                "the acceptance execution_target_profile_digest does not "
                "equal this run's execution target profile digest",
            )


def _profile_argument_names(profile: Any, tool: str) -> tuple[str, ...] | None:
    """Return one profile tool's argument names, or ``None`` when unknown."""
    for resource in getattr(profile, "resources", ()):
        if getattr(resource, "tool_name", None) == tool:
            return tuple(getattr(resource, "argument_names", ()) or ())
    return None


def parse_target_subject_model(payload: Any) -> TargetSubjectModel:
    """Validate one decoded subject-model payload, failing closed.

    Every structural defect — a non-mapping payload, a schema violation,
    one reviewer stamp without the other, competing relations on one
    collection — is ``subject_model_invalid``; nothing is coerced or
    repaired.
    """
    if not isinstance(payload, dict):
        raise SubjectModelError(
            SUBJECT_MODEL_INVALID,
            "the target subject model must be a YAML/JSON mapping",
        )
    try:
        return TargetSubjectModel.model_validate(payload)
    except ValidationError as exc:
        raise SubjectModelError(
            SUBJECT_MODEL_INVALID,
            f"the target subject model is not structurally valid: {exc}",
        ) from exc


def load_target_subject_model(
    path: str | Path,
    *,
    observations_digest: str,
    execution_target_profile_digest: str,
    state: Any,
    profile: Any,
) -> TargetSubjectModel:
    """Load one subject-model file that is structurally valid and accepted.

    The file is absent (the caller never reaches here), proposed, accepted,
    or invalid (spec 1.3).  Structural validation (including the
    target-input checks against ``state`` and ``profile``) runs before the
    acceptance envelope, so a malformed file is invalid even when stamped,
    and a valid unstamped file fails as ``subject_model_unreviewed`` rather
    than silently degrading to "no model".
    """
    path = Path(path)
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SubjectModelError(
            SUBJECT_MODEL_INVALID,
            f"cannot read the target subject model file: {exc}",
        ) from exc
    try:
        payload = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise SubjectModelError(
            SUBJECT_MODEL_INVALID,
            f"the target subject model is not valid YAML: {exc}",
        ) from exc
    model = parse_target_subject_model(payload)
    model.validate_against_target(state, profile)
    model.verify_acceptance(
        observations_digest=observations_digest,
        execution_target_profile_digest=execution_target_profile_digest,
    )
    return model


# ---------------------------------------------------------------------------
# Comparable-string resolution (spec 1.4)


@dataclass(frozen=True)
class ComparableResolution:
    """The outcome of resolving one ``owner_differs_from_session`` operand."""

    status: Literal["ok", "no_role", "unresolved", "session_unobserved"]
    form: Literal["subject", "record", "hop"] | None = None
    comparable: str | None = None
    relation: SubjectRelation | None = None
    collection: str | None = None
    detail: str = ""


def resolve_comparable_string(
    *,
    model: TargetSubjectModel | None,
    index: RecordIndex,
    session: SessionSubject,
    tool: str,
    argument: str,
    value: str,
) -> ComparableResolution:
    """Resolve the string one ``owner_differs_from_session`` draft compares.

    The argument role for this exact tool and argument selects the form:
    ``session_subject`` compares the value directly; ``record_address``
    locates a unique record in the role's collections and applies that
    collection's one declared relation (direct field or one hop).  No role,
    no unique record, a missing relation, a broken hop, or an unobserved
    session subject each resolve to a typed non-``ok`` status; nothing is
    guessed from field names.
    """
    if model is None:
        return ComparableResolution(
            "no_role",
            detail="no accepted target subject model declares argument roles",
        )
    role = model.role_for(tool, argument)
    if role is None:
        return ComparableResolution(
            "no_role",
            detail=(
                f"argument {argument!r} on tool {tool!r} has no declared "
                "record_address or session_subject role"
            ),
        )
    if role.role == "session_subject":
        if not session.observed:
            return ComparableResolution(
                "session_unobserved",
                form="subject",
                detail="the session subject is not observed",
            )
        return ComparableResolution("ok", form="subject", comparable=value)

    found: list[tuple[str, dict[str, Any]]] = []
    for collection in role.collections:
        lookup = index.lookup(collection, value)
        if lookup.status == "ambiguous":
            return ComparableResolution(
                "unresolved",
                collection=collection,
                detail=(f"address {value!r} is ambiguous in collection {collection!r}"),
            )
        if lookup.status == "found" and lookup.record is not None:
            found.append((collection, lookup.record))
    if len(found) > 1:
        return ComparableResolution(
            "unresolved",
            detail=(
                f"address {value!r} matches more than one of the role's "
                f"collections {list(role.collections)}"
            ),
        )
    if not found:
        return ComparableResolution(
            "unresolved",
            detail=(
                f"address {value!r} was not found in the role's collections "
                f"{list(role.collections)}"
            ),
        )
    collection, record = found[0]
    relation = model.relation_for(collection)
    if relation is None:
        return ComparableResolution(
            "unresolved",
            collection=collection,
            detail=(f"collection {collection!r} declares no record-subject relation"),
        )
    if relation.kind == "record_subject":
        comparable = record.get(relation.field)
        if not isinstance(comparable, str) or not comparable:
            return ComparableResolution(
                "unresolved",
                form="record",
                relation=relation,
                collection=collection,
                detail=(
                    f"record {value!r} in {collection!r} has no string "
                    f"{relation.field!r}"
                ),
            )
        form: Literal["record", "hop"] = "record"
    else:
        link = record.get(relation.field)
        if not isinstance(link, str) or not link:
            return ComparableResolution(
                "unresolved",
                form="hop",
                relation=relation,
                collection=collection,
                detail=(
                    f"record {value!r} in {collection!r} has no string hop "
                    f"link {relation.field!r}"
                ),
            )
        target = index.lookup(relation.to_collection or "", link)
        if target.status != "found" or target.record is None:
            return ComparableResolution(
                "unresolved",
                form="hop",
                relation=relation,
                collection=collection,
                detail=(
                    f"hop target {link!r} in {relation.to_collection!r} is "
                    f"{target.status}"
                ),
            )
        comparable = target.record.get(relation.then_field or "")
        if not isinstance(comparable, str) or not comparable:
            return ComparableResolution(
                "unresolved",
                form="hop",
                relation=relation,
                collection=collection,
                detail=(
                    f"hop target {link!r} in {relation.to_collection!r} has "
                    f"no string {relation.then_field!r}"
                ),
            )
        form = "hop"
    if not session.observed:
        return ComparableResolution(
            "session_unobserved",
            form=form,
            relation=relation,
            collection=collection,
            detail="the session subject is not observed",
        )
    return ComparableResolution(
        "ok",
        form=form,
        comparable=comparable,
        relation=relation,
        collection=collection,
    )


__all__ = [
    "ComparableResolution",
    "RecordIndex",
    "RecordLookup",
    "SessionSubject",
    "SubjectArgumentRole",
    "SubjectModelCollection",
    "SubjectModelError",
    "SubjectRelation",
    "TARGET_SUBJECT_MODEL_DIGEST_DOMAIN",
    "TARGET_SUBJECT_MODEL_FILENAME",
    "TARGET_SUBJECT_MODEL_SCHEMA_VERSION",
    "TargetSubjectModel",
    "TargetSubjectModelAcceptance",
    "SUBJECT_MODEL_CONTENT_MISMATCH",
    "SUBJECT_MODEL_INVALID",
    "SUBJECT_MODEL_OBSERVATIONS_MISMATCH",
    "SUBJECT_MODEL_PROFILE_MISMATCH",
    "SUBJECT_MODEL_UNREVIEWED",
    "load_target_subject_model",
    "parse_target_subject_model",
    "resolve_comparable_string",
    "resolve_session_subject",
    "state_value_at_path",
]
