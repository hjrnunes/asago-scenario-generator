"""Pydantic models for the Capability Profile artifact.

The capability profile is produced by Stage 1 (Capability Profile Inference)
and optionally enriched by Stage 2.  It captures structural properties of the
system under assessment that determine which threat families are in scope and
how specific the generated scenarios can be.

Architecture model: Schneider's five-zone model
  input            = Input Surfaces
  reasoning        = Planning & Reasoning
  tool_execution   = Tool Execution
  memory           = Memory & State
  inter_agent      = Inter-Agent Communication
"""

from __future__ import annotations

import hashlib
import logging
import re
from enum import Enum
from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    computed_field,
    field_validator,
    model_validator,
)

from .resource_operations import ResourceOperation

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Zone constants
# ---------------------------------------------------------------------------

ZONE_NAMES: tuple[str, ...] = (
    "input",
    "reasoning",
    "tool_execution",
    "memory",
    "inter_agent",
)

# ---------------------------------------------------------------------------
# OWASP KC sub-code constants
# ---------------------------------------------------------------------------

VALID_KC_SUBCODES: frozenset[str] = frozenset(
    {
        "KC1.1",
        "KC1.2",
        "KC1.3",
        "KC1.4",
        "KC2.1",
        "KC2.2",
        "KC2.3",
        "KC3.1",
        "KC3.2",
        "KC3.3",
        "KC3.4",
        "KC4.1",
        "KC4.2",
        "KC4.3",
        "KC4.4",
        "KC4.5",
        "KC4.6",
        "KC5.1",
        "KC5.2",
        "KC5.3",
        "KC6.1.1",
        "KC6.1.2",
        "KC6.2.1",
        "KC6.2.2",
        "KC6.3.1",
        "KC6.3.2",
        "KC6.3.3",
        "KC6.4",
        "KC6.5",
        "KC6.6",
        "KC6.7",
    }
)

# ---------------------------------------------------------------------------
# asago-scenario-generator KC extensions — NOT from OWASP.
# These gate attack patterns requiring structural capabilities beyond
# standard OWASP KC codes. KCX-prefixed codes are asago-scenario-generator-specific
# and are NOT part of the OWASP Agentic AI taxonomy.
# ---------------------------------------------------------------------------

KCX_SUBCODES: dict[str, str] = {
    "KCX-PRIV": ("System has dynamic privilege tiers or permission escalation paths"),
    "KCX-XAUTH": (
        "System has cross-boundary credential propagation between trust domains"
    ),
    "KCX-PMEM": ("System has persistent memory architecture (cross-session state)"),
    "KCX-SHMEM": ("System has shared writable memory accessible to multiple agents"),
    "KCX-MAGENT": ("System has multi-agent or outbound inter-agent communication"),
    "KCX-VSTORE": ("System has vector store or RAG write access"),
    "KCX-HITL": ("System has human-in-the-loop review or approval controls"),
    "KCX-AUDIT": ("System has exploitable audit or logging architecture"),
    "KCX-PSTATE": (
        "System has persistent state enabling self-model or self-preservation"
    ),
}

KCX_PREFIX = "KCX-"

# ---------------------------------------------------------------------------
# Human-readable names for all KC sub-codes.
# Source of truth: profile_system.j2 KC taxonomy.
# Used by downstream prompts to make opaque codes intelligible to the LLM.
# ---------------------------------------------------------------------------

KC_SUBCODE_NAMES: dict[str, str] = {
    # KC1 — Language Models
    "KC1.1": "Large Language Model (LLM)",
    "KC1.2": "Multimodal LLM (MLLM)",
    "KC1.3": "Small Language Model (SLM)",
    "KC1.4": "Domain-specific or fine-tuned model",
    # KC2 — Orchestration
    "KC2.1": "Predefined workflows",
    "KC2.2": "Hierarchical planning",
    "KC2.3": "Multi-agent collaboration",
    # KC3 — Reasoning / Planning
    "KC3.1": "Structured planning (ReWoo, Plan-and-Execute)",
    "KC3.2": "ReAct — interleaved reasoning and action",
    "KC3.3": "Chain of Thought (CoT)",
    "KC3.4": "Tree of Thoughts (ToT)",
    # KC4 — Memory
    "KC4.1": "In-agent, session-only memory",
    "KC4.2": "Cross-agent, session-only memory",
    "KC4.3": "In-agent, cross-session memory",
    "KC4.4": "Cross-agent, cross-session memory",
    "KC4.5": "In-agent, cross-user memory",
    "KC4.6": "Cross-agent, cross-user memory",
    # KC5 — Tool Integration Framework
    "KC5.1": "Flexible libraries / SDK",
    "KC5.2": "Managed platform",
    "KC5.3": "Managed API",
    # KC6 — Operational Environment
    "KC6.1.1": "Limited API access",
    "KC6.1.2": "Extensive API access",
    "KC6.2.1": "Limited code execution",
    "KC6.2.2": "Extensive code execution",
    "KC6.3.1": "Database read-only",
    "KC6.3.2": "Database full CRUD",
    "KC6.3.3": "RAG context data sources",
    "KC6.4": "Web / browser access",
    "KC6.5": "PC / filesystem operations",
    "KC6.6": "Critical systems (SCADA, ICS)",
    "KC6.7": "IoT device control",
}

ZONE_DISPLAY_NAMES: dict[str, str] = {
    "input": "Input Surfaces",
    "reasoning": "Planning & Reasoning",
    "tool_execution": "Tool Execution",
    "memory": "Memory & State",
    "inter_agent": "Inter-Agent Communication",
}


def build_kc_subcodes_display(kc_subcodes: list[str]) -> dict[str, str]:
    """Build a display dict mapping each KC sub-code to its description.

    Looks up each code in ``KC_SUBCODE_NAMES`` (OWASP codes) and
    ``KCX_SUBCODES`` (asago-scenario-generator extensions).  Unknown codes fall
    back to the code string itself.

    Args:
        kc_subcodes: List of KC sub-code strings.

    Returns:
        Dict mapping each code to its human-readable description.
    """
    display: dict[str, str] = {}
    for code in kc_subcodes:
        if code in KC_SUBCODE_NAMES:
            display[code] = KC_SUBCODE_NAMES[code]
        elif code in KCX_SUBCODES:
            display[code] = KCX_SUBCODES[code]
        else:
            display[code] = code
    return display


def inject_kc_subcodes_display(data: dict) -> dict:
    """Inject ``kc_subcodes_display`` into a dumped profile dict.

    Post-processing hook for ``write_yaml`` — adds a companion
    ``kc_subcodes_display`` field mapping each KC sub-code to its
    human-readable description, using :func:`build_kc_subcodes_display`.

    STPA and preparation persistence adapters call this shared function so
    that the injection logic is defined in exactly one place.
    """
    kc_subcodes = data.get("kc_subcodes")
    if kc_subcodes is not None:
        data["kc_subcodes_display"] = build_kc_subcodes_display(kc_subcodes)
    return data


# ---------------------------------------------------------------------------
# Zone derivation from KC sub-codes
# ---------------------------------------------------------------------------


def derive_zones_from_kc(kc_subcodes: list[str]) -> list[str]:
    """Derive zones_active from KC sub-codes.

    Mapping logic:
    - KC1.*/KC3.* -> input + reasoning (always present since KC1.* is mandatory)
    - KC2.1/KC2.2 -> reasoning (already covered by default)
    - KC2.3 -> inter_agent
    - KC4.1/KC4.2 -> NO zone activation (session-only memory, not persistent)
    - KC4.3-KC4.6 -> memory (cross-session persistence)
    - KC5.* -> tool_execution
    - KC6.* -> tool_execution
    """
    zones: set[str] = {"input", "reasoning"}  # always present (KC1.* is mandatory)
    for kc in kc_subcodes:
        if kc.startswith("KC4.") and kc not in ("KC4.1", "KC4.2"):
            zones.add("memory")
        elif kc.startswith(("KC5.", "KC6.")):
            zones.add("tool_execution")
        elif kc == "KC2.3":
            zones.add("inter_agent")
    return sorted(zones)


# KC4 sub-codes that imply cross-session persistence (not session-only)
_KC4_PERSISTENT: frozenset[str] = frozenset({"KC4.3", "KC4.4", "KC4.5", "KC4.6"})


_KC_MULTI_AGENT: frozenset[str] = frozenset({"KC2.3", "KCX-MAGENT"})
_KC_HITL: frozenset[str] = frozenset({"KCX-HITL"})

# Legacy field names that are now computed from kc_subcodes on CapabilityProfile.
_LEGACY_BOOL_FIELDS: frozenset[str] = frozenset(
    {
        "has_persistent_memory",
        "multi_agent",
        "hitl",
    }
)


def _legacy_flag_values(kc_subcodes: list[str]) -> dict[str, bool]:
    """Derive the computed boolean flags from KC sub-codes.

    Shared by the ``CapabilityProfile`` computed fields and the legacy
    input stripper so the two derivations can never drift apart.
    """
    kc_set = set(kc_subcodes)
    return {
        "has_persistent_memory": bool(kc_set & _KC4_PERSISTENT) or "KCX-PMEM" in kc_set,
        "multi_agent": bool(kc_set & _KC_MULTI_AGENT),
        "hitl": bool(kc_set & _KC_HITL),
    }


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class ConfidenceLevel(str, Enum):
    """How well the use-case description supported Stage 1 inferences."""

    high = "high"
    medium = "medium"
    low = "low"


class DataSensitivity(str, Enum):
    """Sensitivity level for data accessible through a tool or integration."""

    none = "none"
    low = "low"
    medium = "medium"
    high = "high"


class BoundaryConfidence(str, Enum):
    """Whether a trust boundary was explicit, inferred, or hypothesized."""

    explicit = "explicit"
    inferred = "inferred"
    hypothesized = "hypothesized"


class MemoryType(str, Enum):
    """Category of memory mechanism."""

    conversation_history = "conversation_history"
    vector_store = "vector_store"
    key_value_store = "key_value_store"
    relational_db = "relational_db"
    knowledge_graph = "knowledge_graph"
    session_cache = "session_cache"
    other = "other"


class MemoryScope(str, Enum):
    """Whether memory is isolated per user, shared, or global."""

    per_user = "per_user"
    shared = "shared"
    global_ = "global"


class MemoryPersistence(str, Enum):
    """How long data persists in a memory mechanism."""

    session = "session"
    short_term = "short_term"
    long_term = "long_term"
    permanent = "permanent"


class IntegrationType(str, Enum):
    """How the agent connects to an external system."""

    api = "api"
    database = "database"
    message_queue = "message_queue"
    file_system = "file_system"
    web_service = "web_service"
    other = "other"


class AuthMethod(str, Enum):
    """Authentication mechanism used by an external integration."""

    api_key = "api_key"
    oauth = "oauth"
    service_account = "service_account"
    none = "none"
    unknown = "unknown"


# ---------------------------------------------------------------------------
# Stage 2 sub-models
# ---------------------------------------------------------------------------


def _canonical_supported_operations(
    value: tuple[ResourceOperation, ...] | None,
) -> tuple[ResourceOperation, ...] | None:
    """Keep reviewed operation sets unique and serialization-stable."""
    if value is None:
        return None
    if len(value) != len(set(value)):
        raise ValueError("supported_operations must be unique")
    return tuple(sorted(value))


class ToolInventoryEntry(BaseModel):
    """A tool in the system's tool inventory (Stage 1).

    Lightweight description of a tool or API the system can invoke,
    extracted during Stage 1 capability profile inference.  Used to
    ground downstream scenario generation — the LLM may only reference
    tools listed here, preventing phantom tool hallucination.

    The ``tool_id`` is a computed canonical identity (deterministic,
    versioned, 128-bit) derived from the canonical tool name.
    Application-assigned — the LLM never invents IDs.
    """

    name: str = Field(description="Tool or API name")
    description: str = Field(description="What the tool does (one line)")
    supported_operations: tuple[ResourceOperation, ...] | None = Field(
        default=None,
        description=(
            "Complete reviewed operation set; null means operation support is unknown"
        ),
        exclude_if=lambda value: value is None,
    )

    _validate_supported_operations = field_validator("supported_operations")(
        _canonical_supported_operations
    )

    @computed_field
    @property
    def tool_id(self) -> str:
        """Deterministic, versioned, collision-resistant canonical identity."""
        return compute_tool_id(self.name, self.description)


class ToolType(BaseModel):
    """A tool or API the system can invoke, with risk-relevant properties."""

    name: str = Field(
        description="Tool or API name (e.g. 'database_query', 'send_email')"
    )
    zone: str = Field(
        description="Schneider zone where this tool operates (typically 'tool_execution')"
    )
    can_modify_state: bool = Field(
        description="Whether the tool can write/modify external systems"
    )
    data_sensitivity: DataSensitivity = Field(
        description="Sensitivity of data the tool can access"
    )
    code_execution: bool = Field(
        description="Whether the tool can execute arbitrary code"
    )


class DataFlow(BaseModel):
    """A data flow between zones and components."""

    source: str = Field(
        description="Origin of the data (e.g. 'user input', 'RAG store')"
    )
    source_zone: str = Field(description="Schneider zone of the data source")
    destination: str = Field(
        description="Where the data flows to (e.g. 'LLM context', 'tool parameter')"
    )
    destination_zone: str = Field(description="Schneider zone of the destination")
    data_type: str = Field(
        description="Nature of the data (e.g. 'user query', 'retrieved document')"
    )
    validated: bool = Field(
        description="Whether the data is validated/sanitized at this boundary"
    )


class TrustBoundary(BaseModel):
    """A trust boundary in the system architecture."""

    name: str = Field(
        description="Descriptive name for the boundary (e.g. 'user-to-LLM')"
    )
    from_zone: str = Field(description="Schneider zone on the untrusted side")
    to_zone: str = Field(description="Schneider zone on the trusted side")
    controls: list[str] = Field(
        default_factory=list,
        description="Security controls at this boundary (e.g. 'input validation')",
    )
    confidence: BoundaryConfidence = Field(
        description="Whether this boundary was explicit, inferred, or hypothesized",
    )

    @computed_field
    @property
    def trust_boundary_id(self) -> str:
        """Deterministic, versioned, collision-resistant canonical identity."""
        return compute_trust_boundary_id(self.from_zone, self.to_zone, self.name)


class MemoryMechanism(BaseModel):
    """A memory and state persistence mechanism."""

    type: MemoryType = Field(description="Category of memory mechanism")
    scope: MemoryScope = Field(
        description="Whether memory is isolated per user, shared, or global"
    )
    persistence: MemoryPersistence = Field(description="How long data persists")
    writable_by_agent: bool = Field(
        description="Whether the agent can write to this store (vs read-only retrieval)",
    )


class ExternalIntegration(BaseModel):
    """An external system or service the agent integrates with.

    The ``integration_id`` is a computed canonical identity (deterministic,
    versioned, 128-bit) derived from the canonical name and integration type.
    Application-assigned — the LLM never invents IDs.
    """

    name: str = Field(
        description="Name of the external system (e.g. 'CRM', 'payment gateway')"
    )
    integration_type: IntegrationType = Field(
        description="How the agent connects to this system"
    )
    auth_method: AuthMethod = Field(description="Authentication mechanism used")
    data_sensitivity: DataSensitivity = Field(
        description="Sensitivity of data accessible through this integration",
    )
    supported_operations: tuple[ResourceOperation, ...] | None = Field(
        default=None,
        description=(
            "Complete reviewed operation set; null means operation support is unknown"
        ),
        exclude_if=lambda value: value is None,
    )

    _validate_supported_operations = field_validator("supported_operations")(
        _canonical_supported_operations
    )

    @computed_field
    @property
    def integration_id(self) -> str:
        """Deterministic, versioned, collision-resistant canonical identity."""
        return compute_integration_id(
            self.name,
            self.integration_type.value,
            self.auth_method.value,
            self.data_sensitivity.value,
        )


# ---------------------------------------------------------------------------
# Entry point with direction tag
# ---------------------------------------------------------------------------

# --- Entry point controllability classification ---
#
# Classifies entry point names as "direct", "indirect", or "system"
# using keyword matching.  When the capability profile provides an
# explicit ``controllability`` value on the entry point, the heuristic
# is bypassed.

_DIRECT_KEYWORDS: tuple[str, ...] = (
    "user",
    "customer",
    "query",
    "chat",
    "prompt",
    "message",
)

_INDIRECT_KEYWORDS: tuple[str, ...] = (
    "rag",
    "knowledge",
    "retrieval",
    "third-party",
    "third party",
    "data feed",
    "data_feed",
    "context injection",
    "authenticated context",
    "document",
)

_SYSTEM_KEYWORDS: tuple[str, ...] = (
    "api",
    "backend",
    "service",
    "internal",
    "system",
    "cron",
    "scheduler",
)


def classify_entry_point(
    entry_point_name: str,
    direction: str,
    controllability: str | None = None,
) -> str:
    """Classify an entry point as 'direct', 'indirect', or 'system'.

    When *controllability* is provided (not None), it is used — with one
    safety override: ``"system"`` is downgraded to ``"indirect"`` when
    *direction* is not ``"output"``, because a non-output direction means
    data flows in through this entry point and the attacker can influence
    it at least indirectly (e.g. backend API calls triggered by user
    requests).

    When *controllability* is None, falls back to a keyword heuristic on
    the entry point name, refined by the direction tag:

    - Bidirectional entry points are always ``"direct"`` (attacker has
      full interactive access).
    - Output-only entry points are always ``"system"`` (not attacker-
      accessible as ingress).
    - Input-direction entry points are classified by keyword matching:
      indirect keywords (RAG, knowledge, etc.) win over direct keywords
      (user, chat, etc.), which win over system keywords.  If no keyword
      matches, defaults to ``"direct"`` (conservative -- let LLM decide).

    Args:
        entry_point_name: Human-readable entry point name.
        direction: Data flow direction (``"input"``, ``"output"``, ``"bidirectional"``).
        controllability: Explicit controllability from the capability profile.
            When not None, used directly (bypasses heuristic) unless the
            ``"system"`` / non-output override applies.

    Returns:
        One of ``"direct"``, ``"indirect"``, ``"system"``.
    """
    # Use explicit controllability when available.
    # Explicit 'system' from a reviewed profile is preserved as 'system'
    # regardless of direction — heuristics only apply when controllability
    # is None (cmps.9 review correction 5).
    if controllability is not None:
        return controllability

    if direction == "output":
        return "system"
    if direction == "bidirectional":
        return "direct"

    return _classify_entry_name(entry_point_name.lower())


def _classify_entry_name(name: str) -> str:
    """Classify an input entry point using ordered keyword groups."""
    # Indirect keywords take priority (more specific).
    groups = (
        ("indirect", _INDIRECT_KEYWORDS),
        ("system", _SYSTEM_KEYWORDS),
        ("direct", _DIRECT_KEYWORDS),
    )
    for category, words in groups:
        if any(word in name for word in words):
            return category

    # Default: treat as direct (conservative -- let LLM decide).
    return "direct"


# --- Canonical entry point identity ---

_ENTRY_POINT_ID_VERSION = "v1"


def _canonical_entry_point_name(name: str) -> str:
    """Normalize an entry point name for canonical identity comparison.

    Collapses case, whitespace, and trailing punctuation differences so
    that semantically identical entry point names share the same
    canonical form.
    """
    s = name.lower().strip()
    s = re.sub(r"\s+", " ", s)
    s = s.rstrip(".,;:")
    return s


def _kept_zone(direction: str, zone: str | None) -> str | None:
    """Return the stored ingress zone after the output-direction rule.

    Output-only entries are not ingress paths, so any assigned zone is
    discarded. Other directions keep the declared zone.
    """
    if direction == "output":
        return None
    return zone


def _effective_zone(direction: str, zone: str | None) -> str | None:
    """Return the ingress zone used by identity and admission.

    Applies :func:`_kept_zone`, then the direction default: input and
    bidirectional default to ``input``; output has no ingress zone.
    """
    stored = _kept_zone(direction, zone)
    if stored is not None:
        return stored
    if direction in ("input", "bidirectional"):
        return "input"
    return None


def _entry_point_identity_tuple(
    name: str,
    direction: str,
    controllability: str | None,
    ingress_zone: str | None = None,
) -> tuple[str, str, str, str | None]:
    """Return the canonical identity tuple used for both hashing and collision comparison.

    This single definition ensures that the hash preimage and the
    collision-detection comparison use exactly the same canonical
    representation — no drift between the two.
    """
    effective_ctrl = classify_entry_point(name, direction, controllability)
    canonical = _canonical_entry_point_name(name)
    return (
        canonical,
        direction,
        effective_ctrl,
        _effective_zone(direction, ingress_zone),
    )


def compute_entry_point_id(
    name: str,
    direction: str,
    controllability: str | None,
    ingress_zone: str | None = None,
) -> str:
    """Compute a deterministic, versioned, collision-resistant entry_point_id.

    The ID is derived from the canonical (normalized) name, direction,
    *effective* controllability (explicit or inferred via
    :func:`classify_entry_point`), and effective ingress zone. Two entry points that are
    semantically identical produce the same ID; semantically distinct
    entry points produce different IDs (barring a hash collision).

    Format: ``ep:<version>:<32-char hex digest (128-bit)``

    Args:
        name: Human-readable entry point name.
        direction: Data flow direction.
        controllability: Explicit controllability (``None`` for inference).
        ingress_zone: Explicit Schneider ingress zone (``None`` for inference).

    Returns:
        A stable, opaque entry point identifier.
    """
    canonical, direction, effective_ctrl, effective_ingress_zone = (
        _entry_point_identity_tuple(name, direction, controllability, ingress_zone)
    )
    identity = f"{canonical}|{direction}|{effective_ctrl}|{effective_ingress_zone}"
    h = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:32]
    return f"ep:{_ENTRY_POINT_ID_VERSION}:{h}"


def deduplicate_entry_points(
    entry_points: list[EntryPoint],
) -> list[EntryPoint]:
    """Deduplicate semantic duplicates and reject ambiguous/colliding identities.

    Two entry points are *semantic duplicates* when they share the same
    :attr:`EntryPoint.entry_point_id` and the same canonical identity
    tuple — only the first is kept.

    Two entry points *collide* when they share the same
    ``entry_point_id`` but have different canonical identity tuples (a
    hash collision or ambiguous identity).  This is rejected with a
    :class:`ValueError` because the pipeline cannot distinguish them.

    Args:
        entry_points: Raw list of entry points (may contain duplicates).

    Returns:
        Deduplicated list preserving first-encounter order.

    Raises:
        ValueError: If two entry points with different canonical identity
            tuples produce the same ``entry_point_id``.
    """
    seen: dict[str, tuple[tuple[str, str, str, str | None], EntryPoint]] = {}
    for ep in entry_points:
        eid = ep.entry_point_id
        identity_tuple = _entry_point_identity_tuple(
            ep.name, ep.direction, ep.controllability, ep.ingress_zone
        )
        if eid in seen:
            existing_tuple, existing_ep = seen[eid]
            if (
                existing_tuple != identity_tuple
                or existing_ep.entry_point_type != ep.entry_point_type
            ):
                raise ValueError(
                    f"Ambiguous entry point identity: '{ep.name}' and "
                    f"'{existing_ep.name}' resolve to the same "
                    f"entry_point_id {eid} but have different canonical "
                    f"identity or typed ingress semantics. "
                    f"Remove or disambiguate one of them."
                )
            # Exact semantic duplicate — silently dedup (keep first).
            logger.debug(
                "Deduplicating entry point '%s' (same identity as '%s')",
                ep.name,
                existing_ep.name,
            )
            continue
        seen[eid] = (identity_tuple, ep)
    return [ep for _, ep in seen.values()]


# --- Canonical tool identity ---

_TOOL_ID_VERSION = "v1"


def _canonical_tool_name(name: str) -> str:
    """Normalize a tool name for canonical identity comparison."""
    s = name.lower().strip()
    s = re.sub(r"\s+", " ", s)
    s = s.rstrip(".,;:")
    return s


def _tool_identity_tuple(name: str, description: str) -> tuple[str]:
    """Return the canonical identity tuple for a tool.

    Only the name is used for identity — description is non-identity
    metadata that may change without affecting the canonical ID.
    """
    canonical_name = _canonical_tool_name(name)
    return (canonical_name,)


def compute_tool_id(name: str, description: str) -> str:
    """Compute a deterministic, versioned, collision-resistant tool_id.

    Format: ``tool:<version>:<32-char hex digest (128-bit)>``

    The ID is stable under description edits — only the canonical name
    determines identity.
    """
    (canonical_name,) = _tool_identity_tuple(name, description)
    h = hashlib.sha256(canonical_name.encode("utf-8")).hexdigest()[:32]
    return f"tool:{_TOOL_ID_VERSION}:{h}"


def deduplicate_tool_inventory(
    tools: list[ToolInventoryEntry],
) -> list[ToolInventoryEntry]:
    """Deduplicate semantic duplicates and reject ambiguous/colliding tool identities.

    See :func:`deduplicate_entry_points` for the collision/dedup policy.

    Metadata (description) must be canonically equal for deduplication.
    An empty/non-empty description mismatch is rejected — the caller must
    provide a nonblank canonical description or disambiguate the name
    (cmps.9 review correction 4).

    Exact semantic duplicates (same canonical name and same canonical
    description) must also have identical raw ``name`` and raw
    ``description`` — otherwise the first raw representation would be
    preserved order-dependently, making serialization non-deterministic
    (cmps.9 third review correction 3). Only exact raw duplicates
    deduplicate; raw metadata differences are rejected.
    """
    seen: dict[str, tuple[tuple[str], ToolInventoryEntry]] = {}
    for tool in tools:
        tid = tool.tool_id
        identity_tuple = _tool_identity_tuple(tool.name, tool.description)
        if tid not in seen:
            seen[tid] = (identity_tuple, tool)
            continue
        existing_tuple, existing_tool = seen[tid]
        _reject_tool_conflict(tool, existing_tool, tid, identity_tuple, existing_tuple)
        logger.debug(
            "Deduplicating tool '%s' (exact duplicate of '%s')",
            tool.name,
            existing_tool.name,
        )
    return [tool for _, tool in seen.values()]


def _reject_tool_conflict(
    tool: ToolInventoryEntry,
    existing: ToolInventoryEntry,
    tid: str,
    identity: tuple[str],
    prior_identity: tuple[str],
) -> None:
    """Reject non-identical tools that resolve to the same canonical ID."""
    if prior_identity != identity:
        raise ValueError(
            f"Ambiguous tool identity: '{tool.name}' and "
            f"'{existing.name}' resolve to the same "
            f"tool_id {tid} but have different canonical "
            f"identity tuples ({identity} vs {prior_identity}). "
            f"Remove or disambiguate one of them."
        )
    desc = _canonical_tool_name(tool.description)
    prior_desc = _canonical_tool_name(existing.description)
    if desc != prior_desc:
        raise ValueError(
            f"Ambiguous semantic duplicate tool '{tool.name}': "
            f"tool_id {tid} has conflicting descriptions "
            f"('{desc}' vs '{prior_desc}'). "
            f"Empty/non-empty metadata mismatches are rejected — "
            f"provide a nonblank canonical description or use a "
            f"distinct name."
        )
    # Canonical name and canonical description match. Reject raw metadata
    # differences to ensure deterministic serialization.
    if tool.name != existing.name:
        raise ValueError(
            f"Ambiguous semantic duplicate tool: '{tool.name}' "
            f"and '{existing.name}' resolve to the same "
            f"tool_id {tid} and canonical name, but their raw "
            f"names differ. Use the exact same name or "
            f"disambiguate to produce a distinct tool_id."
        )
    if tool.description != existing.description:
        raise ValueError(
            f"Ambiguous semantic duplicate tool '{tool.name}': "
            f"tool_id {tid} has the same canonical description "
            f"but raw descriptions differ "
            f"('{tool.description}' vs "
            f"'{existing.description}'). Use the exact same "
            f"description or disambiguate the name."
        )
    if tool.supported_operations != existing.supported_operations:
        raise ValueError(
            f"Ambiguous semantic duplicate tool '{tool.name}': "
            f"tool_id {tid} has conflicting supported_operations metadata."
        )


# --- Canonical integration identity ---

_INTEGRATION_ID_VERSION = "v1"


def _canonical_integration_name(name: str) -> str:
    """Normalize an integration name for canonical identity comparison."""
    s = name.lower().strip()
    s = re.sub(r"\s+", " ", s)
    s = s.rstrip(".,;:")
    return s


def _integration_identity_tuple(
    name: str,
    integration_type: str,
    auth_method: str,
    data_sensitivity: str,
) -> tuple[str, str]:
    """Return the canonical identity tuple for an integration.

    Authentication and data sensitivity are mutable metadata; only the
    canonical name and integration type determine identity.
    """
    return (
        _canonical_integration_name(name),
        integration_type.lower().strip(),
    )


def compute_integration_id(
    name: str,
    integration_type: str,
    auth_method: str,
    data_sensitivity: str,
) -> str:
    """Compute a deterministic, versioned, collision-resistant integration_id.

    Format: ``int:<version>:<32-char hex digest (128-bit)>``

    The ID is stable under authentication and data-sensitivity edits.
    """
    identity_tuple = _integration_identity_tuple(
        name, integration_type, auth_method, data_sensitivity
    )
    identity = "|".join(identity_tuple)
    h = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:32]
    return f"int:{_INTEGRATION_ID_VERSION}:{h}"


# --- Canonical trust boundary identity (cmps.6) ---

_TRUST_BOUNDARY_ID_VERSION = "v1"


def compute_trust_boundary_id(from_zone: str, to_zone: str, name: str = "") -> str:
    """Compute a deterministic, versioned, collision-resistant trust_boundary_id.

    Format: ``tb:<version>:<32-char hex digest (128-bit)>``

    The ID is derived from the canonical zone transition (from_zone→to_zone)
    **and** the canonicalized boundary name.  Two boundaries with the same
    zone transition but different names produce different IDs; exact
    semantic duplicates (same name + same transition) produce the same ID.
    """
    canonical_name = _canonical_trust_boundary_name(name)
    identity = f"{canonical_name}|{from_zone}|{to_zone}"
    h = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:32]
    return f"tb:{_TRUST_BOUNDARY_ID_VERSION}:{h}"


def _canonical_trust_boundary_name(name: str) -> str:
    """Normalize a trust-boundary name for canonical identity comparison."""
    s = name.lower().strip()
    s = re.sub(r"\s+", " ", s)
    s = s.rstrip(".,;:")
    return s


def _trust_boundary_identity_tuple(
    name: str, from_zone: str, to_zone: str
) -> tuple[str, str, str]:
    """Return the canonical identity tuple for a trust boundary."""
    return (_canonical_trust_boundary_name(name), from_zone, to_zone)


def deduplicate_trust_boundaries(
    trust_boundaries: list[TrustBoundary],
) -> list[TrustBoundary]:
    """Deduplicate semantic duplicates and reject ambiguous/colliding identities.

    Two trust boundaries are *semantic duplicates* when they share the same
    ``trust_boundary_id`` and the same canonical identity tuple — only the
    first is kept.

    Two trust boundaries *collide* when they share the same
    ``trust_boundary_id`` but have different canonical identity tuples.
    This is rejected with a :class:`ValueError`.

    Args:
        trust_boundaries: Raw list of trust boundaries (may contain duplicates).

    Returns:
        Deduplicated list preserving first-encounter order.

    Raises:
        ValueError: If two boundaries with different canonical identity
            tuples produce the same ``trust_boundary_id``.
    """
    seen: dict[str, tuple[tuple[str, str, str], TrustBoundary]] = {}
    for tb in trust_boundaries:
        tbid = tb.trust_boundary_id
        identity_tuple = _trust_boundary_identity_tuple(
            tb.name, tb.from_zone, tb.to_zone
        )
        if tbid in seen:
            existing_tuple, existing_tb = seen[tbid]
            if existing_tuple != identity_tuple:
                raise ValueError(
                    f"Ambiguous trust boundary identity: '{tb.name}' and "
                    f"'{existing_tb.name}' resolve to the same "
                    f"trust_boundary_id {tbid} but have different canonical "
                    f"identity tuples ({identity_tuple} vs {existing_tuple}). "
                    f"Remove or disambiguate one of them."
                )
            logger.debug(
                "Deduplicating trust boundary '%s' (same identity as '%s')",
                tb.name,
                existing_tb.name,
            )
            continue
        seen[tbid] = (identity_tuple, tb)
    return [tb for _, tb in seen.values()]


def deduplicate_external_integrations(
    integrations: list[ExternalIntegration],
) -> list[ExternalIntegration]:
    """Deduplicate semantic duplicates and reject ambiguous/colliding integration identities.

    See :func:`deduplicate_entry_points` for the collision/dedup policy.
    """
    seen: dict[str, tuple[tuple[str, ...], ExternalIntegration]] = {}
    for integ in integrations:
        iid = integ.integration_id
        identity_tuple = _integration_identity_tuple(
            integ.name,
            integ.integration_type.value,
            integ.auth_method.value,
            integ.data_sensitivity.value,
        )
        if iid in seen:
            existing_tuple, existing_integ = seen[iid]
            if existing_tuple != identity_tuple:
                raise ValueError(
                    f"Ambiguous integration identity: '{integ.name}' and "
                    f"'{existing_integ.name}' resolve to the same "
                    f"integration_id {iid} but have different canonical "
                    f"identity tuples ({identity_tuple} vs {existing_tuple}). "
                    f"Remove or disambiguate one of them."
                )
            metadata = (integ.auth_method.value, integ.data_sensitivity.value)
            existing_metadata = (
                existing_integ.auth_method.value,
                existing_integ.data_sensitivity.value,
            )
            if metadata != existing_metadata:
                raise ValueError(
                    f"Ambiguous semantic duplicate integration '{integ.name}': "
                    f"integration_id {iid} has conflicting authentication or "
                    f"data-sensitivity metadata. Use a distinct name or reconcile "
                    f"the metadata."
                )
            _reject_integration_operation_conflict(integ, existing_integ, iid)
            logger.debug(
                "Deduplicating integration '%s' (same identity as '%s')",
                integ.name,
                existing_integ.name,
            )
            continue
        seen[iid] = (identity_tuple, integ)
    return [integ for _, integ in seen.values()]


def _reject_integration_operation_conflict(
    integration: ExternalIntegration,
    existing: ExternalIntegration,
    integration_id: str,
) -> None:
    if integration.supported_operations != existing.supported_operations:
        raise ValueError(
            f"Ambiguous semantic duplicate integration '{integration.name}': "
            f"integration_id {integration_id} has conflicting "
            "supported_operations metadata."
        )


# --- Inventory completeness / evidence state ---


class InventoryCompleteness(str, Enum):
    """Evidence/completeness state for entry-point and tool inventories.

    ``inferred_partial``: inference establishes presence, never absence.
    ``operator_confirmed_complete``: only an operator-reviewed profile may
    declare this, with explicit evidence sources.  Ordinary LLM output
    cannot self-promote.
    """

    inferred_partial = "inferred_partial"
    operator_confirmed_complete = "operator_confirmed_complete"


class EntryPoint(BaseModel):
    """An entry point with a direction tag indicating data flow.

    Direction controls whether the entry point is considered as attacker
    ingress during candidate expansion:
    - ``input``: attacker can send data in (included in candidate cross-product)
    - ``output``: system sends data out only (excluded from candidate cross-product)
    - ``bidirectional``: both input and output (included in candidate cross-product)

    Controllability (optional) indicates how directly an attacker can
    influence data through this entry point:
    - ``direct``: attacker types input directly (e.g. chat prompt)
    - ``indirect``: attacker can influence a data source (e.g. RAG poisoning)
    - ``system``: fully system-controlled, not attacker-accessible
    - ``None``: inferred at runtime by keyword heuristic

    The model is frozen (immutable) so that submitted metadata cannot be
    mutated after the filter protocol has been engaged.
    """

    model_config = ConfigDict(frozen=True)

    name: str = Field(
        description="Entry point description, e.g. 'user prompts via chat widget'."
    )
    entry_point_type: Literal[
        "user_input",
        "external_content",
        "configuration_load",
        "system_event",
        "inter_agent_message",
        "other",
    ] = Field(
        default="other",
        description=(
            "Typed ingress mechanism. This is adapter-neutral semantic metadata; "
            "it does not derive from the entry-point name."
        ),
    )
    direction: Literal["input", "output", "bidirectional"] = Field(
        default="bidirectional",
        description=(
            "Data flow direction: 'input' (attacker can send data in), "
            "'output' (system sends data out), or 'bidirectional' (both)."
        ),
    )
    controllability: Literal["direct", "indirect", "system"] | None = Field(
        default=None,
        description=(
            "Attacker controllability: 'direct' (user types input), "
            "'indirect' (attacker can influence data source), "
            "'system' (fully system-controlled). "
            "When None, inferred by keyword heuristic."
        ),
    )
    ingress_zone: (
        Literal["input", "reasoning", "tool_execution", "memory", "inter_agent"] | None
    ) = Field(
        default=None,
        description=(
            "Canonical Schneider zone for initial ingress through this entry point. "
            "When None, inferred from direction: input→input, bidirectional→input, "
            "output→output. This establishes canonical ingress-zone semantics in "
            "typed profile data rather than inferring from labels."
        ),
    )

    def __str__(self) -> str:
        """Return the entry point name for backward-compatible string formatting."""
        return self.name

    @computed_field
    @property
    def entry_point_id(self) -> str:
        """Deterministic, versioned, collision-resistant canonical identity.

        Computed from the canonical (normalized) name, direction, and
        effective controllability.  See :func:`compute_entry_point_id`.
        """
        return compute_entry_point_id(
            self.name, self.direction, self.controllability, self.ingress_zone
        )

    @property
    def effective_controllability(self) -> str:
        """The resolved controllability (explicit or inferred via heuristic).

        When ``controllability`` is explicitly set to ``"system"`` from a
        reviewed profile, it is preserved as ``"system"`` — heuristics only
        apply when ``controllability`` is ``None`` (cmps.9 review correction 5).
        """
        if self.controllability == "system":
            return "system"
        return classify_entry_point(self.name, self.direction, self.controllability)

    @property
    def effective_ingress_zone(self) -> str | None:
        """The explicit ingress zone, or the direction-derived default."""
        return _effective_zone(self.direction, self.ingress_zone)

    @model_validator(mode="before")
    @classmethod
    def fix_zone(cls, data: object) -> object:
        """Clear ingress zones from output-only entries before construction.

        A before validator is used because Pydantic does not apply a replacement
        returned by a top-level after validator when a model is constructed
        through ``__init__``. This keeps normalization consistent for direct
        construction and dictionary validation.
        """
        if not isinstance(data, dict):
            return data
        zone = _kept_zone(
            data.get("direction", "bidirectional"), data.get("ingress_zone")
        )
        if zone is data.get("ingress_zone"):
            return data
        return {**data, "ingress_zone": zone}


def is_attacker_accessible_ingress(
    ep: EntryPoint,
    active_zones: set[str] | frozenset[str] | None = None,
) -> bool:
    """Centralized predicate: is this entry point an attacker-accessible ingress route?

    An entry point is attacker-accessible for ingress iff ALL hold:
    - ``direction != "output"`` (not output-only)
    - ``effective_controllability != "system"`` (not system-controlled)
    - ``effective_ingress_zone`` is present (not None)
    - when *active_zones* is supplied, the effective ingress zone is active

    Use this single predicate everywhere attacker-accessible ingress is
    determined: candidate expansion, coverage gap denominators, remediation
    selection, pinned ingress generation/admission, final semantic
    validation, and eval expected-entry-point denominators (cmps.9 third
    review correction 2).
    """
    if ep.direction == "output":
        return False
    if ep.effective_controllability == "system":
        return False
    zone = ep.effective_ingress_zone
    if zone is None:
        return False
    return active_zones is None or zone in active_zones


def _coerce_entry_points(
    v: list[str | dict | EntryPoint],
) -> list[EntryPoint]:
    """Coerce a list of mixed entry point representations to EntryPoint objects.

    Accepts:
    - Plain strings (backward compat) -> EntryPoint(name=string, direction="bidirectional")
    - Dicts with at least a ``name`` key -> EntryPoint(**dict)
    - EntryPoint objects -> passed through
    """
    return [_coerce_entry_point(item) for item in v]


def _coerce_entry_point(item: str | dict | EntryPoint) -> EntryPoint:
    """Coerce one supported entry-point representation."""
    if isinstance(item, EntryPoint):
        return item
    if isinstance(item, str):
        return EntryPoint(name=item, direction="bidirectional")
    if isinstance(item, dict):
        return _entry_point_from_data(item)
    raise TypeError(
        f"entry_points items must be str, dict, or EntryPoint, got {type(item)}"
    )


def _entry_point_from_data(data: dict) -> EntryPoint:
    """Build an entry point while ignoring its computed ID."""
    values = {name: value for name, value in data.items() if name != "entry_point_id"}
    return EntryPoint(**values)


def _check_kc(v: list[str]) -> list[str]:
    """Validate and canonicalize OWASP and project KC sub-codes."""
    if not v:
        return v
    # KCX-prefixed codes are asago-scenario-generator extensions (NOT from OWASP)
    # and pass through without checking against VALID_KC_SUBCODES.
    invalid = [
        code
        for code in v
        if not code.startswith(KCX_PREFIX) and code not in VALID_KC_SUBCODES
    ]
    if invalid:
        raise ValueError(
            f"Invalid KC sub-code(s): {invalid}. "
            f"Valid codes: {sorted(VALID_KC_SUBCODES)} "
            f"(codes prefixed with '{KCX_PREFIX}' are also accepted)"
        )
    return sorted(set(v))


EntryPointList = Annotated[list[EntryPoint], BeforeValidator(_coerce_entry_points)]


# ---------------------------------------------------------------------------
# Stage 1-only model (used for LLM inference to avoid schema bloat)
# ---------------------------------------------------------------------------


class Stage1Profile(BaseModel):
    """Slim Stage 1-only profile for the LLM structured-output call.

    Excludes Stage 2 sub-models so the schema stays small and the model
    doesn't generate runaway output trying to fill optional nested fields.

    zones_active is NOT an LLM-inferred field — it is derived from
    kc_subcodes in to_capability_profile().

    Boolean capability flags (has_persistent_memory, multi_agent, hitl)
    are NOT declared here — they are computed from kc_subcodes on
    CapabilityProfile (per project memory decision-boolean-flags-computed-from-kc).
    """

    entry_points: EntryPointList = Field(
        description=(
            "Attack entry points, each with a name, direction tag, and optional "
            "controllability. Direction is one of: input (attacker can send data in), "
            "output (system sends data out), bidirectional (both). Controllability "
            "is one of: direct (user types input), indirect (attacker influences "
            "data source), system (fully system-controlled), or null (inferred later)."
        ),
        min_length=1,
    )
    confidence: ConfidenceLevel = Field(
        description="How well the use-case description supported Stage 1 inferences.",
    )
    kc_subcodes: list[str] = Field(
        default_factory=list,
        description=(
            "OWASP KC (Key Component) sub-codes identifying the system's "
            "granular capabilities. E.g. ['KC1.1', 'KC4.1', 'KC6.1.1']."
        ),
    )
    tool_inventory: list[ToolInventoryEntry] = Field(
        default_factory=list,
        description=(
            "Tools and APIs the system can invoke, extracted from the "
            "use-case description.  Only populated when the system has "
            "tool execution capability (KC5.*/KC6.* sub-codes)."
        ),
    )

    @field_validator("tool_inventory", mode="before")
    @classmethod
    def normalize_redundant_tool_operations(cls, value: object) -> object:
        """Collapse exact operation repeats at the Stage 1 provider boundary.

        Structured-output schemas cannot express the domain model's tuple
        uniqueness validator.  An exact repeated enum value carries no new
        evidence, so normalize only that redundancy before the strict nested
        ``ToolInventoryEntry`` validation runs.  Invalid operation values and
        every other malformed field still reach the normal validators.
        """
        if not isinstance(value, list):
            return value
        normalized: list[object] = []
        for item in value:
            if not isinstance(item, dict):
                normalized.append(item)
                continue
            operations = item.get("supported_operations")
            if not isinstance(operations, (list, tuple)):
                normalized.append(item)
                continue
            deduplicated = []
            for operation in operations:
                if operation not in deduplicated:
                    deduplicated.append(operation)
            normalized.append({**item, "supported_operations": deduplicated})
        return normalized

    @field_validator("kc_subcodes")
    @classmethod
    def validate_kc_subcodes(cls, v: list[str]) -> list[str]:
        return _check_kc(v)

    def to_capability_profile(self) -> CapabilityProfile:
        """Promote to a full CapabilityProfile (Stage 2 fields left as None).

        zones_active is derived from kc_subcodes.  Boolean flags
        (has_persistent_memory, multi_agent, hitl) are computed properties
        on CapabilityProfile derived solely from kc_subcodes.

        Inferred profiles are always forced to ``inferred_partial``
        completeness — the LLM cannot self-promote to
        ``operator_confirmed_complete`` (cmps.9).
        """
        data = self.model_dump()
        data["zones_active"] = derive_zones_from_kc(self.kc_subcodes)
        # Force inferred_partial — LLM output cannot declare completeness.
        data["entry_point_completeness"] = InventoryCompleteness.inferred_partial.value
        data["tool_inventory_completeness"] = (
            InventoryCompleteness.inferred_partial.value
        )
        data.pop("entry_point_evidence", None)
        data.pop("tool_inventory_evidence", None)
        data.pop("inventory_completeness", None)
        data.pop("evidence_sources", None)
        return CapabilityProfile(**data)


def _check_zones(zones: set[str]) -> None:
    """Require the universal zones and reject unknown names."""
    if not {"input", "reasoning"}.issubset(zones):
        raise ValueError(
            "zones_active must contain at least ['input', 'reasoning'] "
            "— all LLM systems have input and reasoning"
        )
    if not zones.issubset(set(ZONE_NAMES)):
        invalid = zones - set(ZONE_NAMES)
        raise ValueError(
            f"zones_active contains invalid zone names: {invalid}. "
            f"Valid names: {ZONE_NAMES}"
        )


def _check_memory(zones: set[str], enabled: bool) -> None:
    """Require persistent memory when its zone is active."""
    if "memory" in zones and not enabled:
        raise ValueError(
            "Zone 'memory' (Memory & State) active implies "
            "has_persistent_memory must be true"
        )


def _check_agents(zones: set[str], enabled: bool) -> None:
    """Require multi-agent capability when its zone is active."""
    if "inter_agent" in zones and not enabled:
        raise ValueError(
            "Zone 'inter_agent' (Inter-Agent Communication) active "
            "implies multi_agent must be true"
        )


def _need_tools(zones: set[str], inventory: list[ToolInventoryEntry] | None) -> None:
    """Require an inventory when tool execution is active."""
    if "tool_execution" in zones and not inventory:
        raise ValueError(
            "Zone 'tool_execution' is active but tool_inventory is "
            "empty or None.  When the system has tool execution "
            "capability, you must provide a tool_inventory listing "
            "the tools and APIs the system can invoke.  Add a "
            "'tool_inventory' section to your capability profile YAML "
            "with at least one entry, e.g.:\n"
            "  tool_inventory:\n"
            "    - name: my_tool\n"
            "      description: What the tool does"
        )


def _check_proof(
    label: str,
    state: InventoryCompleteness,
    evidence: list[str],
) -> None:
    """Require nonblank evidence for confirmed-complete inventories."""
    supplied = any(item and item.strip() for item in evidence)
    if state == InventoryCompleteness.operator_confirmed_complete and not supplied:
        raise ValueError(
            f"{label}_completeness is 'operator_confirmed_complete' but "
            f"{label}_evidence is empty or whitespace-only. Operator-"
            "confirmed complete inventories must provide explicit nonblank "
            "evidence sources."
        )


# ---------------------------------------------------------------------------
# Top-level model
# ---------------------------------------------------------------------------


class CapabilityProfile(BaseModel):
    """Capability profile artifact for a system under assessment.

    Stage 1 fields (required) determine threat scope.
    Stage 2 fields (optional) determine scenario specificity.

    Boolean capability flags (``has_persistent_memory``, ``multi_agent``,
    ``hitl``) are computed properties derived solely from ``kc_subcodes``.
    They cannot be set directly.  Legacy YAML profiles that include these
    fields will have them silently stripped with a deprecation warning.
    """

    # --- Stage 1 (required) ---

    zones_active: list[str] = Field(
        description=(
            "Schneider zones active in the system. "
            "Minimum ['input', 'reasoning']. "
            "Other zones: 'tool_execution', 'memory', 'inter_agent'."
        ),
    )
    entry_points: EntryPointList = Field(
        description=(
            "Attack entry points, each with a name, direction tag, and optional "
            "controllability. Direction is one of: input (attacker can send data in), "
            "output (system sends data out), bidirectional (both). Controllability "
            "is one of: direct (user types input), indirect (attacker influences "
            "data source), system (fully system-controlled), or null (inferred later)."
        ),
        min_length=1,
    )
    confidence: ConfidenceLevel = Field(
        description="How well the use-case description supported Stage 1 inferences.",
    )
    kc_subcodes: list[str] = Field(
        min_length=1,
        description=(
            "OWASP KC (Key Component) sub-codes identifying the system's "
            "granular capabilities. E.g. ['KC1.1', 'KC4.1', 'KC6.1.1']. "
            "Must contain at least one code."
        ),
    )

    # --- Computed boolean flags (derived from kc_subcodes) ---

    @computed_field  # type: ignore[prop-decorator]
    @property
    def has_persistent_memory(self) -> bool:
        """True if any KC code implies cross-session persistence."""
        return _legacy_flag_values(self.kc_subcodes)["has_persistent_memory"]

    @computed_field  # type: ignore[prop-decorator]
    @property
    def multi_agent(self) -> bool:
        """True if KC codes indicate multi-agent collaboration."""
        return _legacy_flag_values(self.kc_subcodes)["multi_agent"]

    @computed_field  # type: ignore[prop-decorator]
    @property
    def hitl(self) -> bool:
        """True if KC codes indicate human-in-the-loop controls."""
        return _legacy_flag_values(self.kc_subcodes)["hitl"]

    # --- Stage 1 tool inventory (optional but required when tool_execution active) ---

    tool_inventory: list[ToolInventoryEntry] | None = Field(
        default=None,
        description=(
            "Tools and APIs the system can invoke.  Required when "
            "'tool_execution' is in zones_active.  Prevents phantom "
            "tool hallucination in downstream scenario generation."
        ),
    )

    # --- Inventory completeness / evidence (cmps.9) ---

    entry_point_completeness: InventoryCompleteness = Field(
        default=InventoryCompleteness.inferred_partial,
        description=(
            "Evidence/completeness state for the entry-point inventory. "
            "Inferred profiles are always 'inferred_partial'. Only operator-reviewed "
            "profiles may declare 'operator_confirmed_complete' with entry_point_evidence."
        ),
    )
    entry_point_evidence: list[str] = Field(
        default_factory=list,
        description=(
            "Explicit evidence sources for operator_confirmed_complete entry-point "
            "inventory. Required when entry_point_completeness is operator_confirmed_complete."
        ),
    )
    tool_inventory_completeness: InventoryCompleteness = Field(
        default=InventoryCompleteness.inferred_partial,
        description=(
            "Evidence/completeness state for the tool inventory. "
            "Inferred profiles are always 'inferred_partial'. Only operator-reviewed "
            "profiles may declare 'operator_confirmed_complete' with tool_inventory_evidence."
        ),
    )
    tool_inventory_evidence: list[str] = Field(
        default_factory=list,
        description=(
            "Explicit evidence sources for operator_confirmed_complete tool "
            "inventory. Required when tool_inventory_completeness is operator_confirmed_complete."
        ),
    )

    # --- Stage 2 (optional) ---

    tool_types: list[ToolType] | None = Field(
        default=None,
        description="Tools and APIs the system can invoke (populated at moderate/thorough depth).",
    )
    data_flows: list[DataFlow] | None = Field(
        default=None,
        description="Data flows between zones and components (populated at moderate/thorough depth).",
    )
    trust_boundaries: list[TrustBoundary] | None = Field(
        default=None,
        description="Trust boundaries in the system architecture (populated at thorough depth).",
    )
    memory_mechanisms: list[MemoryMechanism] | None = Field(
        default=None,
        description="Memory and state persistence mechanisms (populated at moderate/thorough depth).",
    )
    external_integrations: list[ExternalIntegration] | None = Field(
        default=None,
        description="External systems the agent integrates with (populated at moderate/thorough depth).",
    )

    # --- Validation ---

    @model_validator(mode="before")
    @classmethod
    def strip_legacy_bool_fields(cls, data: dict) -> dict:  # type: ignore[override]
        """Strip legacy boolean fields from input data.

        These fields are now computed from kc_subcodes.  Hand-written YAML
        profiles and older serialized profiles may still include them, and
        the project's own serialized output includes the computed values.
        Values that match the kc-derived result are removed silently so
        round-tripping our own output is warning-free; only values that
        disagree with the computed result surface a deprecation warning.
        """
        if not isinstance(data, dict):
            return data
        derived = _legacy_flag_values(list(data.get("kc_subcodes") or []))
        stripped = []
        for field_name in _LEGACY_BOOL_FIELDS:
            if field_name not in data:
                continue
            input_value = data.pop(field_name)
            if input_value != derived[field_name]:
                stripped.append(field_name)
        if stripped:
            logger.warning(
                "Stripped deprecated fields from CapabilityProfile input: %s. "
                "These are now computed from kc_subcodes.",
                ", ".join(sorted(stripped)),
            )
        return data

    @field_validator("kc_subcodes")
    @classmethod
    def validate_kc_subcodes(cls, v: list[str]) -> list[str]:
        return _check_kc(v)

    @model_validator(mode="after")
    def validate_zones_and_flags(self) -> CapabilityProfile:
        """Cross-field validation for zone/flag consistency.

        Zones are derived from kc_subcodes.  Boolean flags are computed
        properties so they always reflect the KC evidence.
        """
        # Derive zones from KC sub-codes
        self.zones_active = derive_zones_from_kc(self.kc_subcodes)

        zones = set(self.zones_active)
        _check_zones(zones)
        _check_memory(zones, self.has_persistent_memory)
        _check_agents(zones, self.multi_agent)
        _need_tools(zones, self.tool_inventory)

        # Deduplicate entry points by canonical identity and reject
        # ambiguous/colliding identities.
        self.entry_points = deduplicate_entry_points(self.entry_points)

        # Deduplicate tool inventory by canonical identity (cmps.9)
        if self.tool_inventory:
            self.tool_inventory = deduplicate_tool_inventory(self.tool_inventory)

        # Deduplicate external integrations by canonical identity (cmps.9)
        if self.external_integrations:
            self.external_integrations = deduplicate_external_integrations(
                self.external_integrations
            )

        # Deduplicate trust boundaries by canonical identity (cmps.6)
        if self.trust_boundaries:
            self.trust_boundaries = deduplicate_trust_boundaries(self.trust_boundaries)

        # Category-specific completeness/evidence validation (cmps.9 review)
        _check_proof(
            "entry_point",
            self.entry_point_completeness,
            self.entry_point_evidence,
        )
        _check_proof(
            "tool_inventory",
            self.tool_inventory_completeness,
            self.tool_inventory_evidence,
        )

        return self

    # --- Resource resolution helpers (cmps.9) ---

    def entry_point_lookup(self) -> dict[str, EntryPoint]:
        """Build a canonical ID → EntryPoint lookup map."""
        return {ep.entry_point_id: ep for ep in self.entry_points}

    def resolve_entry_point(self, entry_point_id: str) -> EntryPoint | None:
        """Resolve a canonical entry_point_id to an EntryPoint, or None if not found."""
        return self.entry_point_lookup().get(entry_point_id)

    def tool_lookup(self) -> dict[str, ToolInventoryEntry]:
        """Build a canonical tool_id → ToolInventoryEntry lookup map."""
        if not self.tool_inventory:
            return {}
        return {t.tool_id: t for t in self.tool_inventory}

    def resolve_tool(self, tool_id: str) -> ToolInventoryEntry | None:
        """Resolve a canonical tool_id to a ToolInventoryEntry, or None if not found."""
        return self.tool_lookup().get(tool_id)

    def integration_lookup(self) -> dict[str, ExternalIntegration]:
        """Build a canonical integration_id → ExternalIntegration lookup map."""
        if not self.external_integrations:
            return {}
        return {i.integration_id: i for i in self.external_integrations}

    def resolve_integration(self, integration_id: str) -> ExternalIntegration | None:
        """Resolve a canonical integration_id to an ExternalIntegration, or None."""
        return self.integration_lookup().get(integration_id)

    def trust_boundary_lookup(self) -> dict[str, TrustBoundary]:
        """Build a canonical trust_boundary_id → TrustBoundary lookup map."""
        if not self.trust_boundaries:
            return {}
        return {tb.trust_boundary_id: tb for tb in self.trust_boundaries}

    def resolve_trust_boundary(self, trust_boundary_id: str) -> TrustBoundary | None:
        """Resolve a canonical trust_boundary_id to a TrustBoundary, or None."""
        return self.trust_boundary_lookup().get(trust_boundary_id)

    def resolve_output_surface(self, entry_point_id: str) -> EntryPoint | None:
        """Resolve a canonical entry_point_id to an output-capable EntryPoint.

        Output surfaces are entry points whose ``direction`` is
        ``"output"`` or ``"bidirectional"`` — the agent's rendered-response
        surface.  A bidirectional entry point supports both input and
        output, so it qualifies as an output surface.  Entry points with
        ``direction == "input"`` do not qualify and resolve to ``None``.
        """
        ep = self.entry_point_lookup().get(entry_point_id)
        if ep is not None and ep.direction not in ("output", "bidirectional"):
            return None
        return ep

    # --- Name-to-ID reverse maps (Phase 3: human-readable prompts) ---

    def entry_point_name_to_id(self) -> dict[str, str]:
        """Map canonical entry-point names to entry_point_ids."""
        return {ep.name: ep.entry_point_id for ep in self.entry_points}

    def tool_name_to_id(self) -> dict[str, str]:
        """Map canonical tool names to tool_ids."""
        return {t.name: t.tool_id for t in (self.tool_inventory or [])}

    def integration_name_to_id(self) -> dict[str, str]:
        """Map canonical integration names to integration_ids."""
        return {i.name: i.integration_id for i in (self.external_integrations or [])}

    def trust_boundary_name_to_id(self) -> dict[str, str]:
        """Map canonical trust boundary names to trust_boundary_ids."""
        return {tb.name: tb.trust_boundary_id for tb in (self.trust_boundaries or [])}

    def id_to_entry_point_name(self) -> dict[str, str]:
        """Map entry_point_ids to canonical entry-point names."""
        return {ep.entry_point_id: ep.name for ep in self.entry_points}

    def id_to_tool_name(self) -> dict[str, str]:
        """Map tool_ids to canonical tool names."""
        return {t.tool_id: t.name for t in (self.tool_inventory or [])}

    def id_to_integration_name(self) -> dict[str, str]:
        """Map integration_ids to canonical integration names."""
        return {i.integration_id: i.name for i in (self.external_integrations or [])}

    def id_to_trust_boundary_name(self) -> dict[str, str]:
        """Map trust_boundary_ids to canonical trust boundary names."""
        return {tb.trust_boundary_id: tb.name for tb in (self.trust_boundaries or [])}

    @property
    def is_entry_point_inventory_complete(self) -> bool:
        """True when entry-point inventory is operator-confirmed complete with evidence."""
        return (
            self.entry_point_completeness
            == InventoryCompleteness.operator_confirmed_complete
        )

    @property
    def is_tool_inventory_complete(self) -> bool:
        """True when tool inventory is operator-confirmed complete with evidence."""
        return (
            self.tool_inventory_completeness
            == InventoryCompleteness.operator_confirmed_complete
        )

    @property
    def is_inventory_complete(self) -> bool:
        """True when ALL inventory categories are operator-confirmed complete."""
        return (
            self.is_entry_point_inventory_complete and self.is_tool_inventory_complete
        )
