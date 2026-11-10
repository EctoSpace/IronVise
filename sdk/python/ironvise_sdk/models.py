"""Shared Pydantic models matching the IronVise API response shapes."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Session(BaseModel):
    """Represents an agent session returned by the IronVise API.

    Field aliases map the server's ``id`` / ``created_at`` names to the
    friendlier ``session_id`` / ``started_at`` names exposed by the SDK.
    ``populate_by_name=True`` allows construction using either name.
    """

    model_config = ConfigDict(populate_by_name=True)

    session_id: str = Field(alias="id")
    goal: str = ""
    goal_hash: str | None = None
    started_at: datetime = Field(alias="created_at")
    finished_at: datetime | None = None
    status: str = ""
    llm_backend: str | None = None
    llm_model: str | None = None
    policy_hash: str | None = None
    session_public_key: str | None = None
    session_did: str | None = None
    enclave_attestation_json: str | None = None


class LedgerEvent(BaseModel):
    """A single immutable event in the append-only ledger.

    Field aliases map the server's native names (``content_hash``,
    ``previous_hash``) to the SDK's public names (``payload_hash``,
    ``prev_hash``).  ``populate_by_name=True`` accepts either form.

    The server returns no per-event signature or public key; ``verify_session``
    reports the signatures.
    """

    model_config = ConfigDict(populate_by_name=True)

    id: int
    sequence: int
    prev_hash: str = Field(alias="previous_hash")
    payload_hash: str = Field(alias="content_hash")
    payload: Any
    created_at: datetime


class AppendResult(BaseModel):
    id: int
    payload_hash: str
    sequence: int


class SignatureVerdict(BaseModel):
    """Whether a session's events are bound to its key, as reported by the server."""

    verified: bool
    verdict: str = ""
    message: str = ""
    signed: int = 0
    unsigned: int = 0


class VerifySessionResult(BaseModel):
    """Full result of ``verify_session()``.

    ``ok`` is the hash chain alone. ``signatures`` is ``None`` on servers that
    predate signature verification.
    """

    ok: bool = False
    signatures: SignatureVerdict | None = None


class ComplianceEvent(BaseModel):
    sequence: int
    content_hash: str


class ComplianceBundle(BaseModel):
    """Typed compliance bundle returned by ``prove_compliance()``.

    It lists each event's sequence and content hash and nothing else; the
    signatures and the chain are checked by ``verify_session``.
    """

    session_id: str
    event_count: int
    events: list[ComplianceEvent]


class MetricsSummary(BaseModel):
    total_sessions: int = 0
    total_events: int = 0
    extra: dict[str, Any] = Field(default_factory=dict)


class SecurityMetrics(BaseModel):
    injection_attempts_detected_7d: int = 0
    injection_attempts_by_layer: dict[str, int] = Field(default_factory=dict)
    sessions_aborted_circuit_breaker: int = 0
    chain_verification_failures: int = 0
    # Added in 0.8.0: ledger row counts, and this server's denial counters.
    total_sessions: int = 0
    total_events: int = 0
    guard_denials: int = 0
    tripwire_rejections: int = 0


class PendingApproval(BaseModel):
    gate_id: str
    action_name: str
    action_params_summary: str
    created_at: datetime


class StatusResponse(BaseModel):
    demo_mode: bool = False
    # True when the server would log the insecure-demo banner. Absent from older servers.
    insecure_demo: bool = False
    version: str = ""
    # Added in 0.8.0; absent (default) from older servers.
    ledger_backend: str = ""
    agent_supported: bool = False
    exports_supported: bool = False
    webhooks_live: bool = False


class TokenListRow(BaseModel):
    token_hash: str
    role: str
    label: str | None = None
    created_at: str
    expires_at: str | None = None


class CreateTokenResponse(BaseModel):
    token: str
    token_hash: str
    role: str
    label: str | None = None


class WebhookListRow(BaseModel):
    id: str
    label: str
    url: str
    siem_format: str = "json"
    filter_kinds: list[str] = Field(default_factory=list)
    enabled: bool = True
    created_at: str


class ConfigResponse(BaseModel):
    database_url: str = ""
    llm_backend: str = ""
    ollama_base_url: str = ""
    # Added in 0.8.0; absent (default) from older servers.
    openai_base_url: str = ""
    ollama_model: str = ""
    guard_required: bool = False
    #: What decided ``guard_required``: the environment, the settings file,
    #: both, or the stricter of two that disagreed. Added in 0.8.0.
    guard_required_source: str = ""
    guard_llm_backend: str | None = None
    guard_llm_model: str | None = None
    max_steps: int = 0
    agent_allowed_domains: list[str] = Field(default_factory=list)
    sandbox_mode: str = ""
    demo_mode: bool = False
    #: Desktop GUI: show Testing / Prometheus / Dev Hub in the sidebar. Added in 0.8.0.
    show_developer_tools: bool = False
    #: Live pool backend: ``"postgres"`` or ``"sqlite"``. Added in 0.8.0.
    ledger_backend: str = ""
    #: Cognitive loop (Home → Run) works on this live pool. Added in 0.8.0.
    agent_supported: bool = False
    #: Certificate / report export works on this live pool. Added in 0.8.0.
    exports_supported: bool = False
    #: Webhook egress worker is delivering events. Added in 0.8.0.
    webhooks_live: bool = False
    #: The policy chosen in Settings for Home → Run, by name. Added in 0.8.0.
    active_policy: str | None = None
    #: ``ECTO_POLICY_PATH`` when set: it wins over ``active_policy``. Added in 0.8.0.
    policy_from_environment: str | None = None


class TripwireConfig(BaseModel):
    allowed_paths: list[str] = Field(default_factory=list)
    allowed_domains: list[str] = Field(default_factory=list)
    banned_command_patterns: list[str] = Field(default_factory=list)
    min_justification_length: int = 0
    require_https: bool = False
    #: MCP tools a call may use, as ``server/tool`` or ``server/*``. Empty:
    #: any. Added in 0.8.0; absent (default empty) from older servers.
    allowed_mcp_tools: list[str] = Field(default_factory=list)
    #: ``GET /api/tripwire`` only: whether a ``tripwire.json`` has been saved,
    #: or this is just the default view. ``None`` on older servers and never
    #: sent back by ``PUT``.
    saved: bool | None = None


class TripwireCheckResult(BaseModel):
    """The answer to ``POST /api/tripwire/check``: whether a proposed action
    would pass the tripwire, without recording anything - no session, no
    ledger event. Runs only the tripwire layer (allowlists and banned
    patterns), not the policy engine or the semantic guard; see
    :meth:`LedgerClient.verify_intent` for the full pipeline against a session.
    """

    allowed: bool
    reason: str | None = None
    #: Which setting would refuse it, e.g. ``allowed_paths``, ``banned_command_patterns``.
    rule: str | None = None
    #: The configured list item that decided the denial, when ``allowed`` is ``False``.
    matched: str | None = None


class IntentCoverage(BaseModel):
    """Which layers an evaluation ran, and which it skipped."""

    #: Layers consulted, in pipeline order: ``policy``, ``tripwire``, ``guard``.
    evaluated: list[str] = []
    #: Layers not consulted on this surface.
    skipped: list[str] = []
    #: SHA-256 of the policy file that decided, when a policy was evaluated.
    policy_hash: str | None = None


class IntentVerdict(BaseModel):
    """The answer to "may I do this?", returned before the caller acts.

    ``verify_intent`` is the difference between an SDK that records what an
    agent did and one that can stop it. The decision is made server-side by the
    shared evaluator; nothing is executed and nothing is committed to the ledger
    by asking.

    Read :attr:`coverage` before treating an ``allow`` as a full evaluation:
    this surface runs the policy, the tripwire, and the semantic guard only
    when the server requires one (``GUARD_REQUIRED``).
    """

    decision: str
    reason: str | None = None
    #: Which check refused: ``policy``, ``tripwire``, ``guard`` or
    #: ``guard_unavailable``. ``None`` when allowed.
    stage: str | None = None
    session_id: str | None = None
    #: Which checks ran and which did not. An ``allow`` from a surface with no
    #: policy and no guard is a weaker statement than one from a surface with
    #: both. ``guard`` is evaluated only when the server requires a guard;
    #: otherwise it is in ``skipped``. ``None`` against a server older than
    #: 0.8.0.
    coverage: "IntentCoverage | None" = None
    #: Always ``False`` here: asking writes nothing to the ledger.
    recorded: bool | None = None

    @property
    def allowed(self) -> bool:
        return self.decision == "allow"

    def raise_if_denied(self) -> None:
        """Raise :class:`IntentDenied` unless the action was allowed.

        For callers that would rather not remember to check a boolean. An
        ignored return value is the most common way a governance call quietly
        becomes a logging call.
        """
        if not self.allowed:
            raise IntentDenied(self)


class IntentDenied(Exception):
    """Raised by :meth:`IntentVerdict.raise_if_denied` for a refused action."""

    def __init__(self, verdict: "IntentVerdict") -> None:
        self.verdict = verdict
        stage = f" at the {verdict.stage} stage" if verdict.stage else ""
        super().__init__(f"IronVise denied this action{stage}: {verdict.reason or 'no reason given'}")
