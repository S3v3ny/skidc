from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


def _clean_id_list(values: list[str], label: str) -> list[str]:
    cleaned: list[str] = []
    for item in values:
        text = item.strip()
        if not text:
            raise ValueError(f"{label} must not contain empty ids")
        if text not in cleaned:
            cleaned.append(text)
    return cleaned


class Settings(BaseModel):
    intent_timeout: int = Field(ge=5)
    reason_timeout: int = Field(ge=5)


class Fact(BaseModel):
    id: str
    description: str
    schema_version: int = Field(default=1, ge=1)
    kind: str = "legacy_text"
    summary: str | None = None
    subject: dict[str, Any] = Field(default_factory=dict)
    data: dict[str, Any] = Field(default_factory=dict)
    parent_fact_ids: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    confidence: float | None = Field(default=None, ge=0, le=1)
    created_by: str | None = None
    created_at: str | None = None
    scope: str | None = None
    vuln_type: str | None = None
    severity: str | None = None
    parent_fact: str | None = None
    verification_of: str | None = None
    goal_type: str | None = None
    status: str | None = None
    recon_category: str | None = None
    recon_executed: bool | None = None
    recon_found_results: bool | None = None
    recon_tool: str | None = None
    recon_target: str | None = None
    recon_evidence_ref: str | None = None
    coverage_refs: list[str] = Field(default_factory=list)
    surface_class: Literal["web", "api", "support_service", "unclassified"] = "unclassified"
    result_class: Literal["confirmed", "limited", "refuted", "informational"] = "informational"
    intent_refs: list[str] = Field(default_factory=list)
    task_log_refs: list[str] = Field(default_factory=list)


class Intent(BaseModel):
    id: str
    from_: list[str] = Field(alias="from")
    to: str | None = None
    description: str
    creator: str
    worker: str | None = None
    last_heartbeat_at: str | None = None
    created_at: str
    concluded_at: str | None = None
    target: str | None = None
    port: int | None = None
    path: str | None = None
    surface_type: str | None = None
    action_kind: str | None = None
    test_variant: str | None = None
    priority: int | None = None
    suggested_tools: list[str] = Field(default_factory=list)
    attempt_count: int = 0
    last_error: str | None = None
    last_worker: str | None = None
    next_retry_at: str | None = None
    failed_at: str | None = None
    dead_lettered_at: str | None = None
    status: str = "open"
    work_key: str | None = None
    coverage_refs: list[str] = Field(default_factory=list)
    hypothesis_id: str | None = None
    execution_status: Literal["pending", "running", "succeeded", "failed"] = "pending"
    execution_artifact_ref: str | None = None
    execution_completed_at: str | None = None
    conclusion_attempt_count: int = 0
    conclusion_last_error: str | None = None
    commit_status: Literal["pending", "committed"] = "pending"

    model_config = {"populate_by_name": True}


class Hint(BaseModel):
    id: str
    content: str
    creator: str
    created_at: str


AttackPathStatus = Literal["hypothesis", "confirmed", "inconclusive", "refuted"]


class AttackPathStep(BaseModel):
    fact_id: str
    required: bool = True
    order: int
    fact_status: str | None = None
    derived_status: AttackPathStatus = "hypothesis"
    reason: str
    coverage_refs: list[str] = Field(default_factory=list)


class AttackPath(BaseModel):
    id: str
    name: str
    fact_chain: list[str]
    description: str
    severity: str
    status: AttackPathStatus = "hypothesis"
    suggested_status: AttackPathStatus = "hypothesis"
    status_reason: str | None = None
    signature: str | None = None
    steps: list[AttackPathStep] = Field(default_factory=list)
    intent_refs: list[str] = Field(default_factory=list)
    task_log_refs: list[str] = Field(default_factory=list)
    derived_from_goal: bool = False
    created_at: str
    updated_at: str | None = None


class CreateAttackPathRequest(BaseModel):
    name: str
    fact_chain: list[str] = Field(min_length=1)
    description: str
    severity: str = "medium"
    status: AttackPathStatus = "hypothesis"

    @field_validator("name", "description")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text

    @field_validator("fact_chain")
    @classmethod
    def validate_fact_chain(cls, value: list[str]) -> list[str]:
        cleaned = []
        for item in value:
            text = item.strip()
            if not text:
                raise ValueError("fact ids must not be empty")
            cleaned.append(text)
        return cleaned


class UpdateAttackPathStatusRequest(BaseModel):
    status: AttackPathStatus


CoverageItemType = Literal["route", "param", "form", "upload_point", "admin_route", "service", "vuln_class"]
CoverageStatus = Literal[
    "untested", "testing", "confirmed", "not_vulnerable", "inconclusive", "failed", "informational",
]
CoverageExecutionStatus = Literal["untested", "queued", "testing", "completed", "blocked"]
CoverageDisposition = Literal["required", "excluded", "deferred"]
CoverageOutcome = Literal[
    "vulnerable", "not_vulnerable", "inconclusive", "not_applicable", "informational",
]
CoverageTestFamily = Literal[
    "surface_config",
    "identity_auth",
    "authorization",
    "session_csrf",
    "injection",
    "file_path",
    "server_side_processing",
    "client_side",
    "business_logic",
    "crypto_transport",
    "api_behavior",
    "support_service",
]

CoverageVariantStatus = Literal[
    "untested", "vulnerable", "not_vulnerable", "conflict", "inconclusive",
    "informational", "not_applicable",
]


class CoverageVariantResult(BaseModel):
    variant: str
    status: CoverageVariantStatus
    fact_ids: list[str] = Field(default_factory=list)
    open_intent_id: str | None = None
    verification: Literal["verified", "unverified"] | None = None
    reason: str



class SurfaceInventoryItem(BaseModel):
    id: str
    fingerprint: str
    surface_group: str
    target: str | None = None
    port: int | None = None
    method: str | None = None
    path_template: str | None = None
    params: list[str] = Field(default_factory=list)
    surface_type: str | None = None
    auth_context: str = "anonymous"
    roles: list[str] = Field(default_factory=list)
    traits: dict[str, Any] = Field(default_factory=dict)
    source_fact_id: str | None = None
    behavior_key: str | None = None
    operation_type: str = "unknown"
    capabilities: list[str] = Field(default_factory=list)
    evidence_fact_ids: list[str] = Field(default_factory=list)
    planning_status: Literal["pending", "assessed"] = "pending"
    created_at: str
    updated_at: str


class UpsertSurfaceInventoryRequest(BaseModel):
    fingerprint: str
    surface_group: str
    target: str | None = None
    port: int | None = None
    method: str | None = None
    path_template: str | None = None
    params: list[str] = Field(default_factory=list)
    surface_type: str | None = None
    auth_context: str = "anonymous"
    roles: list[str] = Field(default_factory=list)
    traits: dict[str, Any] = Field(default_factory=dict)
    source_fact_id: str | None = None
    behavior_key: str | None = None
    operation_type: str = "unknown"
    capabilities: list[str] = Field(default_factory=list)
    evidence_fact_ids: list[str] = Field(default_factory=list)
    planning_status: Literal["pending", "assessed"] = "pending"

    @field_validator("fingerprint", "surface_group", "auth_context")
    @classmethod
    def validate_required_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text

    @field_validator("params", "roles", "capabilities", "evidence_fact_ids")
    @classmethod
    def normalize_string_lists(cls, value: list[str]) -> list[str]:
        return _clean_id_list(value, "values")


class CoverageItem(BaseModel):
    id: str
    item_type: CoverageItemType
    target: str | None = None
    port: int | None = None
    method: str | None = None
    path: str | None = None
    param: str | None = None
    description: str
    status: CoverageStatus = "untested"
    priority: int | None = None
    evidence_ref: str | None = None
    source_fact_id: str | None = None
    intent_id: str | None = None
    intent_ids: list[str] = Field(default_factory=list)
    evidence_fact_ids: list[str] = Field(default_factory=list)
    surface_class: Literal["web", "api", "support_service"] = "web"
    task_log_refs: list[str] = Field(default_factory=list)
    surface_group: str | None = None
    surface_fingerprint: str | None = None
    test_family: CoverageTestFamily | None = None
    test_variants: list[str] = Field(default_factory=list)
    auth_context: str | None = None
    variant_results: list[CoverageVariantResult] = Field(default_factory=list)
    roles: list[str] = Field(default_factory=list)
    applicability_reason: str | None = None
    required: bool = True
    disposition: CoverageDisposition = "required"
    disposition_reason: str | None = None
    standard_refs: list[str] = Field(default_factory=list)
    execution_status: CoverageExecutionStatus = "untested"
    outcome: CoverageOutcome | None = None
    applicability_status: Literal["candidate", "applicable", "not_applicable"] = "applicable"
    created_at: str
    updated_at: str


class CreateCoverageItemRequest(BaseModel):
    item_type: CoverageItemType
    target: str | None = None
    port: int | None = None
    method: str | None = None
    path: str | None = None
    param: str | None = None
    description: str
    status: CoverageStatus = "untested"
    priority: int | None = None
    evidence_ref: str | None = None
    source_fact_id: str | None = None
    intent_id: str | None = None
    surface_group: str | None = None
    surface_fingerprint: str | None = None
    test_family: CoverageTestFamily | None = None
    test_variants: list[str] = Field(default_factory=list)
    auth_context: str | None = None
    roles: list[str] = Field(default_factory=list)
    applicability_reason: str | None = None
    required: bool = True
    disposition: CoverageDisposition = "required"
    disposition_reason: str | None = None
    standard_refs: list[str] = Field(default_factory=list)
    execution_status: CoverageExecutionStatus | None = None
    outcome: CoverageOutcome | None = None
    applicability_status: Literal["candidate", "applicable", "not_applicable"] = "applicable"

    @field_validator("description")
    @classmethod
    def validate_non_empty_description(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text

    @field_validator(
        "target", "method", "path", "param", "evidence_ref", "source_fact_id", "intent_id",
        "surface_group", "surface_fingerprint", "auth_context", "applicability_reason",
        "disposition_reason",
    )
    @classmethod
    def normalize_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        text = value.strip()
        return text or None

    @field_validator("test_variants", "roles", "standard_refs")
    @classmethod
    def normalize_profile_lists(cls, value: list[str]) -> list[str]:
        return _clean_id_list(value, "coverage profile values")


class UpdateCoverageItemRequest(BaseModel):
    status: CoverageStatus | None = None
    evidence_ref: str | None = None
    intent_id: str | None = None
    execution_status: CoverageExecutionStatus | None = None
    outcome: CoverageOutcome | None = None
    disposition: CoverageDisposition | None = None
    disposition_reason: str | None = None

    @field_validator("evidence_ref", "intent_id", "disposition_reason")
    @classmethod
    def normalize_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        text = value.strip()
        return text or None


class BindCoverageIntentRequest(BaseModel):
    intent_id: str

    @field_validator("intent_id")
    @classmethod
    def validate_intent_id(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text


HypothesisStatus = Literal[
    "candidate", "planned", "testing", "supported", "refuted",
    "inconclusive", "blocked_by_precondition", "waived",
]


class Hypothesis(BaseModel):
    id: str
    behavior_key: str
    coverage_id: str | None = None
    test_family: CoverageTestFamily
    test_variant: str
    rationale: str
    trigger_fact_ids: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0, le=1)
    impact: float = Field(default=1, ge=0)
    goal_value: float = Field(default=1, ge=0)
    novelty: float = Field(default=1, ge=0)
    estimated_cost: float = Field(default=1, gt=0)
    score: float = Field(ge=0)
    required: bool = True
    status: HypothesisStatus = "candidate"
    intent_id: str | None = None
    basis_fingerprint: str
    last_error: str | None = None
    created_at: str
    updated_at: str


class CreateHypothesisRequest(BaseModel):
    behavior_key: str
    coverage_id: str | None = None
    test_family: CoverageTestFamily
    test_variant: str
    rationale: str
    trigger_fact_ids: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0, le=1)
    impact: float = Field(default=1, ge=0)
    goal_value: float = Field(default=1, ge=0)
    novelty: float = Field(default=1, ge=0)
    estimated_cost: float = Field(default=1, gt=0)
    score: float = Field(ge=0)
    required: bool = True
    status: HypothesisStatus = "candidate"
    intent_id: str | None = None
    basis_fingerprint: str
    last_error: str | None = None

    @field_validator("behavior_key", "test_variant", "rationale", "basis_fingerprint")
    @classmethod
    def validate_hypothesis_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text

    @field_validator("trigger_fact_ids")
    @classmethod
    def normalize_trigger_facts(cls, value: list[str]) -> list[str]:
        return _clean_id_list(value, "trigger_fact_ids")


class UpdateHypothesisRequest(BaseModel):
    status: HypothesisStatus | None = None
    coverage_id: str | None = None
    intent_id: str | None = None
    last_error: str | None = None


class ProjectReason(BaseModel):
    worker: str
    trigger: str
    started_at: str
    last_heartbeat_at: str


class ScopePolicy(BaseModel):
    allowed_targets: list[str] = Field(default_factory=list)
    blocked_targets: list[str] = Field(default_factory=list)
    allowed_ports: list[int] = Field(default_factory=list)
    blocked_ports: list[int] = Field(default_factory=list)
    allowed_paths: list[str] = Field(default_factory=list)
    blocked_paths: list[str] = Field(default_factory=list)
    support_ports: list[int] = Field(default_factory=list)
    allow_subdomains: bool = True
    allow_domain_scan: bool = True
    rate_limits: dict[str, int] = Field(default_factory=dict)
    passive_only: bool = False

    allow_state_change: bool = True
    allow_destructive: bool = False

class ReconProfile(BaseModel):
    target_type: Literal["domain", "ip", "api", "android", "mixed"] = "domain"
    required_categories: list[str] = Field(default_factory=lambda: ["port_scan", "subdomain", "directory", "asset"])
    optional_categories: list[str] = Field(default_factory=list)
    disabled_categories: list[str] = Field(default_factory=list)
    max_coverage_intents: int = Field(default=200, ge=1)
    coverage_batch_size: int = Field(default=20, ge=1, le=100)
    hypothesis_batch_size: int = Field(default=3, ge=1, le=10)
    hypothesis_min_score: float = Field(default=1.0, ge=0.0, le=20.0)
    max_hypotheses: int = Field(default=24, ge=1, le=1000)
    frontier_breadth_slots: int = Field(default=1, ge=0, le=10)
    branch_no_progress_limit: int = Field(default=2, ge=1, le=10)
    reason_context_limit: int = Field(default=80, ge=20, le=500)


ProjectRunState = Literal[
    "running",
    "completed",
    "stopped",
    "needs_attention",
]


class CompletionBlocker(BaseModel):
    kind: Literal["intent", "coverage", "surface", "fact", "reason"]
    ref: str
    status: str
    reason: str
    priority: int | None = None
    description: str | None = None
    suggested_action: str | None = None
    evidence_ref: str | None = None
    related_refs: list[str] = Field(default_factory=list)
    task_log_refs: list[str] = Field(default_factory=list)
    updated_at: str | None = None


class ProjectMeta(BaseModel):
    id: str
    title: str
    status: Literal["active", "stopped", "completed"]
    bootstrap_enabled: bool
    phase: Literal["recon", "explore"] = "explore"
    mode: Literal["ctf", "real_website"] = "ctf"
    planning_version: int = 1
    scope_policy: ScopePolicy = Field(default_factory=ScopePolicy)
    recon_profile: ReconProfile = Field(default_factory=ReconProfile)
    reason_attempt_count: int = 0
    reason_last_error: str | None = None
    reason_next_retry_at: str | None = None
    reason_dead_lettered_at: str | None = None
    reason_state_fingerprint: str | None = None
    reason_last_outcome: str | None = None
    completion_outcome: str | None = None
    stop_reason_code: str | None = None
    stop_reason_detail: str | None = None
    phase_transition_last_error: str | None = None
    phase_transition_attempted_at: str | None = None
    completion_blocked_at: str | None = None
    run_state: ProjectRunState | None = None
    completion_blockers: list[CompletionBlocker] = Field(default_factory=list)
    last_progress_at: str | None = None
    created_at: str
    reason: ProjectReason | None = None


class ProjectSummary(ProjectMeta):
    fact_count: int
    intent_count: int
    working_intent_count: int
    unclaimed_intent_count: int
    hint_count: int


class ProjectDetail(BaseModel):
    project: ProjectMeta
    facts: list[Fact]
    intents: list[Intent]
    hints: list[Hint]
    attack_paths: list[AttackPath] = Field(default_factory=list)
    coverage_items: list[CoverageItem] = Field(default_factory=list)
    surface_inventory: list[SurfaceInventoryItem] = Field(default_factory=list)
    hypotheses: list["Hypothesis"] = Field(default_factory=list)


class CreateHintInline(BaseModel):
    content: str
    creator: str

    @field_validator("content", "creator")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text


class CreateProjectRequest(BaseModel):
    title: str
    origin: str
    goal: str
    mode: Literal["ctf", "real_website"] | None = None
    bootstrap_enabled: bool = True
    scope_policy: ScopePolicy = Field(default_factory=ScopePolicy)
    recon_profile: ReconProfile | None = None
    hints: list[CreateHintInline] | None = None

    @field_validator("title", "origin", "goal")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text


class CreateHintRequest(BaseModel):
    content: str
    creator: str

    @field_validator("content", "creator")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text


class ContinueBlockedProjectRequest(BaseModel):
    note: str = "Continue processing the current completion blockers."
    creator: str = "human"

    @field_validator("note", "creator")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text


class NeedsAttentionRequest(BaseModel):
    worker: str
    reason_code: str
    detail: str

    @field_validator("worker", "reason_code", "detail")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text


class ExcludeCoverageRequest(BaseModel):
    reason: str
    creator: str = "human"

    @field_validator("reason", "creator")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text


class CreateIntentRequest(BaseModel):
    from_: list[str] = Field(alias="from", min_length=1)
    description: str
    creator: str
    worker: str | None = None
    target: str | None = None
    port: int | None = None
    path: str | None = None
    surface_type: str | None = None
    action_kind: str | None = None
    test_variant: str | None = None
    priority: int | None = None
    suggested_tools: list[str] = Field(default_factory=list)
    coverage_refs: list[str] = Field(default_factory=list)
    hypothesis_id: str | None = None

    model_config = {"populate_by_name": True}

    @field_validator("description", "creator", "worker", "path", "test_variant", "hypothesis_id")
    @classmethod
    def validate_non_empty_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text

    @field_validator("from_")
    @classmethod
    def validate_fact_ids(cls, value: list[str]) -> list[str]:
        cleaned = []
        for item in value:
            text = item.strip()
            if not text:
                raise ValueError("fact ids must not be empty")
            cleaned.append(text)
        return cleaned

    @field_validator("coverage_refs")
    @classmethod
    def validate_coverage_refs(cls, value: list[str]) -> list[str]:
        return _clean_id_list(value, "coverage ids")


class HeartbeatRequest(BaseModel):
    worker: str

    @field_validator("worker")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text


class TaskFailureRequest(BaseModel):
    worker: str
    error: str
    max_attempts: int = Field(default=3, ge=1)
    backoff_seconds: int = Field(default=0, ge=0)

    @field_validator("worker", "error")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text


class ReasonClaimRequest(BaseModel):
    worker: str
    trigger: str

    @field_validator("worker", "trigger")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text


class ConcludeRequest(BaseModel):
    worker: str
    description: str
    scope: str | None = None
    vuln_type: str | None = None
    severity: str | None = None
    parent_fact: str | None = None
    verification_of: str | None = None
    goal_type: str | None = None
    status: str | None = None
    recon_category: str | None = None
    recon_executed: bool | None = None
    recon_found_results: bool | None = None
    recon_tool: str | None = None
    recon_target: str | None = None
    recon_evidence_ref: str | None = None
    coverage_refs: list[str] = Field(default_factory=list)
    observed_surfaces: list[UpsertSurfaceInventoryRequest] = Field(default_factory=list)
    schema_version: int = Field(default=1, ge=1)
    kind: str = "legacy_text"
    summary: str | None = None
    subject: dict[str, Any] = Field(default_factory=dict)
    data: dict[str, Any] = Field(default_factory=dict)
    parent_fact_ids: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    confidence: float | None = Field(default=None, ge=0, le=1)
    created_by: str | None = None

    @field_validator("worker", "description")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text

    @field_validator("coverage_refs")
    @classmethod
    def validate_coverage_refs(cls, value: list[str]) -> list[str]:
        return _clean_id_list(value, "coverage ids")


class MaterializeHypothesisWorkRequest(BaseModel):
    hypothesis: CreateHypothesisRequest
    coverage: CreateCoverageItemRequest
    intent: CreateIntentRequest
    surface_ids: list[str] = Field(default_factory=list)

    @field_validator("surface_ids")
    @classmethod
    def normalize_surface_ids(cls, value: list[str]) -> list[str]:
        return _clean_id_list(value, "surface ids")


class MaterializeHypothesisWorkResponse(BaseModel):
    hypothesis: Hypothesis
    coverage: CoverageItem
    intent: Intent
    created: bool


class CompleteRequest(BaseModel):
    from_: list[str] = Field(alias="from", min_length=1)
    description: str
    worker: str

    model_config = {"populate_by_name": True}

    @field_validator("description", "worker")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text

    @field_validator("from_")
    @classmethod
    def validate_fact_ids(cls, value: list[str]) -> list[str]:
        cleaned = []
        for item in value:
            text = item.strip()
            if not text:
                raise ValueError("fact ids must not be empty")
            cleaned.append(text)
        return cleaned


class ConcludeResponse(BaseModel):
    fact: Fact
    intent: Intent


class UpdateProjectStatusRequest(BaseModel):
    status: Literal["active", "stopped"]


class UpdateProjectPhaseRequest(BaseModel):
    phase: Literal["recon", "explore"]


class PhaseAdvanceResponse(BaseModel):
    advanced: bool
    from_phase: Literal["recon", "explore"]
    to_phase: Literal["recon", "explore"]
    code: str
    message: str
    missing_categories: list[str] = Field(default_factory=list)
    open_recon_intents: list[str] = Field(default_factory=list)


class UpdateProjectModeRequest(BaseModel):
    mode: Literal["ctf", "real_website"]

    @field_validator("mode")
    @classmethod
    def validate_mode(cls, value: str) -> str:
        return value.strip()


class UpdateProjectTitleRequest(BaseModel):
    title: str

    @field_validator("title")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text


class ReopenRequest(BaseModel):
    description: str
    creator: str

    @field_validator("description", "creator")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text


class CreateFactDirectRequest(BaseModel):
    description: str
    schema_version: int = Field(default=1, ge=1)
    kind: str = "legacy_text"
    summary: str | None = None
    subject: dict[str, Any] = Field(default_factory=dict)
    data: dict[str, Any] = Field(default_factory=dict)
    parent_fact_ids: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    confidence: float | None = Field(default=None, ge=0, le=1)
    created_by: str | None = None
    scope: str | None = None
    vuln_type: str | None = None
    severity: str | None = None
    parent_fact: str | None = None
    verification_of: str | None = None
    goal_type: str | None = None
    status: str | None = None
    recon_category: str | None = None
    recon_executed: bool | None = None
    recon_found_results: bool | None = None
    recon_tool: str | None = None
    recon_target: str | None = None
    recon_evidence_ref: str | None = None
    coverage_refs: list[str] = Field(default_factory=list)

    @field_validator("description")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text

    @field_validator("coverage_refs")
    @classmethod
    def validate_coverage_refs(cls, value: list[str]) -> list[str]:
        return _clean_id_list(value, "coverage ids")


class UpdateFactStatusRequest(BaseModel):
    status: str | None = None
    recon_evidence_ref: str | None = None
    verification_of: str | None = None

    @field_validator("status", "recon_evidence_ref", "verification_of")
    @classmethod
    def normalize_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        text = value.strip()
        return text or None


class ReopenResponse(BaseModel):
    project: ProjectMeta
    fact: Fact
    intent: Intent

class CreateTaskLogRequest(BaseModel):
    task_type: str
    intent_id: str | None = None
    worker_name: str
    phase: str
    stdin: str | None = None
    stdout: str | None = None
    stderr: str | None = None
    return_code: int | None = None
    timed_out: bool = False
    duration_ms: int | None = None


class RecordIntentExecutionRequest(BaseModel):
    worker: str
    task_log_id: str


class RecordIntentConclusionFailureRequest(BaseModel):
    worker: str
    error: str


class TaskLogSummary(BaseModel):
    id: str
    task_type: str
    intent_id: str | None = None
    worker_name: str
    phase: str
    return_code: int | None = None
    timed_out: bool = False
    duration_ms: int | None = None
    stdin_preview: str | None = None
    stdout_preview: str | None = None
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    artifact_ref: str | None = None
    created_at: str


class TaskLog(BaseModel):
    id: str
    project_id: str
    task_type: str
    intent_id: str | None = None
    worker_name: str
    phase: str
    stdin: str | None = None
    stdout: str | None = None
    stderr: str | None = None
    return_code: int | None = None
    timed_out: bool = False
    duration_ms: int | None = None
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    artifact_ref: str | None = None
    created_at: str
