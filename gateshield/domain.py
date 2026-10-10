from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


def new_id() -> str:
    return str(uuid4())


class TrustLevel(StrEnum):
    TRUSTED_SYSTEM = "TRUSTED_SYSTEM"
    TRUSTED_APPLICATION = "TRUSTED_APPLICATION"
    USER_CONTROLLED = "USER_CONTROLLED"
    EXTERNAL_RETRIEVAL = "EXTERNAL_RETRIEVAL"
    TOOL_OUTPUT = "TOOL_OUTPUT"
    UNKNOWN = "UNKNOWN"


class DataClassification(StrEnum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"


class Decision(StrEnum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REDACT = "REDACT"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    ALLOW_WITH_RESTRICTIONS = "ALLOW_WITH_RESTRICTIONS"


class ProviderType(StrEnum):
    EXTERNAL = "EXTERNAL"
    LOCAL = "LOCAL"


class RiskLevel(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AgentStatus(StrEnum):
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    REVOKED = "REVOKED"


class AgentSessionStatus(StrEnum):
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    CLOSED = "CLOSED"
    SUSPENDED = "SUSPENDED"


class AgentIdentity(BaseModel):
    id: str
    application_id: str
    owner: str
    role: str
    environment: str
    allowed_tools: list[str] = Field(default_factory=list)
    allowed_resources: dict[str, list[str]] = Field(default_factory=dict)
    risk_profile: dict[str, Any] = Field(default_factory=dict)
    status: AgentStatus = AgentStatus.ACTIVE


class AgentSession(BaseModel):
    id: str
    agent_id: str
    application_id: str
    started_at: datetime
    expires_at: datetime
    request_count: int = 0
    tool_call_count: int = 0
    denied_action_count: int = 0
    policy_manipulation_count: int = 0
    failure_count: int = 0
    cumulative_risk: int = 0
    status: AgentSessionStatus = AgentSessionStatus.ACTIVE


class BehaviorSignal(BaseModel):
    agent_id: str
    session_id: str
    signal: str
    severity: RiskLevel
    evidence: dict[str, Any] = Field(default_factory=dict)


class AIMessage(BaseModel):
    model_config = ConfigDict(extra="allow")
    role: Literal["system", "developer", "user", "assistant", "tool"]
    content: Any = None
    provenance: TrustLevel | None = None
    source: str | None = Field(default=None, max_length=256)


class MessageProvenance(BaseModel):
    message_index: int
    segment_path: str
    role: str
    source: str
    trust_level: TrustLevel


class InputFinding(BaseModel):
    finding_type: str
    severity: RiskLevel
    message_index: int
    segment_path: str
    source: str
    trust_level: TrustLevel
    matched_signal: str
    evidence: dict[str, Any] = Field(default_factory=dict)


class InputInspectionResult(BaseModel):
    provenance: list[MessageProvenance] = Field(default_factory=list)
    findings: list[InputFinding] = Field(default_factory=list)


class OutputFinding(BaseModel):
    finding_type: str
    severity: RiskLevel
    location: str
    matched_signal: str
    evidence: dict[str, Any] = Field(default_factory=dict)


class OutputInspectionResult(BaseModel):
    findings: list[OutputFinding] = Field(default_factory=list)
    sanitized_response: dict[str, Any]
    structured_output_valid: bool | None = None
    validation_error: str | None = None


class AIRequest(BaseModel):
    id: str = Field(default_factory=new_id)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    application_id: str
    user_id: str | None = None
    agent_id: str | None = None
    session_id: str | None = None
    model: str
    messages: list[AIMessage]
    tools: list[dict[str, Any]] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    source: str | None = None


class SecurityContext(BaseModel):
    request_id: str
    trace_id: str
    application_id: str
    user_id: str | None = None
    agent_id: str | None = None
    session_id: str | None = None
    environment: str
    provider_type: ProviderType = ProviderType.EXTERNAL
    message_provenance: list[MessageProvenance] = Field(default_factory=list)
    input_findings: list[InputFinding] = Field(default_factory=list)
    prompt_injection_detected: bool = False
    secret_detected: bool = False
    output_sensitive_data_detected: bool = False
    output_schema_invalid: bool = False
    tool_security_violation: bool = False
    data_classification: DataClassification = DataClassification.INTERNAL
    allowed_tools: list[str] = Field(default_factory=list)
    allowed_models: list[str] = Field(default_factory=list)
    risk_level: RiskLevel = RiskLevel.LOW


class PolicyDecision(BaseModel):
    decision: Decision = Decision.ALLOW
    reason: str = "No Phase 1 policy rules are configured."
    matched_policies: list[str] = Field(default_factory=list)
    risk_score: int = Field(default=0, ge=0, le=100)
    required_actions: list[str] = Field(default_factory=list)
    violations: list[str] = Field(default_factory=list)


class GatewayRequest(BaseModel):
    model_config = ConfigDict(extra="allow")
    model: str = Field(min_length=1, max_length=256, pattern=r"\S")
    messages: list[AIMessage] = Field(min_length=1, max_length=256)
    tools: list[dict[str, Any]] | None = Field(default=None, max_length=64)
    stream: bool = False
    user: str | None = None
    agent_id: str | None = Field(default=None, max_length=128)
    session_id: str | None = Field(default=None, max_length=36)


class GatewayResponse(BaseModel):
    id: str
    object: str = "chat.completion"
    created: int
    model: str
    choices: list[dict[str, Any]]
    usage: dict[str, Any] | None = None


class SecurityEvent(BaseModel):
    id: str = Field(default_factory=new_id)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    request_id: str
    trace_id: str
    application_id: str
    event_type: str
    policy_decision: Decision
    risk: RiskLevel = RiskLevel.LOW
    evidence: dict[str, Any] = Field(default_factory=dict)
    outcome: str
