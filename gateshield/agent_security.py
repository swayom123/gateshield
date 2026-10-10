import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from .domain import (
    AgentIdentity,
    AgentSession,
    AgentSessionStatus,
    AgentStatus,
    BehaviorSignal,
    RiskLevel,
)
from .storage import (
    AgentIdentityRecord,
    AgentSessionRecord,
    BehaviorSignalRecord,
)


class AgentEnrollmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
    owner: str = Field(min_length=1, max_length=256)
    role: str = Field(min_length=1, max_length=128)
    environment: str = Field(min_length=1, max_length=128)
    allowed_tools: list[str] = Field(default_factory=list, max_length=64)
    allowed_resources: dict[str, list[str]] = Field(default_factory=dict)
    risk_profile: dict[str, Any] = Field(default_factory=dict)

    @field_validator("allowed_tools")
    @classmethod
    def unique_tools(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("allowed_tools must not contain duplicates")
        return value

    @field_validator("risk_profile")
    @classmethod
    def bounded_risk_profile(cls, value: dict[str, Any]) -> dict[str, Any]:
        limits = {
            "max_tool_calls_per_session": 1000,
            "max_cumulative_risk": 10000,
            "denied_action_threshold": 100,
            "policy_manipulation_threshold": 100,
            "failure_count_threshold": 100,
        }
        if set(value) - set(limits):
            raise ValueError("risk_profile contains an unsupported threshold")
        for name, maximum in limits.items():
            if name in value and (
                not isinstance(value[name], int)
                or isinstance(value[name], bool)
                or not 1 <= value[name] <= maximum
            ):
                raise ValueError(f"{name} must be between 1 and {maximum}")
        return value

    @model_validator(mode="after")
    def validate_resource_permissions(self) -> "AgentEnrollmentRequest":
        if set(self.allowed_resources) - set(self.allowed_tools):
            raise ValueError("allowed_resources can only further restrict an allowed tool")
        if any(
            not resources
            or len(resources) > 1000
            or any(not item or len(item) > 256 for item in resources)
            for resources in self.allowed_resources.values()
        ):
            raise ValueError("allowed resource lists must contain bounded non-empty identifiers")
        return self


class AgentSessionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ttl_minutes: int | None = Field(default=None, ge=1, le=1440)


class AgentSecurityService:
    def __init__(self, sessions: async_sessionmaker[AsyncSession]) -> None:
        self.sessions = sessions

    async def enroll(
        self, application_id: str, payload: AgentEnrollmentRequest
    ) -> tuple[AgentIdentity, str]:
        token = secrets.token_urlsafe(32)
        async with self.sessions() as session:
            if await session.get(AgentIdentityRecord, payload.id) is not None:
                raise ValueError("Agent ID already exists")
            record = AgentIdentityRecord(
                id=payload.id,
                application_id=application_id,
                owner=payload.owner,
                role=payload.role,
                environment=payload.environment,
                allowed_tools=payload.allowed_tools,
                allowed_resources=payload.allowed_resources,
                risk_profile=payload.risk_profile,
                status=AgentStatus.ACTIVE.value,
                token_hash=_token_hash(token),
                created_at=datetime.now(UTC),
            )
            session.add(record)
            await session.commit()
            return _identity(record), token

    async def authenticate(self, token: str) -> AgentIdentity | None:
        token_hash = _token_hash(token)
        async with self.sessions() as session:
            result = await session.execute(
                select(AgentIdentityRecord).where(AgentIdentityRecord.token_hash == token_hash)
            )
            record = result.scalar_one_or_none()
            if record is None or not hmac.compare_digest(record.token_hash, token_hash):
                return None
            return _identity(record)

    async def get_identity(self, agent_id: str) -> AgentIdentity | None:
        async with self.sessions() as session:
            record = await session.get(AgentIdentityRecord, agent_id)
            return _identity(record) if record is not None else None

    async def create_session(self, identity: AgentIdentity, ttl_minutes: int) -> AgentSession:
        if identity.status is not AgentStatus.ACTIVE:
            raise ValueError("Agent is not active")
        now = datetime.now(UTC)
        value = AgentSessionRecord(
            id=str(uuid4()),
            agent_id=identity.id,
            application_id=identity.application_id,
            started_at=now,
            expires_at=now + timedelta(minutes=ttl_minutes),
            status=AgentSessionStatus.ACTIVE.value,
        )
        async with self.sessions() as session:
            session.add(value)
            await session.commit()
            return _agent_session(value)

    async def validate_session(
        self, identity: AgentIdentity, session_id: str
    ) -> AgentSession | None:
        async with self.sessions() as session:
            value = await session.get(AgentSessionRecord, session_id)
            if (
                value is None
                or value.agent_id != identity.id
                or value.application_id != identity.application_id
            ):
                return None
            expires_at = _aware(value.expires_at)
            if expires_at <= datetime.now(UTC):
                value.status = AgentSessionStatus.EXPIRED.value
                await session.commit()
                return None
            if value.status != AgentSessionStatus.ACTIVE.value:
                return None
            max_tools = int(identity.risk_profile.get("max_tool_calls_per_session", 50))
            max_risk = int(identity.risk_profile.get("max_cumulative_risk", 500))
            signals: list[BehaviorSignal] = []
            if value.tool_call_count >= max_tools:
                value.status = AgentSessionStatus.SUSPENDED.value
                signals.append(
                    _signal(
                        identity.id,
                        session_id,
                        "unusual_tool_volume",
                        RiskLevel.HIGH,
                        {"count": value.tool_call_count, "limit": max_tools},
                    )
                )
            if value.cumulative_risk >= max_risk:
                value.status = AgentSessionStatus.SUSPENDED.value
                signals.append(
                    _signal(
                        identity.id,
                        session_id,
                        "high_cumulative_session_risk",
                        RiskLevel.HIGH,
                        {"cumulative_risk": value.cumulative_risk, "limit": max_risk},
                    )
                )
            if signals:
                await self._save_new_signals(session, signals, None)
                await session.commit()
                return None
            return _agent_session(value)

    async def close_session(self, identity: AgentIdentity, session_id: str) -> bool:
        async with self.sessions() as session:
            value = await session.get(AgentSessionRecord, session_id)
            if value is None or value.agent_id != identity.id:
                return False
            if value.status == AgentSessionStatus.ACTIVE.value:
                value.status = AgentSessionStatus.CLOSED.value
                await session.commit()
            return True

    async def set_status(self, agent_id: str, status: AgentStatus) -> None:
        async with self.sessions() as session:
            record = await session.get(AgentIdentityRecord, agent_id)
            if record is None:
                raise ValueError("Agent does not exist")
            record.status = status.value
            await session.commit()

    async def record_request(
        self,
        session_id: str,
        *,
        request_id: str,
        risk_score: int,
        policy_manipulation: bool,
    ) -> list[BehaviorSignal]:
        async with self.sessions() as session:
            value = await session.get(AgentSessionRecord, session_id, with_for_update=True)
            if value is None or value.status != AgentSessionStatus.ACTIVE.value:
                raise ValueError("Agent session is not active")
            agent = await session.get(AgentIdentityRecord, value.agent_id)
            if agent is None:
                raise ValueError("Agent identity is unavailable")
            value.request_count += 1
            value.cumulative_risk += max(0, risk_score)
            if policy_manipulation:
                value.policy_manipulation_count += 1
            signals: list[BehaviorSignal] = []
            manipulation_limit = int(agent.risk_profile.get("policy_manipulation_threshold", 3))
            risk_limit = int(agent.risk_profile.get("max_cumulative_risk", 500))
            if value.policy_manipulation_count >= manipulation_limit:
                signals.append(
                    _signal(
                        agent.id,
                        session_id,
                        "repeated_policy_manipulation",
                        RiskLevel.HIGH,
                        {"count": value.policy_manipulation_count},
                    )
                )
            if value.cumulative_risk >= risk_limit:
                signals.append(
                    _signal(
                        agent.id,
                        session_id,
                        "high_cumulative_session_risk",
                        RiskLevel.HIGH,
                        {"cumulative_risk": value.cumulative_risk},
                    )
                )
            await self._save_new_signals(session, signals, request_id)
            await session.commit()
            return signals

    async def record_tool_activity(
        self,
        session_id: str,
        *,
        request_id: str | None,
        attempts: int,
        denied: int,
        risk_increment: int = 0,
        resource_scope_violation: bool = False,
    ) -> list[BehaviorSignal]:
        async with self.sessions() as session:
            value = await session.get(AgentSessionRecord, session_id, with_for_update=True)
            if value is None or value.status != AgentSessionStatus.ACTIVE.value:
                raise ValueError("Agent session is not active")
            agent = await session.get(AgentIdentityRecord, value.agent_id)
            if agent is None:
                raise ValueError("Agent identity is unavailable")
            value.tool_call_count += attempts
            value.denied_action_count += denied
            value.cumulative_risk += max(0, risk_increment)
            signals: list[BehaviorSignal] = []
            denied_limit = int(agent.risk_profile.get("denied_action_threshold", 3))
            volume_limit = int(agent.risk_profile.get("max_tool_calls_per_session", 50))
            risk_limit = int(agent.risk_profile.get("max_cumulative_risk", 500))
            if value.denied_action_count >= denied_limit:
                signals.append(
                    _signal(
                        agent.id,
                        session_id,
                        "repeated_denied_actions",
                        RiskLevel.HIGH,
                        {"count": value.denied_action_count},
                    )
                )
            if value.tool_call_count > volume_limit:
                signals.append(
                    _signal(
                        agent.id,
                        session_id,
                        "unusual_tool_volume",
                        RiskLevel.MEDIUM,
                        {"count": value.tool_call_count, "limit": volume_limit},
                    )
                )
            if resource_scope_violation:
                signals.append(
                    _signal(
                        agent.id,
                        session_id,
                        "resource_scope_expansion_attempt",
                        RiskLevel.HIGH,
                        {"denied_action_count": value.denied_action_count},
                    )
                )
            if value.cumulative_risk >= risk_limit:
                signals.append(
                    _signal(
                        agent.id,
                        session_id,
                        "high_cumulative_session_risk",
                        RiskLevel.HIGH,
                        {"cumulative_risk": value.cumulative_risk, "limit": risk_limit},
                    )
                )
            await self._save_new_signals(session, signals, request_id)
            await session.commit()
            return signals

    async def record_failure(self, session_id: str, request_id: str) -> list[BehaviorSignal]:
        async with self.sessions() as session:
            value = await session.get(AgentSessionRecord, session_id, with_for_update=True)
            if value is None:
                return []
            value.failure_count += 1
            agent = await session.get(AgentIdentityRecord, value.agent_id)
            signals: list[BehaviorSignal] = []
            failure_limit = (
                int(agent.risk_profile.get("failure_count_threshold", 5)) if agent else 5
            )
            if value.failure_count >= failure_limit and value.request_count >= 5:
                signals.append(
                    _signal(
                        value.agent_id,
                        session_id,
                        "high_failure_rate",
                        RiskLevel.MEDIUM,
                        {
                            "failure_count": value.failure_count,
                            "request_count": value.request_count,
                        },
                    )
                )
            await self._save_new_signals(session, signals, request_id)
            await session.commit()
            return signals

    async def signals(self, agent_id: str, session_id: str) -> list[BehaviorSignal]:
        async with self.sessions() as session:
            rows = await session.execute(
                select(BehaviorSignalRecord)
                .where(
                    BehaviorSignalRecord.agent_id == agent_id,
                    BehaviorSignalRecord.session_id == session_id,
                )
                .order_by(BehaviorSignalRecord.created_at)
            )
            return [
                BehaviorSignal(
                    agent_id=row.agent_id,
                    session_id=row.session_id,
                    signal=row.signal,
                    severity=RiskLevel(row.severity),
                    evidence=row.evidence,
                )
                for row in rows.scalars()
            ]

    async def _save_new_signals(
        self, session: AsyncSession, signals: list[BehaviorSignal], request_id: str | None
    ) -> None:
        for item in signals:
            exists = await session.scalar(
                select(BehaviorSignalRecord.id).where(
                    BehaviorSignalRecord.session_id == item.session_id,
                    BehaviorSignalRecord.signal == item.signal,
                )
            )
            if exists is None:
                session.add(
                    BehaviorSignalRecord(
                        id=str(uuid4()),
                        agent_id=item.agent_id,
                        session_id=item.session_id,
                        request_id=request_id,
                        signal=item.signal,
                        severity=item.severity.value,
                        evidence=item.evidence,
                        created_at=datetime.now(UTC),
                    )
                )


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _aware(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


def _identity(record: AgentIdentityRecord) -> AgentIdentity:
    return AgentIdentity(
        id=record.id,
        application_id=record.application_id,
        owner=record.owner,
        role=record.role,
        environment=record.environment,
        allowed_tools=record.allowed_tools,
        allowed_resources=record.allowed_resources,
        risk_profile=record.risk_profile,
        status=AgentStatus(record.status),
    )


def _agent_session(record: AgentSessionRecord) -> AgentSession:
    return AgentSession(
        id=record.id,
        agent_id=record.agent_id,
        application_id=record.application_id,
        started_at=_aware(record.started_at),
        expires_at=_aware(record.expires_at),
        request_count=record.request_count,
        tool_call_count=record.tool_call_count,
        denied_action_count=record.denied_action_count,
        policy_manipulation_count=record.policy_manipulation_count,
        failure_count=record.failure_count,
        cumulative_risk=record.cumulative_risk,
        status=AgentSessionStatus(record.status),
    )


def _signal(
    agent_id: str,
    session_id: str,
    name: str,
    severity: RiskLevel,
    evidence: dict[str, Any],
) -> BehaviorSignal:
    return BehaviorSignal(
        agent_id=agent_id,
        session_id=session_id,
        signal=name,
        severity=severity,
        evidence=evidence,
    )


def enrollment_key_matches(configured_key: str, supplied_key: str | None) -> bool:
    return supplied_key is not None and hmac.compare_digest(configured_key, supplied_key)
