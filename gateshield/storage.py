from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, select
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class ApplicationRecord(Base):
    __tablename__ = "applications"
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    organization_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(256))
    enabled: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )


class RequestRecord(Base):
    __tablename__ = "requests"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    trace_id: Mapped[str] = mapped_column(String(36), index=True)
    application_id: Mapped[str] = mapped_column(ForeignKey("applications.id"), index=True)
    user_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    agent_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    session_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    model: Mapped[str] = mapped_column(String(256))
    provider: Mapped[str] = mapped_column(String(64))
    decision: Mapped[str] = mapped_column(String(40))
    risk_level: Mapped[str] = mapped_column(String(20))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    latency_ms: Mapped[int] = mapped_column(Integer)
    request_redacted: Mapped[dict[str, Any]] = mapped_column(JSON)
    response_redacted: Mapped[dict[str, Any]] = mapped_column(JSON)


class SecurityEventRecord(Base):
    __tablename__ = "security_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    request_id: Mapped[str] = mapped_column(ForeignKey("requests.id"), index=True)
    trace_id: Mapped[str] = mapped_column(String(36), index=True)
    application_id: Mapped[str] = mapped_column(String(128), index=True)
    event_type: Mapped[str] = mapped_column(String(80), index=True)
    decision: Mapped[str] = mapped_column(String(40))
    risk: Mapped[str] = mapped_column(String(20))
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON)
    outcome: Mapped[str] = mapped_column(String(80))
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )


class PolicyRecord(Base):
    __tablename__ = "policies"
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    organization_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    current_version: Mapped[int] = mapped_column(Integer, nullable=False)
    active_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )


class PolicyVersionRecord(Base):
    __tablename__ = "policy_versions"
    policy_id: Mapped[str] = mapped_column(
        ForeignKey("policies.id", ondelete="CASCADE"), primary_key=True
    )
    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    definition: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    author: Mapped[str] = mapped_column(String(256), nullable=False)
    changes: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ToolDefinitionRecord(Base):
    __tablename__ = "tool_definitions"
    application_id: Mapped[str] = mapped_column(ForeignKey("applications.id"), primary_key=True)
    name: Mapped[str] = mapped_column(String(128), primary_key=True)
    description: Mapped[str] = mapped_column(String(1000), nullable=False)
    parameters: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    resource_type: Mapped[str] = mapped_column(String(40), nullable=False)
    risk_level: Mapped[str] = mapped_column(String(20), nullable=False)
    scope: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    enabled: Mapped[bool] = mapped_column(default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )


class ToolInvocationRecord(Base):
    __tablename__ = "tool_invocations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    application_id: Mapped[str] = mapped_column(String(128), index=True)
    request_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    tool_name: Mapped[str] = mapped_column(String(128), index=True)
    decision: Mapped[str] = mapped_column(String(40))
    risk_level: Mapped[str] = mapped_column(String(20))
    arguments_redacted: Mapped[dict[str, Any]] = mapped_column(JSON)
    reason: Mapped[str] = mapped_column(String(1000))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), index=True
    )


class AgentIdentityRecord(Base):
    __tablename__ = "agents"
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    application_id: Mapped[str] = mapped_column(ForeignKey("applications.id"), index=True)
    owner: Mapped[str] = mapped_column(String(256), nullable=False)
    role: Mapped[str] = mapped_column(String(128), nullable=False)
    environment: Mapped[str] = mapped_column(String(128), nullable=False)
    allowed_tools: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    allowed_resources: Mapped[dict[str, list[str]]] = mapped_column(JSON, nullable=False)
    risk_profile: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )


class AgentSessionRecord(Base):
    __tablename__ = "agent_sessions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.id"), index=True)
    application_id: Mapped[str] = mapped_column(String(128), index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    request_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    tool_call_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    denied_action_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    policy_manipulation_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    failure_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    cumulative_risk: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    status: Mapped[str] = mapped_column(String(20), nullable=False, index=True)


class BehaviorSignalRecord(Base):
    __tablename__ = "behavior_signals"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.id"), index=True)
    session_id: Mapped[str] = mapped_column(ForeignKey("agent_sessions.id"), index=True)
    request_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    signal: Mapped[str] = mapped_column(String(128), index=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), index=True
    )


def make_engine(database_url: str) -> AsyncEngine:
    return create_async_engine(database_url, pool_pre_ping=True)


def make_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


async def register_application(session: AsyncSession, app_id: str, name: str) -> None:
    record = await session.get(ApplicationRecord, app_id)
    if record is None:
        session.add(ApplicationRecord(id=app_id, name=name, enabled=True))
    elif not record.enabled:
        raise ValueError("Application is disabled")
    await session.commit()


async def ensure_schema(engine: Any) -> None:
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)


async def request_count(session: AsyncSession) -> int:
    result = await session.execute(select(RequestRecord.id))
    return len(result.scalars().all())
