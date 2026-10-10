"""Single-use approval records bound to a complete tool authorization scope."""

import hmac
import json
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from .storage import (
    PolicyRecord,
    PolicyVersionRecord,
    RequestRecord,
    SecurityEventRecord,
    ToolApprovalRecord,
)
from .tool_security import ToolDefinition, _redact_arguments


class ApprovalService:
    def __init__(
        self,
        sessions: async_sessionmaker[AsyncSession],
        signing_key: str | None,
        ttl_minutes: int,
        *,
        application_id: str,
        environment: str,
        provider_type: str,
        classification: str,
        routing_mode: str,
        routes_json: str,
        extra_detectors: frozenset[str] = frozenset(),
    ) -> None:
        self.sessions = sessions
        self.signing_key = signing_key.encode() if signing_key else None
        self.ttl_minutes = ttl_minutes
        self.extra_detectors = extra_detectors
        self.context = {
            "application_id": application_id,
            "environment": environment,
            "provider_type": provider_type,
            "classification": classification,
            "routing_mode": routing_mode,
            "routes_json": routes_json,
        }

    def _digest(self, value: Any) -> str:
        if self.signing_key is None or len(self.signing_key) < 32:
            raise RuntimeError("A 32-character approval signing key is required")
        canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
        return hmac.new(self.signing_key, canonical.encode(), "sha256").hexdigest()

    def _scope_hash(
        self,
        *,
        request_id: str,
        agent_id: str | None,
        session_id: str | None,
        tool_name: str,
        arguments: dict[str, Any],
        target: dict[str, Any] | None,
        definition: ToolDefinition,
    ) -> str:
        return self._digest(
            {
                "application_id": self.context["application_id"],
                "request_id": request_id,
                "agent_id": agent_id,
                "session_id": session_id,
                "tool_name": tool_name,
                "arguments": arguments,
                "target": target,
                "definition": definition.model_dump(mode="json"),
            }
        )

    async def _context_hash(self, request_id: str) -> str:
        async with self.sessions() as session:
            row = await session.get(RequestRecord, request_id)
            if row is None or row.application_id != self.context["application_id"]:
                raise ValueError("Approvals require a persisted request in this application")
            events = await session.execute(
                select(
                    SecurityEventRecord.event_type,
                    SecurityEventRecord.decision,
                    SecurityEventRecord.risk,
                    SecurityEventRecord.evidence,
                )
                .where(SecurityEventRecord.request_id == request_id)
                .order_by(SecurityEventRecord.timestamp)
            )
            request_context = {
                "id": row.id,
                "application_id": row.application_id,
                "agent_id": row.agent_id,
                "session_id": row.session_id,
                "model": row.model,
                "provider": row.provider,
                "decision": row.decision,
                "risk_level": row.risk_level,
                "request": row.request_redacted,
                "response": row.response_redacted,
                "security_events": [
                    {"event_type": kind, "decision": decision, "risk": risk, "evidence": evidence}
                    for kind, decision, risk, evidence in events.all()
                ],
            }
        async with self.sessions() as session:
            policy_rows = await session.execute(
                select(PolicyRecord.id, PolicyRecord.active_version, PolicyVersionRecord.definition)
                .join(PolicyVersionRecord, PolicyVersionRecord.policy_id == PolicyRecord.id)
                .where(
                    PolicyRecord.active_version == PolicyVersionRecord.version,
                    PolicyVersionRecord.status == "ACTIVE",
                )
                .order_by(PolicyRecord.id)
            )
            active_policies = [
                {"id": policy_id, "version": version, "definition": definition}
                for policy_id, version, definition in policy_rows.all()
            ]
        return self._digest(
            {
                "gateway": self.context,
                "request": request_context,
                "active_policies": active_policies,
            }
        )

    async def create_pending(
        self,
        *,
        request_id: str,
        agent_id: str | None,
        session_id: str | None,
        tool_name: str,
        arguments: dict[str, Any],
        target: dict[str, Any] | None,
        definition: ToolDefinition,
    ) -> str:
        scope_hash = self._scope_hash(
            request_id=request_id,
            agent_id=agent_id,
            session_id=session_id,
            tool_name=tool_name,
            arguments=arguments,
            target=target,
            definition=definition,
        )
        context_hash = await self._context_hash(request_id)
        now = datetime.now(UTC)
        approval_id = str(uuid4())
        async with self.sessions() as session:
            session.add(
                ToolApprovalRecord(
                    id=approval_id,
                    application_id=self.context["application_id"],
                    request_id=request_id,
                    agent_id=agent_id,
                    session_id=session_id,
                    tool_name=tool_name,
                    scope_hash=scope_hash,
                    context_hash=context_hash,
                    arguments_redacted=_redact_arguments(arguments, self.extra_detectors),
                    target_redacted=_redact_arguments(target, self.extra_detectors)
                    if target is not None
                    else None,
                    status="PENDING",
                    expires_at=now + timedelta(minutes=self.ttl_minutes),
                    created_at=now,
                )
            )
            await session.commit()
        return approval_id

    async def approve(self, approval_id: str, actor: str) -> bool:
        now = datetime.now(UTC)
        async with self.sessions() as session:
            record = await session.get(ToolApprovalRecord, approval_id)
            if (
                record is None
                or record.application_id != self.context["application_id"]
                or record.status != "PENDING"
            ):
                return False
            if _aware(record.expires_at) <= now:
                record.status = "EXPIRED"
                await session.commit()
                return False
            result = await session.execute(
                update(ToolApprovalRecord)
                .where(
                    ToolApprovalRecord.id == approval_id,
                    ToolApprovalRecord.application_id == self.context["application_id"],
                    ToolApprovalRecord.status == "PENDING",
                    ToolApprovalRecord.expires_at > now,
                )
                .values(status="APPROVED", approved_by=actor, approved_at=now)
            )
            await session.commit()
            return getattr(result, "rowcount", 0) == 1

    async def reject(self, approval_id: str) -> bool:
        now = datetime.now(UTC)
        async with self.sessions() as session:
            record = await session.get(ToolApprovalRecord, approval_id)
            if (
                record is not None
                and record.application_id == self.context["application_id"]
                and _aware(record.expires_at) <= now
                and record.status == "PENDING"
            ):
                record.status = "EXPIRED"
                await session.commit()
                return False
            result = await session.execute(
                update(ToolApprovalRecord)
                .where(
                    ToolApprovalRecord.id == approval_id,
                    ToolApprovalRecord.application_id == self.context["application_id"],
                    ToolApprovalRecord.status == "PENDING",
                    ToolApprovalRecord.expires_at > now,
                )
                .values(status="REJECTED")
            )
            await session.commit()
            return getattr(result, "rowcount", 0) == 1

    async def consume(
        self,
        approval_id: str,
        *,
        request_id: str,
        agent_id: str | None,
        session_id: str | None,
        tool_name: str,
        arguments: dict[str, Any],
        target: dict[str, Any] | None,
        definition: ToolDefinition,
    ) -> bool:
        scope_hash = self._scope_hash(
            request_id=request_id,
            agent_id=agent_id,
            session_id=session_id,
            tool_name=tool_name,
            arguments=arguments,
            target=target,
            definition=definition,
        )
        context_hash = await self._context_hash(request_id)
        now = datetime.now(UTC)
        async with self.sessions() as session:
            record = await session.get(ToolApprovalRecord, approval_id)
            if record is None or record.status != "APPROVED":
                return False
            if _aware(record.expires_at) <= now:
                record.status = "EXPIRED"
                await session.commit()
                return False
            fields_match = (
                record.application_id == self.context["application_id"]
                and record.request_id == request_id
                and record.agent_id == agent_id
                and record.session_id == session_id
                and record.tool_name == tool_name
                and hmac.compare_digest(record.scope_hash, scope_hash)
                and hmac.compare_digest(record.context_hash, context_hash)
            )
            if not fields_match:
                return False
            result = await session.execute(
                update(ToolApprovalRecord)
                .where(
                    ToolApprovalRecord.id == approval_id,
                    ToolApprovalRecord.status == "APPROVED",
                    ToolApprovalRecord.consumed_at.is_(None),
                    ToolApprovalRecord.expires_at > now,
                    ToolApprovalRecord.scope_hash == scope_hash,
                    ToolApprovalRecord.context_hash == context_hash,
                )
                .values(status="CONSUMED", consumed_at=now)
            )
            await session.commit()
            return getattr(result, "rowcount", 0) == 1


def _aware(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value
