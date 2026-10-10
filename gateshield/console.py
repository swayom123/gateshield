"""Authenticated, read-mostly security operations console."""

import hmac
import json
import re
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select

from .config import get_settings
from .policies import PolicyDefinition
from .storage import (
    AgentIdentityRecord,
    AgentSessionRecord,
    ConsoleAuditRecord,
    PolicyRecord,
    PolicyVersionRecord,
    RequestRecord,
    SecurityEventRecord,
    ToolApprovalRecord,
    ToolDefinitionRecord,
    ToolInvocationRecord,
)

router = APIRouter(prefix="/console", tags=["console"])
basic = HTTPBasic(auto_error=False)
ROLES = {"ADMIN", "SECURITY_ADMIN", "POLICY_EDITOR", "ANALYST", "AUDITOR", "VIEWER"}
READ_ROLES = ROLES
OPS_READ = ROLES - {"VIEWER"}
POLICY_WRITE = {"ADMIN", "SECURITY_ADMIN", "POLICY_EDITOR"}


def redact(value: Any) -> Any:
    if isinstance(value, str):
        patterns = (
            re.compile(r"(?i)(api[_-]?key|token|password|secret)\s*[:=]\s*([^\s,;]+)"),
            re.compile(r"\b(?:sk-[A-Za-z0-9_-]{12,}|AKIA[0-9A-Z]{16})\b"),
            re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
            re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}"),
        )
        for pattern in patterns:
            value = pattern.sub(
                lambda m: m.group(1) + "=[REDACTED]" if m.lastindex else "[REDACTED]", value
            )
        return value
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, dict):
        sensitive = re.compile(r"(?i)(secret|token|password|api[_-]?key|authorization|credential)")
        return {
            key: "[REDACTED]" if sensitive.search(str(key)) and item is not None else redact(item)
            for key, item in value.items()
        }
    return value


async def current_user(
    credentials: HTTPBasicCredentials | None = Depends(basic),
) -> dict[str, str]:
    try:
        users = json.loads(get_settings().console_users_json)
    except (ValueError, TypeError) as exc:
        raise HTTPException(503, "Console user configuration is invalid") from exc
    if not isinstance(users, dict) or not users:
        raise HTTPException(503, "Console authentication is not configured")
    if credentials is None:
        raise HTTPException(
            401, "Console authentication required", headers={"WWW-Authenticate": "Basic"}
        )
    user = users.get(credentials.username)
    if not isinstance(user, dict):
        raise HTTPException(
            401, "Invalid console credentials", headers={"WWW-Authenticate": "Basic"}
        )
    password = user.get("password")
    role = user.get("role")
    if (
        not isinstance(password, str)
        or len(password) < 16
        or not hmac.compare_digest(password.encode(), credentials.password.encode())
        or not isinstance(role, str)
        or role not in ROLES
    ):
        raise HTTPException(
            401, "Invalid console credentials", headers={"WWW-Authenticate": "Basic"}
        )
    return {"username": credentials.username, "role": role}


def require_roles(*roles: str) -> Any:
    allowed = set(roles)

    async def dependency(user: dict[str, str] = Depends(current_user)) -> dict[str, str]:
        if user["role"] not in allowed:
            raise HTTPException(403, "This console role cannot perform that action")
        return user

    return dependency


def require_write_roles(*roles: str) -> Any:
    allowed = set(roles)

    async def dependency(
        request: Request, user: dict[str, str] = Depends(current_user)
    ) -> dict[str, str]:
        if user["role"] not in allowed:
            raise HTTPException(403, "This console role cannot perform that action")
        if request.headers.get("X-Console-Action") != "same-origin":
            raise HTTPException(403, "Console mutation requires the same-origin action header")
        return user

    return dependency


class DraftBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    definition: PolicyDefinition
    changes: list[str] = Field(default_factory=list, max_length=20)


class PolicyTestBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    definition: PolicyDefinition
    limit: int = Field(default=100, ge=1, le=500)


@router.get("", response_class=HTMLResponse)
async def console_home(user: dict[str, str] = Depends(current_user)) -> str:
    del user
    return CONSOLE_HTML


@router.get("/api/me")
async def whoami(user: dict[str, str] = Depends(current_user)) -> dict[str, str]:
    return user


@router.get("/api/overview")
async def overview(
    request: Request, user: dict[str, str] = Depends(require_roles(*READ_ROLES))
) -> dict[str, Any]:
    del user
    async with request.app.state.session_factory() as session:
        total = await session.scalar(select(func.count()).select_from(RequestRecord)) or 0
        decisions_result = await session.execute(
            select(RequestRecord.decision, func.count()).group_by(RequestRecord.decision)
        )
        risks_result = await session.execute(
            select(RequestRecord.risk_level, func.count()).group_by(RequestRecord.risk_level)
        )
        events_result = await session.execute(
            select(SecurityEventRecord.event_type, func.count()).group_by(
                SecurityEventRecord.event_type
            )
        )
        latest_request = await session.scalar(select(func.max(RequestRecord.started_at)))
        latest_event = await session.scalar(select(func.max(SecurityEventRecord.timestamp)))
        pending = (
            await session.scalar(
                select(func.count())
                .select_from(ToolApprovalRecord)
                .where(
                    ToolApprovalRecord.application_id == get_settings().application_id,
                    ToolApprovalRecord.status == "PENDING",
                    ToolApprovalRecord.expires_at > datetime.now(UTC),
                )
            )
            or 0
        )
    decisions = dict(decisions_result.all())
    risks = dict(risks_result.all())
    event_types = dict(events_result.all())
    latest_updated = max(
        (value for value in (latest_request, latest_event) if value is not None),
        default=None,
    )
    return {
        "request_total": total,
        "decisions": decisions,
        "blocked": decisions.get("BLOCK", 0),
        "redacted": decisions.get("REDACT", 0),
        "high_risk": risks.get("HIGH", 0) + risks.get("CRITICAL", 0),
        "prompt_injection": sum(
            n for kind, n in event_types.items() if "INJECTION" in kind.upper()
        ),
        "tool_blocks": sum(
            n
            for kind, n in event_types.items()
            if "TOOL" in kind.upper() and "BLOCK" in kind.upper()
        ),
        "pending_approvals": pending,
        "last_updated": latest_updated.isoformat() if latest_updated is not None else None,
    }


@router.get("/api/requests")
async def requests(
    request: Request,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    application_id: str | None = None,
    agent_id: str | None = None,
    decision: str | None = None,
    risk: str | None = None,
    model: str | None = None,
    from_time: datetime | None = None,
    to_time: datetime | None = None,
    user: dict[str, str] = Depends(require_roles(*OPS_READ)),
) -> dict[str, Any]:
    del user
    async with request.app.state.session_factory() as session:
        query = select(RequestRecord)
        for column, value in (
            (RequestRecord.application_id, application_id),
            (RequestRecord.agent_id, agent_id),
            (RequestRecord.decision, decision),
            (RequestRecord.risk_level, risk),
            (RequestRecord.model, model),
        ):
            if value:
                query = query.where(column == value)
        if from_time:
            query = query.where(RequestRecord.started_at >= from_time)
        if to_time:
            query = query.where(RequestRecord.started_at <= to_time)
        total = await session.scalar(select(func.count()).select_from(query.subquery())) or 0
        rows = await session.execute(
            query.order_by(RequestRecord.started_at.desc()).limit(limit).offset(offset)
        )
        items = [_request_row(row) for row in rows.scalars()]
    return {"data": items, "total": total, "limit": limit, "offset": offset}


@router.get("/api/requests/{request_id}")
async def request_detail(
    request_id: str, request: Request, user: dict[str, str] = Depends(require_roles(*OPS_READ))
) -> dict[str, Any]:
    del user
    async with request.app.state.session_factory() as session:
        row = await session.get(RequestRecord, request_id)
        if row is None:
            raise HTTPException(404, "Request not found")
        events = await session.execute(
            select(SecurityEventRecord)
            .where(SecurityEventRecord.request_id == request_id)
            .order_by(SecurityEventRecord.timestamp)
        )
    return {
        "request": _request_row(row, include_content=True),
        "events": [_event_row(event) for event in events.scalars()],
    }


@router.get("/api/events")
async def events(
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    event_type: str | None = None,
    severity: str | None = None,
    application_id: str | None = None,
    policy: str | None = None,
    request_id: str | None = None,
    outcome: str | None = None,
    agent_id: str | None = None,
    from_time: datetime | None = None,
    to_time: datetime | None = None,
    user: dict[str, str] = Depends(require_roles(*OPS_READ)),
) -> dict[str, Any]:
    del user
    async with request.app.state.session_factory() as session:
        query = select(SecurityEventRecord)
        for column, value in (
            (SecurityEventRecord.event_type, event_type),
            (SecurityEventRecord.risk, severity),
            (SecurityEventRecord.application_id, application_id),
            (SecurityEventRecord.request_id, request_id),
            (SecurityEventRecord.outcome, outcome),
        ):
            if value:
                query = query.where(column == value)
        if agent_id:
            query = query.join(
                RequestRecord, RequestRecord.id == SecurityEventRecord.request_id
            ).where(RequestRecord.agent_id == agent_id)
        if from_time:
            query = query.where(SecurityEventRecord.timestamp >= from_time)
        if to_time:
            query = query.where(SecurityEventRecord.timestamp <= to_time)
        if policy:
            rows = await session.execute(query.order_by(SecurityEventRecord.timestamp.desc()))
            filtered = [
                row for row in rows.scalars() if policy in row.evidence.get("matched_policies", [])
            ]
            total = len(filtered)
            selected = filtered[offset : offset + limit]
        else:
            total = await session.scalar(select(func.count()).select_from(query.subquery())) or 0
            rows = await session.execute(
                query.order_by(SecurityEventRecord.timestamp.desc()).limit(limit).offset(offset)
            )
            selected = list(rows.scalars())
    return {
        "data": [_event_row(row) for row in selected],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/api/policies")
async def policies(
    request: Request, user: dict[str, str] = Depends(require_roles(*OPS_READ))
) -> dict[str, Any]:
    del user
    async with request.app.state.session_factory() as session:
        rows = await session.execute(select(PolicyRecord).order_by(PolicyRecord.id))
        result = []
        for policy in rows.scalars():
            versions = await session.execute(
                select(PolicyVersionRecord)
                .where(PolicyVersionRecord.policy_id == policy.id)
                .order_by(PolicyVersionRecord.version)
            )
            result.append(
                {
                    "id": policy.id,
                    "active_version": policy.active_version,
                    "current_version": policy.current_version,
                    "versions": [_version_row(v) for v in versions.scalars()],
                }
            )
    return {"data": result}


@router.post("/api/policies")
async def create_policy(
    body: DraftBody,
    request: Request,
    user: dict[str, str] = Depends(require_write_roles(*POLICY_WRITE)),
) -> dict[str, Any]:
    try:
        version = await request.app.state.policy_repository.create_draft(
            body.definition, author=user["username"], changes=body.changes
        )
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    await _audit_action(
        request,
        user["username"],
        "POLICY_DRAFT_CREATED",
        body.definition.id,
        {"version": version, "changes": body.changes},
    )
    return {"policy_id": body.definition.id, "version": version, "status": "DRAFT"}


@router.post("/api/policies/{policy_id}/versions")
async def revise_policy(
    policy_id: str,
    body: DraftBody,
    request: Request,
    user: dict[str, str] = Depends(require_write_roles(*POLICY_WRITE)),
) -> dict[str, Any]:
    try:
        version = await request.app.state.policy_repository.revise(
            policy_id, body.definition, author=user["username"], changes=body.changes
        )
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    await _audit_action(
        request,
        user["username"],
        "POLICY_DRAFT_REVISED",
        policy_id,
        {"version": version, "changes": body.changes},
    )
    return {"policy_id": policy_id, "version": version, "status": "DRAFT"}


@router.post("/api/policies/{policy_id}/activate")
async def activate_policy(
    policy_id: str,
    request: Request,
    version: int | None = None,
    user: dict[str, str] = Depends(require_write_roles(*POLICY_WRITE)),
) -> dict[str, Any]:
    try:
        await request.app.state.policy_repository.activate(policy_id, version)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc
    await _audit_action(
        request, user["username"], "POLICY_ACTIVATED", policy_id, {"version": version}
    )
    return {"policy_id": policy_id, "active_version": version or "current"}


@router.post("/api/policies/{policy_id}/retire")
async def retire_policy(
    policy_id: str,
    request: Request,
    user: dict[str, str] = Depends(require_write_roles("ADMIN", "SECURITY_ADMIN")),
) -> dict[str, Any]:
    try:
        await request.app.state.policy_repository.retire(policy_id)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc
    await _audit_action(request, user["username"], "POLICY_RETIRED", policy_id, {})
    return {"policy_id": policy_id, "status": "RETIRED"}


@router.post("/api/policies/test")
async def test_policy(
    body: PolicyTestBody,
    request: Request,
    user: dict[str, str] = Depends(require_roles(*POLICY_WRITE)),
) -> dict[str, Any]:
    del user
    # Report only comparisons supported by persisted sanitized evidence.
    condition_fields = set(body.definition.conditions.model_dump(exclude_none=True))
    supported = {
        "application_id",
        "agent_id",
        "user_id",
        "model",
        "has_tools",
        "prompt_injection_detected",
        "secret_detected",
        "output_sensitive_data_detected",
        "tool_security_violation",
    }
    unknown_fields = sorted(condition_fields - supported)
    async with request.app.state.session_factory() as session:
        rows = await session.execute(
            select(RequestRecord).order_by(RequestRecord.started_at.desc()).limit(body.limit)
        )
        records = list(rows.scalars())
        output = []
        for row in records:
            if unknown_fields:
                output.append(
                    {
                        "request_id": row.id,
                        "status": "insufficient_evidence",
                        "unknown_fields": unknown_fields,
                    }
                )
                continue
            values = body.definition.conditions.model_dump(exclude_none=True)
            data = row.request_redacted
            if "has_tools" in values and "tools" not in data:
                output.append(
                    {
                        "request_id": row.id,
                        "status": "insufficient_evidence",
                        "unknown_fields": ["has_tools"],
                    }
                )
                continue
            actual: dict[str, Any] = {
                "application_id": row.application_id,
                "agent_id": row.agent_id,
                "user_id": row.user_id,
                "model": row.model,
                "has_tools": bool(data.get("tools")),
            }
            ev_rows = await session.execute(
                select(SecurityEventRecord.event_type).where(
                    SecurityEventRecord.request_id == row.id
                )
            )
            event_names = [name.upper() for name in ev_rows.scalars()]
            flags = {
                "prompt_injection_detected": any("INJECTION" in name for name in event_names),
                "secret_detected": any(
                    "SECRET" in name or "CREDENTIAL" in name for name in event_names
                ),
                "output_sensitive_data_detected": any(
                    "OUTPUT" in name and ("SENSITIVE" in name or "SECRET" in name or "PII" in name)
                    for name in event_names
                ),
                "tool_security_violation": any(
                    "TOOL" in name and ("BLOCK" in name or "VIOLATION" in name)
                    for name in event_names
                ),
            }
            actual.update(flags)
            matched = all(actual.get(k) == v for k, v in values.items())
            enforced = matched and body.definition.mode.value == "ENFORCE"
            output.append(
                {
                    "request_id": row.id,
                    "status": "would_match" if matched else "would_not_match",
                    "would_decision": body.definition.effect.value if enforced else "ALLOW",
                    "matched_conditions": [k for k, v in values.items() if actual.get(k) == v],
                    "potential_false_positive_review": enforced and row.decision == "ALLOW",
                }
            )
    return {
        "policy_id": body.definition.id,
        "policy_mode": body.definition.mode.value,
        "policy_effect": body.definition.effect.value,
        "fixture": "persisted historical requests",
        "evaluated": len(records),
        "results": output,
        "limitations": [
            "Only sanitized stored evidence was evaluated.",
            "This compares a single policy's conditions; it does not replay policy priority, provider, or tool execution.",
            "Potential false-positive rows are review candidates, not confirmed errors; no analyst labels exist.",
        ],
    }


@router.get("/api/agents")
async def agents(
    request: Request, user: dict[str, str] = Depends(require_roles(*OPS_READ))
) -> dict[str, Any]:
    del user
    async with request.app.state.session_factory() as session:
        rows = await session.execute(
            select(AgentIdentityRecord).order_by(AgentIdentityRecord.created_at.desc())
        )
        values = [
            {
                "id": a.id,
                "application_id": a.application_id,
                "owner": a.owner,
                "role": a.role,
                "environment": a.environment,
                "allowed_tools": a.allowed_tools,
                "allowed_resources": a.allowed_resources,
                "risk_profile": a.risk_profile,
                "status": a.status,
                "created_at": a.created_at,
            }
            for a in rows.scalars()
        ]
    return {"data": values}


@router.get("/api/tools")
async def tools(
    request: Request, user: dict[str, str] = Depends(require_roles(*OPS_READ))
) -> dict[str, Any]:
    del user
    async with request.app.state.session_factory() as session:
        definitions = await session.execute(
            select(ToolDefinitionRecord).order_by(
                ToolDefinitionRecord.application_id, ToolDefinitionRecord.name
            )
        )
        invocations = await session.execute(
            select(ToolInvocationRecord).order_by(ToolInvocationRecord.created_at.desc()).limit(200)
        )
    return {
        "definitions": [
            {
                "application_id": r.application_id,
                "name": r.name,
                "description": r.description,
                "parameters": redact(r.parameters),
                "resource_type": r.resource_type,
                "risk_level": r.risk_level,
                "scope": redact(r.scope),
                "enabled": r.enabled,
            }
            for r in definitions.scalars()
        ],
        "recent_invocations": [
            {
                "id": i.id,
                "application_id": i.application_id,
                "request_id": i.request_id,
                "tool_name": i.tool_name,
                "decision": i.decision,
                "risk_level": i.risk_level,
                "arguments": redact(i.arguments_redacted),
                "reason": i.reason,
                "created_at": i.created_at,
            }
            for i in invocations.scalars()
        ],
    }


@router.get("/api/sessions")
async def sessions(
    request: Request, user: dict[str, str] = Depends(require_roles(*READ_ROLES))
) -> dict[str, Any]:
    del user
    async with request.app.state.session_factory() as session:
        rows = await session.execute(
            select(AgentSessionRecord).order_by(AgentSessionRecord.started_at.desc()).limit(500)
        )
    return {
        "data": [
            {
                "id": s.id,
                "agent_id": s.agent_id,
                "application_id": s.application_id,
                "started_at": s.started_at,
                "expires_at": s.expires_at,
                "request_count": s.request_count,
                "tool_call_count": s.tool_call_count,
                "denied_action_count": s.denied_action_count,
                "failure_count": s.failure_count,
                "cumulative_risk": s.cumulative_risk,
                "status": s.status,
            }
            for s in rows.scalars()
        ]
    }


@router.get("/api/approvals")
async def approvals(
    request: Request, user: dict[str, str] = Depends(require_roles(*OPS_READ))
) -> dict[str, Any]:
    del user
    async with request.app.state.session_factory() as session:
        rows = await session.execute(
            select(ToolApprovalRecord)
            .where(ToolApprovalRecord.application_id == get_settings().application_id)
            .order_by(ToolApprovalRecord.created_at.desc())
            .limit(500)
        )
    return {
        "data": [
            {
                "id": r.id,
                "application_id": r.application_id,
                "request_id": r.request_id,
                "agent_id": r.agent_id,
                "session_id": r.session_id,
                "tool_name": r.tool_name,
                "arguments": redact(r.arguments_redacted),
                "target": redact(r.target_redacted),
                "scope_hash": r.scope_hash[:12],
                "policy_context_hash": r.context_hash[:12],
                "created_at": r.created_at,
                "expires_at": r.expires_at,
                "status": "EXPIRED"
                if r.status == "PENDING" and _aware(r.expires_at) <= datetime.now(UTC)
                else r.status,
                "approved_by": r.approved_by,
            }
            for r in rows.scalars()
        ]
    }


@router.post("/api/approvals/{approval_id}/approve")
async def approve_action(
    approval_id: str,
    request: Request,
    user: dict[str, str] = Depends(require_write_roles("ADMIN", "SECURITY_ADMIN")),
) -> dict[str, Any]:
    approved = await request.app.state.approval_service.approve(approval_id, user["username"])
    if not approved:
        raise HTTPException(409, "Approval is not pending or has expired")
    await _audit_action(request, user["username"], "TOOL_APPROVAL_GRANTED", approval_id, {})
    return {"approval_id": approval_id, "status": "APPROVED"}


@router.post("/api/approvals/{approval_id}/reject")
async def reject_action(
    approval_id: str,
    request: Request,
    user: dict[str, str] = Depends(require_write_roles("ADMIN", "SECURITY_ADMIN")),
) -> dict[str, Any]:
    rejected = await request.app.state.approval_service.reject(approval_id)
    if not rejected:
        raise HTTPException(409, "Approval is not pending or has expired")
    await _audit_action(request, user["username"], "TOOL_APPROVAL_REJECTED", approval_id, {})
    return {"approval_id": approval_id, "status": "REJECTED"}


@router.get("/api/models")
async def observed_models(
    request: Request, user: dict[str, str] = Depends(require_roles(*OPS_READ))
) -> dict[str, Any]:
    del user
    async with request.app.state.session_factory() as session:
        rows = await session.execute(
            select(RequestRecord.model, RequestRecord.provider, func.count(RequestRecord.id))
            .group_by(RequestRecord.model, RequestRecord.provider)
            .order_by(RequestRecord.model)
        )
    return {
        "registry_status": "observed_usage_only",
        "data": [
            {"model": model, "provider": provider, "request_count": count}
            for model, provider, count in rows.all()
        ],
    }


@router.get("/api/settings")
async def settings_view(
    user: dict[str, str] = Depends(require_roles("ADMIN", "SECURITY_ADMIN", "AUDITOR")),
) -> dict[str, Any]:
    del user
    s = get_settings()
    approval_key = s.approval_signing_key.get_secret_value() if s.approval_signing_key else ""
    return {
        "environment": s.environment,
        "application_id": s.application_id,
        "application_name": s.application_name,
        "provider_configured": bool(s.provider_base_url),
        "provider_type": s.provider_type,
        "default_data_classification": s.default_data_classification,
        "model_routing_mode": s.model_routing_mode,
        "semantic_classifier_mode": s.semantic_classifier_mode,
        "semantic_classifier_configured": bool(s.semantic_classifier_url),
        "extra_dlp_detectors": json.loads(s.extra_dlp_detectors_json),
        "approval_workflow": "enabled"
        if len(approval_key) >= 32
        else "disabled (signing key must be at least 32 characters)",
        "approval_ttl_minutes": s.approval_ttl_minutes,
        "logging_mode": s.logging_mode,
        "agent_enrollment_configured": s.agent_enrollment_key is not None,
        "database_backend": s.database_url.split(":", 1)[0],
        "model_registry": "environment-configured route rules",
    }


@router.get("/api/audit")
async def audit_history(
    request: Request,
    actor: str | None = None,
    action: str | None = None,
    target: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    user: dict[str, str] = Depends(require_roles("ADMIN", "SECURITY_ADMIN", "AUDITOR")),
) -> dict[str, Any]:
    del user
    async with request.app.state.session_factory() as session:
        query = select(ConsoleAuditRecord)
        for column, value in (
            (ConsoleAuditRecord.actor, actor),
            (ConsoleAuditRecord.action, action),
            (ConsoleAuditRecord.target, target),
        ):
            if value:
                query = query.where(column == value)
        total = await session.scalar(select(func.count()).select_from(query.subquery())) or 0
        rows = await session.execute(
            query.order_by(ConsoleAuditRecord.timestamp.desc()).limit(limit).offset(offset)
        )
    return {
        "data": [
            {
                "id": r.id,
                "actor": r.actor,
                "action": r.action,
                "target": r.target,
                "details": redact(r.details),
                "timestamp": r.timestamp,
            }
            for r in rows.scalars()
        ],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


async def _audit_action(
    request: Request, actor: str, action: str, target: str, details: dict[str, Any]
) -> None:
    async with request.app.state.session_factory() as session:
        session.add(
            ConsoleAuditRecord(
                id=str(uuid4()),
                actor=actor,
                action=action,
                target=target,
                details=redact(details),
                timestamp=datetime.now(UTC),
            )
        )
        await session.commit()


def _request_row(row: RequestRecord, include_content: bool = False) -> dict[str, Any]:
    data = {
        "id": row.id,
        "trace_id": row.trace_id,
        "application_id": row.application_id,
        "user_id": row.user_id,
        "agent_id": row.agent_id,
        "session_id": row.session_id,
        "model": row.model,
        "provider": row.provider,
        "decision": row.decision,
        "risk_level": row.risk_level,
        "started_at": row.started_at,
        "latency_ms": row.latency_ms,
    }
    if include_content:
        data["request"] = redact(row.request_redacted)
        data["response"] = redact(row.response_redacted)
    return data


def _event_row(row: SecurityEventRecord) -> dict[str, Any]:
    return {
        "id": row.id,
        "request_id": row.request_id,
        "trace_id": row.trace_id,
        "application_id": row.application_id,
        "event_type": row.event_type,
        "decision": row.decision,
        "severity": row.risk,
        "evidence": redact(row.evidence),
        "outcome": row.outcome,
        "timestamp": row.timestamp,
    }


def _version_row(row: PolicyVersionRecord) -> dict[str, Any]:
    return {
        "version": row.version,
        "author": row.author,
        "created_at": row.created_at,
        "changes": row.changes,
        "status": row.status,
        "definition": row.definition,
    }


def _aware(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


CONSOLE_HTML = r"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>GateShield Console</title><style>
:root{color-scheme:dark;--bg:#0c1117;--panel:#141c25;--line:#263341;--text:#e7edf3;--muted:#91a0ae;--accent:#67d5b5;--red:#ff7b72}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px system-ui,-apple-system,sans-serif}header{display:flex;align-items:center;justify-content:space-between;padding:18px 26px;border-bottom:1px solid var(--line)}header strong{font-size:17px}header span,.muted{color:var(--muted)}main{max-width:1350px;margin:auto;padding:24px}.tabs{display:flex;gap:8px;overflow:auto;margin:0 0 20px}.tabs button,button{background:var(--panel);border:1px solid var(--line);color:var(--text);padding:9px 13px;border-radius:7px;cursor:pointer}.tabs button.active,button.primary{border-color:var(--accent);color:var(--accent)}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px}.card,section{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px}.card b{display:block;font-size:27px;margin-top:8px}.card label{color:var(--muted)}.row{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:12px 0}input,select,textarea{background:#0d141b;border:1px solid var(--line);color:var(--text);padding:9px;border-radius:6px}textarea{width:100%;min-height:170px;font:12px ui-monospace,monospace}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:10px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-weight:500}td code{font-size:12px}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#0d141b;padding:12px;border-radius:6px;color:#c5d0da}.scroll{overflow:auto}a{color:var(--accent);cursor:pointer}.status{color:var(--accent)}.danger{color:var(--red)}@media(max-width:650px){main{padding:14px}header{padding:14px}th,td{padding:7px}}
</style></head><body><header><strong>⬡ GateShield <span>Security Console</span></strong><span id="who">Loading…</span></header><main><nav class="tabs" id="tabs"></nav><div id="view"></div></main><script>
const sections=['Overview','Requests','Events','Audit history','Policies','Agents','Tools','Approvals','Models','Sessions','Settings'];let current='Overview';const view=document.querySelector('#view');const tabs=document.querySelector('#tabs');let activeRole='VIEWER';async function api(path,opts={}){const r=await fetch('/console/api/'+path,{...opts,headers:{'Content-Type':'application/json','X-Console-Action':'same-origin',...(opts.headers||{})}});if(!r.ok)throw Error((await r.text()).slice(0,300));return r.json()}function esc(x){return String(x??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}function table(headers,rows){return `<div class="scroll"><table><thead><tr>${headers.map(x=>`<th>${x}</th>`).join('')}</tr></thead><tbody>${rows||'<tr><td colspan="8" class="muted">No stored records</td></tr>'}</tbody></table></div>`}function nav(){const visible=sections.filter(x=>(activeRole!=='VIEWER'||x==='Overview')&&(!['Audit history','Settings'].includes(x)||['ADMIN','SECURITY_ADMIN','AUDITOR'].includes(activeRole)));tabs.innerHTML=visible.map(x=>`<button class="${x===current?'active':''}" onclick="go('${x}')">${x}</button>`).join('')}async function go(s){current=s;nav();view.innerHTML='<p class="muted">Loading…</p>';try{if(s==='Overview')await overview();if(s==='Requests')await requestList();if(s==='Events')await eventList();if(s==='Audit history')await auditList();if(s==='Policies')await policyList();if(s==='Agents')await agents();if(s==='Tools')await tools();if(s==='Approvals')await approvals();if(s==='Models')await models();if(s==='Sessions')await sessions();if(s==='Settings')await settings()}catch(e){view.innerHTML=`<section class="danger">${esc(e.message)}</section>`}}async function overview(){const d=await api('overview');const cards=[['Requests',d.request_total],['Allowed',d.decisions.ALLOW||0],['Blocked',d.blocked],['Redacted',d.redacted],['High risk',d.high_risk],['Prompt injection',d.prompt_injection],['Tool blocks',d.tool_blocks],['Pending approvals',d.pending_approvals]];view.innerHTML=`<div class="grid">${cards.map(([k,v])=>`<div class="card"><label>${k}</label><b>${v}</b></div>`).join('')}</div><p class="muted">Counts come from persisted requests, events, and tool invocation records. No trend comparison is shown.</p>`}async function requestList(){const d=await api('requests');view.innerHTML=`<h2>Requests</h2>${table(['Time','Request / trace','Application','Agent','Model','Decision','Risk','Latency'],d.data.map(x=>`<tr><td>${esc(x.started_at)}</td><td><a onclick="detail('${esc(x.id)}')">${esc(x.id.slice(0,8))}</a><br><code>${esc(x.trace_id.slice(0,12))}…</code></td><td>${esc(x.application_id)}</td><td>${esc(x.agent_id||'—')}</td><td>${esc(x.model)}</td><td>${esc(x.decision)}</td><td>${esc(x.risk_level)}</td><td>${x.latency_ms} ms</td></tr>`).join(''))}`}async function detail(id){const d=await api('requests/'+id);view.innerHTML=`<button onclick="go('Requests')">← Requests</button><h2>Request ${esc(id)}</h2><pre>${esc(JSON.stringify(d,null,2))}</pre>`}async function auditList(){const d=await api('audit');view.innerHTML=`<h2>Console audit history</h2>${table(['Time','Actor','Action','Target','Details'],d.data.map(x=>`<tr><td>${esc(x.timestamp)}</td><td>${esc(x.actor)}</td><td>${esc(x.action)}</td><td>${esc(x.target)}</td><td><code>${esc(JSON.stringify(x.details))}</code></td></tr>`).join(''))}`}async function eventList(){const d=await api('events');view.innerHTML=`<h2>Security events</h2><div class="row"><input id="event_type" placeholder="Event type"><input id="severity" placeholder="Severity"><input id="application_id" placeholder="Application"><input id="agent_id" placeholder="Agent"><input id="policy" placeholder="Policy"><input id="request_id" placeholder="Request ID"><input id="outcome" placeholder="Outcome"><input id="from_time" type="datetime-local"><input id="to_time" type="datetime-local"><button onclick="filterEvents()">Apply filters</button></div><div id="eventtable">${eventRows(d.data)}</div>`}function eventRows(a){return table(['Time','Type','Request','Severity','Decision','Outcome','Evidence'],a.map(x=>`<tr><td>${esc(x.timestamp)}</td><td>${esc(x.event_type)}</td><td><a onclick="detail('${esc(x.request_id)}')">${esc(x.request_id.slice(0,8))}</a></td><td>${esc(x.severity)}</td><td>${esc(x.decision)}</td><td>${esc(x.outcome)}</td><td><code>${esc(JSON.stringify(x.evidence).slice(0,180))}</code></td></tr>`).join(''))}async function filterEvents(){const params=new URLSearchParams();for(const key of ['event_type','severity','application_id','agent_id','policy','request_id','outcome','from_time','to_time']){const el=document.querySelector('#'+key);if(el.value)params.set(key,['from_time','to_time'].includes(key)?new Date(el.value).toISOString():el.value)}const d=await api('events?'+params.toString());document.querySelector('#eventtable').innerHTML=eventRows(d.data)}async function policyList(){const d=await api('policies');view.innerHTML=`<h2>Policies</h2><p class="muted">Definitions are schema validated. Changes create immutable versions; activation and rollback are explicit.</p>${d.data.map(p=>`<section><h3>${esc(p.id)} <span class="muted">active v${esc(p.active_version??'none')}</span></h3>${table(['Version','Status','Author','Changes','Definition'],p.versions.map(v=>`<tr><td>${v.version}</td><td>${esc(v.status)}</td><td>${esc(v.author)}</td><td>${esc((v.changes||[]).join('; '))}</td><td><button onclick="activate('${esc(p.id)}',${v.version})">Activate / rollback</button><details><summary>Definition</summary><pre>${esc(JSON.stringify(v.definition,null,2))}</pre></details></td></tr>`).join(''))}</section>`).join('')}<section><h3>Create policy draft</h3><textarea id="policyjson">{"definition":{"id":"example-policy","description":"","effect":"BLOCK","mode":"ENFORCE","conditions":{"model":"example"},"priority":100},"changes":["Initial draft"]}</textarea><div class="row"><button class="primary" onclick="createPolicy()">Save draft</button><button onclick="testPolicy()">Test against history</button></div><pre id="policyresult"></pre></section>`}async function createPolicy(){try{const d=JSON.parse(document.querySelector('#policyjson').value);const out=await api('policies',{method:'POST',body:JSON.stringify(d)});document.querySelector('#policyresult').textContent=JSON.stringify(out,null,2);await policyList()}catch(e){document.querySelector('#policyresult').textContent=e.message}}async function testPolicy(){try{const d=JSON.parse(document.querySelector('#policyjson').value);const out=await api('policies/test',{method:'POST',body:JSON.stringify({definition:d.definition})});document.querySelector('#policyresult').textContent=JSON.stringify(out,null,2)}catch(e){document.querySelector('#policyresult').textContent=e.message}}async function activate(id,v){if(!confirm(`Activate policy ${id} version ${v}?`))return;await api(`policies/${encodeURIComponent(id)}/activate?version=${v}`,{method:'POST'});await policyList()}async function agents(){const d=await api('agents');view.innerHTML=`<h2>Agent registry</h2>${table(['ID','Application','Owner','Role','Environment','Status','Allowed tools','Resources'],d.data.map(x=>`<tr><td>${esc(x.id)}</td><td>${esc(x.application_id)}</td><td>${esc(x.owner)}</td><td>${esc(x.role)}</td><td>${esc(x.environment)}</td><td>${esc(x.status)}</td><td>${esc(x.allowed_tools.join(', '))}</td><td><code>${esc(JSON.stringify(x.allowed_resources))}</code></td></tr>`).join(''))}`}async function tools(){const d=await api('tools');view.innerHTML=`<h2>Tool registry</h2>${table(['Application','Tool','Risk','Enabled','Scope','Schema'],d.definitions.map(x=>`<tr><td>${esc(x.application_id)}</td><td>${esc(x.name)}</td><td>${esc(x.risk_level)}</td><td>${esc(x.enabled)}</td><td>${esc(JSON.stringify(x.scope))}</td><td><code>${esc(JSON.stringify(x.parameters))}</code></td></tr>`).join(''))}<h3>Recent authorization records</h3>${table(['Time','Tool','Decision','Risk','Reason','Arguments'],d.recent_invocations.map(x=>`<tr><td>${esc(x.created_at)}</td><td>${esc(x.tool_name)}</td><td>${esc(x.decision)}</td><td>${esc(x.risk_level)}</td><td>${esc(x.reason)}</td><td><code>${esc(JSON.stringify(x.arguments))}</code></td></tr>`).join(''))}`}async function sessions(){const d=await api('sessions');view.innerHTML=`<h2>Agent sessions</h2>${table(['ID','Agent','Application','Started','Expires','Requests','Tools','Denied','Failures','Risk','Status'],d.data.map(x=>`<tr><td>${esc(x.id)}</td><td>${esc(x.agent_id)}</td><td>${esc(x.application_id)}</td><td>${esc(x.started_at)}</td><td>${esc(x.expires_at)}</td><td>${x.request_count}</td><td>${x.tool_call_count}</td><td>${x.denied_action_count}</td><td>${x.failure_count}</td><td>${x.cumulative_risk}</td><td>${esc(x.status)}</td></tr>`).join(''))}`}async function approvals(){const d=await api('approvals');view.innerHTML=`<h2>Scoped approval queue</h2><p class="muted">Approval is single-use and bound to the request, agent, session, tool, arguments/resource, current tool definition, and active policy context.</p>${table(['Created','Expires','Tool','Request','Agent / session','Arguments / target (sanitized)','Scope','Policy context','Status','Reviewer'],d.data.map(x=>`<tr><td>${esc(x.created_at)}</td><td>${esc(x.expires_at)}</td><td>${esc(x.tool_name)}</td><td>${esc(x.request_id)}</td><td>${esc(x.agent_id||'—')}<br>${esc(x.session_id||'—')}</td><td><code>${esc(JSON.stringify({arguments:x.arguments,target:x.target}))}</code></td><td><code>${esc(x.scope_hash)}</code></td><td><code>${esc(x.policy_context_hash)}</code></td><td>${esc(x.status)}</td><td>${esc(x.approved_by||'—')} ${x.status==='PENDING'&&['ADMIN','SECURITY_ADMIN'].includes(activeRole)?`<button onclick="approveAction('${esc(x.id)}')">Approve</button><button onclick="rejectAction('${esc(x.id)}')">Reject</button>`:''}</td></tr>`).join(''))}`}async function approveAction(id){if(!confirm('Approve this exact scoped action?'))return;await api('approvals/'+encodeURIComponent(id)+'/approve',{method:'POST'});await approvals()}async function rejectAction(id){if(!confirm('Reject this scoped action?'))return;await api('approvals/'+encodeURIComponent(id)+'/reject',{method:'POST'});await approvals()}async function models(){const d=await api('models');view.innerHTML=`<h2>Observed model usage</h2><p class="muted">Persisted use only; this is not an allowlist.</p>${table(['Model','Provider','Requests'],d.data.map(x=>`<tr><td>${esc(x.model)}</td><td>${esc(x.provider)}</td><td>${x.request_count}</td></tr>`).join(''))}`}async function settings(){const d=await api('settings');view.innerHTML=`<h2>System settings</h2><pre>${esc(JSON.stringify(d,null,2))}</pre><p>Model registry: ${esc(d.model_registry)}. Approval workflow: ${esc(d.approval_workflow)}.</p>`}api('me').then(u=>{activeRole=u.role;document.querySelector('#who').textContent=`${u.username} · ${u.role}`;go('Overview')}).catch(e=>view.innerHTML=`<section>${esc(e.message)}. Configure console users using GATESHIELD_CONSOLE_USERS.</section>`);</script></body></html>"""
