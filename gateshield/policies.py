from collections.abc import Sequence
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from .domain import (
    AIRequest,
    DataClassification,
    Decision,
    PolicyDecision,
    ProviderType,
    SecurityContext,
)
from .storage import PolicyRecord, PolicyVersionRecord


class PolicyMode(StrEnum):
    ENFORCE = "ENFORCE"
    MONITOR = "MONITOR"
    OFF = "OFF"


class PolicyStatus(StrEnum):
    ACTIVE = "ACTIVE"
    DRAFT = "DRAFT"
    RETIRED = "RETIRED"


class PolicyConditions(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    application_id: str | None = None
    agent_id: str | None = None
    user_id: str | None = None
    model: str | None = None
    environment: str | None = None
    provider_type: ProviderType | None = None
    data_classification: DataClassification | None = None
    has_tools: bool | None = None
    prompt_injection_detected: bool | None = None
    secret_detected: bool | None = None
    output_sensitive_data_detected: bool | None = None
    output_schema_invalid: bool | None = None
    tool_security_violation: bool | None = None

    @model_validator(mode="after")
    def require_match_field(self) -> "PolicyConditions":
        if not self.model_fields_set or all(
            getattr(self, name) is None for name in type(self).model_fields
        ):
            raise ValueError("At least one non-null policy condition is required")
        return self

    def matches(self, request: AIRequest, context: SecurityContext) -> bool:
        values: dict[str, Any] = {
            "application_id": context.application_id,
            "agent_id": context.agent_id,
            "user_id": context.user_id,
            "model": request.model,
            "environment": context.environment,
            "provider_type": context.provider_type,
            "data_classification": context.data_classification.value,
            "has_tools": bool(request.tools),
            "prompt_injection_detected": context.prompt_injection_detected,
            "secret_detected": context.secret_detected,
            "output_sensitive_data_detected": context.output_sensitive_data_detected,
            "output_schema_invalid": context.output_schema_invalid,
            "tool_security_violation": context.tool_security_violation,
        }
        return all(
            expected is None or values[name] == expected
            for name, expected in self.model_dump(exclude_none=True).items()
        )


class PolicyDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._:-]*$")
    description: str = Field(min_length=1, max_length=1000)
    effect: Decision
    mode: PolicyMode = PolicyMode.ENFORCE
    conditions: PolicyConditions
    priority: int = Field(default=100, ge=0, le=10000)


def default_policy_definitions() -> tuple[PolicyDefinition, ...]:
    return (
        PolicyDefinition(
            id="default-block-prompt-injection",
            description="Block deterministic prompt injection findings in untrusted input.",
            effect=Decision.BLOCK,
            mode=PolicyMode.ENFORCE,
            conditions=PolicyConditions(prompt_injection_detected=True),
        ),
        PolicyDefinition(
            id="default-block-secrets",
            description="Block requests containing a detected credential or private key.",
            effect=Decision.BLOCK,
            mode=PolicyMode.ENFORCE,
            conditions=PolicyConditions(secret_detected=True),
        ),
        PolicyDefinition(
            id="default-redact-output-sensitive-data",
            description="Redact detected credentials and personal identifiers from model output.",
            effect=Decision.REDACT,
            mode=PolicyMode.ENFORCE,
            conditions=PolicyConditions(output_sensitive_data_detected=True),
        ),
        PolicyDefinition(
            id="default-block-invalid-structured-output",
            description="Block model output that fails the caller-declared JSON format or schema.",
            effect=Decision.BLOCK,
            mode=PolicyMode.ENFORCE,
            conditions=PolicyConditions(output_schema_invalid=True),
        ),
        PolicyDefinition(
            id="default-block-unauthorized-tool-calls",
            description="Block malformed, unregistered, or out-of-scope tool calls.",
            effect=Decision.BLOCK,
            mode=PolicyMode.ENFORCE,
            conditions=PolicyConditions(tool_security_violation=True),
        ),
    )


class PolicyRepository:
    """Versioned policy persistence operations; activation is explicit."""

    def __init__(self, sessions: async_sessionmaker[AsyncSession]) -> None:
        self.sessions = sessions

    async def ensure_default(self, definition: PolicyDefinition) -> None:
        if await self.version_history(definition.id):
            return
        await self.create_draft(
            definition,
            author="gateshield",
            changes=["Installed built-in security policy."],
        )
        await self.activate(definition.id)

    async def create_draft(
        self,
        definition: PolicyDefinition,
        *,
        author: str,
        changes: Sequence[str] = (),
    ) -> int:
        async with self.sessions() as session:
            existing = await session.get(PolicyRecord, definition.id)
            if existing is not None:
                raise ValueError(f"Policy {definition.id!r} already exists")
            session.add(PolicyRecord(id=definition.id, current_version=1, active_version=None))
            session.add(
                PolicyVersionRecord(
                    policy_id=definition.id,
                    version=1,
                    definition=definition.model_dump(mode="json"),
                    author=author,
                    changes=list(changes),
                    status=PolicyStatus.DRAFT.value,
                    created_at=datetime.now(UTC),
                )
            )
            await session.commit()
        return 1

    async def revise(
        self,
        policy_id: str,
        definition: PolicyDefinition,
        *,
        author: str,
        changes: Sequence[str] = (),
    ) -> int:
        if policy_id != definition.id:
            raise ValueError("Policy ID cannot change between versions")
        async with self.sessions() as session:
            record = await session.get(PolicyRecord, policy_id)
            if record is None:
                raise ValueError(f"Policy {policy_id!r} does not exist")
            version = record.current_version + 1
            record.current_version = version
            session.add(
                PolicyVersionRecord(
                    policy_id=policy_id,
                    version=version,
                    definition=definition.model_dump(mode="json"),
                    author=author,
                    changes=list(changes),
                    status=PolicyStatus.DRAFT.value,
                    created_at=datetime.now(UTC),
                )
            )
            await session.commit()
        return version

    async def activate(self, policy_id: str, version: int | None = None) -> None:
        async with self.sessions() as session:
            record = await session.get(PolicyRecord, policy_id)
            if record is None:
                raise ValueError(f"Policy {policy_id!r} does not exist")
            target_version = version or record.current_version
            target = await session.get(PolicyVersionRecord, (policy_id, target_version))
            if target is None:
                raise ValueError(f"Policy version {target_version} does not exist")
            previous = await session.execute(
                select(PolicyVersionRecord).where(
                    PolicyVersionRecord.policy_id == policy_id,
                    PolicyVersionRecord.status == PolicyStatus.ACTIVE.value,
                )
            )
            for active in previous.scalars():
                active.status = PolicyStatus.RETIRED.value
            target.status = PolicyStatus.ACTIVE.value
            record.active_version = target_version
            await session.commit()

    async def retire(self, policy_id: str) -> None:
        async with self.sessions() as session:
            record = await session.get(PolicyRecord, policy_id)
            if record is None:
                raise ValueError(f"Policy {policy_id!r} does not exist")
            if record.active_version is not None:
                active = await session.get(PolicyVersionRecord, (policy_id, record.active_version))
                if active is not None:
                    active.status = PolicyStatus.RETIRED.value
                record.active_version = None
            await session.commit()

    async def active_definitions(self) -> list[PolicyDefinition]:
        async with self.sessions() as session:
            rows = await session.execute(
                select(PolicyVersionRecord)
                .join(PolicyRecord, PolicyRecord.id == PolicyVersionRecord.policy_id)
                .where(
                    PolicyVersionRecord.status == PolicyStatus.ACTIVE.value,
                    PolicyRecord.active_version == PolicyVersionRecord.version,
                )
                .order_by(PolicyVersionRecord.policy_id)
            )
            return [PolicyDefinition.model_validate(row.definition) for row in rows.scalars()]

    async def version_history(self, policy_id: str) -> list[dict[str, Any]]:
        async with self.sessions() as session:
            rows = await session.execute(
                select(PolicyVersionRecord)
                .where(PolicyVersionRecord.policy_id == policy_id)
                .order_by(PolicyVersionRecord.version)
            )
            return [
                {
                    "version": row.version,
                    "author": row.author,
                    "created_at": row.created_at,
                    "changes": row.changes,
                    "status": row.status,
                    "definition": row.definition,
                }
                for row in rows.scalars()
            ]


class DeterministicPolicyEngine:
    """Evaluates exact, typed condition matches; no model classifier is consulted."""

    def __init__(self, repository: PolicyRepository) -> None:
        self.repository = repository

    async def evaluate(self, request: AIRequest, context: SecurityContext) -> PolicyDecision:
        matching: list[PolicyDefinition] = []
        for policy in await self.repository.active_definitions():
            if policy.mode is not PolicyMode.OFF and policy.conditions.matches(request, context):
                matching.append(policy)

        monitored = [p for p in matching if p.mode is PolicyMode.MONITOR]
        enforced = [p for p in matching if p.mode is PolicyMode.ENFORCE]
        evidence = [f"monitor:{p.id}:{p.effect.value}" for p in monitored]
        matched_ids = [p.id for p in matching]

        if not enforced:
            return PolicyDecision(
                decision=Decision.ALLOW,
                reason="No matching ENFORCE policy; matching MONITOR policies are observational.",
                matched_policies=matched_ids,
                violations=evidence,
            )

        # Denials dominate. Unsupported effects remain non-ALLOW so the gateway fails closed.
        precedence = {
            Decision.BLOCK: 4,
            Decision.REQUIRE_APPROVAL: 3,
            Decision.REDACT: 2,
            Decision.ALLOW_WITH_RESTRICTIONS: 2,
            Decision.ALLOW: 1,
        }
        enforced.sort(key=lambda policy: (-precedence[policy.effect], policy.priority, policy.id))
        selected = enforced[0]
        reason = f"Policy {selected.id}: {selected.description}"
        violations = evidence + [
            f"enforce:{policy.id}:{policy.effect.value}" for policy in enforced
        ]
        return PolicyDecision(
            decision=selected.effect,
            reason=reason,
            matched_policies=matched_ids,
            risk_score=100 if selected.effect is Decision.BLOCK else 50,
            required_actions=(["approval"] if selected.effect is Decision.REQUIRE_APPROVAL else []),
            violations=violations,
        )
