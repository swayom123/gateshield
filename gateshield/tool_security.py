import asyncio
import ipaddress
import json
import math
import re
import socket
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from .domain import AgentIdentity, Decision, OutputFinding, RiskLevel
from .output_inspection import _redact_text
from .storage import ToolDefinitionRecord, ToolInvocationRecord


class ToolDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(min_length=1, max_length=128, pattern=r"^[a-zA-Z][a-zA-Z0-9_.-]*$")
    description: str = Field(min_length=1, max_length=1000)
    parameters: dict[str, Any]
    resource_type: str = Field(min_length=1, max_length=40)
    risk_level: RiskLevel = RiskLevel.LOW
    scope: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True

    @model_validator(mode="after")
    def validate_parameters(self) -> "ToolDefinition":
        if _contains_reference(self.parameters):
            raise ValueError("Tool argument schemas cannot contain references")
        try:
            Draft202012Validator.check_schema(self.parameters)
        except SchemaError as exc:
            raise ValueError("Tool argument schema is invalid") from exc
        return self


@dataclass(frozen=True)
class ToolAuthorization:
    decision: Decision
    definition: ToolDefinition | None
    arguments: dict[str, Any]
    reason: str
    risk_level: RiskLevel = RiskLevel.LOW
    normalized_target: dict[str, Any] | None = None


class ToolSecurityError(ValueError):
    pass


def _reject_json_constant(value: str) -> None:
    raise ToolSecurityError(f"Non-standard JSON number {value!r} is not allowed.")


class ToolAuthorizationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=128)
    arguments: dict[str, Any]
    request_id: str | None = Field(default=None, max_length=36)
    agent_id: str | None = Field(default=None, max_length=128)
    session_id: str | None = Field(default=None, max_length=36)
    approval_id: str | None = Field(default=None, max_length=36)


def default_tool_definitions() -> tuple[ToolDefinition, ...]:
    return (
        ToolDefinition(
            name="search_documents",
            description="Search documents available to the calling application.",
            parameters={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "minLength": 1, "maxLength": 500},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 20},
                },
                "required": ["query"],
                "additionalProperties": False,
            },
            resource_type="search",
        ),
        ToolDefinition(
            name="read_document",
            description="Read a document by an application-scoped document identifier.",
            parameters={
                "type": "object",
                "properties": {
                    "document_id": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 128,
                    }
                },
                "required": ["document_id"],
                "additionalProperties": False,
            },
            resource_type="document",
            scope={"agent_resource_argument": "document_id"},
        ),
    )


def _contains_reference(value: Any) -> bool:
    if isinstance(value, dict):
        return any(
            key in {"$ref", "$dynamicRef", "$recursiveRef"} or _contains_reference(child)
            for key, child in value.items()
        )
    if isinstance(value, list):
        return any(_contains_reference(item) for item in value)
    return False


class ToolRegistry:
    def __init__(self, sessions: async_sessionmaker[AsyncSession]) -> None:
        self.sessions = sessions

    async def register(self, application_id: str, definition: ToolDefinition) -> None:
        async with self.sessions() as session:
            existing = await session.get(ToolDefinitionRecord, (application_id, definition.name))
            if existing is not None:
                raise ValueError(f"Tool {definition.name!r} is already registered")
            session.add(
                ToolDefinitionRecord(
                    application_id=application_id,
                    name=definition.name,
                    description=definition.description,
                    parameters=definition.parameters,
                    resource_type=definition.resource_type,
                    risk_level=definition.risk_level.value,
                    scope=definition.scope,
                    enabled=definition.enabled,
                    created_at=datetime.now(UTC),
                )
            )
            await session.commit()

    async def ensure_default(self, application_id: str, definition: ToolDefinition) -> None:
        if await self.get(application_id, definition.name) is None:
            await self.register(application_id, definition)

    async def get(self, application_id: str, name: str) -> ToolDefinition | None:
        async with self.sessions() as session:
            record = await session.get(ToolDefinitionRecord, (application_id, name))
            if record is None:
                return None
            return _from_record(record)

    async def list_enabled(self, application_id: str) -> list[ToolDefinition]:
        async with self.sessions() as session:
            records = await session.execute(
                select(ToolDefinitionRecord).where(
                    ToolDefinitionRecord.application_id == application_id,
                    ToolDefinitionRecord.enabled.is_(True),
                )
            )
            return [_from_record(record) for record in records.scalars()]


def _from_record(record: ToolDefinitionRecord) -> ToolDefinition:
    return ToolDefinition(
        name=record.name,
        description=record.description,
        parameters=record.parameters,
        resource_type=record.resource_type,
        risk_level=RiskLevel(record.risk_level),
        scope=record.scope,
        enabled=record.enabled,
    )


class DeterministicToolAuthorizer:
    def __init__(self, registry: ToolRegistry) -> None:
        self.registry = registry

    async def authorize(
        self,
        application_id: str,
        name: str,
        arguments: Any,
        identity: AgentIdentity | None = None,
    ) -> ToolAuthorization:
        definition = await self.registry.get(application_id, name)
        if definition is None or not definition.enabled:
            return ToolAuthorization(
                Decision.BLOCK,
                definition,
                {},
                "Tool is not registered and enabled for this application.",
                RiskLevel.HIGH,
            )
        if identity is not None and name not in identity.allowed_tools:
            return ToolAuthorization(
                Decision.BLOCK,
                definition,
                {},
                "Agent identity does not permit this tool.",
                RiskLevel.HIGH,
            )
        if not isinstance(arguments, dict):
            return ToolAuthorization(
                Decision.BLOCK,
                definition,
                {},
                "Tool arguments must be a JSON object.",
                RiskLevel.HIGH,
            )
        errors = list(Draft202012Validator(definition.parameters).iter_errors(arguments))
        if errors:
            return ToolAuthorization(
                Decision.BLOCK,
                definition,
                {},
                "Tool arguments failed registered schema validation.",
                RiskLevel.HIGH,
            )
        try:
            target = await validate_tool_target(definition, arguments)
            if definition.resource_type == "database":
                target = build_read_only_query(definition.scope, arguments)
            if identity is not None:
                allowed_resources = identity.allowed_resources.get(name)
                resource_key = definition.scope.get("agent_resource_argument")
                if isinstance(resource_key, str):
                    resource_value = arguments.get(resource_key)
                    if not allowed_resources or resource_value not in allowed_resources:
                        raise ToolSecurityError(
                            "Agent identity is outside its assigned resource scope."
                        )
        except ToolSecurityError as exc:
            return ToolAuthorization(Decision.BLOCK, definition, {}, str(exc), RiskLevel.HIGH)
        if definition.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            return ToolAuthorization(
                Decision.REQUIRE_APPROVAL,
                definition,
                arguments,
                "Tool risk requires an approval workflow that is not enabled.",
                definition.risk_level,
                target,
            )
        return ToolAuthorization(
            Decision.ALLOW,
            definition,
            arguments,
            "Tool is registered, scoped, and its arguments are valid.",
            definition.risk_level,
            target,
        )

    async def validate_offered_tools(
        self,
        application_id: str,
        offered: list[dict[str, Any]],
        identity: AgentIdentity | None = None,
    ) -> list[dict[str, Any]]:
        registered = {item.name: item for item in await self.registry.list_enabled(application_id)}
        safe_tools: list[dict[str, Any]] = []
        for entry in offered:
            function = entry.get("function") if isinstance(entry, dict) else None
            name = function.get("name") if isinstance(function, dict) else None
            definition = registered.get(name) if isinstance(name, str) else None
            if definition is None:
                raise ToolSecurityError(
                    "Request offered a tool not registered for this application."
                )
            if identity is not None and definition.name not in identity.allowed_tools:
                raise ToolSecurityError("Agent identity does not permit an offered tool.")
            resource_key = definition.scope.get("agent_resource_argument")
            if (
                identity is not None
                and isinstance(resource_key, str)
                and not identity.allowed_resources.get(definition.name)
            ):
                raise ToolSecurityError("Agent identity has no resource scope for this tool.")
            safe_tools.append(
                {
                    "type": "function",
                    "function": {
                        "name": definition.name,
                        "description": definition.description,
                        "parameters": definition.parameters,
                    },
                }
            )
        return safe_tools

    async def inspect_completion(
        self,
        application_id: str,
        completion: dict[str, Any],
        identity: AgentIdentity | None = None,
        offered_tool_names: set[str] | None = None,
    ) -> list[OutputFinding]:
        findings: list[OutputFinding] = []
        choices = completion.get("choices", [])
        total_calls = sum(
            len(choice.get("message", {}).get("tool_calls", []))
            for choice in choices
            if isinstance(choice, dict)
            and isinstance(choice.get("message"), dict)
            and isinstance(choice["message"].get("tool_calls", []), list)
        )
        if total_calls > 32:
            return [
                OutputFinding(
                    finding_type="TOOL_BLOCKED",
                    severity=RiskLevel.HIGH,
                    location="choices[*].message.tool_calls",
                    matched_signal="tool_call_limit",
                    evidence={"reason": "Completion exceeded the 32-call inspection limit."},
                )
            ]
        for choice_index, choice in enumerate(choices):
            message = choice.get("message", {}) if isinstance(choice, dict) else {}
            calls = message.get("tool_calls", []) if isinstance(message, dict) else []
            if not isinstance(calls, list):
                calls = [None]
            for call_index, call in enumerate(calls):
                function = call.get("function") if isinstance(call, dict) else None
                name = function.get("name") if isinstance(function, dict) else None
                raw_arguments = function.get("arguments") if isinstance(function, dict) else None
                try:
                    if not isinstance(name, str) or not isinstance(raw_arguments, str):
                        raise ToolSecurityError("Tool call is malformed.")
                    if offered_tool_names is not None and name not in offered_tool_names:
                        raise ToolSecurityError("Tool was not offered in the originating request.")
                    if len(raw_arguments.encode()) > 65_536:
                        raise ToolSecurityError("Tool arguments exceed the inspection size limit.")
                    arguments = json.loads(raw_arguments, parse_constant=_reject_json_constant)
                    result = await self.authorize(application_id, name, arguments, identity)
                    if result.decision is not Decision.ALLOW:
                        findings.append(
                            OutputFinding(
                                finding_type=(
                                    "APPROVAL_REQUIRED"
                                    if result.decision is Decision.REQUIRE_APPROVAL
                                    else "TOOL_BLOCKED"
                                ),
                                severity=result.risk_level,
                                location=f"choices[{choice_index}].message.tool_calls[{call_index}]",
                                matched_signal="tool_authorization",
                                evidence={
                                    "tool_name": name,
                                    "reason": result.reason,
                                },
                            )
                        )
                        continue
                except ValueError as exc:
                    findings.append(
                        OutputFinding(
                            finding_type="TOOL_BLOCKED",
                            severity=RiskLevel.HIGH,
                            location=f"choices[{choice_index}].message.tool_calls[{call_index}]",
                            matched_signal="tool_authorization",
                            evidence={
                                "tool_name": name if isinstance(name, str) else "unknown",
                                "reason": str(exc),
                            },
                        )
                    )
        return findings


async def validate_tool_target(
    definition: ToolDefinition,
    arguments: dict[str, Any],
    resolver: Any = None,
) -> dict[str, Any] | None:
    if definition.resource_type == "filesystem":
        path_arg = definition.scope.get("path_argument", "path")
        root = definition.scope.get("root")
        path = arguments.get(path_arg)
        if not isinstance(root, str) or not isinstance(path, str):
            raise ToolSecurityError("Filesystem tool has no configured root or path argument.")
        from pathlib import Path

        root_path = Path(root).resolve()
        target = Path(path).resolve()
        try:
            target.relative_to(root_path)
        except ValueError as exc:
            raise ToolSecurityError("Filesystem path is outside the configured root.") from exc
        return {"path": str(target)}
    if definition.resource_type == "http":
        url_arg = definition.scope.get("url_argument", "url")
        url = arguments.get(url_arg)
        allowed_hosts = definition.scope.get("allowed_hosts", [])
        allowed_ports = definition.scope.get("allowed_ports")
        allow_private = definition.scope.get("allow_private_addresses", False)
        if (
            not isinstance(url, str)
            or not isinstance(allowed_hosts, list)
            or (allowed_ports is not None and not isinstance(allowed_ports, list))
            or not isinstance(allow_private, bool)
        ):
            raise ToolSecurityError("HTTP tool has no valid URL or host allowlist.")
        return await validate_http_target(
            url, allowed_hosts, resolver, allowed_ports, allow_private
        )
    if definition.resource_type == "database":
        return None
    if definition.resource_type not in {"document", "search", "ticket"}:
        raise ToolSecurityError("Unsupported tool resource type.")
    return None


async def validate_http_target(
    url: str,
    allowed_hosts: list[str],
    resolver: Any = None,
    allowed_ports: list[int] | None = None,
    allow_private_addresses: bool = False,
) -> dict[str, Any]:
    try:
        parsed = urlsplit(url)
        port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise ToolSecurityError("URL is malformed.") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ToolSecurityError("Only HTTP and HTTPS URLs are supported.")
    default_port = 443 if parsed.scheme == "https" else 80
    if port not in (allowed_ports if allowed_ports is not None else [default_port]):
        raise ToolSecurityError("URL port is not allowlisted.")
    if parsed.username or parsed.password or parsed.fragment:
        raise ToolSecurityError("URL credentials and fragments are not allowed.")
    host = parsed.hostname.rstrip(".").lower()
    if host not in {item.rstrip(".").lower() for item in allowed_hosts}:
        raise ToolSecurityError("URL host is not allowlisted.")
    if host in {"localhost", "metadata.google.internal"}:
        raise ToolSecurityError("Local and metadata destinations are blocked.")
    resolved: list[str]
    try:
        address = ipaddress.ip_address(host)
        resolved = [str(address)]
    except ValueError:
        lookup = resolver or _resolve_host
        resolved = await lookup(host, port)
    if not resolved:
        raise ToolSecurityError("URL host did not resolve to an address.")
    for value in resolved:
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ToolSecurityError("URL host resolution returned an invalid address.") from exc
        if address.is_link_local or address.is_multicast or address.is_reserved:
            raise ToolSecurityError("URL resolves to a blocked special-purpose address.")
        if not address.is_global and not allow_private_addresses:
            raise ToolSecurityError("URL resolves to a non-public network address.")
    return {"url": url, "host": host, "resolved_addresses": resolved}


async def _resolve_host(host: str, port: int) -> list[str]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return sorted({item[4][0] for item in infos})


def build_read_only_query(scope: Mapping[str, Any], arguments: dict[str, Any]) -> dict[str, Any]:
    allowed = scope.get("tables", {})
    table = arguments.get("table")
    fields = arguments.get("fields")
    filters = arguments.get("filters", {})
    limit = arguments.get("limit", 100)
    order_by = arguments.get("order_by")
    if not isinstance(allowed, dict) or not isinstance(table, str) or table not in allowed:
        raise ToolSecurityError("Database table is not allowlisted.")
    allowed_fields = allowed[table]
    if (
        not isinstance(allowed_fields, list)
        or not isinstance(fields, list)
        or not fields
        or any(not isinstance(field, str) for field in allowed_fields)
        or any(not isinstance(field, str) for field in fields)
    ):
        raise ToolSecurityError("Database fields are not valid.")
    if any(field not in allowed_fields for field in fields):
        raise ToolSecurityError("Database field is not allowlisted.")
    identifier = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")
    if not identifier.fullmatch(table) or any(
        not isinstance(field, str) or not identifier.fullmatch(field)
        for field in [*allowed_fields, *fields]
    ):
        raise ToolSecurityError("Database identifiers are malformed.")
    if not isinstance(filters, dict) or any(key not in allowed_fields for key in filters):
        raise ToolSecurityError("Database filter field is not allowlisted.")
    if len(filters) > 20 or any(
        not isinstance(value, (str, int, float, bool))
        and value is not None
        or isinstance(value, float)
        and not math.isfinite(value)
        for value in filters.values()
    ):
        raise ToolSecurityError("Database filters must use bounded scalar values.")
    if any(isinstance(value, str) and len(value) > 4096 for value in filters.values()):
        raise ToolSecurityError("Database filter value exceeds the size limit.")
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 1000:
        raise ToolSecurityError("Database query limit must be between 1 and 1000.")
    if order_by is not None and order_by not in allowed_fields:
        raise ToolSecurityError("Database sort field is not allowlisted.")
    quoted_fields = ", ".join(f'"{field}"' for field in fields)
    sql = f'SELECT {quoted_fields} FROM "{table}"'
    params: dict[str, Any] = {}
    if filters:
        clauses = []
        for index, (key, value) in enumerate(filters.items()):
            param = f"p{index}"
            clauses.append(f'"{key}" = :{param}')
            params[param] = value
        sql += " WHERE " + " AND ".join(clauses)
    if order_by is not None:
        sql += f' ORDER BY "{order_by}"'
    sql += " LIMIT :limit"
    params["limit"] = limit
    return {"sql": sql, "parameters": params}


async def persist_invocation(
    sessions: async_sessionmaker[AsyncSession],
    *,
    application_id: str,
    request_id: str | None,
    tool_name: str,
    authorization: ToolAuthorization,
    extra_detectors: frozenset[str] = frozenset(),
) -> None:
    async with sessions() as session:
        session.add(
            ToolInvocationRecord(
                id=str(uuid4()),
                application_id=application_id,
                request_id=request_id,
                tool_name=tool_name,
                decision=authorization.decision.value,
                risk_level=authorization.risk_level.value,
                arguments_redacted=_redact_arguments(authorization.arguments, extra_detectors),
                reason=authorization.reason,
                created_at=datetime.now(UTC),
            )
        )
        await session.commit()


def _redact_arguments(
    arguments: dict[str, Any], extra_detectors: frozenset[str] = frozenset()
) -> dict[str, Any]:
    sensitive = {"password", "secret", "token", "api_key", "authorization", "credential"}

    def clean(value: Any, key: str = "") -> Any:
        if any(term in key.lower() for term in sensitive):
            return "[REDACTED]"
        if isinstance(value, str):
            return _redact_text(value, extra_detectors)[0]
        if isinstance(value, list):
            return [clean(item) for item in value]
        if isinstance(value, dict):
            return {
                str(child_key): clean(child, str(child_key)) for child_key, child in value.items()
            }
        return value

    cleaned = clean(arguments)
    if not isinstance(cleaned, dict):
        return {}
    return cleaned
