import json
import asyncio
import logging
import re
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any, cast
from uuid import uuid4

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy import text
from starlette.middleware.base import RequestResponseEndpoint
from starlette.responses import Response

from .agent_security import (
    AgentEnrollmentRequest,
    AgentSecurityService,
    AgentSessionRequest,
    enrollment_key_matches,
)
from .approvals import ApprovalService
from .classifier import SemanticClassifier
from .config import get_settings
from .console import router as console_router
from .domain import (
    AgentIdentity,
    AgentStatus,
    AIRequest,
    DataClassification,
    Decision,
    GatewayRequest,
    GatewayResponse,
    InputFinding,
    InputInspectionResult,
    OutputInspectionResult,
    PolicyDecision,
    RiskLevel,
    SecurityContext,
    TrustLevel,
)
from .inspection import DeterministicInputInspector
from .output_inspection import DeterministicOutputInspector, validate_response_format
from .policies import (
    DeterministicPolicyEngine,
    PolicyRepository,
    default_policy_definitions,
)
from .providers import OpenAICompatibleProvider
from .routing import assess_model_route
from .request_guard import RequestSizeLimitMiddleware
from .storage import (
    RequestRecord,
    SecurityEventRecord,
    ensure_schema,
    make_engine,
    make_session_factory,
    register_application,
)
from .telemetry import configure_tracing, parent_context, stage_span
from .tool_security import (
    DeterministicToolAuthorizer,
    ToolAuthorizationRequest,
    ToolAuthorization,
    ToolRegistry,
    ToolSecurityError,
    default_tool_definitions,
    persist_invocation,
)

SECRET_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|token|password|secret)\s*[:=]\s*([^\s,;]+)"),
    re.compile(r"\b(?:sk-[A-Za-z0-9_-]{12,}|AKIA[0-9A-Z]{16})\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}"),
    re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^:/\s]+:[^@/\s]{4,}@"),
    re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?"
        r"-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
    ),
]


def redact(value: Any) -> Any:
    if isinstance(value, str):
        output = value
        for pattern in SECRET_PATTERNS:
            output = pattern.sub(
                lambda m: (
                    m.group(1) + "=" + _mask(m.group(2))
                    if m.lastindex and m.lastindex >= 2
                    else _mask(m.group(0))
                ),
                output,
            )
        return output
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, dict):
        sensitive_key = re.compile(
            r"(?i)(secret|token|password|api[_-]?key|authorization|credential)"
        )
        return {
            key: _mask(str(item))
            if sensitive_key.search(str(key)) and item is not None
            else redact(item)
            for key, item in value.items()
        }
    return value


def _mask(secret: str) -> str:
    if len(secret) <= 8:
        return "[REDACTED]"
    return f"{secret[:4]}...{secret[-4:]}"


def _risk_level_for_score(score: int) -> RiskLevel:
    if score >= 75:
        return RiskLevel.CRITICAL
    if score >= 50:
        return RiskLevel.HIGH
    if score >= 25:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def _tool_call_count(response: dict[str, Any]) -> int:
    total = 0
    for choice in response.get("choices", []):
        if not isinstance(choice, dict):
            continue
        message = choice.get("message")
        calls = message.get("tool_calls", []) if isinstance(message, dict) else []
        if isinstance(calls, list):
            total += len(calls)
    return total


async def _record_agent_failure(
    request: Request, agent_session: Any, request_id: str, trace_id: str
) -> None:
    if agent_session is None:
        return
    try:
        await request.app.state.agent_service.record_failure(agent_session.id, request_id)
    except Exception as exc:
        logger.warning(
            "agent_failure_signal_recording_failed",
            extra={"request_id": request_id, "trace_id": trace_id, "event": type(exc).__name__},
        )


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key in ("request_id", "trace_id", "event"):
            if hasattr(record, key):
                payload[key] = getattr(record, key)
        return json.dumps(payload, separators=(",", ":"))


def configure_logging() -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(logging.INFO)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    extra_dlp_detectors = json.loads(settings.extra_dlp_detectors_json)
    if not isinstance(extra_dlp_detectors, list) or any(
        not isinstance(name, str) for name in extra_dlp_detectors
    ):
        raise ValueError("GATESHIELD_EXTRA_DLP_DETECTORS must be a JSON array of detector names")
    extra_dlp_detector_set = set(extra_dlp_detectors)
    configure_logging()
    telemetry_provider = None
    if settings.opentelemetry_enabled:
        telemetry_provider = configure_tracing(
            settings.opentelemetry_endpoint or "",
            settings.opentelemetry_service_name,
        )
    engine = make_engine(
        settings.database_url,
        pool_size=settings.database_pool_size,
        max_overflow=settings.database_max_overflow,
    )
    if settings.environment == "development":
        await ensure_schema(engine)
    factory = make_session_factory(engine)
    async with factory() as session:
        await register_application(session, settings.application_id, settings.application_name)
    app.state.engine = engine
    app.state.telemetry_provider = telemetry_provider
    app.state.session_factory = factory
    app.state.policy_repository = PolicyRepository(factory)
    for default_policy in default_policy_definitions():
        await app.state.policy_repository.ensure_default(default_policy)
    app.state.policy_engine = DeterministicPolicyEngine(app.state.policy_repository)
    app.state.approval_service = ApprovalService(
        factory,
        settings.approval_signing_key.get_secret_value() if settings.approval_signing_key else None,
        settings.approval_ttl_minutes,
        application_id=settings.application_id,
        environment=settings.environment,
        provider_type=settings.provider_type,
        classification=settings.default_data_classification,
        routing_mode=settings.model_routing_mode,
        routes_json=settings.model_routes_json,
        extra_detectors=frozenset(extra_dlp_detector_set),
    )
    app.state.input_inspector = DeterministicInputInspector()
    app.state.extra_dlp_detectors = frozenset(extra_dlp_detector_set)
    app.state.output_inspector = DeterministicOutputInspector(extra_dlp_detector_set)
    app.state.semantic_classifier = SemanticClassifier(
        settings.semantic_classifier_url,
        settings.semantic_classifier_timeout_seconds,
        settings.semantic_classifier_api_key.get_secret_value(),
    )
    app.state.tool_registry = ToolRegistry(factory)
    for definition in default_tool_definitions():
        await app.state.tool_registry.ensure_default(settings.application_id, definition)
    app.state.tool_authorizer = DeterministicToolAuthorizer(app.state.tool_registry)
    app.state.agent_service = AgentSecurityService(factory)
    if settings.logging_mode == "FULL_CONTENT":
        logger.warning("full_content_logging_enabled", extra={"event": "PRIVACY_CONFIGURATION"})
    if settings.provider_base_url:
        app.state.provider = OpenAICompatibleProvider(
            settings.provider_base_url,
            settings.provider_api_key.get_secret_value(),
            settings.provider_timeout_seconds,
        )
    else:
        app.state.provider = None
    try:
        yield
    finally:
        try:
            if telemetry_provider is not None:
                await asyncio.to_thread(telemetry_provider.force_flush, 5000)
                await asyncio.to_thread(telemetry_provider.shutdown)
        finally:
            await engine.dispose()


app = FastAPI(title="GateShield", version="0.1.0", lifespan=lifespan)
app.add_middleware(RequestSizeLimitMiddleware)
logger = logging.getLogger("gateshield.gateway")


@app.exception_handler(RequestValidationError)
async def request_validation_error(request: Request, error: RequestValidationError) -> JSONResponse:
    issues = [
        {"location": list(item["loc"]), "message": item["msg"], "type": item["type"]}
        for item in error.errors()
    ]
    return JSONResponse(
        status_code=422,
        content={
            "detail": issues,
            "request_id": getattr(request.state, "request_id", None),
            "trace_id": getattr(request.state, "trace_id", None),
        },
    )


@app.middleware("http")
async def request_ids(request: Request, call_next: RequestResponseEndpoint) -> Response:
    request_id = str(uuid4())
    traceparent = request.headers.get("traceparent", "")
    trace_parts = traceparent.split("-")
    trace_id = (
        trace_parts[1]
        if len(trace_parts) == 4 and re.fullmatch(r"[0-9a-fA-F]{32}", trace_parts[1])
        else str(uuid4()).replace("-", "")
    )
    request.state.request_id = request_id
    request.state.trace_id = trace_id
    extracted_context = parent_context(request.headers)
    with stage_span(
        "gateshield.http.server",
        context=extracted_context,
        http_request_method=request.method,
        http_route=request.url.path,
        gateshield_request_id=request_id,
    ) as span:
        span_context = span.get_span_context()
        if span_context.is_valid:
            trace_id = f"{span_context.trace_id:032x}"
            request.state.trace_id = trace_id
        response = await call_next(request)
        response.headers["x-request-id"] = request_id
        response.headers["x-trace-id"] = trace_id
        response.headers["x-content-type-options"] = "nosniff"
        response.headers["x-frame-options"] = "DENY"
        response.headers["referrer-policy"] = "no-referrer"
        response.headers["permissions-policy"] = "camera=(), microphone=(), geolocation=()"
        span.set_attribute("http_response_status_code", response.status_code)
        return response


@app.get("/health")
async def health(request: Request) -> dict[str, Any]:
    try:
        async with request.app.state.session_factory() as session:
            await session.execute(text("SELECT 1"))
        configured = request.app.state.provider is not None
        return {"status": "ok", "database": "ok", "provider_configured": configured}
    except Exception as exc:
        logger.error("health_check_failed", extra={"event": type(exc).__name__})
        raise HTTPException(status_code=503, detail="Gateway dependency check failed") from exc


@app.get("/ready")
async def readiness(request: Request) -> dict[str, Any]:
    """Readiness probe for traffic routing; liveness remains available at /health."""
    try:
        async with request.app.state.session_factory() as session:
            await session.execute(text("SELECT 1"))
        if request.app.state.provider is None:
            raise HTTPException(status_code=503, detail="Provider is not configured")
        return {"status": "ready", "database": "ok", "provider": "configured"}
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("readiness_check_failed", extra={"event": type(exc).__name__})
        raise HTTPException(status_code=503, detail="Gateway dependencies are not ready") from exc


@app.get("/v1/tools")
async def list_tools(request: Request) -> dict[str, Any]:
    settings = get_settings()
    try:
        definitions = await request.app.state.tool_registry.list_enabled(settings.application_id)
        return {
            "data": [
                {
                    "type": "function",
                    "function": {
                        "name": item.name,
                        "description": item.description,
                        "parameters": item.parameters,
                    },
                    "risk_level": item.risk_level.value,
                }
                for item in definitions
            ]
        }
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Tool registry is unavailable") from exc


@app.post("/v1/tools/authorize")
async def authorize_tool(
    body: ToolAuthorizationRequest,
    request: Request,
    x_gateshield_agent_token: str | None = Header(default=None),
) -> JSONResponse:
    application_id = get_settings().application_id
    try:
        correlated_request = None
        if body.request_id:
            async with request.app.state.session_factory() as session_db:
                correlated_request = await session_db.get(RequestRecord, body.request_id)
                if (
                    correlated_request is not None
                    and correlated_request.application_id != application_id
                ):
                    raise HTTPException(status_code=404, detail="Request was not found")
        request_was_agent_scoped = (
            correlated_request is not None and correlated_request.agent_id is not None
        )
        identity = None
        session = None
        if (
            body.agent_id is not None
            or body.session_id is not None
            or x_gateshield_agent_token
            or request_was_agent_scoped
        ):
            if body.agent_id is None or body.session_id is None:
                raise HTTPException(
                    status_code=401, detail="Agent ID, session ID, and agent token are required"
                )
            if not body.request_id or correlated_request is None:
                raise HTTPException(
                    status_code=403,
                    detail="Agent tool authorization requires a persisted gateway request ID",
                )
            identity = await _authenticate_agent(request, x_gateshield_agent_token)
            if identity.id != body.agent_id:
                raise HTTPException(status_code=403, detail="Agent token does not match agent ID")
            if (
                correlated_request.agent_id != identity.id
                or correlated_request.session_id != body.session_id
                or correlated_request.decision
                in (Decision.BLOCK.value, Decision.REQUIRE_APPROVAL.value)
            ):
                raise HTTPException(
                    status_code=403,
                    detail="Agent identity or session does not match the originating request",
                )
            session = await request.app.state.agent_service.validate_session(
                identity, body.session_id
            )
            if session is None:
                raise HTTPException(status_code=403, detail="Agent session is expired or inactive")
        with stage_span(
            "gateshield.tool.authorize",
            gateshield_request_id=body.request_id or request.state.request_id,
            gateshield_application_id=application_id,
            gateshield_tool_name=body.name,
        ):
            authorization = await request.app.state.tool_authorizer.authorize(
                application_id, body.name, body.arguments, identity
            )
        pending_approval_id = None
        if authorization.decision is Decision.REQUIRE_APPROVAL:
            if body.approval_id and authorization.definition is not None and body.request_id:
                consumed = await request.app.state.approval_service.consume(
                    body.approval_id,
                    request_id=body.request_id,
                    agent_id=body.agent_id,
                    session_id=body.session_id,
                    tool_name=body.name,
                    arguments=body.arguments,
                    target=authorization.normalized_target,
                    definition=authorization.definition,
                )
                if consumed:
                    authorization = ToolAuthorization(
                        Decision.ALLOW,
                        authorization.definition,
                        authorization.arguments,
                        "Approval is valid for this exact tool action and was consumed.",
                        authorization.risk_level,
                        authorization.normalized_target,
                    )
                else:
                    authorization = ToolAuthorization(
                        Decision.BLOCK,
                        authorization.definition,
                        {},
                        "Approval is invalid, expired, consumed, or no longer matches the action or policy context.",
                        authorization.risk_level,
                        authorization.normalized_target,
                    )
            elif body.approval_id:
                authorization = ToolAuthorization(
                    Decision.BLOCK,
                    authorization.definition,
                    {},
                    "Scoped approval requires the original persisted request context.",
                    authorization.risk_level,
                    authorization.normalized_target,
                )
            elif body.request_id and authorization.definition is not None:
                pending_approval_id = await request.app.state.approval_service.create_pending(
                    request_id=body.request_id,
                    agent_id=body.agent_id,
                    session_id=body.session_id,
                    tool_name=body.name,
                    arguments=body.arguments,
                    target=authorization.normalized_target,
                    definition=authorization.definition,
                )
            else:
                authorization = ToolAuthorization(
                    Decision.BLOCK,
                    authorization.definition,
                    {},
                    "High-risk actions require a persisted request ID for scoped approval.",
                    authorization.risk_level,
                    authorization.normalized_target,
                )
        await persist_invocation(
            request.app.state.session_factory,
            application_id=application_id,
            request_id=body.request_id,
            tool_name=body.name,
            authorization=authorization,
            extra_detectors=request.app.state.extra_dlp_detectors,
        )
        behavior_signals = []
        if identity is not None and session is not None:
            behavior_signals = await request.app.state.agent_service.record_tool_activity(
                session.id,
                request_id=body.request_id or request.state.request_id,
                attempts=1,
                denied=int(authorization.decision is not Decision.ALLOW),
                risk_increment={
                    RiskLevel.LOW: 0,
                    RiskLevel.MEDIUM: 20,
                    RiskLevel.HIGH: 50,
                    RiskLevel.CRITICAL: 100,
                }[authorization.risk_level],
                resource_scope_violation="resource scope" in authorization.reason.lower(),
            )
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(
            "tool_authorization_failed",
            extra={
                "request_id": getattr(request.state, "request_id", None),
                "trace_id": getattr(request.state, "trace_id", None),
                "event": type(exc).__name__,
            },
        )
        raise HTTPException(
            status_code=503,
            detail="Tool authorization failed; execution must be denied",
        ) from exc
    status = 200 if authorization.decision is Decision.ALLOW else 403
    return JSONResponse(
        status_code=status,
        content={
            "decision": authorization.decision.value,
            "authorized": authorization.decision is Decision.ALLOW,
            "execution_performed": False,
            "tool": body.name,
            "reason": authorization.reason,
            "risk_level": authorization.risk_level.value,
            "validated_target": authorization.normalized_target,
            "request_id": body.request_id,
            "approval_id": pending_approval_id,
            "behavior_signals": [signal.model_dump(mode="json") for signal in behavior_signals],
        },
        headers={"x-request-id": request.state.request_id, "x-trace-id": request.state.trace_id},
    )


@app.post("/v1/agents/enroll")
async def enroll_agent(
    body: AgentEnrollmentRequest,
    request: Request,
    x_gateshield_enrollment_key: str | None = Header(default=None),
) -> dict[str, Any]:
    settings = get_settings()
    configured_key = settings.agent_enrollment_key
    if configured_key is None:
        raise HTTPException(status_code=503, detail="Agent enrollment is not configured")
    if not enrollment_key_matches(configured_key.get_secret_value(), x_gateshield_enrollment_key):
        raise HTTPException(status_code=403, detail="Agent enrollment credential is invalid")
    registered_tools = {
        definition.name
        for definition in await request.app.state.tool_registry.list_enabled(
            settings.application_id
        )
    }
    if any(tool not in registered_tools for tool in body.allowed_tools):
        raise HTTPException(status_code=422, detail="Agent includes an unregistered tool")
    if body.environment != settings.environment:
        raise HTTPException(status_code=422, detail="Agent environment does not match gateway")
    try:
        identity, token = await request.app.state.agent_service.enroll(
            settings.application_id, body
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {
        "agent": identity.model_dump(mode="json"),
        "agent_token": token,
        "token_display": "This token is shown once. Store it in a secret manager.",
    }


@app.post("/v1/agents/sessions")
async def create_agent_session(
    body: AgentSessionRequest,
    request: Request,
    x_gateshield_agent_token: str | None = Header(default=None),
) -> dict[str, Any]:
    identity = await _authenticate_agent(request, x_gateshield_agent_token)
    ttl_minutes = body.ttl_minutes or get_settings().agent_session_ttl_minutes
    try:
        session = await request.app.state.agent_service.create_session(identity, ttl_minutes)
    except ValueError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    return {"session": session.model_dump(mode="json")}


@app.get("/v1/agents/me")
async def current_agent(
    request: Request,
    x_gateshield_agent_token: str | None = Header(default=None),
) -> dict[str, Any]:
    identity = await _authenticate_agent(request, x_gateshield_agent_token)
    return {"agent": identity.model_dump(mode="json")}


@app.get("/v1/agents/sessions/{session_id}/signals")
async def agent_session_signals(
    session_id: str,
    request: Request,
    x_gateshield_agent_token: str | None = Header(default=None),
) -> dict[str, Any]:
    identity = await _authenticate_agent(request, x_gateshield_agent_token)
    signals = await request.app.state.agent_service.signals(identity.id, session_id)
    return {"data": [signal.model_dump(mode="json") for signal in signals]}


@app.delete("/v1/agents/sessions/{session_id}")
async def close_agent_session(
    session_id: str,
    request: Request,
    x_gateshield_agent_token: str | None = Header(default=None),
) -> dict[str, bool]:
    identity = await _authenticate_agent(request, x_gateshield_agent_token)
    closed = await request.app.state.agent_service.close_session(identity, session_id)
    if not closed:
        raise HTTPException(status_code=404, detail="Agent session was not found")
    return {"closed": True}


async def _authenticate_agent(request: Request, token: str | None) -> AgentIdentity:
    if not token:
        raise HTTPException(status_code=401, detail="Agent credential is required")
    identity = await request.app.state.agent_service.authenticate(token)
    settings = get_settings()
    if identity is None:
        raise HTTPException(status_code=401, detail="Agent credential is invalid")
    if identity.status is not AgentStatus.ACTIVE:
        raise HTTPException(status_code=403, detail=f"Agent is {identity.status.value.lower()}")
    if (
        identity.application_id != settings.application_id
        or identity.environment != settings.environment
    ):
        raise HTTPException(status_code=403, detail="Agent is outside this application environment")
    return cast(AgentIdentity, identity)


@app.post("/v1/chat/completions")
async def chat_completions(
    body: GatewayRequest,
    request: Request,
    x_gateshield_agent_token: str | None = Header(default=None),
) -> JSONResponse:
    settings = get_settings()
    raw_len = request.headers.get("content-length")
    if raw_len and int(raw_len) > settings.max_request_bytes:
        raise HTTPException(status_code=413, detail="Request exceeds configured size limit")
    if body.stream:
        raise HTTPException(status_code=501, detail="Streaming is not available")
    try:
        validate_response_format(getattr(body, "response_format", None))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    provider = request.app.state.provider
    if provider is None:
        raise HTTPException(status_code=503, detail="No upstream model provider is configured")

    started = time.monotonic()
    request_id = request.state.request_id
    trace_id = request.state.trace_id
    ai_request = AIRequest(
        id=request_id,
        application_id=settings.application_id,
        user_id=body.user,
        agent_id=body.agent_id,
        session_id=body.session_id,
        model=body.model,
        messages=body.messages,
        tools=body.tools or [],
        metadata={},
        source="openai-compatible-api",
    )
    context = SecurityContext(
        request_id=request_id,
        trace_id=trace_id,
        application_id=settings.application_id,
        environment=settings.environment,
        provider_type=settings.provider_type,
        data_classification=DataClassification(settings.default_data_classification),
        allowed_models=[body.model],
    )
    agent_identity: AgentIdentity | None = None
    agent_session = None
    if body.agent_id is not None or body.session_id is not None or x_gateshield_agent_token:
        try:
            if body.agent_id is None or body.session_id is None:
                raise HTTPException(
                    status_code=401,
                    detail="Agent ID, session ID, and agent token are required together",
                )
            agent_identity = await _authenticate_agent(request, x_gateshield_agent_token)
            if agent_identity.id != body.agent_id:
                raise HTTPException(status_code=403, detail="Agent token does not match agent ID")
            agent_session = await request.app.state.agent_service.validate_session(
                agent_identity, body.session_id
            )
            if agent_session is None:
                raise HTTPException(status_code=403, detail="Agent session is expired or inactive")
            context.allowed_tools = list(agent_identity.allowed_tools)
        except HTTPException as exc:
            denial = PolicyDecision(
                decision=Decision.BLOCK,
                reason=str(exc.detail),
                risk_score=100,
                violations=["agent_identity_or_session_invalid"],
            )
            try:
                await _persist_block(
                    request, ai_request, context, denial, started, InputInspectionResult()
                )
            except Exception as persist_exc:
                raise HTTPException(
                    status_code=503,
                    detail="Agent denial audit failed; provider forwarding was denied",
                ) from persist_exc
            return JSONResponse(
                status_code=exc.status_code,
                content={"detail": exc.detail, "request_id": request_id, "trace_id": trace_id},
                headers={"x-request-id": request_id, "x-trace-id": trace_id},
            )
    inspection_result = InputInspectionResult()
    try:
        with stage_span(
            "gateshield.input.inspect",
            gateshield_request_id=request_id,
            gateshield_application_id=settings.application_id,
        ):
            inspection_result = await request.app.state.input_inspector.inspect(ai_request, context)
        if settings.semantic_classifier_mode != "OFF":
            try:
                signal = await request.app.state.semantic_classifier.classify(ai_request)
                context.semantic_risk_score = signal.risk_score
                context.semantic_classifier_status = "AVAILABLE"
                if signal.injection_likely:
                    threshold = settings.semantic_classifier_enforce_threshold
                    severity = (
                        RiskLevel.HIGH if signal.risk_score >= threshold else RiskLevel.MEDIUM
                    )
                    inspection_result.findings.append(
                        InputFinding(
                            finding_type="SEMANTIC_RISK_SIGNAL",
                            severity=severity,
                            message_index=0,
                            segment_path="semantic_classifier",
                            source="semantic_classifier",
                            trust_level=TrustLevel.UNKNOWN,
                            matched_signal="injection_likely",
                            evidence={"risk_score": signal.risk_score},
                        )
                    )
                    if (
                        settings.semantic_classifier_mode == "ENFORCE"
                        and signal.risk_score >= threshold
                    ):
                        context.semantic_enforcement_triggered = True
                        inspection_result.findings.append(
                            InputFinding(
                                finding_type="SEMANTIC_INJECTION_ENFORCED",
                                severity=RiskLevel.HIGH,
                                message_index=0,
                                segment_path="semantic_classifier",
                                source="semantic_classifier",
                                trust_level=TrustLevel.UNKNOWN,
                                matched_signal="injection_likely_above_threshold",
                                evidence={"risk_score": signal.risk_score, "threshold": threshold},
                            )
                        )
            except Exception as classifier_error:
                context.semantic_classifier_status = "UNAVAILABLE"
                inspection_result.findings.append(
                    InputFinding(
                        finding_type="SEMANTIC_CLASSIFIER_UNAVAILABLE",
                        severity=RiskLevel.HIGH
                        if settings.semantic_classifier_mode == "ENFORCE"
                        else RiskLevel.MEDIUM,
                        message_index=0,
                        segment_path="semantic_classifier",
                        source="semantic_classifier",
                        trust_level=TrustLevel.UNKNOWN,
                        matched_signal="classifier_unavailable",
                        evidence={"mode": settings.semantic_classifier_mode},
                    )
                )
                logger.warning(
                    "semantic_classifier_unavailable",
                    extra={
                        "request_id": request_id,
                        "trace_id": trace_id,
                        "event": type(classifier_error).__name__,
                    },
                )
                if settings.semantic_classifier_mode == "ENFORCE":
                    denial = PolicyDecision(
                        decision=Decision.BLOCK,
                        reason="Semantic enforcement is configured but classifier evaluation failed.",
                        risk_score=100,
                        violations=["semantic_classifier_unavailable"],
                    )
                    try:
                        await _persist_block(
                            request, ai_request, context, denial, started, inspection_result
                        )
                    except Exception as persist_error:
                        raise HTTPException(
                            status_code=503,
                            detail="Classifier failure audit failed; request was denied",
                        ) from persist_error
                    return JSONResponse(
                        status_code=503,
                        content={
                            "detail": denial.reason,
                            "request_id": request_id,
                            "trace_id": trace_id,
                        },
                    )
        context.message_provenance = inspection_result.provenance
        context.input_findings = inspection_result.findings
        context.prompt_injection_detected = any(
            finding.finding_type in ("PROMPT_INJECTION_DETECTED", "INDIRECT_INJECTION_DETECTED")
            for finding in inspection_result.findings
        )
        context.secret_detected = any(
            finding.finding_type == "SECRET_DETECTED" for finding in inspection_result.findings
        )
        if agent_identity is not None and agent_session is not None:
            await request.app.state.agent_service.record_request(
                agent_session.id,
                request_id=request_id,
                risk_score=50
                if context.prompt_injection_detected
                else 25
                if context.secret_detected
                else 0,
                policy_manipulation=context.prompt_injection_detected,
            )
        if inspection_result.findings:
            context.risk_level = max(
                (finding.severity for finding in inspection_result.findings),
                key=lambda level: list(RiskLevel).index(level),
            )
        with stage_span(
            "gateshield.policy.input",
            gateshield_request_id=request_id,
            gateshield_application_id=settings.application_id,
        ):
            decision: PolicyDecision = await request.app.state.policy_engine.evaluate(
                ai_request, context
            )
    except Exception as exc:
        await _record_agent_failure(request, agent_session, request_id, trace_id)
        logger.error(
            "critical_inspection_failed",
            extra={"request_id": request_id, "trace_id": trace_id, "event": type(exc).__name__},
        )
        raise HTTPException(
            status_code=503,
            detail={
                "message": "Request inspection failed; upstream forwarding was denied",
                "request_id": request_id,
                "trace_id": trace_id,
            },
        ) from exc
    if decision.decision is not Decision.ALLOW:
        await _persist_block(request, ai_request, context, decision, started, inspection_result)
        status_code = (
            403 if decision.decision in (Decision.BLOCK, Decision.REQUIRE_APPROVAL) else 501
        )
        return JSONResponse(
            status_code=status_code,
            content={
                "error": {
                    "message": decision.reason,
                    "type": "policy_error",
                    "code": "request_blocked"
                    if status_code == 403
                    else "policy_action_not_implemented",
                },
                "request_id": request_id,
                "trace_id": trace_id,
            },
        )

    route_decision = assess_model_route(
        model=body.model,
        application_id=settings.application_id,
        environment=settings.environment,
        classification=context.data_classification.value,
        provider_type=settings.provider_type,
        mode=settings.model_routing_mode,
        routes_json=settings.model_routes_json,
    )
    context.model_route_status = route_decision.status
    context.model_route_reason = route_decision.reason
    if not route_decision.allowed:
        route_block = PolicyDecision(
            decision=Decision.BLOCK,
            reason=route_decision.reason,
            matched_policies=decision.matched_policies,
            risk_score=100 if context.data_classification is DataClassification.RESTRICTED else 75,
            violations=[f"model_route:{route_decision.status}"],
        )
        await _persist_block(request, ai_request, context, route_block, started, inspection_result)
        return JSONResponse(
            status_code=403,
            content={
                "detail": route_decision.reason,
                "request_id": request_id,
                "trace_id": trace_id,
            },
            headers={"x-request-id": request_id, "x-trace-id": trace_id},
        )
    if route_decision.status == "MONITOR_MISMATCH" and context.risk_level == RiskLevel.LOW:
        context.risk_level = RiskLevel.MEDIUM
    safe_tools: list[dict[str, Any]] = []
    if body.tools:
        try:
            safe_tools = await request.app.state.tool_authorizer.validate_offered_tools(
                settings.application_id, body.tools, agent_identity
            )
        except (ToolSecurityError, Exception) as exc:
            tool_decision = PolicyDecision(
                decision=Decision.BLOCK,
                reason=str(exc)
                if isinstance(exc, ToolSecurityError)
                else "Tool registry evaluation failed.",
                risk_score=100,
                violations=["unregistered_or_invalid_tool_definition"],
            )
            try:
                await _persist_block(
                    request, ai_request, context, tool_decision, started, inspection_result
                )
            except Exception as persist_exc:
                raise HTTPException(
                    status_code=503,
                    detail="Tool request audit failed; provider forwarding was denied",
                ) from persist_exc
            raise HTTPException(status_code=403, detail=tool_decision.reason) from exc

    provider_payload = body.model_dump(
        exclude_none=True, exclude={"messages", "agent_id", "session_id"}
    )
    if body.tools:
        provider_payload["tools"] = safe_tools
    provider_payload["messages"] = [
        message.model_dump(exclude_none=True, exclude={"provenance", "source"})
        for message in body.messages
    ]
    try:
        with stage_span(
            "gateshield.provider.request",
            gateshield_request_id=request_id,
            gateshield_application_id=settings.application_id,
            gateshield_model=body.model,
            gateshield_provider_type=settings.provider_type,
        ):
            upstream = await provider.complete(provider_payload)
        response_model = _response_model(upstream)
        with stage_span(
            "gateshield.output.inspect",
            gateshield_request_id=request_id,
            gateshield_application_id=settings.application_id,
        ):
            output_inspection = await request.app.state.output_inspector.inspect(
                response_model, context, getattr(body, "response_format", None)
            )
        with stage_span(
            "gateshield.tool.inspect_completion",
            gateshield_request_id=request_id,
            gateshield_application_id=settings.application_id,
        ):
            tool_findings = await request.app.state.tool_authorizer.inspect_completion(
                settings.application_id,
                upstream,
                agent_identity,
                {
                    tool["function"]["name"]
                    for tool in safe_tools
                    if isinstance(tool.get("function"), dict)
                    and isinstance(tool["function"].get("name"), str)
                },
            )
        output_inspection.findings.extend(tool_findings)
        if tool_findings:
            context.risk_level = RiskLevel.HIGH
        sensitive_tool_argument = any(
            finding.finding_type == "OUTPUT_SENSITIVE_DATA_DETECTED"
            and ".tool_calls[" in finding.location
            for finding in output_inspection.findings
        )
        context.tool_security_violation = (
            any(finding.finding_type == "TOOL_BLOCKED" for finding in tool_findings)
            or sensitive_tool_argument
        )
        if agent_identity is not None and agent_session is not None:
            attempts = _tool_call_count(upstream)
            denied_attempts = min(
                attempts,
                sum(finding.finding_type == "TOOL_BLOCKED" for finding in tool_findings)
                + int(sensitive_tool_argument),
            )
            if attempts:
                await request.app.state.agent_service.record_tool_activity(
                    agent_session.id,
                    request_id=request_id,
                    attempts=attempts,
                    denied=denied_attempts,
                    risk_increment=50
                    * (
                        attempts
                        if any(f.finding_type == "APPROVAL_REQUIRED" for f in tool_findings)
                        else denied_attempts
                    ),
                    resource_scope_violation=any(
                        finding.finding_type == "TOOL_BLOCKED"
                        and "scope" in str(finding.evidence).lower()
                        for finding in tool_findings
                    ),
                )
    except Exception as exc:
        await _record_agent_failure(request, agent_session, request_id, trace_id)
        logger.error(
            "upstream_or_output_failure",
            extra={"request_id": request_id, "trace_id": trace_id, "event": type(exc).__name__},
        )
        raise HTTPException(
            status_code=502,
            detail={
                "message": "Upstream response failed or could not be inspected",
                "request_id": request_id,
                "trace_id": trace_id,
            },
        ) from exc

    try:
        with stage_span(
            "gateshield.policy.output",
            gateshield_request_id=request_id,
            gateshield_application_id=settings.application_id,
        ):
            output_decision: PolicyDecision = await request.app.state.policy_engine.evaluate(
                ai_request, context
            )
    except Exception as exc:
        await _record_agent_failure(request, agent_session, request_id, trace_id)
        logger.error(
            "output_policy_evaluation_failed",
            extra={"request_id": request_id, "trace_id": trace_id, "event": type(exc).__name__},
        )
        raise HTTPException(
            status_code=503,
            detail={
                "message": "Output policy evaluation failed; provider response was withheld",
                "request_id": request_id,
                "trace_id": trace_id,
            },
        ) from exc

    if context.tool_security_violation and output_decision.decision is not Decision.BLOCK:
        output_decision = PolicyDecision(
            decision=Decision.BLOCK,
            reason="Tool proposal failed deterministic authorization or argument inspection.",
            matched_policies=output_decision.matched_policies,
            risk_score=max(output_decision.risk_score, 75),
            violations=output_decision.violations + ["deterministic_tool_authorization_block"],
        )

    if output_decision.decision in (Decision.BLOCK, Decision.REQUIRE_APPROVAL):
        await _persist_output_result(
            request,
            ai_request,
            context,
            output_decision,
            inspection_result,
            output_inspection,
            output_inspection.sanitized_response,
            provider.provider_name,
            started,
        )
        return JSONResponse(
            status_code=502,
            content={
                "error": {
                    "message": "Upstream response was withheld by output security policy",
                    "type": "output_policy_error",
                    "code": "output_blocked",
                },
                "request_id": request_id,
                "trace_id": trace_id,
            },
            headers={"x-request-id": request_id, "x-trace-id": trace_id},
        )
    if output_decision.decision not in (Decision.ALLOW, Decision.REDACT):
        output_decision = PolicyDecision(
            decision=Decision.BLOCK,
            reason="Unsupported output policy action; response withheld.",
            matched_policies=output_decision.matched_policies,
            risk_score=max(output_decision.risk_score, 75),
            violations=output_decision.violations
            + [f"unsupported_output_action:{output_decision.decision.value}"],
        )
        await _persist_output_result(
            request,
            ai_request,
            context,
            output_decision,
            inspection_result,
            output_inspection,
            output_inspection.sanitized_response,
            provider.provider_name,
            started,
        )
        return JSONResponse(
            status_code=502,
            content={
                "error": {
                    "message": output_decision.reason,
                    "type": "output_policy_error",
                    "code": "output_blocked",
                },
                "request_id": request_id,
                "trace_id": trace_id,
            },
            headers={"x-request-id": request_id, "x-trace-id": trace_id},
        )

    returned_response = (
        output_inspection.sanitized_response
        if output_decision.decision is Decision.REDACT
        else upstream
    )

    latency_ms = int((time.monotonic() - started) * 1000)
    try:
        async with request.app.state.session_factory() as session:
            session.add(
                RequestRecord(
                    id=request_id,
                    trace_id=trace_id,
                    application_id=ai_request.application_id,
                    user_id=ai_request.user_id,
                    agent_id=ai_request.agent_id,
                    session_id=ai_request.session_id,
                    model=ai_request.model,
                    provider=provider.provider_name,
                    decision=output_decision.decision.value,
                    risk_level=context.risk_level.value,
                    started_at=ai_request.timestamp,
                    latency_ms=latency_ms,
                    request_redacted=_stored_request(ai_request, settings.logging_mode),
                    response_redacted=_stored_response(
                        output_inspection.sanitized_response, settings.logging_mode
                    ),
                )
            )
            session.add(
                SecurityEventRecord(
                    id=str(uuid4()),
                    request_id=request_id,
                    trace_id=trace_id,
                    application_id=ai_request.application_id,
                    event_type=(
                        "CONTENT_REDACTED"
                        if output_decision.decision is Decision.REDACT
                        else "REQUEST_ALLOWED"
                    ),
                    decision=output_decision.decision.value,
                    risk=context.risk_level.value,
                    evidence=redact(
                        {
                            "reason": output_decision.reason,
                            "risk_score": output_decision.risk_score,
                            "matched_policies": output_decision.matched_policies,
                            "violations": output_decision.violations,
                            "required_actions": output_decision.required_actions,
                            "semantic_risk_score": context.semantic_risk_score,
                            "semantic_classifier_status": context.semantic_classifier_status,
                            "semantic_enforcement_triggered": context.semantic_enforcement_triggered,
                            "data_classification": context.data_classification.value,
                            "model_route_status": context.model_route_status,
                            "model_route_reason": context.model_route_reason,
                            "message_provenance": [
                                segment.model_dump(mode="json")
                                for segment in context.message_provenance
                            ],
                        }
                    ),
                    outcome=(
                        "redacted" if output_decision.decision is Decision.REDACT else "forwarded"
                    ),
                )
            )
            _add_finding_events(session, ai_request, context, inspection_result, decision)
            _add_output_finding_events(
                session, ai_request, context, output_inspection, output_decision
            )
            await session.commit()
    except Exception as exc:
        logger.error(
            "request_persistence_failed",
            extra={"request_id": request_id, "trace_id": trace_id, "event": type(exc).__name__},
        )
        raise HTTPException(
            status_code=503,
            detail={
                "message": "Request audit persistence failed; response withheld",
                "request_id": request_id,
                "trace_id": trace_id,
            },
        ) from exc
    logger.info(
        "request_forwarded",
        extra={"request_id": request_id, "trace_id": trace_id, "event": "REQUEST_ALLOWED"},
    )
    return JSONResponse(
        content=returned_response, headers={"x-request-id": request_id, "x-trace-id": trace_id}
    )


def _response_model(upstream: dict[str, Any]) -> GatewayResponse:
    return GatewayResponse.model_validate(upstream)


def _stored_request(ai_request: AIRequest, mode: str) -> dict[str, Any]:
    if mode == "METADATA_ONLY":
        return {
            "id": ai_request.id,
            "timestamp": ai_request.timestamp.isoformat(),
            "application_id": ai_request.application_id,
            "user_id": ai_request.user_id,
            "agent_id": ai_request.agent_id,
            "session_id": ai_request.session_id,
            "model": ai_request.model,
            "source": ai_request.source,
        }
    return cast(dict[str, Any], redact(ai_request.model_dump(mode="json")))


def _stored_response(response: dict[str, Any], mode: str) -> dict[str, Any]:
    if mode == "METADATA_ONLY":
        return {key: response.get(key) for key in ("id", "object", "created", "model", "usage")}
    return cast(dict[str, Any], redact(response))


async def _persist_block(
    request: Request,
    ai_request: AIRequest,
    context: SecurityContext,
    decision: PolicyDecision,
    started: float,
    inspection: InputInspectionResult,
) -> None:
    async with request.app.state.session_factory() as session:
        session.add(
            RequestRecord(
                id=context.request_id,
                trace_id=context.trace_id,
                application_id=context.application_id,
                user_id=ai_request.user_id,
                agent_id=ai_request.agent_id,
                session_id=ai_request.session_id,
                model=ai_request.model,
                provider="not_called",
                decision=decision.decision.value,
                risk_level=_risk_level_for_score(decision.risk_score).value,
                started_at=ai_request.timestamp,
                latency_ms=int((time.monotonic() - started) * 1000),
                request_redacted=_stored_request(ai_request, get_settings().logging_mode),
                response_redacted={},
            )
        )
        session.add(
            SecurityEventRecord(
                id=str(uuid4()),
                request_id=context.request_id,
                trace_id=context.trace_id,
                application_id=context.application_id,
                event_type="REQUEST_BLOCKED",
                decision=decision.decision.value,
                risk=_risk_level_for_score(decision.risk_score).value,
                evidence=redact(
                    {
                        "reason": decision.reason,
                        "risk_score": decision.risk_score,
                        "matched_policies": decision.matched_policies,
                        "violations": decision.violations,
                        "required_actions": decision.required_actions,
                        "semantic_risk_score": context.semantic_risk_score,
                        "semantic_classifier_status": context.semantic_classifier_status,
                        "semantic_enforcement_triggered": context.semantic_enforcement_triggered,
                        "data_classification": context.data_classification.value,
                        "model_route_status": context.model_route_status,
                        "model_route_reason": context.model_route_reason,
                        "message_provenance": [
                            segment.model_dump(mode="json")
                            for segment in context.message_provenance
                        ],
                    }
                ),
                outcome="blocked",
            )
        )
        _add_finding_events(session, ai_request, context, inspection, decision)
        await session.commit()


def _add_finding_events(
    session: Any,
    ai_request: AIRequest,
    context: SecurityContext,
    inspection: InputInspectionResult,
    decision: PolicyDecision,
) -> None:
    for finding in inspection.findings:
        session.add(
            SecurityEventRecord(
                id=str(uuid4()),
                request_id=context.request_id,
                trace_id=context.trace_id,
                application_id=ai_request.application_id,
                event_type=finding.finding_type,
                decision=decision.decision.value,
                risk=finding.severity.value,
                evidence=redact(finding.model_dump(mode="json")),
                outcome="blocked" if decision.decision is not Decision.ALLOW else "observed",
            )
        )


async def _persist_output_result(
    request: Request,
    ai_request: AIRequest,
    context: SecurityContext,
    decision: PolicyDecision,
    input_inspection: InputInspectionResult,
    output_inspection: OutputInspectionResult,
    sanitized_response: dict[str, Any],
    provider_name: str,
    started: float,
) -> None:
    async with request.app.state.session_factory() as session:
        session.add(
            RequestRecord(
                id=context.request_id,
                trace_id=context.trace_id,
                application_id=context.application_id,
                user_id=ai_request.user_id,
                agent_id=ai_request.agent_id,
                session_id=ai_request.session_id,
                model=ai_request.model,
                provider=provider_name,
                decision=decision.decision.value,
                risk_level=_risk_level_for_score(decision.risk_score).value,
                started_at=ai_request.timestamp,
                latency_ms=int((time.monotonic() - started) * 1000),
                request_redacted=_stored_request(ai_request, get_settings().logging_mode),
                response_redacted=_stored_response(sanitized_response, get_settings().logging_mode),
            )
        )
        session.add(
            SecurityEventRecord(
                id=str(uuid4()),
                request_id=context.request_id,
                trace_id=context.trace_id,
                application_id=context.application_id,
                event_type="OUTPUT_BLOCKED",
                decision=decision.decision.value,
                risk=_risk_level_for_score(decision.risk_score).value,
                evidence=redact(
                    {
                        "reason": decision.reason,
                        "matched_policies": decision.matched_policies,
                        "violations": decision.violations,
                        "semantic_risk_score": context.semantic_risk_score,
                        "semantic_classifier_status": context.semantic_classifier_status,
                        "semantic_enforcement_triggered": context.semantic_enforcement_triggered,
                        "data_classification": context.data_classification.value,
                        "model_route_status": context.model_route_status,
                        "model_route_reason": context.model_route_reason,
                    }
                ),
                outcome="withheld",
            )
        )
        _add_finding_events(session, ai_request, context, input_inspection, decision)
        _add_output_finding_events(session, ai_request, context, output_inspection, decision)
        await session.commit()


def _add_output_finding_events(
    session: Any,
    ai_request: AIRequest,
    context: SecurityContext,
    inspection: OutputInspectionResult,
    decision: PolicyDecision,
) -> None:
    for finding in inspection.findings:
        session.add(
            SecurityEventRecord(
                id=str(uuid4()),
                request_id=context.request_id,
                trace_id=context.trace_id,
                application_id=ai_request.application_id,
                event_type=finding.finding_type,
                decision=decision.decision.value,
                risk=finding.severity.value,
                evidence=redact(finding.model_dump(mode="json")),
                outcome="redacted"
                if decision.decision is Decision.REDACT
                else "withheld"
                if decision.decision in (Decision.BLOCK, Decision.REQUIRE_APPROVAL)
                else "observed",
            )
        )


app.include_router(console_router)
