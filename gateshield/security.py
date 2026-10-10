from typing import Any, Protocol

from .domain import (
    AIRequest,
    GatewayResponse,
    InputInspectionResult,
    OutputInspectionResult,
    PolicyDecision,
    SecurityContext,
)


class PolicyEngine(Protocol):
    async def evaluate(self, request: AIRequest, context: SecurityContext) -> PolicyDecision: ...


class InputInspector(Protocol):
    async def inspect(
        self, request: AIRequest, context: SecurityContext
    ) -> InputInspectionResult: ...


class OutputInspector(Protocol):
    async def inspect(
        self, response: GatewayResponse, context: SecurityContext, response_format: Any = None
    ) -> OutputInspectionResult: ...


class RiskEngine(Protocol):
    async def assess(self, request: AIRequest, context: SecurityContext) -> int: ...


class DLPScanner(Protocol):
    async def scan(self, text: str) -> list[str]: ...


class AgentAuthorizer(Protocol):
    async def authorize(self, agent_id: str | None, application_id: str) -> bool: ...


class ToolAuthorizer(Protocol):
    async def authorize(
        self, agent_id: str | None, tool_name: str, arguments: dict[str, Any]
    ) -> bool: ...


class AuditService(Protocol):
    async def record(self, event: dict[str, Any]) -> None: ...


class NoopInputInspector:
    async def inspect(self, request: AIRequest, context: SecurityContext) -> InputInspectionResult:
        return InputInspectionResult()


class NoopOutputInspector:
    async def inspect(
        self, response: GatewayResponse, context: SecurityContext, response_format: Any = None
    ) -> OutputInspectionResult:
        return OutputInspectionResult(sanitized_response=response.model_dump(mode="json"))
