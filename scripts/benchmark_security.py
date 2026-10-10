"""Measure local GateShield stages using synthetic data and a loopback-only stub provider."""

from __future__ import annotations

import argparse
import asyncio
import json
import platform
import statistics
import time
from collections.abc import Callable
from typing import Any

import httpx
from fastapi import FastAPI
from uvicorn import Config, Server

from gateshield.domain import (
    AgentIdentity,
    AIRequest,
    DataClassification,
    ProviderType,
    SecurityContext,
)
from gateshield.inspection import DeterministicInputInspector
from gateshield.policies import (
    DeterministicPolicyEngine,
    PolicyRepository,
    default_policy_definitions,
)
from gateshield.storage import ApplicationRecord, ensure_schema, make_engine, make_session_factory
from gateshield.tool_security import DeterministicToolAuthorizer, ToolDefinition, ToolRegistry


async def main_async(iterations: int) -> dict[str, Any]:
    engine = make_engine("sqlite+aiosqlite:///:memory:")
    await ensure_schema(engine)
    sessions = make_session_factory(engine)
    async with sessions() as session:
        session.add(ApplicationRecord(id="bench-app", name="Synthetic benchmark"))
        await session.commit()
    policies = PolicyRepository(sessions)
    for definition in default_policy_definitions():
        await policies.ensure_default(definition)
    policy_engine = DeterministicPolicyEngine(policies)
    inspector = DeterministicInputInspector()
    request = AIRequest(
        application_id="bench-app",
        model="fixture",
        messages=[{"role": "user", "content": "Summarize this local synthetic document."}],
    )
    context = SecurityContext(
        request_id=request.id,
        trace_id="bench",
        application_id="bench-app",
        environment="benchmark",
        provider_type=ProviderType.EXTERNAL,
        data_classification=DataClassification.INTERNAL,
    )
    registry = ToolRegistry(sessions)
    await registry.register(
        "bench-app",
        ToolDefinition(
            name="read_note",
            description="Read note",
            resource_type="document",
            parameters={
                "type": "object",
                "properties": {"note_id": {"type": "string"}},
                "required": ["note_id"],
                "additionalProperties": False,
            },
            scope={"agent_resource_argument": "note_id"},
        ),
    )
    authorizer = DeterministicToolAuthorizer(registry)
    identity = AgentIdentity(
        id="bench-agent",
        application_id="bench-app",
        owner="fixture",
        role="reader",
        environment="benchmark",
        allowed_tools=["read_note"],
        allowed_resources={"read_note": ["n-1"]},
    )

    async def measure(operation: Callable[[], Any]) -> dict[str, float | int]:
        samples = []
        for _ in range(iterations):
            start = time.perf_counter_ns()
            await operation()
            samples.append((time.perf_counter_ns() - start) / 1_000_000)
        return {
            "iterations": iterations,
            "mean_ms": statistics.fmean(samples),
            "median_ms": statistics.median(samples),
            "p95_ms": sorted(samples)[int(0.95 * (len(samples) - 1))],
        }

    async def inspection() -> None:
        await inspector.inspect(request, context)

    async def policy() -> None:
        await policy_engine.evaluate(request, context)

    async def tool() -> None:
        await authorizer.authorize("bench-app", "read_note", {"note_id": "n-1"}, identity)

    async def gateway_overhead() -> None:
        await inspection()
        await policy()

    stub_app = FastAPI()

    @stub_app.get("/complete")
    async def complete() -> dict[str, str]:
        return {"status": "ok"}

    server = Server(
        Config(stub_app, host="127.0.0.1", port=0, log_level="critical", lifespan="off")
    )
    # Bind an ephemeral loopback port through a pre-bound socket; no external provider is contacted.
    import socket

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    task = asyncio.create_task(server.serve(sockets=[sock]))
    try:
        for _ in range(200):
            if server.started:
                break
            await asyncio.sleep(0.01)
        async with httpx.AsyncClient() as client:

            async def provider_stub() -> None:
                response = await client.get(f"http://127.0.0.1:{port}/complete")
                response.raise_for_status()

            await provider_stub()  # Exclude connection startup from measured samples.
            results = {
                "gateway_local_overhead": await measure(gateway_overhead),
                "input_inspection": await measure(inspection),
                "policy_evaluation": await measure(policy),
                "tool_authorization": await measure(tool),
                "provider_latency_loopback_stub": await measure(provider_stub),
            }
    finally:
        server.should_exit = True
        await task
        await engine.dispose()
    return {
        "methodology": (
            "Single-process local benchmark; SQLite in-memory policy/tool records; HTTP "
            "provider stub bound to loopback only. Not representative of production/provider "
            "latency. The stub is warmed before samples are collected."
        ),
        "environment": {"python": platform.python_version(), "platform": platform.platform()},
        "iterations": iterations,
        "measurements": results,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=100)
    parser.add_argument("--output")
    args = parser.parse_args()
    if args.iterations < 1:
        parser.error("--iterations must be positive")
    report = asyncio.run(main_async(args.iterations))
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        with open(args.output, "w", encoding="utf-8") as output:
            output.write(text)
    else:
        print(text, end="")


if __name__ == "__main__":
    main()
