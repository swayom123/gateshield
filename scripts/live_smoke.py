"""Run GateShield against a local OpenAI-compatible test provider."""

import asyncio
import io
import logging
import os
import tempfile
from typing import Any

import httpx
from fastapi import FastAPI
from sqlalchemy import select
from uvicorn import Config, Server


async def main() -> None:
    temp_dir = tempfile.TemporaryDirectory(prefix="gateshield-smoke-")
    os.environ["GATESHIELD_DATABASE_URL"] = f"sqlite+aiosqlite:///{temp_dir.name}/smoke.db"
    os.environ["GATESHIELD_PROVIDER_BASE_URL"] = "http://127.0.0.1:19001/v1"
    os.environ["GATESHIELD_APPLICATION_ID"] = "local-smoke"
    os.environ["GATESHIELD_APPLICATION_NAME"] = "Local smoke test"

    from gateshield.config import get_settings

    get_settings.cache_clear()
    from gateshield.app import app
    from gateshield.storage import RequestRecord, SecurityEventRecord

    provider_app = FastAPI()
    provider_hits = 0

    @provider_app.post("/v1/chat/completions")
    async def complete(payload: dict[str, Any]) -> dict[str, Any]:
        nonlocal provider_hits
        provider_hits += 1
        return {
            "id": "local-test-completion",
            "object": "chat.completion",
            "created": 1,
            "model": payload["model"],
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "Local provider response."},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 3, "completion_tokens": 4, "total_tokens": 7},
        }

    provider_server = Server(Config(provider_app, host="127.0.0.1", port=19001, log_level="error"))
    gateway_server = Server(Config(app, host="127.0.0.1", port=18000, log_level="error"))
    provider_task = asyncio.create_task(provider_server.serve())
    gateway_task = asyncio.create_task(gateway_server.serve())
    try:
        for _ in range(200):
            if provider_server.started and gateway_server.started:
                break
            await asyncio.sleep(0.05)
        if not (provider_server.started and gateway_server.started):
            raise RuntimeError("Local test servers did not start")

        captured_logs = io.StringIO()
        logging.getLogger().handlers = [logging.StreamHandler(captured_logs)]
        secret_fixture = "ghp_phase3_fixture_12345678901234567890"
        async with httpx.AsyncClient() as client:
            health = await client.get("http://127.0.0.1:18000/health")
            forwarded_response = await client.post(
                "http://127.0.0.1:18000/v1/chat/completions",
                json={
                    "model": "local-test-model",
                    "messages": [{"role": "user", "content": "Summarize this public document."}],
                },
            )
            blocked_response = await client.post(
                "http://127.0.0.1:18000/v1/chat/completions",
                json={
                    "model": "local-test-model",
                    "messages": [{"role": "user", "content": f"api_key={secret_fixture}"}],
                },
            )
        assert health.status_code == 200 and health.json()["database"] == "ok"
        assert forwarded_response.status_code == 200, forwarded_response.text
        assert (
            forwarded_response.json()["choices"][0]["message"]["content"]
            == "Local provider response."
        )
        assert forwarded_response.headers.get("x-request-id")
        assert forwarded_response.headers.get("x-trace-id")
        assert blocked_response.status_code == 403
        assert provider_hits == 1

        async with app.state.session_factory() as session:
            records = (await session.execute(select(RequestRecord))).scalars().all()
            assert len(records) == 2
            record = next(item for item in records if "api_key" in str(item.request_redacted))
            forwarded_record = next(item for item in records if item.provider != "not_called")
            persisted = str(record.request_redacted)
            assert forwarded_record.trace_id == forwarded_response.headers["x-trace-id"]
            assert secret_fixture not in persisted
            assert "ghp_...7890" in persisted
            secret_event = (
                await session.execute(
                    select(SecurityEventRecord).where(
                        SecurityEventRecord.event_type == "SECRET_DETECTED"
                    )
                )
            ).scalar_one()
            assert secret_fixture not in str(secret_event.evidence)
        assert secret_fixture not in captured_logs.getvalue()
        print("PASS: HTTP forwarding, policy block, stored IDs, secret masking, and private logs")
    finally:
        gateway_server.should_exit = True
        provider_server.should_exit = True
        await asyncio.gather(gateway_task, provider_task, return_exceptions=True)
        temp_dir.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
