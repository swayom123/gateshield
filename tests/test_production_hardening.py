import subprocess
import sys
from datetime import UTC, datetime
from importlib.util import find_spec

import pytest
from httpx import ASGITransport, AsyncClient
from pydantic import ValidationError

from gateshield.app import app
from gateshield.config import Settings
from gateshield.storage import (
    ApplicationRecord,
    RequestRecord,
    SecurityEventRecord,
    ensure_schema,
    make_engine,
    make_session_factory,
)
from scripts.expire_data import expire


def test_production_rejects_sqlite_and_full_content_logging():
    with pytest.raises(ValidationError, match="PostgreSQL"):
        Settings(
            environment="production",
            application_id="production-app",
            database_url="sqlite+aiosqlite:///./production.db",
            provider_base_url="https://provider.example/v1",
            console_users_json='{"admin":{"password":"a-long-enough-password","role":"ADMIN"}}',
        )

    with pytest.raises(ValidationError, match="FULL_CONTENT"):
        Settings(
            environment="production",
            application_id="production-app",
            database_url="postgresql+asyncpg://user:password@db.internal/gateshield",
            provider_base_url="https://provider.example/v1",
            logging_mode="FULL_CONTENT",
            console_users_json='{"admin":{"password":"a-long-enough-password","role":"ADMIN"}}',
        )


def test_production_accepts_postgres_and_validated_console_configuration():
    settings = Settings(
        environment="production",
        application_id="production-app",
        database_url="postgresql+asyncpg://user:password@db.internal/gateshield",
        provider_base_url="https://provider.example/v1",
        console_users_json='{"admin":{"password":"a-long-enough-password","role":"ADMIN"}}',
    )

    assert settings.database_pool_size == 10


def test_otlp_tracing_requires_an_endpoint_when_enabled():
    with pytest.raises(ValidationError, match="OTLP endpoint"):
        Settings(opentelemetry_enabled=True)


def test_otel_stage_spans_keep_w3c_trace_correlation_without_payloads():
    if find_spec("opentelemetry.sdk") is None:
        pytest.skip("Install the observability extra to run SDK span integration coverage")
    code = """
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from gateshield.telemetry import parent_context, stage_span

exporter = InMemorySpanExporter()
provider = TracerProvider()
provider.add_span_processor(SimpleSpanProcessor(exporter))
trace.set_tracer_provider(provider)
parent = parent_context({"traceparent": "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"})
with stage_span("gateshield.test", context=parent, gateshield_request_id="request-fixture"):
    pass
spans = exporter.get_finished_spans()
assert len(spans) == 1
assert f"{spans[0].context.trace_id:032x}" == "0123456789abcdef0123456789abcdef"
assert spans[0].attributes == {"gateshield_request_id": "request-fixture"}
provider.shutdown()
"""
    subprocess.run([sys.executable, "-c", code], check=True, capture_output=True, text=True)


@pytest.mark.asyncio
async def test_readiness_and_response_security_headers(tmp_path, monkeypatch):
    settings = Settings(
        database_url=f"sqlite+aiosqlite:///{tmp_path}/ready.db",
        provider_base_url="https://provider.example/v1",
    )
    monkeypatch.setattr("gateshield.app.get_settings", lambda: settings)
    async with app.router.lifespan_context(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/ready")
            assert response.status_code == 200
            assert response.json()["status"] == "ready"
            assert response.headers["x-content-type-options"] == "nosniff"
            assert response.headers["x-frame-options"] == "DENY"


@pytest.mark.asyncio
async def test_retention_preview_is_read_only_and_apply_removes_correlated_rows(
    tmp_path, monkeypatch
):
    db_url = f"sqlite+aiosqlite:///{tmp_path}/retention.db"
    settings = Settings(database_url=db_url)
    monkeypatch.setattr("scripts.expire_data.get_settings", lambda: settings)
    engine = make_engine(db_url)
    await ensure_schema(engine)
    factory = make_session_factory(engine)
    started = datetime(2020, 1, 1, tzinfo=UTC)
    async with factory() as session:
        session.add(ApplicationRecord(id="retention-app", name="Retention fixture"))
        await session.flush()
        session.add(
            RequestRecord(
                id="retention-request",
                trace_id="retention-trace",
                application_id="retention-app",
                user_id=None,
                agent_id=None,
                session_id=None,
                model="fixture",
                provider="not_called",
                decision="BLOCK",
                risk_level="HIGH",
                started_at=started,
                latency_ms=0,
                request_redacted={},
                response_redacted={},
            )
        )
        await session.flush()
        session.add(
            SecurityEventRecord(
                id="retention-event",
                request_id="retention-request",
                trace_id="retention-trace",
                application_id="retention-app",
                event_type="FIXTURE",
                decision="BLOCK",
                risk="HIGH",
                evidence={},
                outcome="blocked",
            )
        )
        await session.commit()
    cutoff = datetime(2021, 1, 1, tzinfo=UTC)
    preview = await expire(cutoff, apply=False)
    assert preview["counts"] == {
        "security_events": 1,
        "tool_invocations": 0,
        "behavior_signals": 0,
        "requests": 1,
    }
    applied = await expire(cutoff, apply=True)
    assert applied["counts"] == preview["counts"]
    async with factory() as session:
        assert await session.get(RequestRecord, "retention-request") is None
        assert await session.get(SecurityEventRecord, "retention-event") is None
    await engine.dispose()
