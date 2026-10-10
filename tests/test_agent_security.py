from datetime import UTC, datetime, timedelta

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker

from gateshield.agent_security import AgentEnrollmentRequest, AgentSecurityService
from gateshield.app import app
from gateshield.domain import AgentSessionStatus, AgentStatus
from gateshield.storage import (
    AgentIdentityRecord,
    AgentSessionRecord,
    ApplicationRecord,
    Base,
    BehaviorSignalRecord,
    make_engine,
)


@pytest.mark.asyncio
async def test_agent_token_is_hashed_and_sessions_expire_and_close(tmp_path):
    engine = make_engine(f"sqlite+aiosqlite:///{tmp_path}/agents.db")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    async with sessions() as db:
        db.add(ApplicationRecord(id="agent-app", name="Agent app"))
        await db.commit()
    service = AgentSecurityService(sessions)
    identity, token = await service.enroll(
        "agent-app",
        AgentEnrollmentRequest(
            id="reports-agent",
            owner="analytics-team",
            role="reader",
            environment="test",
            allowed_tools=["search_documents"],
        ),
    )

    authenticated = await service.authenticate(token)
    agent_session = await service.create_session(identity, 10)
    assert authenticated is not None
    assert authenticated.id == identity.id
    async with sessions() as db:
        record = await db.get(AgentIdentityRecord, identity.id)
        assert record is not None
        assert record.token_hash != token

    async with sessions() as db:
        record = await db.get(AgentSessionRecord, agent_session.id)
        assert record is not None
        record.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        await db.commit()
    assert await service.validate_session(identity, agent_session.id) is None
    async with sessions() as db:
        record = await db.get(AgentSessionRecord, agent_session.id)
        assert record is not None
        assert record.status == AgentSessionStatus.EXPIRED.value
    await service.set_status(identity.id, AgentStatus.REVOKED)
    revoked_identity = await service.authenticate(token)
    assert revoked_identity is not None
    assert revoked_identity.status is AgentStatus.REVOKED
    await engine.dispose()


@pytest.mark.asyncio
async def test_session_behavior_signals_are_deterministic_and_deduplicated(tmp_path):
    engine = make_engine(f"sqlite+aiosqlite:///{tmp_path}/behavior.db")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    async with sessions() as db:
        db.add(ApplicationRecord(id="behavior-app", name="Behavior app"))
        await db.commit()
    service = AgentSecurityService(sessions)
    identity, _ = await service.enroll(
        "behavior-app",
        AgentEnrollmentRequest(
            id="injection-agent",
            owner="security",
            role="reader",
            environment="test",
            risk_profile={"policy_manipulation_threshold": 2, "max_cumulative_risk": 100},
        ),
    )
    agent_session = await service.create_session(identity, 10)

    await service.record_request(
        agent_session.id, request_id="request-1", risk_score=50, policy_manipulation=True
    )
    await service.record_request(
        agent_session.id, request_id="request-2", risk_score=50, policy_manipulation=True
    )
    await service.record_request(
        agent_session.id, request_id="request-3", risk_score=50, policy_manipulation=True
    )
    signals = await service.signals(identity.id, agent_session.id)

    assert {signal.signal for signal in signals} == {
        "repeated_policy_manipulation",
        "high_cumulative_session_risk",
    }
    async with sessions() as db:
        stored = (await db.execute(select(BehaviorSignalRecord))).scalars().all()
        assert len(stored) == 2
        session = await db.get(AgentSessionRecord, agent_session.id)
        assert session is not None
        assert session.request_count == 3
    await engine.dispose()


class AgentStubProvider:
    provider_name = "agent-test-provider"

    async def complete(self, payload):
        return {
            "id": "agent-completion",
            "object": "chat.completion",
            "created": 1,
            "model": payload["model"],
            "choices": [{"message": {"role": "assistant", "content": "ok"}}],
        }


@pytest.mark.asyncio
async def test_agent_auth_session_tool_permissions_and_correlated_authorization(
    tmp_path, monkeypatch
):
    from gateshield.config import Settings

    monkeypatch.setattr(
        "gateshield.app.get_settings",
        lambda: Settings(
            database_url=f"sqlite+aiosqlite:///{tmp_path}/agent-gateway.db",
            application_id="agent-gateway-app",
            environment="development",
            agent_enrollment_key="enroll-key",
        ),
    )
    async with app.router.lifespan_context(app):
        app.state.provider = AgentStubProvider()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            enrolled = await client.post(
                "/v1/agents/enroll",
                headers={"x-gateshield-enrollment-key": "enroll-key"},
                json={
                    "id": "search-agent",
                    "owner": "docs-team",
                    "role": "reader",
                    "environment": "development",
                    "allowed_tools": ["search_documents"],
                    "risk_profile": {"denied_action_threshold": 1},
                },
            )
            agent_token = enrolled.json()["agent_token"]
            agent_id = enrolled.json()["agent"]["id"]
            created_session = await client.post(
                "/v1/agents/sessions", headers={"x-gateshield-agent-token": agent_token}, json={}
            )
            session_id = created_session.json()["session"]["id"]
            unauthorized = await client.post(
                "/v1/chat/completions",
                json={
                    "model": "local-test",
                    "agent_id": agent_id,
                    "session_id": session_id,
                    "messages": [{"role": "user", "content": "hello"}],
                },
            )
            completion = await client.post(
                "/v1/chat/completions",
                headers={"x-gateshield-agent-token": agent_token},
                json={
                    "model": "local-test",
                    "agent_id": agent_id,
                    "session_id": session_id,
                    "messages": [{"role": "user", "content": "search"}],
                },
            )
            allowed_tool = await client.post(
                "/v1/tools/authorize",
                headers={"x-gateshield-agent-token": agent_token},
                json={
                    "name": "search_documents",
                    "arguments": {"query": "annual report"},
                    "agent_id": agent_id,
                    "session_id": session_id,
                    "request_id": completion.headers["x-request-id"],
                },
            )
            denied_tool = await client.post(
                "/v1/tools/authorize",
                headers={"x-gateshield-agent-token": agent_token},
                json={
                    "name": "read_document",
                    "arguments": {"document_id": "doc-1"},
                    "agent_id": agent_id,
                    "session_id": session_id,
                    "request_id": completion.headers["x-request-id"],
                },
            )
            signals = await client.get(
                f"/v1/agents/sessions/{session_id}/signals",
                headers={"x-gateshield-agent-token": agent_token},
            )
        assert enrolled.status_code == 200
        assert unauthorized.status_code == 401
        assert completion.status_code == 200
        assert allowed_tool.status_code == 200
        assert allowed_tool.json()["execution_performed"] is False
        assert denied_tool.status_code == 403
        assert any(item["signal"] == "repeated_denied_actions" for item in signals.json()["data"])
