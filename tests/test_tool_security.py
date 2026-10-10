import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker

from gateshield.domain import AgentIdentity, Decision
from gateshield.storage import Base, make_engine
from gateshield.tool_security import (
    DeterministicToolAuthorizer,
    ToolDefinition,
    ToolRegistry,
    ToolSecurityError,
    build_read_only_query,
    validate_http_target,
    validate_tool_target,
)


@pytest.mark.asyncio
async def test_filesystem_tool_rejects_path_traversal(tmp_path):
    definition = ToolDefinition(
        name="read_file",
        description="Read a scoped file.",
        resource_type="filesystem",
        scope={"root": str(tmp_path / "workspace")},
        parameters={
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    )

    with pytest.raises(ToolSecurityError, match="outside"):
        await validate_tool_target(
            definition, {"path": str(tmp_path / "workspace" / ".." / "secret")}
        )


@pytest.mark.asyncio
async def test_url_guard_blocks_local_private_and_unallowlisted_targets():
    async def resolver(host: str, port: int) -> list[str]:
        return ["127.0.0.1"]

    with pytest.raises(ToolSecurityError, match="allowlisted"):
        await validate_http_target("https://example.com/", [], resolver)
    with pytest.raises(ToolSecurityError, match="non-public"):
        await validate_http_target("https://example.com/", ["example.com"], resolver)
    with pytest.raises(ToolSecurityError, match="supported"):
        await validate_http_target("file:///etc/passwd", ["example.com"], resolver)


@pytest.mark.asyncio
async def test_url_guard_accepts_only_allowlisted_public_resolved_addresses():
    async def resolver(host: str, port: int) -> list[str]:
        assert host == "docs.example.com"
        return ["93.184.216.34"]

    result = await validate_http_target(
        "https://docs.example.com/page", ["docs.example.com"], resolver
    )
    assert result["resolved_addresses"] == ["93.184.216.34"]


@pytest.mark.asyncio
async def test_url_guard_requires_explicit_private_network_opt_in():
    async def resolver(host: str, port: int) -> list[str]:
        return ["10.4.5.6"]

    result = await validate_http_target(
        "https://internal.example.com/",
        ["internal.example.com"],
        resolver,
        allow_private_addresses=True,
    )
    assert result["resolved_addresses"] == ["10.4.5.6"]


def test_database_query_is_allowlisted_and_parameterized():
    result = build_read_only_query(
        {"tables": {"documents": ["id", "owner_id", "title"]}},
        {
            "table": "documents",
            "fields": ["id", "title"],
            "filters": {"owner_id": "user-1' OR 1=1"},
            "limit": 5,
        },
    )
    assert "OR 1=1" not in result["sql"]
    assert result["parameters"] == {"p0": "user-1' OR 1=1", "limit": 5}
    with pytest.raises(ToolSecurityError, match="not allowlisted"):
        build_read_only_query(
            {"tables": {"documents": ["id"]}}, {"table": "users", "fields": ["id"]}
        )


@pytest.mark.asyncio
async def test_tool_registry_scopes_and_authorizes_registered_schemas(tmp_path):
    engine = make_engine(f"sqlite+aiosqlite:///{tmp_path}/tools.db")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    async with sessions() as session:
        from gateshield.storage import ApplicationRecord

        session.add(ApplicationRecord(id="app-a", name="Application A"))
        await session.commit()
    registry = ToolRegistry(sessions)
    await registry.register(
        "app-a",
        ToolDefinition(
            name="read_record",
            description="Read one record.",
            resource_type="document",
            parameters={
                "type": "object",
                "properties": {"record_id": {"type": "string"}},
                "required": ["record_id"],
                "additionalProperties": False,
            },
        ),
    )
    authorizer = DeterministicToolAuthorizer(registry)

    allowed = await authorizer.authorize("app-a", "read_record", {"record_id": "r-1"})
    unknown = await authorizer.authorize("app-b", "read_record", {"record_id": "r-1"})
    invalid = await authorizer.authorize(
        "app-a", "read_record", {"record_id": "r-1", "sql": "DROP TABLE"}
    )

    assert allowed.decision is Decision.ALLOW
    assert unknown.decision is Decision.BLOCK
    assert invalid.decision is Decision.BLOCK
    await engine.dispose()


@pytest.mark.asyncio
async def test_agent_permissions_restrict_tools_and_exact_resources(tmp_path):
    engine = make_engine(f"sqlite+aiosqlite:///{tmp_path}/agent-tool-scope.db")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    async with sessions() as session:
        from gateshield.storage import ApplicationRecord

        session.add(ApplicationRecord(id="scoped-app", name="Scoped app"))
        await session.commit()
    registry = ToolRegistry(sessions)
    await registry.register(
        "scoped-app",
        ToolDefinition(
            name="read_document",
            description="Read a scoped document.",
            resource_type="document",
            scope={"agent_resource_argument": "document_id"},
            parameters={
                "type": "object",
                "properties": {"document_id": {"type": "string"}},
                "required": ["document_id"],
                "additionalProperties": False,
            },
        ),
    )
    authorizer = DeterministicToolAuthorizer(registry)
    identity = AgentIdentity(
        id="reader-agent",
        application_id="scoped-app",
        owner="team",
        role="reader",
        environment="test",
        allowed_tools=["read_document"],
        allowed_resources={"read_document": ["doc-1"]},
    )

    allowed = await authorizer.authorize(
        "scoped-app", "read_document", {"document_id": "doc-1"}, identity
    )
    denied = await authorizer.authorize(
        "scoped-app", "read_document", {"document_id": "doc-2"}, identity
    )
    assert allowed.decision is Decision.ALLOW
    assert denied.decision is Decision.BLOCK
    await engine.dispose()


@pytest.mark.asyncio
async def test_sensitive_tool_arguments_are_redacted_for_audit(tmp_path):
    from gateshield.tool_security import _redact_arguments

    value = "ghp_testsecret_12345678901234567890"
    masked = _redact_arguments({"query": f"token={value}", "credentials": {"password": "private"}})
    assert value not in str(masked)
    assert masked["credentials"] == "[REDACTED]"
