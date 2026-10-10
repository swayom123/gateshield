import pytest
from pydantic import ValidationError

from gateshield.domain import (
    AIRequest,
    DataClassification,
    Decision,
    ProviderType,
    SecurityContext,
)
from gateshield.policies import (
    DeterministicPolicyEngine,
    PolicyConditions,
    PolicyDefinition,
    PolicyMode,
    PolicyRepository,
    PolicyStatus,
)
from gateshield.storage import ensure_schema, make_engine, make_session_factory


def policy(
    effect: Decision = Decision.BLOCK,
    mode: PolicyMode = PolicyMode.ENFORCE,
    policy_id: str = "restricted-external",
) -> PolicyDefinition:
    return PolicyDefinition(
        id=policy_id,
        description="Restricted data must not use an external provider.",
        effect=effect,
        mode=mode,
        conditions=PolicyConditions(
            data_classification=DataClassification.RESTRICTED,
            provider_type=ProviderType.EXTERNAL,
        ),
    )


def request_context() -> tuple[AIRequest, SecurityContext]:
    request = AIRequest(
        application_id="app-one",
        model="approved-model",
        messages=[{"role": "user", "content": "hello"}],
    )
    context = SecurityContext(
        request_id=request.id,
        trace_id="trace-1",
        application_id=request.application_id,
        environment="test",
        data_classification=DataClassification.RESTRICTED,
        provider_type=ProviderType.EXTERNAL,
    )
    return request, context


@pytest.mark.asyncio
async def test_policy_mode_enforce_monitor_and_off(tmp_path):
    engine = make_engine(f"sqlite+aiosqlite:///{tmp_path}/modes.db")
    await ensure_schema(engine)
    repository = PolicyRepository(make_session_factory(engine))
    request, context = request_context()

    for definition in (
        policy(Decision.BLOCK, PolicyMode.ENFORCE, "enforced"),
        policy(Decision.BLOCK, PolicyMode.MONITOR, "monitored"),
        policy(Decision.BLOCK, PolicyMode.OFF, "disabled"),
    ):
        await repository.create_draft(definition, author="security-team")
        await repository.activate(definition.id)

    decision = await DeterministicPolicyEngine(repository).evaluate(request, context)
    assert decision.decision is Decision.BLOCK
    assert decision.matched_policies == ["enforced", "monitored"]
    assert decision.violations == ["monitor:monitored:BLOCK", "enforce:enforced:BLOCK"]

    await repository.retire("enforced")
    decision = await DeterministicPolicyEngine(repository).evaluate(request, context)
    assert decision.decision is Decision.ALLOW
    assert decision.matched_policies == ["monitored"]
    assert decision.violations == ["monitor:monitored:BLOCK"]
    await engine.dispose()


@pytest.mark.asyncio
async def test_versions_are_draft_until_activated_and_can_be_rolled_back(tmp_path):
    engine = make_engine(f"sqlite+aiosqlite:///{tmp_path}/versions.db")
    await ensure_schema(engine)
    repository = PolicyRepository(make_session_factory(engine))
    request, context = request_context()
    evaluator = DeterministicPolicyEngine(repository)

    await repository.create_draft(policy(), author="alice", changes=["initial policy"])
    await repository.activate("restricted-external")
    assert (await evaluator.evaluate(request, context)).decision is Decision.BLOCK

    allow = policy(Decision.ALLOW)
    version = await repository.revise(
        "restricted-external", allow, author="bob", changes=["temporary exception"]
    )
    assert version == 2
    assert (await evaluator.evaluate(request, context)).decision is Decision.BLOCK
    await repository.activate("restricted-external", version)
    assert (await evaluator.evaluate(request, context)).decision is Decision.ALLOW
    await repository.activate("restricted-external", 1)
    assert (await evaluator.evaluate(request, context)).decision is Decision.BLOCK

    history = await repository.version_history("restricted-external")
    assert [entry["version"] for entry in history] == [1, 2]
    assert history[0]["status"] == PolicyStatus.ACTIVE.value
    assert history[1]["status"] == PolicyStatus.RETIRED.value
    assert history[1]["author"] == "bob"
    await engine.dispose()


def test_policy_definition_rejects_unknown_or_empty_conditions():
    with pytest.raises(ValidationError):
        PolicyDefinition(
            id="bad-policy",
            description="No arbitrary condition fields.",
            effect=Decision.BLOCK,
            conditions={"message_contains": "anything"},
        )
    with pytest.raises(ValidationError):
        PolicyConditions()
