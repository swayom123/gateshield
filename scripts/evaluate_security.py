"""Run deterministic security evaluation on checked-in, synthetic fixtures only."""

from __future__ import annotations

import argparse
import asyncio
import json
import platform
from pathlib import Path
from typing import Any

from gateshield.domain import (
    AgentIdentity,
    AIRequest,
    DataClassification,
    Decision,
    ProviderType,
    SecurityContext,
    TrustLevel,
)
from gateshield.inspection import DeterministicInputInspector
from gateshield.policies import (
    DeterministicPolicyEngine,
    PolicyRepository,
    default_policy_definitions,
)
from gateshield.storage import ApplicationRecord, ensure_schema, make_engine, make_session_factory
from gateshield.tool_security import (
    DeterministicToolAuthorizer,
    ToolDefinition,
    ToolRegistry,
)

FIXTURE_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "security_eval_v1.json"


def rate(numerator: int, denominator: int) -> dict[str, int | float | None]:
    return {
        "numerator": numerator,
        "denominator": denominator,
        "rate": numerator / denominator if denominator else None,
    }


async def evaluate() -> dict[str, Any]:
    corpus = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    engine = make_engine("sqlite+aiosqlite:///:memory:")
    await ensure_schema(engine)
    sessions = make_session_factory(engine)
    async with sessions() as session:
        session.add(ApplicationRecord(id="eval-app", name="Synthetic evaluation"))
        await session.commit()
    repository = PolicyRepository(sessions)
    for definition in default_policy_definitions():
        await repository.ensure_default(definition)
    policy_engine = DeterministicPolicyEngine(repository)
    inspector = DeterministicInputInspector()
    injection_tp = injection_fp = injection_fn = injection_tn = 0
    secret_tp = secret_fp = secret_fn = secret_tn = 0
    policy_correct = 0
    per_case = []
    for case in corpus["cases"]:
        trust = TrustLevel(case["provenance"]) if case.get("provenance") else None
        request = AIRequest(
            application_id="eval-app",
            model="fixture-model",
            messages=[{"role": "user", "content": case["text"], "provenance": trust}],
        )
        context = SecurityContext(
            request_id=request.id,
            trace_id="eval-trace",
            application_id="eval-app",
            environment="evaluation",
            provider_type=ProviderType.EXTERNAL,
            data_classification=DataClassification.INTERNAL,
        )
        inspected = await inspector.inspect(request, context)
        has_injection = any("INJECTION_DETECTED" in f.finding_type for f in inspected.findings)
        has_secret = any(f.finding_type == "SECRET_DETECTED" for f in inspected.findings)
        injection_tp += bool(has_injection and case["injection"])
        injection_fp += bool(has_injection and not case["injection"])
        injection_fn += bool(not has_injection and case["injection"])
        injection_tn += bool(not has_injection and not case["injection"])
        secret_tp += bool(has_secret and case["secret"])
        secret_fp += bool(has_secret and not case["secret"])
        secret_fn += bool(not has_secret and case["secret"])
        secret_tn += bool(not has_secret and not case["secret"])
        context.prompt_injection_detected = has_injection
        context.secret_detected = has_secret
        decision = await policy_engine.evaluate(request, context)
        expected = Decision.BLOCK if case["injection"] or case["secret"] else Decision.ALLOW
        policy_correct += decision.decision is expected
        per_case.append(
            {
                "id": case["id"],
                "injection_detected": has_injection,
                "secret_detected": has_secret,
                "policy_decision": decision.decision.value,
                "expected_policy_decision": expected.value,
            }
        )

    registry = ToolRegistry(sessions)
    await registry.register(
        "eval-app",
        ToolDefinition(
            name="read_note",
            description="Read one synthetic note.",
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
    tool_correct = 0
    tool_rows = []
    for case in corpus["tool_cases"]:
        identity = AgentIdentity(
            id="eval-agent",
            application_id="eval-app",
            owner="fixture",
            role="reader",
            environment="evaluation",
            allowed_tools=["read_note"] if case["assigned"] else [],
            allowed_resources={"read_note": ["n-1"]} if case["assigned"] else {},
        )
        result = await authorizer.authorize("eval-app", case["tool"], case["arguments"], identity)
        actual = result.decision is Decision.ALLOW
        tool_correct += actual is case["authorized"]
        tool_rows.append(
            {"id": case["id"], "authorized": actual, "expected_authorized": case["authorized"]}
        )
    await engine.dispose()
    return {
        "fixture_set": corpus["fixture_set"],
        "fixture_version": corpus["version"],
        "methodology": (
            "Synthetic local text and tool arguments; deterministic input inspector, active "
            "built-in policies, and SQLite in-memory tool registry. No provider or external "
            "network calls."
        ),
        "environment": {"python": platform.python_version(), "platform": platform.platform()},
        "metrics": {
            "prompt_injection": {
                "true_positive_rate": rate(injection_tp, injection_tp + injection_fn),
                "false_positive_rate": rate(injection_fp, injection_fp + injection_tn),
                "true_positives": injection_tp,
                "false_positives": injection_fp,
                "false_negatives": injection_fn,
                "true_negatives": injection_tn,
            },
            "secret_detection": {
                "recall": rate(secret_tp, secret_tp + secret_fn),
                "false_positive_rate": rate(secret_fp, secret_fp + secret_tn),
                "true_positives": secret_tp,
                "false_positives": secret_fp,
                "false_negatives": secret_fn,
                "true_negatives": secret_tn,
            },
            "policy_enforcement": {
                "correct": policy_correct,
                "denominator": len(corpus["cases"]),
                "accuracy": rate(policy_correct, len(corpus["cases"])),
            },
            "tool_authorization": {
                "correct": tool_correct,
                "denominator": len(corpus["tool_cases"]),
                "accuracy": rate(tool_correct, len(corpus["tool_cases"])),
            },
        },
        "cases": per_case,
        "tool_cases": tool_rows,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="Write report JSON here; stdout otherwise.")
    args = parser.parse_args()
    report = asyncio.run(evaluate())
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")


if __name__ == "__main__":
    main()
