"""Preview or apply deletion of request records older than an explicit cutoff."""

from __future__ import annotations

import argparse
import asyncio
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import delete, func, select

from gateshield.config import get_settings
from gateshield.storage import (
    BehaviorSignalRecord,
    RequestRecord,
    SecurityEventRecord,
    ToolInvocationRecord,
    make_engine,
    make_session_factory,
)


def parse_cutoff(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise argparse.ArgumentTypeError("cutoff must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise argparse.ArgumentTypeError("cutoff must include a timezone")
    return parsed.astimezone(UTC)


async def expire(cutoff: datetime, apply: bool) -> dict[str, Any]:
    settings = get_settings()
    engine = make_engine(
        settings.database_url,
        pool_size=settings.database_pool_size,
        max_overflow=settings.database_max_overflow,
    )
    factory = make_session_factory(engine)
    counts: dict[str, int] = {}
    try:
        async with factory() as session, session.begin():
            old_request_ids = select(RequestRecord.id).where(RequestRecord.started_at < cutoff)
            statements = {
                "security_events": delete(SecurityEventRecord).where(
                    SecurityEventRecord.request_id.in_(old_request_ids)
                ),
                "tool_invocations": delete(ToolInvocationRecord).where(
                    ToolInvocationRecord.request_id.in_(old_request_ids)
                ),
                "behavior_signals": delete(BehaviorSignalRecord).where(
                    BehaviorSignalRecord.request_id.in_(old_request_ids)
                ),
                "requests": delete(RequestRecord).where(RequestRecord.started_at < cutoff),
            }
            for name, statement in statements.items():
                if apply:
                    result = await session.execute(statement)
                    counts[name] = result.rowcount or 0
                else:
                    table = {
                        "security_events": SecurityEventRecord,
                        "tool_invocations": ToolInvocationRecord,
                        "behavior_signals": BehaviorSignalRecord,
                        "requests": RequestRecord,
                    }[name]
                    count_query = (
                        select(func.count())
                        .select_from(table)
                        .where(table.request_id.in_(old_request_ids))
                        if name != "requests"
                        else select(func.count())
                        .select_from(table)
                        .where(table.started_at < cutoff)
                    )
                    counts[name] = int((await session.scalar(count_query)) or 0)
    finally:
        await engine.dispose()
    return {
        "mode": "applied" if apply else "preview",
        "cutoff": cutoff.isoformat(),
        "counts": counts,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--before", required=True, type=parse_cutoff, help="ISO-8601 cutoff with timezone"
    )
    parser.add_argument(
        "--apply", action="store_true", help="Commit deletion; default reports counts only"
    )
    args = parser.parse_args()
    import json

    print(json.dumps(asyncio.run(expire(args.before, args.apply)), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
