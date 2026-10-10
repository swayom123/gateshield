"""Fail-safe model approval and data-classification routing checks."""

import json
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError


class ModelRoute(BaseModel):
    model_config = ConfigDict(extra="forbid")
    provider_type: Literal["LOCAL", "EXTERNAL"]
    applications: list[str] = Field(default_factory=list, max_length=100)
    environments: list[str] = Field(default_factory=list, max_length=100)
    classifications: list[Literal["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"]] = Field(
        default_factory=list, max_length=4
    )


class RouteDecision(BaseModel):
    allowed: bool
    status: str
    reason: str
    expected_provider: str | None = None


def assess_model_route(
    *,
    model: str,
    application_id: str,
    environment: str,
    classification: str,
    provider_type: str,
    mode: str,
    routes_json: str,
) -> RouteDecision:
    try:
        raw: Any = json.loads(routes_json)
        if not isinstance(raw, dict):
            raise ValueError("Model route registry must be a JSON object")
        routes = {name: ModelRoute.model_validate(route) for name, route in raw.items()}
    except (ValueError, TypeError, ValidationError) as exc:
        return RouteDecision(
            allowed=False,
            status="CONFIG_ERROR",
            reason=f"Model route configuration is invalid: {type(exc).__name__}",
        )

    route = routes.get(model)
    mismatch: str | None = None
    if route is None:
        mismatch = "Model is not present in the approved route registry."
    elif route.provider_type != provider_type:
        mismatch = "Configured provider does not match the model's approved provider type."
    elif route.applications and application_id not in route.applications:
        mismatch = "Application is outside the model route scope."
    elif route.environments and environment not in route.environments:
        mismatch = "Environment is outside the model route scope."
    elif route.classifications and classification not in route.classifications:
        mismatch = "Data classification is outside the model route scope."

    restricted = classification == "RESTRICTED"
    if restricted and (
        route is None
        or route.provider_type != "LOCAL"
        or "RESTRICTED" not in route.classifications
        or mismatch is not None
    ):
        return RouteDecision(
            allowed=False,
            status="BLOCKED",
            reason="Restricted data requires an explicitly approved local model route.",
        )
    if mode == "OFF":
        return RouteDecision(
            allowed=True,
            status="OFF",
            reason="Model routing controls are off for non-restricted data.",
            expected_provider=route.provider_type if route else None,
        )
    if mismatch is None:
        return RouteDecision(
            allowed=True,
            status="APPROVED",
            reason="Model, provider, application, environment, and classification match the approved route.",
            expected_provider=route.provider_type if route else None,
        )
    if mode == "MONITOR":
        return RouteDecision(
            allowed=True,
            status="MONITOR_MISMATCH",
            reason=mismatch,
            expected_provider=route.provider_type if route else None,
        )
    return RouteDecision(
        allowed=False,
        status="BLOCKED",
        reason=mismatch,
        expected_provider=route.provider_type if route else None,
    )
