import json
from functools import lru_cache
from typing import Literal

from pydantic import AliasChoices, Field, SecretStr, ValidationError, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from .routing import ModelRoute


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="GATESHIELD_", env_file=".env", extra="ignore", populate_by_name=True
    )

    environment: str = "development"
    database_url: str = "sqlite+aiosqlite:///./gateshield.db"
    provider_base_url: str | None = None
    provider_type: Literal["EXTERNAL", "LOCAL"] = "EXTERNAL"
    provider_api_key: SecretStr = SecretStr("")
    agent_enrollment_key: SecretStr | None = None
    agent_session_ttl_minutes: int = Field(default=30, gt=0, le=1440)
    provider_timeout_seconds: float = Field(default=30, gt=0, le=300)
    logging_mode: Literal["METADATA_ONLY", "REDACTED_CONTENT", "FULL_CONTENT"] = "REDACTED_CONTENT"
    application_id: str = "local-development"
    application_name: str = "Local Development"
    max_request_bytes: int = Field(default=1_048_576, gt=0, le=20_000_000)
    console_users_json: str = Field(
        default="{}",
        validation_alias=AliasChoices("GATESHIELD_CONSOLE_USERS", "GATESHIELD_CONSOLE_USERS_JSON"),
    )
    default_data_classification: Literal["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"] = (
        "INTERNAL"
    )
    model_routing_mode: Literal["OFF", "MONITOR", "ENFORCE"] = "OFF"
    model_routes_json: str = "{}"
    semantic_classifier_mode: Literal["OFF", "MONITOR", "ENFORCE"] = "OFF"
    semantic_classifier_url: str | None = None
    semantic_classifier_api_key: SecretStr = SecretStr("")
    semantic_classifier_timeout_seconds: float = Field(default=5, gt=0, le=30)
    semantic_classifier_enforce_threshold: int = Field(default=85, ge=1, le=100)
    extra_dlp_detectors_json: str = Field(
        default="[]",
        validation_alias=AliasChoices(
            "GATESHIELD_EXTRA_DLP_DETECTORS", "GATESHIELD_EXTRA_DLP_DETECTORS_JSON"
        ),
    )
    approval_signing_key: SecretStr | None = None
    approval_ttl_minutes: int = Field(default=15, ge=1, le=1440)
    database_pool_size: int = Field(default=10, ge=1, le=100)
    database_max_overflow: int = Field(default=20, ge=0, le=200)
    opentelemetry_enabled: bool = False
    opentelemetry_endpoint: str | None = None
    opentelemetry_service_name: str = "gateshield"

    @model_validator(mode="after")
    def validate_deployment_settings(self) -> "Settings":
        try:
            routes = json.loads(self.model_routes_json)
            if not isinstance(routes, dict):
                raise ValueError("Model route registry must be a JSON object")
            for route in routes.values():
                ModelRoute.model_validate(route)
            detectors = json.loads(self.extra_dlp_detectors_json)
            if not isinstance(detectors, list) or any(
                name not in {"US_PHONE", "IPV4"} for name in detectors
            ):
                raise ValueError("Extra DLP detectors must be US_PHONE or IPV4")
        except (ValueError, TypeError, ValidationError) as exc:
            raise ValueError("Model route or extra DLP detector configuration is invalid") from exc
        if self.semantic_classifier_mode != "OFF" and not self.semantic_classifier_url:
            raise ValueError("Classifier URL is required when classifier mode is enabled")
        if self.opentelemetry_enabled and not self.opentelemetry_endpoint:
            raise ValueError("OTLP endpoint is required when OpenTelemetry is enabled")
        if self.opentelemetry_endpoint and not self.opentelemetry_endpoint.startswith(
            ("http://", "https://")
        ):
            raise ValueError("OTLP endpoint must use HTTP or HTTPS")
        if self.environment == "production":
            if self.application_id == "local-development":
                raise ValueError("Production requires an explicit application ID")
            if not self.database_url.startswith("postgresql+asyncpg://"):
                raise ValueError("Production requires a PostgreSQL asyncpg database URL")
            if self.logging_mode == "FULL_CONTENT":
                raise ValueError("FULL_CONTENT logging is prohibited in production")
            if self.provider_base_url is None:
                raise ValueError("Production requires GATESHIELD_PROVIDER_BASE_URL")
            if not self.provider_base_url.startswith("https://"):
                raise ValueError("Production provider URL must use HTTPS")
            if self.semantic_classifier_url and not self.semantic_classifier_url.startswith(
                "https://"
            ):
                raise ValueError("Production classifier URL must use HTTPS")
            try:
                users = json.loads(self.console_users_json)
            except ValueError as exc:
                raise ValueError("Production console users must be valid JSON") from exc
            if not isinstance(users, dict) or not users:
                raise ValueError("Production requires at least one console account")
            valid_roles = {
                "ADMIN",
                "SECURITY_ADMIN",
                "POLICY_EDITOR",
                "ANALYST",
                "AUDITOR",
                "VIEWER",
            }
            if any(
                not isinstance(user, dict)
                or not isinstance(user.get("password"), str)
                or len(user["password"]) < 16
                or user.get("role") not in valid_roles
                for user in users.values()
            ):
                raise ValueError(
                    "Production console accounts need 16+ character passwords and valid roles"
                )
        if (
            self.environment == "production"
            and self.agent_enrollment_key is not None
            and len(self.agent_enrollment_key.get_secret_value()) < 32
        ):
            raise ValueError("Production agent enrollment key must be at least 32 characters")
        if (
            self.environment == "production"
            and self.approval_signing_key is not None
            and len(self.approval_signing_key.get_secret_value()) < 32
        ):
            raise ValueError("Production approval signing key must be at least 32 characters")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
