from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="GATESHIELD_", env_file=".env", extra="ignore")

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


@lru_cache
def get_settings() -> Settings:
    return Settings()
