from typing import Any, Protocol

import httpx


class ModelProvider(Protocol):
    provider_name: str

    async def complete(self, payload: dict[str, Any]) -> dict[str, Any]: ...


class OpenAICompatibleProvider:
    provider_name = "openai-compatible"

    def __init__(self, base_url: str, api_key: str = "", timeout_seconds: float = 30) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds

    async def complete(self, payload: dict[str, Any]) -> dict[str, Any]:
        headers = {"content-type": "application/json"}
        if self.api_key:
            headers["authorization"] = f"Bearer {self.api_key}"
        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            response = await client.post(
                f"{self.base_url}/chat/completions", json=payload, headers=headers
            )
            response.raise_for_status()
            body = response.json()
            if not isinstance(body, dict) or not isinstance(body.get("choices"), list):
                raise ValueError("Provider returned an invalid chat completion")
            return body
