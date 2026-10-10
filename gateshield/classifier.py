"""Optional semantic triage adapter. Its output is a signal, never an allow decision."""

import json
from typing import Any
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .domain import AIRequest
from .inspection import _text_leaves, resolve_trust
from .inspection import _redact_text


class ClassifierSignal(BaseModel):
    model_config = ConfigDict(extra="forbid")
    risk_score: int = Field(ge=0, le=100, strict=True)
    injection_likely: bool = Field(strict=True)


class SemanticClassifier:
    def __init__(self, endpoint: str | None, timeout_seconds: float, api_key: str = "") -> None:
        self.endpoint = endpoint
        self.timeout_seconds = timeout_seconds
        self.api_key = api_key

    async def classify(self, request: AIRequest) -> ClassifierSignal:
        if not self.endpoint:
            raise RuntimeError("Semantic classifier endpoint is not configured")
        parsed = urlsplit(self.endpoint)
        loopback = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        if parsed.scheme != "https" and not (parsed.scheme == "http" and loopback):
            raise RuntimeError("Classifier endpoint must use HTTPS, except for loopback development")
        if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise RuntimeError("Classifier endpoint URL contains unsupported components")
        segments: list[str] = []
        remaining_bytes = 128 * 1024
        for message in request.messages:
            trust = resolve_trust(message.role, message.provenance)
            for text, _ in _text_leaves(message.content):
                # Trusted system/application content is excluded from external triage input.
                if trust.value not in ("TRUSTED_SYSTEM", "TRUSTED_APPLICATION"):
                    scrubbed = _redact_text(text)
                    encoded = scrubbed.encode("utf-8")[:remaining_bytes]
                    if encoded:
                        segments.append(encoded.decode("utf-8", errors="ignore"))
                        remaining_bytes -= len(encoded)
                    if remaining_bytes <= 0:
                        break
            if remaining_bytes <= 0:
                break
        payload: dict[str, Any] = {"segments": segments[:256], "model": request.model}
        headers = {"authorization": f"Bearer {self.api_key}"} if self.api_key else None
        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            async with client.stream("POST", self.endpoint, json=payload, headers=headers) as response:
                response.raise_for_status()
                raw = bytearray()
                async for chunk in response.aiter_bytes():
                    raw.extend(chunk)
                    if len(raw) > 4096:
                        raise RuntimeError("Semantic classifier response exceeded the size limit")
            body = json.loads(raw)
        try:
            return ClassifierSignal.model_validate(body)
        except (ValidationError, TypeError, ValueError) as exc:
            raise RuntimeError("Semantic classifier response failed schema validation") from exc
