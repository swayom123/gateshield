import base64
import binascii
import html
import re
import unicodedata
from collections.abc import Iterator
from typing import Any
from urllib.parse import unquote

from .domain import (
    AIRequest,
    InputFinding,
    InputInspectionResult,
    MessageProvenance,
    RiskLevel,
    SecurityContext,
    TrustLevel,
)

INJECTION_SIGNALS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "instruction_override",
        re.compile(
            r"\b(?:ignore|disregard|forget|override)\b.{0,80}"
            r"\b(?:previous|prior|above|all|system|developer|safety)?\s*instructions?\b",
            re.IGNORECASE,
        ),
    ),
    (
        "system_prompt_disclosure",
        re.compile(
            r"\b(?:reveal|show|print|repeat|expose)\b.{0,60}"
            r"\b(?:the\s+)?(?:system|developer|hidden)\s+(?:prompt|instructions?)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "instruction_boundary_override",
        re.compile(
            r"(?:</\s*(?:system|developer)\s*>|<<\s*SYS\s*>>|\[\s*SYSTEM\s*\])", re.IGNORECASE
        ),
    ),
)
BASE64_CANDIDATE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/])")

SECRET_SIGNALS: tuple[tuple[str, re.Pattern[str], int], ...] = (
    (
        "private_key",
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
            r"[\s\S]{1,12000}?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
        ),
        0,
    ),
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"), 0),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"), 0),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), 0),
    ("bearer_token", re.compile(r"(?i)\bBearer\s+([A-Za-z0-9._~+/=-]{12,})"), 1),
    (
        "credential_assignment",
        re.compile(
            r"(?i)\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|password|secret)"
            r"\s*[:=]\s*['\"]?([^\s,;\"']{4,})"
        ),
        1,
    ),
    (
        "url_password",
        re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^:/\s]+:([^@/\s]{4,})@"),
        1,
    ),
)

UNTRUSTED_LEVELS = {
    TrustLevel.USER_CONTROLLED,
    TrustLevel.EXTERNAL_RETRIEVAL,
    TrustLevel.TOOL_OUTPUT,
    TrustLevel.UNKNOWN,
}


def resolve_trust(role: str, declared: TrustLevel | None) -> TrustLevel:
    role_default = {
        "system": TrustLevel.UNKNOWN,
        "developer": TrustLevel.UNKNOWN,
        "user": TrustLevel.USER_CONTROLLED,
        "tool": TrustLevel.TOOL_OUTPUT,
        "assistant": TrustLevel.UNKNOWN,
    }.get(role, TrustLevel.UNKNOWN)
    if declared in UNTRUSTED_LEVELS:
        return declared
    # Request supplied metadata cannot elevate content to either trusted level.
    return role_default


def _text_leaves(value: Any, path: str = "content") -> Iterator[tuple[str, str]]:
    if isinstance(value, str):
        yield value, path
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _text_leaves(child, f"{path}[{index}]")
    elif isinstance(value, dict):
        for key, child in value.items():
            name = str(key)
            safe_name = (
                name
                if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,31}", name)
                and not re.search(r"(?i)(secret|token|password|credential|api[_-]?key)", name)
                else "<field>"
            )
            yield from _text_leaves(child, f"{path}.{safe_name}")


def _mask(value: str) -> str:
    if len(value) <= 8:
        return "[REDACTED]"
    return f"{value[:4]}...{value[-4:]}"


def _redact_text(text: str) -> str:
    output = text
    for _, pattern, secret_group in SECRET_SIGNALS:

        def replace(match: re.Match[str], secret_group: int = secret_group) -> str:
            secret = match.group(secret_group) if secret_group else match.group(0)
            if secret_group:
                return match.group(0).replace(secret, _mask(secret), 1)
            return _mask(secret)

        output = pattern.sub(replace, output)
    return output


def _direct_injection_matches(text: str) -> Iterator[tuple[str, str]]:
    for signal_id, pattern in INJECTION_SIGNALS:
        match = pattern.search(text)
        if match:
            yield signal_id, match.group(0)[:160]


def _injection_matches(text: str) -> Iterator[tuple[str, str]]:
    normalized = unicodedata.normalize("NFKC", html.unescape(unquote(text)))
    normalized = "".join(
        char for char in normalized
        if char not in "\u200b\u200c\u200d\u2060\ufeff\ufe0e\ufe0f"
    )
    seen: set[str] = set()
    for signal_id, excerpt in _direct_injection_matches(normalized):
        if signal_id not in seen:
            seen.add(signal_id)
            yield signal_id, excerpt

    for candidate_match in BASE64_CANDIDATE.finditer(normalized):
        candidate = candidate_match.group(0)
        try:
            decoded_bytes = base64.b64decode(candidate, validate=True)
            decoded = decoded_bytes.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):
            continue
        if not all(char.isprintable() or char in "\r\n\t" for char in decoded):
            continue
        for signal_id, _ in _direct_injection_matches(decoded):
            encoded_signal = f"encoded_{signal_id}"
            if encoded_signal not in seen:
                seen.add(encoded_signal)
                yield encoded_signal, "[encoded instruction detected]"


class DeterministicInputInspector:
    """Scans untrusted request text using bounded, deterministic patterns."""

    async def inspect(self, request: AIRequest, context: SecurityContext) -> InputInspectionResult:
        provenance: list[MessageProvenance] = []
        findings: list[InputFinding] = []

        for message_index, message in enumerate(request.messages):
            trust = resolve_trust(message.role, message.provenance)
            source = message.source or message.role
            for text, segment_path in _text_leaves(message.content):
                provenance.append(
                    MessageProvenance(
                        message_index=message_index,
                        segment_path=segment_path,
                        role=message.role,
                        source=source,
                        trust_level=trust,
                    )
                )
                if trust in (TrustLevel.TRUSTED_SYSTEM, TrustLevel.TRUSTED_APPLICATION):
                    continue

                injection_kind = (
                    "INDIRECT_INJECTION_DETECTED"
                    if trust in (TrustLevel.EXTERNAL_RETRIEVAL, TrustLevel.TOOL_OUTPUT)
                    else "PROMPT_INJECTION_DETECTED"
                )
                for signal_id, excerpt in _injection_matches(text):
                    findings.append(
                        InputFinding(
                            finding_type=injection_kind,
                            severity=RiskLevel.HIGH,
                            message_index=message_index,
                            segment_path=segment_path,
                            source=_redact_text(source),
                            trust_level=trust,
                            matched_signal=signal_id,
                            evidence={"excerpt": _redact_text(excerpt)},
                        )
                    )

                secret_spans: set[tuple[int, int]] = set()
                for signal_id, pattern, secret_group in SECRET_SIGNALS:
                    for match in pattern.finditer(text):
                        secret = match.group(secret_group) if secret_group else match.group(0)
                        span = match.span(secret_group) if secret_group else match.span()
                        if span in secret_spans:
                            continue
                        secret_spans.add(span)
                        masked = _mask(secret)
                        findings.append(
                            InputFinding(
                                finding_type="SECRET_DETECTED",
                                severity=RiskLevel.HIGH,
                                message_index=message_index,
                                segment_path=segment_path,
                                source=_redact_text(source),
                                trust_level=trust,
                                matched_signal=signal_id,
                                evidence={"masked_value": masked},
                            )
                        )

        return InputInspectionResult(provenance=provenance, findings=findings)
