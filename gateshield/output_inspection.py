import json
import re
from collections.abc import Iterator
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError

from .domain import (
    GatewayResponse,
    OutputFinding,
    OutputInspectionResult,
    RiskLevel,
    SecurityContext,
)
from .inspection import SECRET_SIGNALS, _mask

MAX_SCHEMA_BYTES = 32_768
MAX_SCHEMA_NODES = 10_000
MAX_SCHEMA_DEPTH = 32
MAX_STRUCTURED_OUTPUT_BYTES = 1_048_576
EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
SSN = re.compile(r"\b(?!000|666|9\d\d)\d{3}[- ]?(?!00)\d{2}[- ]?(?!0000)\d{4}\b")
CARD = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
FORBIDDEN_SCHEMA_KEYS = {"$ref", "$dynamicRef", "$recursiveRef"}
UNBOUNDED_SCHEMA_KEYS = {"pattern", "patternProperties"}


def validate_response_format(response_format: Any) -> None:
    """Reject invalid or remotely-referencing schemas before any provider call."""
    if response_format is None:
        return
    if not isinstance(response_format, dict):
        raise ValueError("response_format must be an object")
    format_type = response_format.get("type")
    if format_type == "json_object":
        return
    if format_type != "json_schema":
        raise ValueError("response_format type must be json_object or json_schema")
    descriptor = response_format.get("json_schema")
    schema = descriptor.get("schema") if isinstance(descriptor, dict) else None
    if not isinstance(schema, dict):
        raise ValueError("json_schema.schema must be an object")
    if len(json.dumps(schema, separators=(",", ":")).encode()) > MAX_SCHEMA_BYTES:
        raise ValueError("JSON schema exceeds the configured size limit")
    _validate_schema_tree(schema)
    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError as exc:
        raise ValueError("JSON schema is invalid") from exc


def _validate_schema_tree(schema: dict[str, Any]) -> None:
    pending: list[tuple[Any, int]] = [(schema, 1)]
    nodes = 0
    while pending:
        value, depth = pending.pop()
        nodes += 1
        if nodes > MAX_SCHEMA_NODES or depth > MAX_SCHEMA_DEPTH:
            raise ValueError("JSON schema exceeds structural limits")
        if isinstance(value, dict):
            if FORBIDDEN_SCHEMA_KEYS.intersection(value):
                raise ValueError("JSON schema references are not supported")
            if UNBOUNDED_SCHEMA_KEYS.intersection(value):
                raise ValueError("JSON schema pattern constraints are not supported")
            pending.extend((child, depth + 1) for child in value.values())
        elif isinstance(value, list):
            pending.extend((child, depth + 1) for child in value)


def _text_locations(value: Any, path: str = "response") -> Iterator[tuple[str, str]]:
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _text_locations(child, f"{path}[{index}]")
    elif isinstance(value, dict):
        for key, child in value.items():
            yield from _text_locations(child, f"{path}.{key}")


def _has_luhn_checksum(value: str) -> bool:
    digits = [int(char) for char in value if char.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def _redact_text(text: str) -> tuple[str, list[tuple[str, str]]]:
    output = text
    detected: list[tuple[str, str]] = []
    detectors = [(name, pattern, group) for name, pattern, group in SECRET_SIGNALS]
    detectors.extend([("email_address", EMAIL, 0), ("us_ssn", SSN, 0)])
    for name, pattern, group in detectors:

        def replace(match: re.Match[str], name: str = name, group: int = group) -> str:
            value = match.group(group) if group else match.group(0)
            detected.append((name, value))
            masked = _mask(value)
            if group:
                return match.group(0).replace(value, masked, 1)
            return masked

        output = pattern.sub(replace, output)

    def replace_card(match: re.Match[str]) -> str:
        value = match.group(0)
        if _has_luhn_checksum(value):
            detected.append(("payment_card", value))
            return _mask(re.sub(r"\D", "", value))
        return value

    return CARD.sub(replace_card, output), detected


class DeterministicOutputInspector:
    async def inspect(
        self,
        response: GatewayResponse,
        context: SecurityContext,
        response_format: Any = None,
    ) -> OutputInspectionResult:
        sanitized = response.model_dump(mode="json", exclude_none=True)
        if len(json.dumps(sanitized, separators=(",", ":")).encode()) > MAX_STRUCTURED_OUTPUT_BYTES:
            raise ValueError("Upstream response exceeds the inspection size limit")
        findings: list[OutputFinding] = []
        for location, text in _text_locations(sanitized):
            _, detected = _redact_text(text)
            for detector, value in detected:
                findings.append(
                    OutputFinding(
                        finding_type="OUTPUT_SENSITIVE_DATA_DETECTED",
                        severity=RiskLevel.HIGH,
                        location=location,
                        matched_signal=detector,
                        evidence={"masked_value": _mask(value)},
                    )
                )
        sanitized = _redact_tree(sanitized)
        structured_valid: bool | None = None
        validation_error = None
        if response_format is not None:
            structured_valid, validation_error = _validate_response_body(sanitized, response_format)
            if not structured_valid:
                findings.append(
                    OutputFinding(
                        finding_type="INVALID_STRUCTURED_OUTPUT",
                        severity=RiskLevel.HIGH,
                        location="choices[*].message.content",
                        matched_signal=(
                            "json_schema_validation"
                            if response_format.get("type") == "json_schema"
                            else "json_parse"
                        ),
                        evidence={
                            "reason": validation_error or "Output did not match declared format."
                        },
                    )
                )
        context.output_sensitive_data_detected = any(
            finding.finding_type == "OUTPUT_SENSITIVE_DATA_DETECTED" for finding in findings
        )
        context.output_schema_invalid = structured_valid is False
        if findings:
            context.risk_level = RiskLevel.HIGH
        return OutputInspectionResult(
            findings=findings,
            sanitized_response=sanitized,
            structured_output_valid=structured_valid,
            validation_error=validation_error,
        )


def _redact_tree(value: Any) -> Any:
    if isinstance(value, str):
        return _redact_text(value)[0]
    if isinstance(value, list):
        return [_redact_tree(item) for item in value]
    if isinstance(value, dict):
        return {key: _redact_tree(item) for key, item in value.items()}
    return value


def _validate_response_body(
    response: dict[str, Any], response_format: dict[str, Any]
) -> tuple[bool, str | None]:
    choices = response.get("choices")
    if not isinstance(choices, list) or not choices:
        return False, "Response has no choices to validate."
    for choice in choices:
        message = choice.get("message") if isinstance(choice, dict) else None
        content = message.get("content") if isinstance(message, dict) else None
        if not isinstance(content, str):
            return False, "Structured response content must be a JSON string."
        if len(content.encode()) > MAX_STRUCTURED_OUTPUT_BYTES:
            return False, "Structured response content exceeds the validation size limit."
        try:
            instance = json.loads(content)
        except (ValueError, TypeError):
            return False, "Response content is not valid JSON."
        if response_format.get("type") == "json_schema":
            descriptor = response_format.get("json_schema", {})
            schema = descriptor.get("schema", {}) if isinstance(descriptor, dict) else {}
            errors = list(Draft202012Validator(schema).iter_errors(instance))
            if errors:
                return False, "Response JSON does not match the declared schema."
    return True, None
