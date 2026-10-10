import pytest

from gateshield.domain import GatewayResponse, SecurityContext
from gateshield.output_inspection import (
    DeterministicOutputInspector,
    validate_response_format,
)


def make_context() -> SecurityContext:
    return SecurityContext(
        request_id="request-1",
        trace_id="trace-1",
        application_id="app-1",
        environment="test",
    )


@pytest.mark.asyncio
async def test_output_inspector_masks_secret_and_personal_identifiers():
    response = GatewayResponse.model_validate(
        {
            "id": "completion-1",
            "created": 1,
            "model": "local-test",
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": "token=ghp_12345678901234567890 contact alice@example.com",
                    }
                }
            ],
        }
    )
    context = make_context()

    result = await DeterministicOutputInspector().inspect(response, context)

    text = result.sanitized_response["choices"][0]["message"]["content"]
    assert "ghp_12345678901234567890" not in text
    assert "alice@example.com" not in text
    assert {finding.matched_signal for finding in result.findings} >= {
        "github_token",
        "email_address",
    }
    assert context.output_sensitive_data_detected
    assert all("12345678901234567890" not in str(finding.evidence) for finding in result.findings)


@pytest.mark.asyncio
async def test_output_inspector_checks_declared_json_schema():
    response = GatewayResponse.model_validate(
        {
            "id": "completion-1",
            "created": 1,
            "model": "local-test",
            "choices": [{"message": {"role": "assistant", "content": '{"count":"many"}'}}],
        }
    )
    response_format = {
        "type": "json_schema",
        "json_schema": {
            "name": "count",
            "schema": {
                "type": "object",
                "properties": {"count": {"type": "integer"}},
                "required": ["count"],
            },
        },
    }
    context = make_context()

    result = await DeterministicOutputInspector().inspect(response, context, response_format)

    assert result.structured_output_valid is False
    assert context.output_schema_invalid
    assert result.findings[0].finding_type == "INVALID_STRUCTURED_OUTPUT"


def test_schema_validation_rejects_remote_references_and_invalid_schemas():
    with pytest.raises(ValueError, match="references"):
        validate_response_format(
            {
                "type": "json_schema",
                "json_schema": {"schema": {"$ref": "https://example.invalid/schema"}},
            }
        )
    with pytest.raises(ValueError, match="invalid"):
        validate_response_format(
            {"type": "json_schema", "json_schema": {"schema": {"type": "not-a-type"}}}
        )
    with pytest.raises(ValueError, match="pattern constraints"):
        validate_response_format(
            {
                "type": "json_schema",
                "json_schema": {"schema": {"type": "string", "pattern": ".*"}},
            }
        )
