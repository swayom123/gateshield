# GateShield

GateShield is a Python security gateway for OpenAI-compatible model APIs. It applies deterministic request policies, inspects untrusted input and model output, validates declared JSON responses, and records sanitized request evidence.

## Why it exists

Applications often send prompts, retrieved content, and tool requests directly to a model provider. A gateway creates one enforceable point to inspect, route, record, and later authorize those interactions.

## Architecture

```text
AI application → input inspection → deterministic policy → configured provider
       ↑                                                   ↓
       └──── validated / redacted response ← output inspection
                           ↓
                    SQLite audit store
```

## Current capabilities

- OpenAI-compatible `POST /v1/chat/completions` forwarding.
- Provider selection through configuration, with no implicit provider fallback.
- Request and trace IDs returned in response headers.
- SQLite persistence for applications, requests, and security events.
- Validated exact-match policies with `ENFORCE`, `MONITOR`, and `OFF` modes.
- Draft/active/retired policy versions with explicit activation and rollback.
- Message segment provenance and deterministic prompt injection and credential checks.
- Bounded request body parsing, validated message roles, and versioned default block policies.
- Redacted request and response copies in audit storage.
- Deterministic output DLP for common credentials, email addresses, US SSNs, and valid payment card numbers.
- Versioned default output policies that redact sensitive findings or block invalid structured responses.
- Local `json_object` and Draft 2020-12 `json_schema` validation with schema size and structure limits.
- Output findings and sanitized response snapshots persisted without raw detected values.
- Application-scoped tool registry with canonical schemas, deterministic argument and resource checks, and authorization audit records.
- Provider tool proposals are checked against registry entries; unregistered or invalid calls are withheld.
- Filesystem traversal, SSRF target, and parameterized read-only database query guards for registered tool definitions.
- `GET /v1/tools` and `POST /v1/tools/authorize` endpoints; authorization does not execute the requested tool.
- Hashed agent credentials, application/environment binding, expiring sessions, per-agent tool/resource scopes, and deterministic session behavior signals.
- Agent enrollment, session, identity, and signal endpoints; enrollment requires a configured secret.
- Health endpoint with a database check.

Role-based console administration remains future work. Built-in active policies block deterministic prompt injection and input secret findings, redact detected output-sensitive data, block invalid declared structured output, and block invalid tool calls. Other activity is allowed unless an active `ENFORCE` policy matches.

## Quick start

Requires Python 3.12 or newer.

```bash
cd gateshield
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
cp .env.example .env
uvicorn gateshield.app:app --reload
```

Configure `GATESHIELD_PROVIDER_BASE_URL` to a trusted OpenAI-compatible server, such as a local inference server exposing `/v1/chat/completions`. Set `GATESHIELD_PROVIDER_API_KEY` only when required. Without a configured provider, chat requests return `503`.

Example request:

```bash
curl http://127.0.0.1:8000/v1/chat/completions \
  -H 'content-type: application/json' \
  -d '{"model":"local-model","messages":[{"role":"user","content":"Summarize this public document."}]}'
```

## Security model

Provider calls occur only after request validation, input inspection, and policy evaluation. `BLOCK` and `REQUIRE_APPROVAL` decisions prevent forwarding. Output policy evaluation happens before persistence or return; `BLOCK` and `REQUIRE_APPROVAL` withhold the provider response, while `REDACT` returns its sanitized form. If inspection or policy evaluation fails, the gateway withholds the response. Request and response snapshots are sanitized before storage; logs contain IDs and event names, not prompt content.

Do not treat the current deterministic detectors as complete protection. Applications must authenticate callers at a trusted ingress until gateway authentication is implemented.

## Development

```bash
pytest
ruff check .
mypy gateshield
python scripts/live_smoke.py
alembic upgrade head
```

The local smoke script starts GateShield and a small OpenAI-compatible test provider on loopback ports, sends a request through the HTTP gateway, and checks persistence and secret masking. It uses a temporary database and does not contact an external provider.

The schema can be initialized at startup for local development. Alembic migrations are the production schema-change path.

For policy authoring, use `PolicyDefinition` and `PolicyRepository` from `gateshield.policies`. Policy creation and activation are server-side operations; there is no unauthenticated policy administration endpoint.

Tool definitions can be added by trusted setup code through `ToolRegistry` in `gateshield.tool_security`. Applications should call `/v1/tools/authorize` immediately before executing any tool and must deny on errors or non-`ALLOW` decisions.

Configure `GATESHIELD_AGENT_ENROLLMENT_KEY` before enrolling agent credentials. See [agent security](docs/agent-security.md) for the enrollment and session flow.

## Limitations

- No end-user authentication, administrative RBAC, tenant isolation, or general key management. Agent tokens cover only registered agents.
- Pattern-based detection has limited coverage and can produce false positives.
- Output inspection buffers a response up to 1 MiB; streaming is not supported.
- JSON Schema pattern and reference keywords are rejected to bound validation behavior.
- No model allowlist or security-aware routing policy.
- Streaming is not supported.
- GateShield does not execute tool adapters; the integrating application must enforce authorization before execution and sandbox any adapter.
- URL validation does not perform requests or follow redirects; the integrating adapter must revalidate each redirect destination.
- Request-size checks rely on the declared `Content-Length`; deployments should also enforce a body limit at ingress.
- API credentials are passed to the configured provider but are never persisted by GateShield.
- No real external provider request was performed while building this foundation; use a trusted provider endpoint and credentials to verify that deployment-specific path.

## Roadmap

The remaining planned work is documented in [docs/roadmap.md](docs/roadmap.md), covering Phases 7–10: management console, advanced security, evaluation, and production hardening.
