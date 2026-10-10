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
                  persisted audit store
```

## Current capabilities

- OpenAI-compatible `POST /v1/chat/completions` forwarding.
- Provider selection through configuration, with no implicit provider fallback.
- Request and trace IDs returned in response headers.
- SQLAlchemy persistence for applications, requests, security events, policies, tools, and agent records; SQLite for development and PostgreSQL for production.
- Validated exact-match policies with `ENFORCE`, `MONITOR`, and `OFF` modes.
- Draft/active/retired policy versions with explicit activation and rollback.
- Message segment provenance and deterministic prompt injection and credential checks.
- Bounded request body parsing, validated message roles, and versioned default block policies.
- Redacted request and response copies in audit storage.
- Deterministic output DLP for common credentials, email addresses, US SSNs, and valid payment card numbers.
- Optional US phone and IPv4 output detectors configured with `GATESHIELD_EXTRA_DLP_DETECTORS`.
- Optional semantic classifier in `OFF`, `MONITOR`, or `ENFORCE` mode; classifier output is a risk signal, and enforcement still passes through deterministic policies.
- Classification-aware model route controls; `RESTRICTED` data requires a configured `LOCAL` model route that explicitly allows the classification.
- Versioned default output policies that redact sensitive findings or block invalid structured responses.
- Local `json_object` and Draft 2020-12 `json_schema` validation with schema size and structure limits.
- Output findings and sanitized response snapshots persisted without raw detected values.
- Application-scoped tool registry with canonical schemas, deterministic argument and resource checks, and authorization audit records.
- Provider tool proposals are checked against registry entries; unregistered or invalid calls are withheld. High-risk proposals remain pending intents for the integrating application, which must call tool authorization before execution.
- Filesystem traversal, SSRF target, and parameterized read-only database query guards for registered tool definitions.
- `GET /v1/tools` and `POST /v1/tools/authorize` endpoints; authorization does not execute the requested tool.
- Expiring, single-use high-risk tool approvals bound to the originating request, agent/session, exact tool arguments and target, tool definition, active policies, and routing context.
- Hashed agent credentials, application/environment binding, expiring sessions, per-agent tool/resource scopes, and deterministic session behavior signals.
- Agent enrollment, session, identity, and signal endpoints; enrollment requires a configured secret.
- Health endpoint with a database check.
- Authenticated operations console at `/console` with role-protected request, event, policy, agent, tool, session, and settings views.
- Persisted overview counts, request inspectors, server-side filters, policy draft/version activation and rollback, and historical policy condition comparisons.

Built-in active policies block deterministic prompt injection and input secret findings, redact detected output-sensitive data, block invalid declared structured output, and block invalid tool calls. Other activity is allowed unless an active `ENFORCE` policy matches.

Configure console accounts with `GATESHIELD_CONSOLE_USERS` as a JSON object mapping usernames to password and role, for example `GATESHIELD_CONSOLE_USERS='{"admin":{"password":"replace-with-a-long-secret","role":"ADMIN"},"analyst":{"password":"another-long-secret","role":"ANALYST"}}'`. Passwords must be at least 16 characters. Supported roles are `ADMIN`, `SECURITY_ADMIN`, `POLICY_EDITOR`, `ANALYST`, `AUDITOR`, and `VIEWER`. The console uses HTTP Basic authentication; serve it over HTTPS outside local development. It is disabled until at least one valid account is configured. Model usage shows observed stored usage rather than a model allowlist.

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

For model routing, set `GATESHIELD_MODEL_ROUTING_MODE=ENFORCE` and configure `GATESHIELD_MODEL_ROUTES_JSON` as a model-keyed JSON object. Each entry has `provider_type` (`LOCAL` or `EXTERNAL`) and optional `applications`, `environments`, and `classifications` lists. The configured provider type must match the route. `GATESHIELD_DEFAULT_DATA_CLASSIFICATION=RESTRICTED` is an operator setting; the request body cannot lower it. Restricted data is denied unless its route explicitly uses `LOCAL` and includes `RESTRICTED` in `classifications`.

An optional semantic classifier requires `GATESHIELD_SEMANTIC_CLASSIFIER_URL` and `GATESHIELD_SEMANTIC_CLASSIFIER_MODE`. The endpoint accepts a JSON object with redacted untrusted `segments` and `model`, and must return only `{"risk_score":0,"injection_likely":false}` fields with a 0–100 integer score. `ENFORCE` fails closed if the classifier is unavailable and escalates high-confidence injection signals through active deterministic injection policies. Requests are sent only to the explicitly configured endpoint; inspect its data handling before enabling it. `GATESHIELD_EXTRA_DLP_DETECTORS` accepts a JSON array containing `US_PHONE` and/or `IPV4`. Scoped tool approvals require `GATESHIELD_APPROVAL_SIGNING_KEY` with at least 32 characters and an authenticated `ADMIN` or `SECURITY_ADMIN` approver.

Example request:

```bash
curl http://127.0.0.1:8000/v1/chat/completions \
  -H 'content-type: application/json' \
  -d '{"model":"local-model","messages":[{"role":"user","content":"Summarize this public document."}]}'
```

## Security model

Provider calls occur only after request validation, input inspection, and policy evaluation. `BLOCK` and `REQUIRE_APPROVAL` decisions prevent forwarding. Output policy evaluation happens before persistence or return; `BLOCK` and `REQUIRE_APPROVAL` withhold the provider response, while `REDACT` returns its sanitized form. If inspection or policy evaluation fails, the gateway withholds the response. Request and response snapshots are sanitized before storage; logs contain IDs and event names, not prompt content.

Do not treat the current deterministic detectors as complete protection. Applications must authenticate callers at a trusted ingress; agent tokens cover registered agent calls, and console credentials protect only `/console`.

## Development

```bash
pytest
ruff check .
mypy gateshield
python scripts/live_smoke.py
alembic upgrade head
```

The local smoke script starts GateShield and a small OpenAI-compatible test provider on loopback ports, sends a request through the HTTP gateway, and checks persistence and secret masking. It uses a temporary database and does not contact an external provider.

Run the deterministic local security evaluation with:

```bash
python scripts/evaluate_security.py
python scripts/benchmark_security.py --iterations 100
```

The evaluator uses the versioned synthetic corpus in `fixtures/security_eval_v1.json`, an in-memory SQLite database, and no provider or external network calls. Its JSON report includes fixture version, environment, methodology, per-case outcomes, and denominators. The benchmark uses in-memory records and a loopback-only stub provider; its provider timing is not representative of an upstream service. Store analyst review labels using the shape in `fixtures/analyst_feedback.schema.json`; labels are not fed into detectors or policies.

The schema can be initialized at startup for local development. Alembic migrations are the production schema-change path.

For production deployment, use PostgreSQL, run Alembic migrations as a release step, and probe `/ready` before routing traffic. `/health` checks process/database liveness; `/ready` also requires a configured provider. See [production operations](docs/production-operations.md) for container, backup, restore, retention, and key rotation procedures. Production settings reject SQLite, full-content logging, missing HTTPS provider configuration, weak or missing console accounts, and invalid route/DLP settings.

OpenTelemetry tracing is optional. Install with `pip install -e '.[observability]'`, then set `GATESHIELD_OPENTELEMETRY_ENABLED=true` and `GATESHIELD_OPENTELEMETRY_ENDPOINT` to an OTLP/HTTP trace endpoint. GateShield traces HTTP requests and inspection, policy, provider, and tool stages with request/trace correlation. It does not attach message content, tool arguments, secrets, or provider responses to spans. A host process that already configured an OpenTelemetry provider retains control of its exporter and lifecycle.

For policy authoring, use `PolicyDefinition` and `PolicyRepository` from `gateshield.policies`. Policy creation and activation are server-side operations; there is no unauthenticated policy administration endpoint.

Tool definitions can be added by trusted setup code through `ToolRegistry` in `gateshield.tool_security`. Applications should call `/v1/tools/authorize` immediately before executing any tool and must deny on errors or non-`ALLOW` decisions. A high-risk authorization returns `REQUIRE_APPROVAL` and an `approval_id`; after an `ADMIN` or `SECURITY_ADMIN` grants it in the console, retry the same request with that ID. GateShield consumes the approval once and only then returns `ALLOW`.

Configure `GATESHIELD_AGENT_ENROLLMENT_KEY` before enrolling agent credentials. See [agent security](docs/agent-security.md) for the enrollment and session flow.

## Limitations

- No general end-user authentication, tenant isolation, or full key management. Agent tokens cover only registered agents.
- Pattern-based detection has limited coverage and can produce false positives.
- Output inspection buffers a response up to 1 MiB; streaming is not supported.
- JSON Schema pattern and reference keywords are rejected to bound validation behavior.
- Model route enforcement is opt-in, uses the single configured provider adapter, and requires operators to maintain the route JSON.
- Classifier enforcement depends on an operator-managed classifier endpoint and active deterministic policies. Classifier output cannot grant an action.
- Approval records store only keyed scope hashes and sanitized arguments; approvers must review the displayed action before granting it.
- Streaming is not supported.
- GateShield does not execute tool adapters; the integrating application must enforce authorization before execution and sandbox any adapter.
- URL validation does not perform requests or follow redirects; the integrating adapter must revalidate each redirect destination.
- Request-size checks rely on the declared `Content-Length`; deployments should also enforce a body limit at ingress.
- API credentials are passed to the configured provider but are never persisted by GateShield.
- No real external provider request was performed while building this foundation; use a trusted provider endpoint and credentials to verify that deployment-specific path.

## Roadmap

The remaining planned work is documented in [docs/roadmap.md](docs/roadmap.md), covering Phases 7–10: management console, advanced security, evaluation, and production hardening.
