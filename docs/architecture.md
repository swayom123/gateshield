# Architecture

GateShield is a modular monolith. The FastAPI application owns the request lifecycle and delegates model calls through `ModelProvider`. SQLAlchemy persists applications, requests, and security events. Domain models are independent of HTTP and storage.

## Request lifecycle

1. Assign request and trace IDs.
2. Validate the OpenAI-compatible body and request-size declaration.
3. Resolve the configured application record and security context.
4. Resolve provenance for each nested message text segment, normalize common encoding obfuscations for inspection, optionally collect a semantic triage signal, then load active, versioned deterministic policies.
5. Deny on `BLOCK`, `REQUIRE_APPROVAL`, detected prompt injection/secrets under built-in policies, or unsupported effects; inspection and policy errors deny forwarding.
6. Check model, provider, application, environment, and configured data classification against model routes. Restricted data requires an explicitly allowed local route. Call only the configured provider adapter.
7. Validate the completion response and inspect output for sensitive data and declared JSON constraints.
8. Evaluate output findings with deterministic policies; block, redact, or pass according to the active policy.
9. Persist sanitized request/response snapshots and security events.
10. Return the permitted response with GateShield IDs.

If the audit write fails after upstream execution, GateShield returns an error and withholds the completion. This can cause a caller retry; idempotency is a later concern.

## Boundaries

- The application is responsible for authenticating its end users until gateway authentication exists.
- GateShield uses message role as a conservative baseline and preserves per-segment provenance. Caller metadata may lower trust but cannot promote content into a trusted level.
- The upstream provider is an explicit configuration boundary. An absent or failed provider never causes direct client access or a fallback route.
- GateShield does not execute tool adapters; external executors must require a successful authorization result.
- Requests without a matching `ENFORCE` policy can pass; deployments must configure policies for their risk requirements.

## Policy evaluation

Policy definitions use typed request/security context fields. Exact fields use equality; `semantic_risk_min` uses a numeric lower bound. `ENFORCE` effects participate in a deny-overrides decision; `MONITOR` matches are recorded without changing the result; `OFF` policies are skipped. Policies are drafts until explicitly activated. Each revision is immutable and activation can select an earlier version for rollback. The optional classifier can supply a risk signal but cannot authorize or allow an action; an active deterministic policy decides whether that signal changes a request decision. Classifier enforcement fails closed on classifier errors.

## Input and output inspection

The input inspector emits segment provenance and deterministic findings. Client supplied trust metadata can lower trust but cannot promote a message into a trusted level. Direct and indirect injection findings plus detected secrets are evaluated by built-in, versioned deterministic policies. Detection normalizes Unicode, HTML entities, percent encoding, and zero-width characters while retaining the original message location. Custom provenance annotations are removed before forwarding upstream. When enabled, semantic triage receives only bounded, untrusted text with detected credentials redacted.

The output inspector detects common credentials and personal identifiers, records masked evidence, and prepares a sanitized body. Optional phone and IPv4 detectors can be enabled from configuration. Output findings are evaluated by deterministic policy rules after the provider call. Declared JSON output is parsed and JSON Schema Draft 2020-12 constraints are applied locally; schema references are rejected to prevent external resolution. Invalid output is withheld.

Tool definitions are application scoped and persisted separately from request records. Requests can offer only enabled registry tools, and GateShield forwards the canonical registry schemas. Returned tool proposals are parsed and validated before they leave the gateway; invalid or unregistered proposals are withheld. A high-risk proposal is surfaced for the integration to pass through `/v1/tools/authorize`, which returns an expiring approval ID rather than permission to execute. A console administrator can approve it; the integration must retry authorization with the exact request and action. The approval is consumed atomically once and fails if scope, active policies, route configuration, or expiry has changed. GateShield does not execute tool adapters.

Agent requests add a hashed agent credential and an active, expiring session to the same path. The identity supplies the allowed tool set and exact resource assignments. Session counters and deterministic behavior signals span requests; they can deny a later request when configured session limits are reached.

## Domain models

`AIRequest`, `SecurityContext`, `PolicyDecision`, `GatewayRequest`, `GatewayResponse`, and `SecurityEvent` carry request and decision state. Persisted `RequestRecord` stores redacted JSON only. The application key includes an organization ID field for future isolation, but multi-tenant authorization is not implemented.

## Provider interface

`ModelProvider.complete(payload)` returns a validated OpenAI-compatible response mapping. The initial adapter uses HTTPX and has a finite timeout. Streaming is rejected explicitly.
