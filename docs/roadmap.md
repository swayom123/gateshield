# GateShield Remaining Phases

This document records planned work after the completed Phase 6 agent identity and session foundation. It is a roadmap, not a claim that these features already exist. Implement and review each phase before starting the next.

## Phase 7 — Management Console

Build a restrained, authenticated security operations console. It should surface persisted GateShield data and show zero activity when there are no stored events; live mode must not use generated dashboard data.

Planned work:

- Overview of request totals and allowed, blocked, redacted, high-risk, prompt-injection, tool-block, and pending-approval counts. Omit trend indicators until comparable historical data exists.
- Request list and inspector with request/trace IDs, application, agent, model/provider, timing, decision, risk factors, input/output findings, tool calls, matched policies, and sanitized evidence.
- Security event view with filtering by time, event type, severity, application, agent, policy, request, and outcome.
- Policy management for readable validated definitions, draft/active/retired versions, activation, rollback, and a historical-request test interface designed to report would-allow/block/redact outcomes and likely false positives.
- Agent and tool registry views, approval queue, model registry, data-protection settings, analytics, audit history, and system settings.
- Server-side authentication and authorization for console users. Planned roles: `ADMIN`, `SECURITY_ADMIN`, `POLICY_EDITOR`, `ANALYST`, `AUDITOR`, and `VIEWER`.
- Privacy-aware rendering: never reveal full secrets; display sanitized request evidence according to logging policy.

Acceptance direction: every displayed count and row must be backed by stored records, filters must be enforced server-side, and role checks must protect reads and mutations.

## Phase 8 — Advanced Security

Extend the deterministic gateway without making an LLM classifier the final authority for authorization.

Planned work:

- Stronger indirect prompt-injection analysis that preserves provenance for retrieved documents, web content, and tool output. Untrusted content must not acquire policy authority.
- Optional semantic classifier as an additional risk/triage signal, with explicit `ENFORCE`, `MONITOR`, and `OFF` policy modes where applicable. It must not override deterministic authorization rules.
- Broader configurable DLP detectors and classification-aware transfer controls. Never store raw detected secrets in normal logs or audit evidence.
- Security-aware model routing based on data classification, approved providers/models, environment, and application policy. Restricted data should route only to explicitly approved local models or be blocked.
- Scoped approval workflow for high-risk actions. An approval must bind to the exact agent, action, arguments/resource, policy context, and expiry; it must not become reusable general permission.
- Failure-safe behavior: classifier, routing, or approval infrastructure failures must not silently bypass critical controls.

Acceptance direction: policy decisions remain explainable with matched policies, deterministic factors, restrictions, and evidence; tests demonstrate that explicit blocks cannot be overridden by classifier output.

## Phase 9 — Evaluation

Create a repeatable local evaluation and regression program using controlled fixtures only. Do not contact or attack real external systems.

Planned work:

- Defensive fixtures for direct and nested indirect injection, mixed benign/malicious content, encoded attempts, secret exfiltration, malformed tool schemas, oversized requests, Unicode edge cases, path traversal, SSRF destinations and redirects, SQL-like tool arguments, authorization bypass, and expired/revoked identities.
- Measure prompt-injection detection, false-positive rate, secret detection, policy enforcement, and tool authorization against labeled fixtures. Report only results from actual runs, with fixture set/version and methodology.
- Regression tests for security invariants: blocked requests never reach providers; blocked tools never execute; blocked secrets never leave the gateway; retrieved content cannot change policy; agents cannot use unassigned tools; dashboard counts equal persisted event data; normal APIs cannot edit audit events.
- Local performance benchmarks for gateway overhead, inspection, policy evaluation, provider latency, and tool authorization. Record environment and results; do not claim unrun targets as measured facts.
- Analyst feedback labels (`TRUE_POSITIVE`, `FALSE_POSITIVE`, `EXPECTED`, `UNKNOWN`) as evaluation data. Do not silently train or adapt detectors from feedback.

Acceptance direction: evaluation is deterministic and rerunnable, fixtures remain local, and every metric includes its denominator and test conditions.

## Phase 10 — Production Hardening

Harden the deployment and operational model after the preceding security workflows are stable.

Planned work:

- PostgreSQL deployment support, reviewed migrations, backup/restore procedures, retention and deletion policies, and operational recovery checks. Add Redis only if measured requirements justify it.
- OpenTelemetry-ready traces and metrics across request inspection, policy, provider, output, and tool-authorization stages, correlated by request and trace IDs.
- Strong console authentication, SSO, server-side RBAC, organization/application isolation, credential rotation, and secret-management integration.
- Multi-instance deployment design, health/readiness checks, graceful shutdown, configuration validation, ingress body limits, rate limiting, and deployment documentation.
- CI/CD for formatting, lint, type checking, unit/integration/security regression tests, migration checks, dependency review, and release artifacts.
- Security review of threat model, isolation boundaries, audit integrity, provider configuration, tool adapter contracts, approval handling, and incident response procedures.

Acceptance direction: document tested deployment topology and recovery procedures; verify tenant/application isolation and migrations in CI; publish no performance or security claims without evidence.

## Phase boundaries and current status

Phases 1–6 establish the gateway foundation, deterministic policies, input/output inspection, tool authorization boundaries, and agent identity/session controls. The gateway does not execute tools itself, and integrating applications must enforce authorization immediately before execution. This document lists future work only; completing one phase does not imply later phase capabilities are available.
