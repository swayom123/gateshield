# Tool security

The application-scoped registry stores tool name, description, JSON Schema arguments, risk, resource type, scope, and enabled state. The initial registry seeds two read-only document tools. Trusted setup code can register additional definitions through `ToolRegistry`; there is no unauthenticated registry mutation route.

Chat requests that offer tools must name enabled registry entries. The gateway sends the registry's description and argument schema upstream, ignoring caller-supplied schemas. Provider tool calls are parsed as JSON objects and checked against that registered schema and resource scope. Malformed, unregistered, schema-invalid, high-risk, or out-of-scope calls are withheld and audited. Deterministic policies block invalid tool calls.

`POST /v1/tools/authorize` checks a call before an application executor runs it and writes a redacted invocation record. It never executes a tool. The caller must treat any error or non-`ALLOW` result as a denial. The endpoint uses the configured application identity; until gateway authentication exists, deploy it behind a trusted application ingress.

Filesystem tools must configure a root; resolved paths must remain beneath it, including symlink resolution. HTTP tools need exact host and port allowlists. The guard allows only HTTP(S), rejects credentials, fragments, local or metadata targets, and non-public resolved addresses. Revalidate every redirect destination through GateShield. Database tools use `resource_type: database` with trusted table/field allowlists; GateShield creates read-only `SELECT` text with bound values and never accepts caller SQL. This phase does not execute generated queries or shell commands.

Agent identities and role-based authorization are Phase 6. This phase scopes registry entries to the configured application and cannot independently prove which end user or agent is calling. Tool adapters and their execution sandbox remain outside Phase 5.
