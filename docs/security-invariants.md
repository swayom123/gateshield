# Security invariants

1. A request with `BLOCK` or `REQUIRE_APPROVAL` does not reach the provider.
2. Input inspection or policy evaluation errors deny upstream forwarding.
3. An unconfigured provider returns an explicit service error; no provider is selected implicitly.
4. Provider failures and invalid response shapes are returned as explicit gateway errors.
5. A response is withheld if output inspection or audit persistence fails.
6. Prompt and completion content are not written to application logs.
7. Persisted request and response content passes through secret redaction.
8. GateShield never executes model-generated tool calls or shell commands.
9. Streaming requests are rejected rather than passed through without inspection.
10. Request records and dashboard counts (when added) derive from stored gateway traffic only.
11. Output `BLOCK` and `REQUIRE_APPROVAL` decisions never return the provider body.
12. Output `REDACT` returns the sanitized body, and raw detector matches never enter findings.
13. Declared structured output that fails local validation is withheld.
14. Invalid or oversized schemas are rejected before provider forwarding.
15. A caller cannot offer a tool absent from its application-scoped enabled registry.
16. Malformed or unauthorized model tool calls are withheld before reaching the application.
17. Tool authorization errors and non-`ALLOW` results must not be treated as permission to execute.
18. Database tool values are bound parameters; generated tool input is never treated as SQL text.
19. GateShield does not execute arbitrary shell commands.
20. An agent request reaches the provider only with an active identity and matching active session.
21. Agent tool permissions are the intersection of registry permissions and identity permissions.
22. Agent tokens are stored as hashes and are never forwarded to the model provider.
23. Session behavior signals use deterministic evidence and do not make unsupported maliciousness claims.

Automated tests cover provider suppression on policy and tool blocks, forwarding and persistence with local stubs, input/output secret masking, invalid structured output suppression, schema canonicalization, path traversal, SSRF targets, and parameterized database query construction. Agent identity and real tool adapter execution remain outside this phase.
