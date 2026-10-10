# Initial threat model

Scope: OpenAI-compatible chat completion gateway, SQLite persistence, deterministic input and output inspection, versioned policies, one configured upstream adapter, optional semantic triage, model-route checks, and scoped tool approvals. STRIDE is used to organize threats.

| Threat | Phase 5 treatment | Remaining exposure |
|---|---|---|
| Spoofing: malicious application or stolen caller identity | No gateway authentication; bind behind trusted ingress | Any network caller able to reach the API may submit requests |
| Spoofing: stolen agent credential or forged agent ID | Random agent tokens are hash-stored; agent requests bind token, ID, application, environment, and session | Token theft remains possible; enrollment and ingress secrets need external protection |
| Tampering: altered requests or audit rows | Request validation; normal API has no audit mutation endpoint | Database file access can alter records; no tamper-evident chain |
| Repudiation: caller denies a request | Request/trace IDs and persisted event | Caller identity is caller-provided; no signed identity assertion |
| Information disclosure: prompt/secret in logs or DB | Structured logs omit content; stored snapshots pass through redaction | Redaction is heuristic and incomplete; raw prompts can contain unknown secret formats |
| Denial of service: oversized or repeated requests | Body size is bounded, including chunked request bodies; provider timeout | Rate limiting is not implemented |
| Elevation of privilege: prompt injection or tool abuse | Deterministic checks normalize common encoding obfuscations; tool calls must match application-scoped registry schemas and target scope; high-risk authorization requires a scoped single-use approval | Detection is incomplete; caller supplied provenance is not authenticated; external tool adapters must enforce authorization |
| SSRF: malicious URL through a tool | HTTP tool guard requires exact host/port allowlists and public resolved addresses; local and metadata targets are denied | External adapters must revalidate every redirect and pin the validated destination |
| Malicious retrieved document | Applications can label retrieved message content `EXTERNAL_RETRIEVAL`; deterministic patterns inspect it and the built-in policy blocks findings; optional semantic triage adds a policy signal | GateShield does not fetch or verify the document; caller supplied provenance is advisory; classifier output and deterministic detectors can be wrong |
| Malicious tool output | Tool proposals are checked against application-scoped registry schemas and resource scope before return | GateShield does not execute tool adapters; integrating applications must enforce authorization and sandbox execution |
| Malicious model provider | Explicit provider boundary, response shape checks, deterministic DLP, optional structured-output validation, and model route allow rules | Pattern-based DLP can miss sensitive content; response semantics are not established; only one provider endpoint is configured |
| Restricted data sent to an unapproved model | Operator-controlled classification and a mandatory explicit local route for `RESTRICTED` data | Classification must be configured correctly; local provider type is an operator assertion |
| Reused or widened tool approval | Keyed action/context hashes, expiry, and atomic one-time consumption | Signing key rotation invalidates pending approvals; operator review and external executor enforcement remain necessary |
| Policy misconfiguration | Versioned policies, built-in deterministic controls, server-side console roles, and policy-change audit | User accounts are environment configured; multi-tenant isolation and stronger identity management are future work |

## Security boundaries and guarantees

GateShield does not forward requests when input inspection, enforced routing, or policy evaluation fails or blocks. Classifier errors block requests in classifier `ENFORCE` mode. A high-risk tool authorization remains denied until its exact approval is granted and consumed. Output block/approval decisions withhold the provider body, and output inspection or policy errors withhold the response. These controls do not guarantee detection of prompt injection, secret leakage, or unsafe model output. A trusted ingress must provide caller authentication and network protection. Do not expose the development service directly to untrusted networks.
