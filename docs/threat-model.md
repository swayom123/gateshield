# Initial threat model

Scope: OpenAI-compatible chat completion gateway, SQLite persistence, deterministic input and output inspection, versioned policies, and one configured upstream adapter. STRIDE is used to organize threats.

| Threat | Phase 5 treatment | Remaining exposure |
|---|---|---|
| Spoofing: malicious application or stolen caller identity | No gateway authentication; bind behind trusted ingress | Any network caller able to reach the API may submit requests |
| Spoofing: stolen agent credential or forged agent ID | Random agent tokens are hash-stored; agent requests bind token, ID, application, environment, and session | Token theft remains possible; enrollment and ingress secrets need external protection |
| Tampering: altered requests or audit rows | Request validation; normal API has no audit mutation endpoint | Database file access can alter records; no tamper-evident chain |
| Repudiation: caller denies a request | Request/trace IDs and persisted event | Caller identity is caller-provided; no signed identity assertion |
| Information disclosure: prompt/secret in logs or DB | Structured logs omit content; stored snapshots pass through redaction | Redaction is heuristic and incomplete; raw prompts can contain unknown secret formats |
| Denial of service: oversized or repeated requests | Body size is bounded, including chunked request bodies; provider timeout | Rate limiting is not implemented |
| Elevation of privilege: prompt injection or tool abuse | Deterministic checks detect common instruction overrides; tool calls must match application-scoped registry schemas and target scope | Detection is pattern based; agent identity is not implemented; external tool adapters must enforce authorization |
| SSRF: malicious URL through a tool | HTTP tool guard requires exact host/port allowlists and public resolved addresses; local and metadata targets are denied | External adapters must revalidate every redirect and pin the validated destination |
| Malicious retrieved document | Applications can label retrieved message content `EXTERNAL_RETRIEVAL`; deterministic patterns inspect it and the built-in policy blocks findings | GateShield does not fetch or verify the document; caller supplied provenance is advisory |
| Malicious tool output | Tool proposals are checked against application-scoped registry schemas and resource scope before return | GateShield does not execute tool adapters; integrating applications must enforce authorization and sandbox execution |
| Malicious model provider | Explicit provider boundary, response shape checks, deterministic DLP, and optional structured-output schema validation | Pattern-based DLP can miss sensitive content; response semantics are not established |
| Policy misconfiguration | Versioned policies and built-in deterministic controls | No policy management authentication or approval workflow |

## Security boundaries and guarantees

GateShield guarantees that requests are not forwarded when the configured input inspector/policy raises an error or returns a block/approval decision. Output block/approval decisions withhold the provider body, and an output inspection or policy error withholds the response. It does not guarantee detection of prompt injection, secret leakage, or unsafe model output. A trusted ingress must provide authentication and network protection. Do not expose the development service directly to untrusted networks.
