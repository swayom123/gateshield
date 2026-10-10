# Output data protection

GateShield runs deterministic output inspection after the upstream response and before persistence or return. Initial DLP rules cover common provider credentials, private keys, credential assignments, email addresses, US Social Security numbers, and payment card numbers with a valid Luhn checksum. Findings contain detector IDs, locations, and masked values; raw matches are not included in audit evidence.

The built-in `default-redact-output-sensitive-data` policy runs in `ENFORCE` mode and returns the masked response. Policy teams can version and change its action. `MONITOR` records a finding without changing the returned response; `OFF` skips that policy. Stored response content is sanitized under the default logging modes.

Callers can request `json_object` or `json_schema` response formats. Schemas are checked before provider forwarding, limited to 32 KiB, 10,000 nodes, and 32 levels, validated against JSON Schema Draft 2020-12, and cannot contain references or regular-expression constraints. Responses are limited to 1 MiB for local inspection. Invalid or oversized output is withheld; invalid declared structured output is blocked by policy. Phase 4 does not retry or repair model output.

These deterministic patterns have limited coverage and can produce false positives. They do not establish that output is safe in every context. Applications should retain authorization checks at the system that owns the data.
