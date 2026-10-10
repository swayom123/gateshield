# Output data protection

GateShield runs deterministic output inspection after the upstream response and before persistence or return. Built-in DLP rules cover common provider credentials, private keys, credential assignments, email addresses, US Social Security numbers, and payment card numbers with a valid Luhn checksum. Operators can additionally enable `US_PHONE` and `IPV4` using `GATESHIELD_EXTRA_DLP_DETECTORS='["US_PHONE","IPV4"]'`. Findings contain detector IDs, locations, and masked values; raw matches are not included in audit evidence.

The built-in `default-redact-output-sensitive-data` policy runs in `ENFORCE` mode and returns the masked response. Policy teams can version and change its action. `MONITOR` records a finding without changing the returned response; `OFF` skips that policy. Stored response content is sanitized under the default logging modes.

Callers can request `json_object` or `json_schema` response formats. Schemas are checked before provider forwarding, limited to 32 KiB, 10,000 nodes, and 32 levels, validated against JSON Schema Draft 2020-12, and cannot contain references or regular-expression constraints. Responses are limited to 1 MiB for local inspection. Invalid or oversized output is withheld; invalid declared structured output is blocked by policy. Phase 4 does not retry or repair model output.

These deterministic patterns have limited coverage and can produce false positives. They do not establish that output is safe in every context. Applications should retain authorization checks at the system that owns the data.

## Classification-aware routing

`GATESHIELD_DEFAULT_DATA_CLASSIFICATION` is an operator-controlled value and cannot be lowered by a request caller. When it is `RESTRICTED`, requests are blocked unless `GATESHIELD_MODEL_ROUTES_JSON` contains the requested model with `provider_type: "LOCAL"` and an explicit `RESTRICTED` classification, and the configured provider type is also `LOCAL`. `GATESHIELD_MODEL_ROUTING_MODE=ENFORCE` applies the route registry to all classifications; `MONITOR` records mismatches while allowing non-restricted requests; `OFF` disables general route checks but does not disable the restricted-data local-route requirement. The first adapter uses one configured provider endpoint, so route configuration can approve or block that provider but does not yet select among multiple endpoints.
