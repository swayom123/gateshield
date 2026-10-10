# Input trust and prompt injection

GateShield preserves provenance for each text segment it inspects. Standard message roles provide a baseline: `user` is `USER_CONTROLLED`, `tool` is `TOOL_OUTPUT`, `assistant` is `UNKNOWN`, and `system`/`developer` are `UNKNOWN` because the current gateway has no authenticated way to verify who supplied them. A caller may mark a segment as `EXTERNAL_RETRIEVAL` or `TOOL_OUTPUT` to lower trust. Caller supplied metadata cannot elevate content to `TRUSTED_SYSTEM` or `TRUSTED_APPLICATION`.

For retrieved content, send the ordinary message content and include `provenance: "EXTERNAL_RETRIEVAL"` on that message. GateShield strips its `provenance` and `source` annotations before forwarding the OpenAI-compatible request. Resolved labels and finding evidence are recorded in the security event.

The deterministic input inspector checks untrusted text for instruction overrides, requests to disclose system/developer instructions, and common instruction boundary markers. It also decodes one layer of syntactically valid base64 text locally and checks the decoded text against the same patterns. It does not make network calls or use an LLM classifier.

Built-in versioned policies block detected direct and indirect injection findings. They also block detected credentials and private keys. These policies are installed once and remain editable through the policy repository, including changing their mode to `MONITOR` or `OFF`. Findings produce separate audit events. Evidence contains pattern identifiers, location, provenance, and masked excerpts or values; it does not contain full detected secrets.

## Limits

Pattern checks can miss novel, multilingual, obfuscated, or context-dependent attacks, and can flag benign discussion of attack phrases. Base64 detection is intentionally limited to one decoded layer. Provenance metadata is caller supplied and cannot prove a source; use it to preserve known boundaries, not as authentication. The gateway has no trusted system-prompt injection mechanism yet, so inbound system/developer messages are treated as unknown and inspected as untrusted content.
