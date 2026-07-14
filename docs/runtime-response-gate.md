# Runtime MCP response gate

`gateway-stdio` treats every upstream `tools/call` result and error as untrusted.
Before the original JSON-RPC response can reach the client, PolicyLatch adapts
the envelope in memory to the versioned `tool_result` scanner contract.

```text
upstream tools/call result/error -> bounded JSON adapter -> result scanner
                                                        |
                              clean --------------------+-> original response
                              review/block ------------+-> local redacted error
```

The adapter fingerprints request, response, and tool identity. Scanner reports
retain only fingerprints, fixed rule IDs, counts, and outcome. Raw response text,
tool arguments, result/error data, URLs, and secret-like values are never copied
to the session summary or local error.

## Outcomes

- `clean`: forward the original, unmodified upstream envelope.
- `review`: withhold by default; a fingerprint-bound explicit approval may
  forward it. A short exact-scope session grant is allowed.
- `block-next-step`: withhold by default; only a one-shot explicit approval may
  forward it. Session grants are rejected.
- malformed, duplicate-key, non-finite, oversized, overlong-line, notification,
  or uncorrelated output: close the session with a local fail-closed error.

The result scan does not claim DLP, malware detection, or proof that content is
safe. It is a deterministic post-flight policy signal for the fixed v1 marker
categories.

## Scope boundary

This gate covers the result or error correlated to `tools/call`. The current
sequential runtime rejects interleaved upstream notifications. Initialize,
`ping`, and `tools/list` responses are validated for correlation and basic
JSON-RPC shape but are not passed through the tool-result scanner. In particular,
dynamic tool descriptions remain untrusted and require a separate manifest/tool
metadata policy before PolicyLatch can claim to gate them.

The same transport bypass applies: a client configured directly to the upstream
server avoids both pre-flight and post-flight checks.
