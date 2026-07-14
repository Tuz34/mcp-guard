# MCP gateway contract

`gateway-check` is the first, deliberately non-forwarding slice of the local MCP
permission gateway. It proves the protocol-to-policy boundary without starting a
server, opening a socket, or executing a tool.

## Current data flow

```text
saved synthetic JSON-RPC request
              |
              v
strict tools/call parser -> local YAML policy -> ALLOW | WARN | DENY
              |
              +-----------------------------> forwarded: false
```

Example:

```bash
policylatch gateway-check \
  --request examples/gateway/denied-shell-call.json \
  --policy examples/policies/gateway-strict.yaml
```

For multiple synthetic requests, `gateway-replay` reads one JSON-RPC object per
JSONL line and returns the most restrictive aggregate decision:

```bash
policylatch gateway-replay \
  --input examples/gateway/synthetic-trace.jsonl \
  --policy examples/policies/gateway-strict.yaml
```

Only JSON-RPC 2.0 `tools/call` requests are accepted. Invalid JSON, unsupported
methods, malformed params, and invalid recognized arguments exit with code `3`.
An integration must treat every non-zero exit code as a closed gate unless it has
an explicit human-approval path for `warn`.

The saved request is capped at 1 MiB before JSON parsing. Tool names and string
request IDs are capped at 256 characters because both may be copied into the
decision document. Excessive JSON nesting is also rejected as invalid input.
Trace replay additionally caps each line at 1 MiB, the full trace at 8 MiB, and
the evaluated record count at 1,000. It reads incrementally and aborts the entire
replay on the first invalid record.

The stable 2025-11-25 MCP revision introduced experimental task-augmented tool
calls. The current gateway records only a `task_augmented` boolean and returns
`warn`; it does not copy task metadata or claim to support the asynchronous task
lifecycle.

## Policy projection

The tool name is checked against `mcp_tools.allow_names`, `deny_names`, and
`warn_if_name_contains`. Name allow/deny patterns use case-insensitive complete
glob matching: `read_file` is exact, while `read_*` is a family.

The current parser also projects these top-level argument keys into the existing
policy engine:

| Argument | Capability policy |
|---|---|
| `command` | `shell` |
| `path` | `files` |
| exactly one of `url` or `domain` | `network` |

If multiple recognized capabilities are present, all are evaluated and the most
restrictive finding wins. Supplying both `url` and `domain` is ambiguous and is
rejected as invalid input. Nested arguments and server-specific aliases are not
inferred. Any unknown top-level argument adds an `unclassified` capability and a
`warn` finding, even when a recognized capability and allowlisted tool name are
also present. A future adapter must declare such mappings explicitly instead of
guessing from arbitrary data.

The decision output includes the request ID, method, tool name, capability names,
and policy findings. It intentionally does not copy raw `arguments` or a raw
non-allowlisted hostname; source and policy paths are reduced to basenames in
gateway decisions.

## Current security boundary

The current command does not:

- forward a request or connect to an MCP server;
- intercept a live stdio, HTTP, or SSE transport;
- execute a command or tool;
- validate arguments against a server-provided input schema;
- observe calls that were not explicitly supplied to it;
- prove that an agent did not use another execution path.

Use `default_decision: deny` with a small `allow_names` list for gateway policies.
The bundled `gateway-strict.yaml` is a synthetic starting point, not a universal
production policy.

## Planned enforcement boundary

The next transport milestone will wrap one explicitly configured stdio MCP
server. Before forwarding is considered, the design must define message-size
limits, backpressure, timeouts, process cleanup, request/response correlation,
approval behavior, and fail-open versus fail-closed semantics. HTTP/SSE, TLS
interception, automatic client reconfiguration, and background monitoring are
not part of this first transport milestone.

Even after forwarding exists, only calls routed through the configured gateway
can be observed or blocked. That bypass boundary will remain explicit in the UI,
documentation, and reports.
