# MCP gateway contract

PolicyLatch has two deliberately non-forwarding commands and one separate,
explicitly opt-in stdio enforcement command. `gateway-check` and
`gateway-replay` never start a server. `gateway-stdio` starts exactly one argv
from a reviewed local config and forwards only calls decided `allow`.

## Current data flow

```text
saved synthetic JSON-RPC request
              |
              v
strict tools/call parser -> local YAML policy -> ALLOW | WARN | DENY
              |
              +-----------------------------> forwarded: false
```

Runtime mode is a different boundary:

```text
MCP client -> bounded lifecycle parser -> YAML policy -> allow -> upstream stdio
                                           | warn/deny
                                           +-----------> local JSON-RPC error
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

## Opt-in stdio enforcement

The upstream config is strict JSON with exactly four fields:

```json
{
  "schema_version": 1,
  "server_id": "reviewed-local-server",
  "argv": ["python", "path/to/server.py"],
  "cwd": "."
}
```

`argv` is passed as a list with `shell=False`; PolicyLatch never constructs a
shell string. Relative `cwd` is resolved from the config file and must already
be a directory. Forwarding stays disabled unless `--enable-forwarding` is set.
The command reserves stdin/stdout for newline-delimited MCP JSON-RPC, so the
config cannot be read from stdin and stdout never contains diagnostics.

The implemented lifecycle is intentionally narrow: `initialize`,
`notifications/initialized`, `ping`, `tools/list`, and `tools/call`. A tool call
before initialization, a notification-style tool call, a reused request ID, an
unknown method, a mismatched response ID, malformed output, timeout, oversized
message, or broken pipe closes the session. Each request is evaluated before its
bytes reach the child. `allow` forwards once; `warn` and `deny` return a local
error and never reach upstream. Upstream stderr is drained and discarded, with
only a truncation boolean retained.

The bundled `synthetic-upstream.json` launches only the repository's fake echo
server. The fake server never executes a command, opens a network connection, or
uses tool arguments. A real upstream is outside that synthetic demo boundary and
may execute an allowed call.

## Security boundary

The no-forward commands do not:

- forward a request or connect to an MCP server;
- intercept a live stdio, HTTP, or SSE transport;
- execute a command or tool;
- validate arguments against a server-provided input schema;
- observe calls that were not explicitly supplied to it;
- prove that an agent did not use another execution path.

Use `default_decision: deny` with a small `allow_names` list for gateway policies.
The bundled `gateway-strict.yaml` is a synthetic starting point, not a universal
production policy.

With `--interactive-approval`, a `warn` may be approved once or by a bounded
in-memory session grant. Missing console input, timeout, or ambiguity denies;
`deny` is never overridable. See [scoped approvals](approvals.md). The stdio
command does not scan or classify upstream response content yet; that is a
separate post-flight gate. It also does not support HTTP/SSE, TLS interception,
automatic client reconfiguration, background monitoring, task-augmented calls,
or arbitrary MCP extension methods.

Only calls routed through `gateway-stdio` can be observed or blocked. Direct MCP
client-to-server configuration remains a complete bypass. The session summary is
data-minimized: policy and upstream fingerprints plus counts and cleanup state;
it never copies argv, cwd, environment, arguments, results, or server stderr.
