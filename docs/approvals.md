# Scoped approvals

PolicyLatch keeps approval outside the policy engine. A policy `deny` is final;
only a `warn` from `gateway-stdio` may ask for an explicit local approval.
Without `--interactive-approval`, every `warn` remains closed.
Experimental task-augmented calls are not approval-eligible because their
asynchronous lifecycle is not implemented.

```bash
policylatch gateway-stdio \
  --upstream-config reviewed-upstream.json \
  --policy policy.yaml \
  --enable-forwarding \
  --interactive-approval \
  --approval-timeout-seconds 30
```

The protocol stream remains on stdin/stdout. Interactive input is opened from
the local console (`CONIN$` on Windows or `/dev/tty` on POSIX), and the redacted
approval request is written to stderr as one JSONL object. If no console exists,
the console closes, the response is ambiguous, or the timeout expires, the
answer is `deny`. CI never prompts unless the flag is explicitly supplied.

## Request contract

An approval request contains only:

- upstream and policy fingerprints;
- a tool fingerprint, capability names, and target class;
- a semantic request fingerprint that excludes the JSON-RPC ID but includes the
  complete call content in the hash calculation;
- matched rule IDs and the bounded approval timeout.

It does not serialize the tool name, arguments, prompt, target value, upstream
argv/cwd, environment, or credentials. Changing any semantic call value changes
the scope fingerprint and requires another approval.

The accepted response contract is strict JSON:

```json
{
  "schema_version": 1,
  "kind": "approval_response",
  "request_fingerprint": "sha256:<64 lowercase hex characters>",
  "decision": "approve",
  "grant": null
}
```

Terminal input accepts `approve`, `deny`, or `grant <ttl-seconds> <uses>`.
Everything else denies. A grant is held only in memory, applies only to the exact
scope fingerprint, and permits at most 20 future uses for at most 300 seconds.
It never edits a policy or persists a broad allow rule.

Agent adapters can use `build_approval_request()` and
`parse_approval_response()` to exchange the same versioned documents over their
own trusted local channel. Supplying a response for another pending fingerprint
is rejected.

## Bypass boundary

Approval does not make PolicyLatch a host sandbox. Calls routed directly to the
MCP server bypass the gateway. Anyone who can replace the reviewed upstream
config or policy is already outside this boundary. Upstream result content is a
separate post-flight decision; approving a call does not approve its response.
`block-next-step` responses never receive reusable grants.
