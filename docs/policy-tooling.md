# Policy authoring toolkit

PolicyLatch keeps policy authoring deterministic and offline. The toolkit never
rewrites a policy and never forwards a fixture to a tool.

## Contract tests

Each JSON fixture contains one action or MCP `tools/call` request plus an
`_expected` value (`allow`, `warn`, or `deny`). All keys beginning with `_` are
test metadata and are removed before evaluation.

```bash
policylatch policy-test \
  --fixtures examples/policy-tests \
  --policy examples/policies/balanced.yaml
```

The command exits `0` when every expectation matches and `2` when any fixture
regresses. Use `--format sarif` for GitHub Code Scanning.

## Semantic lint

```bash
policylatch policy-lint --policy policy.yaml
```

Lint reports duplicate case-insensitive patterns, exact allow/deny conflicts,
obviously broad patterns, and warn patterns that an equal or broader deny
substring always supersedes. Findings are review signals; no automatic fix is
applied. Exit code `1` means findings were reported.

## JSON Schema

Export the versioned Draft 2020-12 schema for an editor or CI validator:

```bash
policylatch schema --kind policy --output policy-v1.schema.json
policylatch schema --kind action --output action-v1.schema.json
policylatch schema --kind gateway-request --output gateway-request-v1.schema.json
policylatch schema --kind report --output report-v1.schema.json
```

The schemas are generated from the same rule-key and decision constants tested
by the runtime. Unknown policy fields remain closed by default.
