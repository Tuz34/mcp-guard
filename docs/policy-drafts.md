# Draft-only policy generator

`policy-init` turns a saved MCP manifest into a stable review artifact. It uses
fixed local classifiers only: there is no model call, network request, tool
execution, or manifest instruction following.

```bash
policylatch policy-init \
  --mcp-config examples/mcp/risky-server.json \
  --output policy.draft.yaml
```

Generated YAML has a top-level `draft: true` wrapper. It is deliberately not a
valid enforcement policy: `check`, `scan`, and gateway commands reject it until
a person reviews the recommendations and manually creates a normal policy.

The generator:

- emits no allow rule;
- maps known powerful name/schema-key categories to review suggestions;
- maps fixed blocked-description categories to deny-review suggestions;
- leaves uncertain tools as TODO;
- records one provenance row for every generated pattern;
- omits raw descriptions, schema defaults, prompt text, and secret-like values;
- refuses to replace an existing output unless `--force` is explicit.

Descriptions are treated as untrusted data. A phrase can trigger a fixed safety
category, but it cannot add a rule, change the default decision, or inject YAML.

Check whether an existing policy gives every tool an explicit signal:

```bash
policylatch policy-init \
  --mcp-config examples/mcp/safe-server.json \
  --check \
  --policy examples/policies/balanced.yaml
```

Coverage exits `1` when any tool relies only on the policy default. JSON and
SARIF outputs contain tool names and decisions, never raw descriptions or schema
default values.
