# Bounded workspace inventory

`workspace-scan` inventories MCP JSON configuration under one explicit root.
It does not search the home directory, mounted disks, or sibling projects.

```bash
policylatch workspace-scan \
  --root examples/workspace \
  --policy examples/policies/gateway-strict.yaml \
  --output workspace-baseline.json
```

Known names are `.mcp.json`, `mcp.json`, `mcp-config.json`, and
`claude_desktop_config.json`. Repeat `--pattern` for a bounded relative glob;
absolute patterns and `..` are rejected. Only JSON files are accepted. Version
control, dependency, virtual-environment, cache, build, and distribution
directories are skipped by a fixed list.

Default limits are depth 8, 100 matched files, 1 MiB per file, 8 MiB total input,
and 20,000 visited directory entries. CLI flags may lower or raise the first
three only within their hard caps. Reaching a traversal, count, byte, malformed
JSON, duplicate-key, inaccessible-path, or matching-symlink boundary fails
closed instead of returning a partial baseline.

## Data minimization

Each inventory entry stores:

- relative path and one fixed config-shape label;
- tool count, allow/warn/deny counts, and aggregate decision/risk;
- a value-aware content fingerprint and canonical entry fingerprint.

Raw commands, args, names, descriptions, schemas, defaults, URLs, credentials,
and secret-like values are not serialized. The content fingerprint detects a
value-only change but is not a substitute for reviewing the source file.

## Baseline diff

```bash
policylatch workspace-diff \
  --before workspace-before.json \
  --after workspace-after.json \
  --fail-on risk-increase \
  --format sarif
```

The diff validates entry and baseline fingerprints before comparing. It reports
added, removed, changed, risk-increased relative paths, and a policy-fingerprint
change even when file decisions remain stable. `risk-increase`
returns exit code 2 when a changed decision becomes more restrictive or a newly
added config is not `allow`; `--fail-on never` still reports the change but exits
zero. Neither command mutates the workspace, runs Git, starts MCP servers, or
makes network requests.
