# Policy reference

`PolicyLatch` policies are local YAML files. Version 1 intentionally has a small,
explicit vocabulary. Unknown sections and rule names are errors, so a typo cannot
silently weaken a policy.

## Top-level fields

| Field | Required | Meaning |
|---|---:|---|
| `version` | yes | Must be `1`. |
| `default_decision` | no | `allow`, `warn`, or `deny`; defaults to `warn`. |
| `profile` | no | Built-in `minimal`, `balanced`, `strict`, or `ci` base. |
| `extends` | no | Relative local policy path, or a list merged left-to-right. |
| `rules` | no | Mapping of rule sections. |
| `budgets` | no | Named cumulative UTC window limits; see [policy budgets](policy-budgets.md). |

## Profiles and local inheritance

Use a built-in profile directly from the CLI:

```bash
policylatch doctor --profile balanced
policylatch check --action action.json --profile balanced
```

A project policy can start from a profile and replace selected rule lists:

```yaml
version: 1
profile: balanced
default_decision: warn
rules:
  network:
    allow_domains: ["github.com", "api.github.com"]
```

Local policy inheritance uses `extends` with a relative path or a list of relative
paths. Sources are merged left-to-right; the current file is applied last. A
defined `default_decision` replaces the inherited value, and each named rule list
replaces rather than appends to the inherited list. Use an empty list to clear a
rule explicitly.

Includes must stay below the root policy directory. Absolute paths, parent
traversal, URLs, cycles, more than 8 levels, more than 16 files, and more than
4 MiB of total policy input fail closed. Policy resolution never accesses the
network.

`doctor` reports the resolved profile, sources, default, and rule counts without
modifying files. Decision JSON and Markdown include `policy_provenance`; `explain`
reads a saved decision and maps each finding to the profile or policy file that
defined the matched rule.

Named budgets replace the inherited budget with the same ID. Budget provenance
is recorded alongside normal rule provenance, and `doctor` reports the resolved
budget count.

## Rule sections

### `shell`

- `deny_patterns`: shell text patterns that produce `deny`.
- `warn_patterns`: shell text patterns that produce `warn`.

Patterns are case-insensitive. `*` and `?` use glob matching; patterns without
wildcards use substring matching. `PolicyLatch` only compares text. It does not parse
or execute a shell command. Keep plain patterns specific: `remove` matches
`Remove-Item -Recurse`, while the shorter text `rm` does not occur contiguously in
that command and therefore does not match it.

### `files`

- `deny_paths`: path patterns that produce `deny`.
- `warn_paths`: path patterns that produce `warn`.

Both `/` and `\` separators are normalized before case-insensitive glob matching.
The `**/` prefix means zero or more directories, so `**/secrets/**` matches both
`secrets/demo.json` and `nested/secrets/demo.json`. Matching respects complete
path segments: that pattern does not match `mysecrets/demo.json`.

### `network`

- `deny_domains`: domain patterns that produce `deny`.
- `allow_domains`: when non-empty, destinations outside this list produce `warn`.

Domain matching is case-insensitive. `github.com` matches that exact hostname;
`*.github.com` matches subdomains such as `api.github.com`, but intentionally does
not match the apex `github.com`. List both patterns when both forms are allowed.
Patterns apply to the complete hostname but retain glob semantics: a broad pattern
such as `github*` matches both `github.com` and `github.io`, so exact hostnames or
explicit subdomain patterns are safer. A deny match takes precedence over an
allow-list warning.

### `mcp_tools`

- `allow_names`: complete tool-name globs. When present, a matching name creates
  an explicit allow baseline; a non-matching name produces `deny`.
- `deny_names`: complete tool-name globs that produce `deny`.
- `deny_if_description_contains`: blocked phrases in a tool description.
- `warn_if_name_contains`: powerful-capability phrases in a tool name.
- `warn_if_schema_contains`: sensitive terms in the serialized `inputSchema`.

`allow_names` and `deny_names` use case-insensitive complete glob matching.
`read_file` therefore matches only that name, while `read_*` matches a family.
The description, warning, and schema rules retain case-insensitive text/glob
matching. Dynamic `tools/call` behavior is described in the
[gateway contract](gateway.md).

## Precedence

The outcome is deterministic:

1. Any deny finding results in `deny` and high risk.
2. Otherwise, any warn finding results in `warn` and medium risk.
3. Otherwise, an `mcp_tools.allow_names` match supplies an explicit `allow`
   baseline for that tool.
4. Otherwise, `default_decision` determines the result.

`default_decision` is only the no-match fallback. An explicit warn rule therefore
returns `warn` even when the default is `deny`; use a deny rule for an unconditional
block.

Every finding includes its rule, effect, matched policy value, and explanation.
An allowlist miss uses the fixed marker `outside-allowlist` instead of copying the
untrusted tool name or destination hostname into the finding.

The same decision document can be rendered as JSON, Markdown, or a self-contained
HTML report. Rendering never changes the underlying decision.

## Policy authoring guidance

- Prefer a small set of high-confidence deny rules.
- Use warn for broad capability indicators that need human context.
- Start sensitive environments with `default_decision: warn` or `deny`.
- Review policy changes like application code.
- Test both expected matches and false positives before sharing a policy.
