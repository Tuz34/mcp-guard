# Policy reference

`mcp-guard` policies are local YAML files. Version 1 intentionally has a small,
explicit vocabulary. Unknown sections and rule names are errors, so a typo cannot
silently weaken a policy.

## Top-level fields

| Field | Required | Meaning |
|---|---:|---|
| `version` | yes | Must be `1`. |
| `default_decision` | no | `allow`, `warn`, or `deny`; defaults to `warn`. |
| `rules` | no | Mapping of rule sections. |

## Rule sections

### `shell`

- `deny_patterns`: shell text patterns that produce `deny`.
- `warn_patterns`: shell text patterns that produce `warn`.

Patterns are case-insensitive. `*` and `?` use glob matching; patterns without
wildcards use substring matching. `mcp-guard` only compares text. It does not parse
or execute a shell command.

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
A deny match takes precedence over an allow-list warning.

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

The same decision document can be rendered as JSON, Markdown, or a self-contained
HTML report. Rendering never changes the underlying decision.

## Policy authoring guidance

- Prefer a small set of high-confidence deny rules.
- Use warn for broad capability indicators that need human context.
- Start sensitive environments with `default_decision: warn` or `deny`.
- Review policy changes like application code.
- Test both expected matches and false positives before sharing a policy.
