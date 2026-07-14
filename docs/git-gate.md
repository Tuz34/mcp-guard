# Supplied Git diff gate

`git-check` parses a unified diff supplied by the user, pre-commit, or CI. The
PolicyLatch process never invokes Git, a shell, changed commands, or hooks.

```bash
policylatch git-check \
  --diff examples/git/manifest-change.diff \
  --manifest examples/workspace/mcp.json \
  --policy examples/policies/gateway-strict.yaml \
  --fail-on warn
```

Use `--diff -` to read a diff from stdin. Input is limited to 2 MiB, 20,000
lines, 64 KiB per line, and 500 file sections. The parser validates UTF-8,
CRLF/LF normalization, safe relative `a/` and `b/` paths, quoted space paths,
complete rename metadata, and exact unified-hunk line counts. Absolute,
traversal, ambiguous, NUL/control, oversized, malformed, and truncated inputs
fail closed. Binary changes receive `deny`; unknown metadata receives `warn`.

Reports contain relative paths, fixed status/category labels, fingerprints, and
fixed findings. Added/removed/context lines are never copied to JSON, Markdown,
or SARIF.

## Evidence reuse

- A current added/modified/renamed MCP config requires one explicit clean
  `--manifest` scan and a `--policy` or `--profile`. Repeat `--manifest` once per
  current MCP config in the supplied diff; each manifest basename must match its
  changed diff path.
- Exactly one policy-file change requires `--policy-before`, `--policy-after`,
  and `--fixtures`. These inputs run the existing deterministic `policy-diff`
  gate with `--policy-fail-on`; the after-policy basename must match the changed
  diff path.
- A deleted MCP config and a changed synthetic fixture remain review findings.
  Unrelated text source changes do not become findings.

The default `--fail-on warn` makes review and deny findings return exit code 2.
Use `deny` to fail only deny findings or `never` for report-only operation. Input
diff and evidence files are explicit local claims, not signed VCS provenance; a
caller that fabricates all inputs is outside this advisory gate boundary.

## Review-first snippets

```bash
policylatch git-snippet --kind pre-commit
policylatch git-snippet --kind github-actions
```

Generation only prints or writes the requested artifact. It never edits
`.pre-commit-config.yaml`, workflow files, Git configuration, or hooks. The
generated snippets contain the external Git step that the user/runner will
execute after manual review. Add the required manifest or policy evidence flags
for the repository's relevant paths before installation.
