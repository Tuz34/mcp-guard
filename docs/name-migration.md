# PolicyLatch name migration

The project formerly named `mcp-guard` is now **PolicyLatch**. The new name keeps
the product centered on an explicit local policy decision and a call-time latch,
without implying that the current no-forward evaluator is already a production
proxy, mesh, or sandbox.

## Primary names

| Surface | Primary name |
|---|---|
| Brand | PolicyLatch |
| Python distribution | `policylatch` |
| Python package | `policylatch` |
| CLI | `policylatch` |
| Environment prefix | `POLICYLATCH_` |

## Compatibility window

The following former names remain supported for one transition release:

- `mcp-guard` invokes the same CLI as `policylatch`.
- `python -m mcp_guard` invokes the same CLI as `python -m policylatch`.
- Imports such as `mcp_guard.gateway` resolve to the corresponding
  `policylatch.gateway` module object. This preserves monkeypatch and module-state
  behavior instead of copying implementation symbols into wrappers.
- `MCP_GUARD_WINDOWS_INTEGRATION=1` remains an alias for
  `POLICYLATCH_WINDOWS_INTEGRATION=1`. If both variables are present, the new
  `POLICYLATCH_` value is authoritative.

The JSON schemas, policy version, decision values, and exit codes do not change as
part of the rename.

## GitHub Action transition

During migration review, the repository remains at `Tuz34/mcp-guard`, so existing
commit-pinned Action references continue to use that path. After the code migration,
compatibility tests, review, and cross-platform CI are green, the repository will be
renamed to `Tuz34/policylatch` and documentation links will be updated in a final
metadata commit. No release tag exists yet.

## Rollback

Before a release or package publication, the migration can be rolled back by
reverting the migration commits. If the GitHub repository has already been renamed,
rename it back and restore the local `origin` URL. The compatibility CLI, import, and
environment aliases prevent an abrupt break while the migration is under review.
