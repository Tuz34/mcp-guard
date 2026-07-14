# PolicyLatch

**A local-first permission gateway for MCP tool calls and AI agents.**

`PolicyLatch` is evolving from a policy-checking CLI into a local gateway that can
make an explained permission decision before an MCP tool call reaches its server.
The current codebase provides the deterministic policy engine, manifest scanner,
reports, and an experimental **no-forward** check for one MCP JSON-RPC
`tools/call` request.

> [!IMPORTANT]
> The current gateway check never forwards a request, starts an MCP server, or
> executes a tool. Live interception is planned work, not a current capability.

## Why?

AI agents can request shell, filesystem, network, and database capabilities. Reviewing each request by eye does not scale, while full runtime isolation is often too heavy for a development workflow. `PolicyLatch` provides a deterministic local permission decision:

```text
MCP tools/call / proposed action / manifest -> local YAML policy -> ALLOW | WARN | DENY
```

Policies and inputs stay on your machine. The CLI has no telemetry and makes no network calls. Results explain exactly which rule matched and can be emitted as versioned JSON for automation or Markdown for review.

## Quickstart

Requires Python 3.10 or newer.

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
python -m pip install -e .
```

The primary entry points are `policylatch` and `python -m policylatch`. The former
`mcp-guard` command and `python -m mcp_guard` remain compatibility aliases for one
transition release.

The Python distribution, primary import package, and GitHub repository are now
`policylatch`. See the [name migration guide](docs/name-migration.md) for CLI,
import, environment, Action, and rollback details.

Evaluate a synthetic MCP tool call without forwarding it anywhere:

```bash
policylatch gateway-check \
  --request examples/gateway/denied-shell-call.json \
  --policy examples/policies/gateway-strict.yaml
```

The result contains `"mode": "dry-run"`, `"forwarded": false`, and an explained
`deny` decision. Raw tool arguments are not copied into the result.

Replay a bounded synthetic JSONL trace through the same no-forward boundary:

```bash
policylatch gateway-replay \
  --input examples/gateway/synthetic-trace.jsonl \
  --policy examples/policies/gateway-strict.yaml \
  --format markdown
```

Evaluate a synthetic runtime hook and generate a review-first configuration
snippet without changing Claude Code or Codex settings:

```bash
policylatch adapter-check --runtime claude-code \
  --input examples/adapters/claude-code-denied-shell.json \
  --profile strict
policylatch adapter-config --runtime claude-code --profile strict \
  --output claude-hook.json
```

Claude Code can consume a blocking `PreToolUse` decision. The current Codex
command-hook contract is advisory only, so PolicyLatch does not describe that
adapter as a security boundary. See [runtime adapters](docs/runtime-adapters.md)
for setup, rollback, and bypass details.

Evaluate a proposed agent action:

```bash
policylatch check \
  --action examples/actions/risky-shell-command.json \
  --policy examples/policies/balanced.yaml \
  --format markdown
```

Or use a versioned built-in profile and inspect its resolved sources first:

```bash
policylatch doctor --profile balanced
policylatch check \
  --action examples/actions/risky-shell-command.json \
  --profile balanced
```

Projects can extend a built-in profile or another local policy with deterministic,
replace-by-rule merge semantics. Includes are local-only and bounded; see the
[policy reference](docs/policy-reference.md#profiles-and-local-inheritance).

Policy authors can run synthetic expected-decision fixtures, semantic lint, and
export versioned JSON Schemas without installing another framework:

```bash
policylatch policy-test --fixtures examples/policy-tests --profile strict
policylatch policy-lint --policy policy.yaml --format sarif
policylatch schema --kind policy --output policy-v1.schema.json
```

See the [policy authoring toolkit](docs/policy-tooling.md) for fixture metadata,
lint semantics, and CI exit codes.

To bootstrap review from an MCP manifest, generate a non-enforceable draft. It
never emits allow rules and refuses to overwrite an existing file by default:

```bash
policylatch policy-init --mcp-config examples/mcp/risky-server.json \
  --output policy.draft.yaml
policylatch policy-init --mcp-config examples/mcp/safe-server.json \
  --check --policy examples/policies/balanced.yaml
```

See [draft-only policy generation](docs/policy-drafts.md) for the promotion and
untrusted-description boundary.

Expected decision:

```text
Overall decision: DENY

DENY shell.deny_patterns matched Remove-Item -Recurse
```

Scan an MCP tool manifest and save machine-readable output:

```bash
policylatch scan \
  --mcp-config examples/mcp/risky-server.json \
  --policy examples/policies/balanced.yaml \
  --output scan-result.json
```

Turn a saved JSON result into a review artifact:

```bash
policylatch report --input scan-result.json --format markdown --output report.md
policylatch report --input scan-result.json --format html --output report.html
```

New decision reports include a deterministic, redacted receipt. Extract it as
canonical JSONL without raw action arguments:

```bash
policylatch receipt --input scan-result.json --format jsonl --output receipt.jsonl
```

See [decision receipts](docs/decision-receipts.md) for canonical hashing,
privacy-preserving projection collisions, schema versioning, and the explicit
no-execution claim.

Persist receipt references only when local history is explicitly enabled, then
check a short replay window or render a static filtered report:

```bash
policylatch journal-append --input report.json --journal audit.jsonl \
  --stage evaluated --enable-journal
policylatch journal-check --input report.json --journal audit.jsonl
policylatch journal-report --input audit.jsonl --format html --output audit.html
```

The [agent action journal](docs/action-journal.md) is data-minimized, bounded,
always unverified, and separate from Windows state observation.

Exit codes are automation-friendly: `0` allow, `1` warn, `2` deny, and `3` invalid input or policy.

## Policy example

```yaml
version: 1
default_decision: allow

rules:
  shell:
    deny_patterns:
      - "rm -rf"
      - "Remove-Item -Recurse"
    warn_patterns:
      - "git push"
      - "npm publish"

  files:
    deny_paths:
      - ".env"
      - "**/secrets/**"
    warn_paths:
      - "**/*.pem"

  network:
    allow_domains:
      - "github.com"
    deny_domains:
      - "*.webhook.site"

  mcp_tools:
    allow_names:
      - "read_file"
      - "fetch_url"
    deny_names:
      - "admin_*"
      - "upload_*"
    deny_if_description_contains:
      - "ignore previous instructions"
      - "send file contents"
    warn_if_name_contains:
      - "shell"
      - "exec"
    warn_if_schema_contains:
      - "command"
      - "path"
```

Four policy profiles live in [`examples/policies`](examples/policies): `balanced`,
`strict`, `ci`, and the default-deny `gateway-strict`. See the
[policy reference](docs/policy-reference.md) for exact matching and precedence
rules. Unknown policy fields are rejected instead of silently ignored.

## Input formats

An action is a JSON object. Fields used by v0 depend on `action_type`:

| Type | Inspected field | Example |
|---|---|---|
| `shell` | `command` | A proposed CLI command |
| `file` / `filesystem` | `path` | A proposed file target |
| `network` | `url` or `domain` | A proposed destination |

An MCP manifest uses a top-level `tools` array (or `server.tools`). Each tool may provide `name`, `description`, and `inputSchema`. Common client configs with an `mcpServers` mapping are also supported; their declared `command` and `args` are checked as text. The scanner does not connect to an MCP server.

The experimental gateway input is one JSON-RPC 2.0 `tools/call` request. It
checks the complete tool name and recognized top-level `command`, `path`, `url`,
and `domain` arguments. See the [gateway contract](docs/gateway.md) for the exact
runtime boundary, and the [gateway threat model](docs/gateway-threat-model.md) for
known bypasses and the forwarding go/no-go criteria.

All files under [`examples`](examples) are deliberately synthetic. They contain no real credentials, endpoints, or user data.

### Experimental Windows audit foundation

The first opt-in Windows audit contract is documented in
[`docs/windows-audit.md`](docs/windows-audit.md). It keeps `proposed`, `observed`,
and `verified` states separate and rejects raw setting values and value hashes.
Windows reads are off by default and there is no background agent. Built-in
providers cover HKCU key presence, service runtime/startup state, firewall profile
enablement/rule presence, and the selected long-path policy. Every read requires the
`enabled=True` provider gate. Outputs contain only presence and allowlisted
normalized facts; raw Registry values, service paths, and arbitrary text are never
serialized.

The audit library can also compare before/after presence snapshots and append
strictly validated, summary-only records to opt-in local JSONL history. Category,
verification-state, and ISO-8601 time filters produce static views without
rewriting the stored audit file. See the [Windows audit contract](docs/windows-audit.md)
for the exact trust and privacy boundaries.

```bash
policylatch audit-append --input record.json --history audit.jsonl --enable-history
policylatch audit-report --input audit.jsonl --format html --state verified --output audit.html
```

History HTML is compact and self-contained. Filters are applied explicitly during
generation, so the report keeps the project's no-JavaScript and no-network model.

The complete opt-in Windows flow is also available from the CLI:

```bash
policylatch windows-snapshot --provider service --target SyntheticDemoService \
  --enable-windows-audit --output before.json
policylatch windows-compare --before before.json --after after.json \
  --output comparison.json
policylatch audit-append --input comparison.json --history audit.jsonl --enable-history
```

Snapshot files are always `observed`. A `verified` record must contain a
consistent before/after change and the comparison provenance format emitted by
`windows-compare`; `audit-append` rejects unmarked verified claims. Local history
is strictly validated but is not cryptographically tamper-evident.

## What it checks

- Blocked and review-required shell substrings.
- Sensitive file paths using glob-style matching.
- Blocked, allowed, and unknown network destinations.
- MCP tool names that imply powerful capabilities.
- Tool descriptions containing prompt-injection or exfiltration phrases.
- Sensitive capability terms exposed through a tool's `inputSchema`.

Matching is deterministic and case-insensitive. Plain shell/description patterns
use substring matching, while domain rules use complete-hostname glob matching.
Prefer specific text and hostname patterns; broad values such as `remove` or
`github*` intentionally match a wider surface. A deny finding wins over warn;
otherwise the policy's `default_decision` applies.

## Reports

JSON output is stable and easy to consume in CI:

```json
{
  "schema_version": 1,
  "kind": "action_evaluation",
  "decision": "deny",
  "risk_level": "high",
  "reasons": [
    {
      "rule": "shell.deny_patterns",
      "effect": "deny",
      "matched": "Remove-Item -Recurse",
      "message": "Blocked shell pattern detected."
    }
  ],
  "recommended_action": "Do not execute this proposed action under the current policy."
}
```

Manifest scans also contain an aggregate `decision`, `risk_level`, per-decision counts, and individual tool results. Markdown reports provide a compact decision table and finding list for pull requests, audits, or issue comments.

HTML reports are self-contained visual artifacts with responsive dark/light themes and print styles. They include no JavaScript, external assets, telemetry, or network requests, so a report can be opened directly from disk or attached to a CI artifact.

## Gateway status

The product direction is a local MCP permission gateway:

```text
MCP client -> local gateway -> policy decision -> approval or deny -> MCP server
```

Only the policy-facing pieces exist today. `gateway-check` parses and evaluates
a saved request but always reports `forwarded: false`. A later, separately
reviewed transport layer will wrap an explicitly configured MCP server and
enforce the same decision before forwarding. Calls that do not pass through that
transport cannot be observed or blocked.

## Agent and CI integration

The CLI is the public integration boundary. An agent orchestrator can write its proposed action as JSON, run the guard, parse stdout, and only continue when its own approval logic accepts both the decision and process exit code.

```python
import json
import subprocess

completed = subprocess.run(
    [
        "policylatch",
        "check",
        "--action", "proposed-action.json",
        "--policy", "guard-policy.yaml",
    ],
    capture_output=True,
    check=False,
    text=True,
)
result = json.loads(completed.stdout)

if completed.returncode != 0:
    raise RuntimeError(f"Agent action needs review: {result['decision']}")
```

This example demonstrates decision consumption only. `PolicyLatch` does not run the proposed action. In production, treat malformed output and exit code `3` as a closed gate.

## How it is built

The implementation deliberately stays small:

```text
JSON input -> strict validation -> deterministic matchers -> explained decision -> JSON/Markdown
YAML policy ------^                                      |
                                                         +-> no execution

MCP tools/call -> gateway parser -> tool/argument policy -+
```

- Python standard library for the CLI, models, matching, and reports.
- PyYAML is the only runtime dependency.
- No database, daemon, cloud service, telemetry, or plugin runtime.
- Each rule emits an explicit `warn` or `deny` effect; the engine never infers severity from prose.

## Security model and limitations

`PolicyLatch` evaluates declarations. It does **not**:

- Execute commands, agent actions, or MCP tools.
- Proxy or intercept a live MCP connection.
- Isolate code or provide a runtime sandbox.
- Detect every dangerous command or prompt injection.
- Replace least-privilege configuration and human review.

Treat policy files as code: review them, version them with the project, and start with conservative defaults for sensitive environments. Inputs may contain sensitive material in real workflows; do not publish raw reports without reviewing them.

See [SECURITY.md](SECURITY.md) for the reporting policy and safe reproduction requirements.
The [competitive landscape](docs/competitive-landscape.md) records product-level
lessons and explicit adopt/adapt/reject decisions. Contributions influenced by
adjacent projects must follow the
[clean-room development policy](docs/clean-room-development.md).

## GitHub Action

Use the repository as a composite action to evaluate a checked-in policy and a
JSON action or MCP manifest. It installs `PolicyLatch` from the selected action
revision and does not execute the proposed tool call.

```yaml
- name: Guard proposed agent action
  id: guard
  uses: Tuz34/policylatch@<reviewed-commit-or-release>
  with:
    command: check
    input-file: examples/actions/safe-file-read.json
    policy-file: examples/policies/balanced.yaml
    output-file: artifacts/policylatch.json
    fail-on: deny

- name: Show decision
  run: echo "Decision: ${{ steps.guard.outputs.decision }}"
```

`command` accepts `check`, `scan`, `gateway-check`, or `gateway-replay`. For
gateway commands, `input-file` must point to one saved JSON-RPC `tools/call`
request or a synthetic JSONL trace. Both modes remain no-forward. `fail-on`
accepts `never`, `warn`, or `deny`; malformed input/configuration always fails
with exit code `3`. Pin a reviewed commit until a release tag is available.

For GitHub Code Scanning, generate SARIF without hiding the subsequent upload
step behind a policy decision, then upload the artifact with GitHub's CodeQL
action:

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v7
  - id: guard
    uses: Tuz34/policylatch@<reviewed-commit-or-release>
    with:
      command: scan
      input-file: examples/mcp/risky-server.json
      policy-file: examples/policies/balanced.yaml
      format: sarif
      output-file: artifacts/policylatch.sarif
      fail-on: never
  - uses: github/codeql-action/upload-sarif@v3
    with:
      sarif_file: artifacts/policylatch.sarif
```

SARIF messages intentionally omit the raw `matched` value, and absolute input
paths are reduced to a basename to avoid publishing local path or matched-content
details to Code Scanning.

## Development

```bash
python -m pip install -e ".[dev]"
pytest
ruff check .
ruff format --check .
python -m build
```

The GitHub Actions workflow runs tests, lint, and formatting checks on Python 3.10
and 3.12 across both Ubuntu and Windows. Contributions that add focused rule
types, fixtures, and false-positive tests are welcome.

## Roadmap

- **v0.1 (current MVP):** Policy checks, MCP/tool manifest scanning, explained
  JSON/Markdown/HTML reports, synthetic examples, and cross-platform tests.
- **Current development (unreleased):** No-forward `tools/call` gateway checks
  and bounded synthetic trace replay, explicit tool allow/deny rules, opt-in
  Windows audit snapshots/history, SARIF, the reusable GitHub Action, and thin
  review-first Claude Code/Codex hook adapters.
- **Next gateway milestone:** A narrowly scoped stdio transport wrapper with an
  explicit upstream command, fail-closed limits, synthetic replay tests, and no
  hidden configuration changes.
- **Later:** Local approval workflow, workspace baselines, and an optional policy
  adapter such as OPA/Rego.

The PolicyLatch name is approved and the compatibility migration is under review.
No release/tag or package publication is implied by the current development state.

## License

[MIT](LICENSE)
