# mcp-guard

**A local-first permission firewall for MCP tools and AI agents.**

Stop risky MCP tools before your agent runs them. `mcp-guard` is a small Python CLI that checks proposed agent actions and MCP tool manifests against a readable YAML policy. Think of it as a pre-flight safety check for AI agent tool calls.

> [!IMPORTANT]
> v0 never executes an action or calls an MCP tool. It is a policy evaluator, not a sandbox and not a replacement for human approval.

## Why?

AI agents can request shell, filesystem, network, and database capabilities. Reviewing each request by eye does not scale, while full runtime isolation is often too heavy for a development workflow. `mcp-guard` provides a deterministic local checkpoint:

```text
proposed action / MCP manifest -> local YAML policy -> ALLOW | WARN | DENY
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

The installed `mcp-guard` command and `python -m mcp_guard` are equivalent.

Evaluate a proposed agent action:

```bash
mcp-guard check \
  --action examples/actions/risky-shell-command.json \
  --policy examples/policies/balanced.yaml \
  --format markdown
```

Expected decision:

```text
Overall decision: DENY

DENY shell.deny_patterns matched Remove-Item -Recurse
```

Scan an MCP tool manifest and save machine-readable output:

```bash
mcp-guard scan \
  --mcp-config examples/mcp/risky-server.json \
  --policy examples/policies/balanced.yaml \
  --output scan-result.json
```

Turn a saved JSON result into a review artifact:

```bash
mcp-guard report --input scan-result.json --format markdown --output report.md
mcp-guard report --input scan-result.json --format html --output report.html
```

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

Three complete policy profiles live in [`examples/policies`](examples/policies): `balanced`, `strict`, and `ci`. See the [policy reference](docs/policy-reference.md) for exact matching and precedence rules. Unknown policy fields are rejected instead of silently ignored.

## Input formats

An action is a JSON object. Fields used by v0 depend on `action_type`:

| Type | Inspected field | Example |
|---|---|---|
| `shell` | `command` | A proposed CLI command |
| `file` / `filesystem` | `path` | A proposed file target |
| `network` | `url` or `domain` | A proposed destination |

An MCP manifest uses a top-level `tools` array (or `server.tools`). Each tool may provide `name`, `description`, and `inputSchema`. Common client configs with an `mcpServers` mapping are also supported; their declared `command` and `args` are checked as text. The scanner does not connect to an MCP server.

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
mcp-guard audit-append --input record.json --history audit.jsonl --enable-history
mcp-guard audit-report --input audit.jsonl --format html --state verified --output audit.html
```

History HTML is compact and self-contained. Filters are applied explicitly during
generation, so the report keeps the project's no-JavaScript and no-network model.

The complete opt-in Windows flow is also available from the CLI:

```bash
mcp-guard windows-snapshot --provider service --target SyntheticDemoService \
  --enable-windows-audit --output before.json
mcp-guard windows-compare --before before.json --after after.json \
  --output comparison.json
mcp-guard audit-append --input comparison.json --history audit.jsonl --enable-history
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

Matching is deterministic and case-insensitive. A deny finding wins over warn; otherwise the policy's `default_decision` applies.

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

## Agent and CI integration

The CLI is the public integration boundary. An agent orchestrator can write its proposed action as JSON, run the guard, parse stdout, and only continue when its own approval logic accepts both the decision and process exit code.

```python
import json
import subprocess

completed = subprocess.run(
    [
        "mcp-guard",
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

This example demonstrates decision consumption only. `mcp-guard` does not run the proposed action. In production, treat malformed output and exit code `3` as a closed gate.

## How it is built

The implementation deliberately stays small:

```text
JSON input -> strict validation -> deterministic matchers -> explained decision -> JSON/Markdown
YAML policy ------^                                      |
                                                         +-> no execution
```

- Python standard library for the CLI, models, matching, and reports.
- PyYAML is the only runtime dependency.
- No database, daemon, cloud service, telemetry, or plugin runtime.
- Each rule emits an explicit `warn` or `deny` effect; the engine never infers severity from prose.

## Security model and limitations

`mcp-guard` evaluates declarations. It does **not**:

- Execute commands, agent actions, or MCP tools.
- Proxy or intercept a live MCP connection.
- Isolate code or provide a runtime sandbox.
- Detect every dangerous command or prompt injection.
- Replace least-privilege configuration and human review.

Treat policy files as code: review them, version them with the project, and start with conservative defaults for sensitive environments. Inputs may contain sensitive material in real workflows; do not publish raw reports without reviewing them.

See [SECURITY.md](SECURITY.md) for the reporting policy and safe reproduction requirements.

## GitHub Action

Use the repository as a composite action to evaluate a checked-in policy and a
JSON action or MCP manifest. It installs `mcp-guard` from the selected action
revision and does not execute the proposed tool call.

```yaml
- name: Guard proposed agent action
  id: guard
  uses: Tuz34/mcp-guard@<reviewed-commit-or-release>
  with:
    command: check
    input-file: examples/actions/safe-file-read.json
    policy-file: examples/policies/balanced.yaml
    output-file: artifacts/mcp-guard.json
    fail-on: deny

- name: Show decision
  run: echo "Decision: ${{ steps.guard.outputs.decision }}"
```

`command` accepts `check` or `scan`. `fail-on` accepts `never`, `warn`, or
`deny`; malformed input/configuration always fails with exit code `3`. Pin a
reviewed commit until a release tag is available.

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
    uses: Tuz34/mcp-guard@<reviewed-commit-or-release>
    with:
      command: scan
      input-file: examples/mcp/risky-server.json
      policy-file: examples/policies/balanced.yaml
      format: sarif
      output-file: artifacts/mcp-guard.sarif
      fail-on: never
  - uses: github/codeql-action/upload-sarif@v3
    with:
      sarif_file: artifacts/mcp-guard.sarif
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
- **v0.2.0 (next, not released):** Opt-in Windows audit snapshots/history,
  SARIF output, and a reusable GitHub Action. The release remains blocked on a
  green cross-platform CI run and final review.
- **v0.3:** Tool registry scanning and workspace risk baselines, still without
  executing agent actions.
- **v1:** Optional runtime proxy/dry-run interception, approval workflows, and a
  policy adapter such as OPA/Rego.

## License

[MIT](LICENSE)
