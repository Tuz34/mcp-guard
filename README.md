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
Windows reads are off by default and there is no background agent. The first
built-in provider can report only whether an explicitly named HKCU Registry key
exists, and only through the `enabled=True` provider gate; it never queries a
Registry value. Service, firewall, policy, and broader Registry adapters remain
roadmap work.

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

## Development

```bash
python -m pip install -e ".[dev]"
pytest
ruff check .
ruff format --check .
python -m build
```

The GitHub Actions workflow runs the same checks on Python 3.10 and 3.12. Contributions that add focused rule types, fixtures, and false-positive tests are welcome.

## Roadmap

- **v0.1:** More built-in rule packs, SARIF and HTML reports, reusable GitHub Action.
- **v0.2:** Tool registry scanning, workspace baselines, MCP proxy dry-run mode.
- **Windows audit:** More read-only snapshot providers and Windows CI, built on
  the existing summary-only history and report flow without hidden monitoring.
- **v1:** Optional runtime proxy, approval workflows, and a policy adapter such as OPA/Rego.

## License

[MIT](LICENSE)
