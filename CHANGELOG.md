# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Planned for `0.2.0`. No tag or release has been created; publication requires a
green cross-platform CI run and final review.

### Changed

- Renamed the project, Python distribution, primary package, and CLI to
  **PolicyLatch** / `policylatch`.
- Kept the former `mcp-guard` CLI, `python -m mcp_guard`, `mcp_guard.*` imports,
  and `MCP_GUARD_WINDOWS_INTEGRATION` environment variable as transition aliases.
- Made `POLICYLATCH_WINDOWS_INTEGRATION` authoritative when both environment
  variable spellings are present.

### Added

- Offline policy contract tests, JSON/SARIF semantic lint, and versioned JSON
  Schema export for policies, actions, gateway requests, and reports.
- Review-first Claude Code and Codex `PreToolUse` adapters with bounded event
  normalization, data-minimized decisions, generated config snippets, offline
  doctor checks, and explicit blocking-versus-advisory capability labels.
- Built-in `minimal`, `balanced`, `strict`, and `ci` policy profiles; bounded
  local-only inheritance; policy provenance; and offline `doctor`/`explain`
  commands.
- Competitive capability matrix and a clean-room development policy that
  records product-level provenance without reusing third-party implementation,
  rules, tests, fixtures, or prose.
- Experimental `gateway-check` command for one MCP JSON-RPC `tools/call`
  request. It is strictly no-forward, starts no upstream process, and omits raw
  tool arguments from its decision output.
- MCP tool-name `allow_names` and `deny_names` policy rules with complete,
  case-insensitive glob matching.
- Default-deny synthetic gateway policy, safe/denied request fixtures, and an
  explicit gateway trust/bypass contract.
- Composite GitHub Action support for synthetic no-forward `gateway-check` runs.
- Bounded no-forward `gateway-replay` for synthetic JSONL traces, with per-line,
  total-size, record-count, identifier, and nesting limits.
- Versioned MCP protocol baseline and a documented stdio threat model covering
  bypass, confused-deputy, replay, task lifecycle, backpressure, cleanup, and
  fail-closed invariants.
- Reusable composite GitHub Action for `check` and `scan`, with explicit decision,
  exit-code, report-path, and fail-threshold outputs.
- Deterministic SARIF 2.1.0 reports for GitHub Code Scanning, with deduplicated
  rules and data-minimized messages/locations.
- Self-contained, responsive HTML reports with no scripts or external assets.
- Experimental, summary-only Windows audit record contract with synthetic
  fixtures and strict proposed/observed/verified trust states. This foundation
  parser performs no system reads.
- Explicit opt-in provider interface that stays closed before platform or provider
  access and cannot label a provider observation as verified.
- Narrow HKCU Registry key-presence provider that uses read-only key access and
  never queries or writes Registry values.
- Summary-only snapshot comparison with conservative verification semantics.
- Strict, opt-in local JSONL audit history with category, trust-state, and time
  filtering.
- `audit-append` and `audit-report` CLI commands with compact, script-free HTML
  history output and explicit static filters.
- GitHub Actions coverage for Python 3.10 and 3.12 on both Ubuntu and Windows,
  with read-only repository permissions and fail-fast disabled.
- Explicitly opt-in, read-only Windows integration checks for fixed service,
  HKCU, firewall-profile, and policy targets on GitHub-hosted Windows runners.
- Allowlisted normalized audit facts for service runtime, service startup,
  firewall profile, and selected policy state without raw values.
- Read-only service runtime/startup, firewall profile, and long-path policy
  providers with explicit target allowlists and fail-closed error handling.
- Firewall rule-presence provider for one explicitly supplied rule ID, with no
  enumeration and no rule-content output.
- `windows-snapshot` and `windows-compare` CLI commands for an explicit,
  summary-only collection and verification workflow.

### Fixed

- Gateway checks now flag unknown top-level arguments even when a recognized
  capability is present, and reject calls with two conflicting network targets.
- Allowlist-miss findings no longer copy a raw destination hostname into JSON,
  Markdown, HTML, or gateway replay output.
- The reusable Action now rejects multiline report paths before writing step
  outputs and emits output values with fixed `printf` formats.
- Single-document JSON and YAML policy reads are bounded before parsing, and
  Windows snapshots now reuse one normalized collection timestamp.
- Verified Windows audit records now require the comparison provenance format
  `snapshot_comparison:<before-source>-><after-source>`; unmarked verified claims
  are rejected by `audit-append`.
- Oversized JSONL records are bounded during reads, and Registry/service handle
  cleanup failures no longer hide the original provider read error.
- The service cleanup regression test now installs the Windows-only
  `ctypes.get_last_error` test double portably on non-Windows runners.
- Third-party Windows provider summaries are revalidated before snapshot output,
  preventing unallowlisted fact keys or free-form values from escaping.
- Top-level paths now match `**/` policy patterns, preventing sensitive paths such
  as `secrets/...` and `id_rsa` from bypassing deny rules.
- Sensitive path globs now respect path-segment boundaries, avoiding false denies
  for names such as `mysecrets/...`.
- Non-string network `url` and `domain` values now return a clean input error instead
  of raising an uncaught `TypeError`.

## [0.1.0] - 2026-07-13

### Added

- Python CLI with `check`, `scan`, and `report` commands.
- Strict YAML policy validation with allow, warn, and deny decisions.
- Shell, file, network, MCP description, tool name, and input schema checks.
- Common `tools`, `server.tools`, and `mcpServers` input support.
- Versioned JSON output, Markdown reports, and automation-friendly exit codes.
- Synthetic policies, actions, manifests, tests, and GitHub Actions workflow.
