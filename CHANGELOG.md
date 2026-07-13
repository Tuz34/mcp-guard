# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Self-contained, responsive HTML reports with no scripts or external assets.
- Experimental, summary-only Windows audit record contract with synthetic
  fixtures and strict proposed/observed/verified trust states. This foundation
  performs no system reads.
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
- Allowlisted normalized audit facts for service runtime, service startup,
  firewall profile, and selected policy state without raw values.
- Read-only service runtime/startup, firewall profile, and long-path policy
  providers with explicit target allowlists and fail-closed error handling.
- `windows-snapshot` and `windows-compare` CLI commands for an explicit,
  summary-only collection and verification workflow.

### Fixed

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
