# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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
