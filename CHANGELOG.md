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
