# Competitive landscape

PolicyLatch is intentionally narrower than a general MCP security platform. It
is a small, offline, deterministic permission gateway for proposed tool calls.
This document records product-level lessons from adjacent projects without
copying their code, tests, rule text, examples, or architecture.

The review was performed on 2026-07-14 against public repository documentation.
Capabilities are documentation claims, not independent security validation.

## Capability matrix

| Project | Pre-flight | Post-flight | Live proxy | Audit/UI | Identity | Profiles | CI | PolicyLatch decision |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| [SaravanaGuhan/mcp-guard](https://github.com/SaravanaGuhan/mcp-guard) | Repository/server scan | Dynamic testing claim | No | Reports | No | No | SARIF/JUnit claim | Adapt report and gate ergonomics; reject repository download and dynamic execution in core |
| [GenTelLab/MCP-Guard](https://github.com/GenTelLab/MCP-Guard) | Multi-stage request detection | No documented result gate | Framework integration | Benchmark-oriented | No | Detector pipeline | Research workflow | Adapt fast deterministic first stage; reject mandatory neural/LLM arbitration |
| [APK Security Guard MCP Suite](https://github.com/il-il1/APK-Security-Guard-MCP-Suite) | Domain-specific analysis orchestration | Tool-specific results | MCP tool suite | Tool UIs | No | No | Not a core focus | Reject domain tooling; adopt only the principle of a small shared contract around specialized adapters |
| [MCP-Dandan](https://github.com/82ch/MCP-Dandan) | Real-time request inspection | Response/traffic analysis | Yes | Electron dashboard | No | Custom detection settings | No documented reusable action | Adapt clear request/result boundaries; reject desktop/runtime dependencies for the core CLI |
| [CapiscIO demos](https://github.com/capiscio/a2a-demos) | Trust-based tool authorization | Event visibility | Integration gateway | Hosted dashboard/events | DID and badges | Central policy | Demo workflows | Defer identity as a separate adapter; reject required cloud registry/API keys in core |
| [Stallion](https://github.com/efij/secure-claude-code) | Runtime preflight | Output inspection | Runtime integrations | Local audit/status | Local trust tracking | Minimal/balanced/strict | Repository workflows | Adapt profiles, doctor, runtime adapter ergonomics and explicit uninstall; independently specify all behavior |
| [Valet](https://github.com/pedrobraiti/agentic-trading-mcp) | Guard on every order | Structured result envelope | Domain MCP servers | Trade journal/status | Account binding | Environment gates | Tests | Adapt paper/dry-run defaults, real-state verification and cumulative caps; reject trading-specific rules |

Empty or negative cells mean the reviewed public documentation did not establish
that capability. They are not claims that the project cannot support it.

## Independent product decisions

### Adopt

- Deterministic checks before a proposed action crosses an execution boundary.
- Versioned machine-readable contracts and CI-friendly exit codes.
- Installable conservative profiles with a diagnostic command.
- Separate request, result, audit, and runtime-forwarding boundaries.
- Cumulative limits for repeated individually valid operations.

### Adapt

- Runtime adapters stay thin and call the same core evaluator used by the CLI.
- Post-flight inspection starts as a no-forward synthetic evaluator before any
  runtime integration.
- Identity can become an optional evidence provider; it never replaces local
  policy and is not required by the core package.
- Rich UI remains a report surface, not a daemon or source of policy truth.

### Reject from the core

- Automatic repository downloads, dynamic target execution, or fuzzing.
- Mandatory LLM, embedding, cloud registry, account, API key, or telemetry.
- Hidden policy updates or remote policy includes.
- Product claims such as "complete protection", "first", or "enterprise-grade"
  without independently reproducible evidence.
- Domain-specific APK, trading, identity, or malware engines in the base package.

## Positioning rule

Public descriptions should state what PolicyLatch does today and identify future
runtime work as unreleased. Comparisons should describe boundaries, not declare
superiority. A feature inspired by an observed problem must be re-specified as:

1. the general problem;
2. an independent PolicyLatch requirement;
3. synthetic acceptance tests written without consulting competitor tests; and
4. a source note linking only to the product-level documentation.

