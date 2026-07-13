# Windows audit contract (experimental)

The Windows audit foundation defines how `mcp-guard` can describe a requested or
detected Windows setting change without storing the setting value. It is an
explicit, opt-in capability under development.

> [!IMPORTANT]
> Windows reads are **off by default**. There is no background process, command
> execution, elevation, remediation, telemetry, or network access. The contract
> parser only validates an in-memory JSON-compatible object. The optional
> providers described below perform narrow reads only after explicit opt-in.

## Trust states

Every record carries exactly one verification state:

- `proposed`: an agent or tool declared an intended change.
- `observed`: a named read-only source reported a state; it is not independently
  proven.
- `verified`: known before and after snapshots were compared consistently.

An `observed` record is never promoted to `verified`. The producer must create a
new verified record from an independent comparison.

## Summary-only input

```json
{
  "action_type": "windows_setting",
  "timestamp": "2026-01-15T10:02:00Z",
  "verification_state": "verified",
  "source": "snapshot_comparison:synthetic_registry_provider->synthetic_registry_provider",
  "category": "registry",
  "target": "HKCU\\Software\\SyntheticDemo\\Theme",
  "operation": "compare_setting_presence",
  "change": "created",
  "before": {"present": false},
  "after": {"present": true},
  "actor": "demo-agent",
  "tool": "synthetic-registry-adapter"
}
```

Supported categories are `registry`, `service`, `firewall`, `policy`, and
`setting`. Change kinds are `created`, `updated`, `deleted`, `unchanged`, and
`unknown`. Timestamps must include a UTC offset or `Z` suffix.

`before` and `after` always contain presence and may contain only allowlisted,
normalized facts: `runtime_state`, `startup_type`, and `policy_state`. Their values
are closed enums such as `running`, `automatic`, or `enabled`; arbitrary text is
rejected. The normalized record adds `redacted: true` to both summaries. Raw values
and value hashes are rejected because hashes can still disclose low-entropy
settings through guessing. Unknown fields are also rejected so an adapter cannot
silently leak data through an undocumented property.

The pure parser is available to integrations:

```python
from mcp_guard.windows_audit import parse_windows_setting_action

record = parse_windows_setting_action(action)
document = record.to_dict()
```

Parsing does not inspect the host and does not evaluate policy. The existing
`mcp-guard check` command continues to support its documented shell, file, and
network action types only.

## Opt-in provider boundary

`collect_windows_snapshot` is the single call gate for future read-only providers.
Its `enabled` keyword is required and only the literal value `True` opens the gate.
When disabled, it does not inspect the platform or call provider code. When
enabled outside Windows, it returns a clear `UnsupportedPlatformError` without
calling the provider.

Providers implement the small `WindowsSnapshotProvider` protocol and may return
only a redacted `StateSummary` with the allowlisted facts above. Their result is
always labeled `observed`; a provider cannot claim independent verification.

### Registry key-presence provider

`RegistryKeyPresenceProvider` is the first deliberately narrow built-in adapter.
It accepts `HKCU` / `HKEY_CURRENT_USER` key paths and reports only whether the key
exists. It calls `winreg.OpenKey` with `KEY_READ` and closes the handle; it never
calls a Registry value query or write API. Missing keys, access-denied errors, and
other OS errors remain distinct outcomes.

```python
from mcp_guard.windows_providers import collect_windows_snapshot
from mcp_guard.windows_registry import RegistryKeyPresenceProvider

snapshot = collect_windows_snapshot(
    RegistryKeyPresenceProvider(),
    "HKCU\\Software\\SyntheticDemo",
    enabled=True,
)
```

There is no automatic discovery path. Importing the module does not read the
Registry or Service Control Manager.

### Service providers

`ServiceRuntimeProvider` uses the Windows Service Control Manager query API through
`ctypes`. It requests `SERVICE_QUERY_STATUS` only and normalizes documented runtime
states; it never starts, stops, pauses, or reconfigures a service.

`ServiceStartupProvider` reads only the selected service's allowlisted `Start`
DWORD and maps values `0..4` to `boot`, `system`, `automatic`, `manual`, or
`disabled`. Service names are validated before any Windows access.

### Firewall and selected policy providers

`FirewallProfileProvider` accepts only `domain`, `private`, or `public` and reads
the corresponding allowlisted `EnableFirewall` DWORD. `LongPathsPolicyProvider`
accepts only `long_paths_enabled` and reads the allowlisted `LongPathsEnabled`
DWORD. Both normalize `0/1` to `disabled/enabled`; other values fail closed.

`FirewallRulePresenceProvider` checks only one explicitly supplied rule ID under
the fixed `FirewallRules` key. It does not enumerate rules and discards the queried
rule content immediately; output contains presence only. Rule IDs use a narrow
character allowlist.

These providers query only fixed key/value names owned by their implementation.
There is no arbitrary Registry-value reader. Missing, not-configured,
access-denied, invalid-type, and unexpected-value outcomes remain distinct.
HKLM state providers request the 64-bit Registry view when Windows exposes it.

## Presence comparison

`compare_windows_snapshots` accepts a before and after observation for the same
category and target. When both presence states are known, the resulting record is
`verified`; an unknown state remains `observed`. A matching `proposed` record can
be supplied to carry the declared operation, actor, and tool into the comparison.

The comparison is intentionally conservative. It can verify that a target
appeared, disappeared, or kept the same presence. When both snapshots have the
same normalized fact keys, it can verify whether those safe facts changed. A
different fact shape remains `observed/unknown`; the engine never guesses about
hidden Registry values or uncollected service configuration.

## Explicit snapshot and comparison CLI

Collecting a Windows snapshot requires the opt-in flag. Without it, platform and
provider code are not called:

```bash
mcp-guard windows-snapshot \
  --provider service \
  --target SyntheticDemoService \
  --enable-windows-audit \
  --output before.json
```

Provider choices are `registry-key`, `service`, `firewall`, `firewall-rule`, and
`long-paths`. The service provider returns runtime and startup facts together.
Firewall profile targets are `domain`, `private`, or `public`; `firewall-rule`
accepts one rule ID; the long-path provider accepts only `long_paths_enabled`.

Two saved observations can be compared without another Windows read:

```bash
mcp-guard windows-compare \
  --before before.json \
  --after after.json \
  --output comparison.json
```

An optional `--proposed` action carries the declared operation, actor, and tool
into the comparison. Saved snapshots are strictly revalidated and cannot claim
`verified`. Verified records must carry the comparison provenance format emitted
by `windows-compare`; `audit-append` rejects unmarked verified claims.

## Local JSONL history

Summary-only records can be appended to a local JSONL file after a separate
explicit opt-in:

```python
from mcp_guard.windows_history import append_audit_record, load_audit_history

append_audit_record("audit.jsonl", record, enabled=True)
records = load_audit_history("audit.jsonl")
```

Every line is strictly revalidated on write and read. Unknown fields, raw values,
value hashes, malformed JSON, oversized lines, and histories above the configured
record limit fail closed with a line-specific error. Loading never changes the
file.

The comparison marker is a local workflow invariant, not a cryptographic
signature. A user who can edit the JSONL file can also alter its contents;
`mcp-guard` does not claim tamper-evident storage.

`filter_audit_history` creates a static view by category, verification state, and
inclusive ISO-8601 time range. Filtering does not rewrite the stored history. See
[`synthetic-history.jsonl`](../examples/windows-audit/synthetic-history.jsonl) for
a synthetic two-record example.

## CLI history workflow

Append a validated action or normalized audit record. The explicit history flag
is required; without it, no file is created or changed:

```bash
mcp-guard audit-append \
  --input examples/windows-audit/verified-registry-change.json \
  --history output/windows-audit.jsonl \
  --enable-history
```

Generate a filtered JSON or compact HTML view:

```bash
mcp-guard audit-report \
  --input output/windows-audit.jsonl \
  --format html \
  --category registry \
  --state verified \
  --from 2026-01-01T00:00:00Z \
  --to 2026-12-31T23:59:59Z \
  --output output/windows-audit.html
```

Filters are applied during generation and listed in the report. The self-contained
HTML contains no JavaScript, external assets, telemetry, or network requests. An
empty filter result produces an explicit empty table instead of failing or showing
unfiltered data.

All providers use the same validated history and report boundary. Additional
Windows surfaces, if any, must be separately allowlisted in later versions.

All examples in [`examples/windows-audit`](../examples/windows-audit) are
synthetic and contain no user or machine data.

The default test suite uses synthetic backends. A separate Windows CI step sets
`MCP_GUARD_WINDOWS_INTEGRATION=1` and performs read-only checks against the fixed
`EventLog` service, `HKCU\Control Panel\Desktop`, the public firewall profile,
and the long-path policy. This validates the ctypes structure and 64-bit HKLM
Registry view on a disposable GitHub-hosted runner without changing system state.
