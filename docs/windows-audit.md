# Windows audit contract (experimental)

The Windows audit foundation defines how `mcp-guard` can describe a requested or
detected Windows setting change without storing the setting value. It is an
explicit, opt-in capability under development.

> [!IMPORTANT]
> Windows reads are **off by default**. There is no background process, command
> execution, elevation, remediation, telemetry, or network access. The contract
> parser only validates an in-memory JSON-compatible object. The optional
> Registry provider described below performs one narrow read only after explicit
> opt-in.

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
  "source": "synthetic_snapshot_comparison",
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

`before` and `after` deliberately contain presence only. The normalized record
adds `redacted: true` to both summaries. Raw values and value hashes are rejected,
because hashes can still disclose low-entropy settings through guessing. Unknown
fields are also rejected so an adapter cannot silently leak data through an
undocumented property.

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
only a redacted `StateSummary`. Their result is always labeled `observed`; a
provider cannot claim independent verification.

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
Registry. Service, firewall, policy, and Registry-value adapters remain
unimplemented.

## Presence comparison

`compare_windows_snapshots` accepts a before and after observation for the same
category and target. When both presence states are known, the resulting record is
`verified`; an unknown state remains `observed`. A matching `proposed` record can
be supplied to carry the declared operation, actor, and tool into the comparison.

The comparison is intentionally narrow. It can verify that a target appeared,
disappeared, or kept the same **presence**. Two `present: true` snapshots do not
prove that a hidden Registry value or service configuration stayed unchanged.
The engine therefore never infers an `updated` change from presence-only data.

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

Service, firewall, and selected policy providers plus Windows CI remain the next
adapter work. They will use the same validated history and report boundary.

All examples in [`examples/windows-audit`](../examples/windows-audit) are
synthetic and contain no user or machine data.
