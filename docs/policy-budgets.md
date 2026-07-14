# Policy budgets

Policy budgets limit cumulative, user-declared impact across deterministic UTC
hour/day windows. They do not execute a tool or verify that a declared impact,
target, payload size, or confirmation is true.

```yaml
budgets:
  hourly_shell_calls:
    metric: calls
    limit: 2
    window: hour
    effect: deny
    action_types: [shell]
    per_tool: true
    count_duplicates: true
```

Metrics are `calls`, numeric `impact`, and `unique_targets`. Rules can scope by
action type, the current tool fingerprint, and payload-size classes
(`small`/`medium`/`large`). Retries count by default so duplicate submission does
not bypass a cap.

## Reservation-first workflow

Budget checks require a receipt-bound proposed-stage journal reservation:

```bash
policylatch check --action action.json --policy policy.yaml --output report.json
policylatch journal-append --input report.json --journal audit.jsonl \
  --stage proposed --enable-journal --output reservation.json
policylatch budget-check --input report.json --journal audit.jsonl \
  --event-id <event_id-from-reservation> --policy policy.yaml
```

The selected policy must match the report's canonical policy hash. The event ID
must identify the same receipt at stage `proposed`. Missing/corrupt/mutating
journal state, a missing/mismatched reservation, non-confirmed state, or a
missing metric dimension produces `deny` with `status: unknown`.

This reservation protocol makes concurrent retries visible before their own
budget decisions. PolicyLatch also compares journal size/mtime before and after
the bounded read and denies if it changed. It is not a distributed transaction;
all callers must follow the same reservation-first boundary.

## Data boundary

An action may provide explicit budget metadata:

```json
{
  "confirmation": "confirmed",
  "impact": 4,
  "payload_bytes": 128,
  "target_id": "opaque-local-target"
}
```

The exact numeric impact is deliberately journaled because cumulative arithmetic
requires it. Payload bytes are reduced to a size class; target and tool IDs are
SHA-256 fingerprints. Raw action commands, paths, domains, target IDs, prompts,
secrets, and payloads are never written to the journal.
