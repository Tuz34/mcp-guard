# Agent action journal

The general action journal is separate from Windows audit history. It is an
explicitly enabled, append-only JSONL record of PolicyLatch decision receipts.
It never stores raw actions, prompts, file contents, tool output, credentials,
paths, hostnames, or query strings.

```bash
policylatch journal-append \
  --input report.json \
  --journal local-audit.jsonl \
  --stage evaluated \
  --enable-journal
```

Each record contains stable request/event fingerprints, receipt and policy
hashes, decision, evaluator version, rule IDs, normalized UTC time, and replay
metadata. Action evaluations also carry a one-way, value-aware action
fingerprint plus explicit numeric impact, redacted tool/target, and payload-size
budget facts. Raw action values are hashed in memory and are never written.
Lifecycle stages are `proposed`, `evaluated`, and `observed-result`.
They are caller assertions; every record remains `verification_state:
unverified`, and an observed-result record stores no result body.

Appending requires `--enable-journal`. Existing lines are strictly revalidated
before a bounded single-write append and `fsync`. Line, total-byte, record-count,
time-window, and incomplete-final-line limits fail closed.

## Replay check

```bash
policylatch journal-check \
  --input report.json \
  --journal local-audit.jsonl \
  --window-seconds 300
```

A matching redacted request fingerprint and, for action evaluations, matching
value-aware action fingerprint inside the window produces `warn`.
When the journal does not exist, PolicyLatch does not pretend the action is new:
it returns `warn` with `status: source-unavailable` and does not create a file.
Legacy or non-action records without a value-aware fingerprint retain the
conservative shape-based comparison. A duplicate remains a review signal rather
than proof that two raw requests were byte-identical.

## Static reports

```bash
policylatch journal-report --input local-audit.jsonl --format json
policylatch journal-report --input local-audit.jsonl --format html \
  --stage observed-result --duplicate true --output action-journal.html
```

Filters include stage, decision, duplicate flag, and an ISO-8601 time range. The
HTML output is self-contained and contains no JavaScript or external assets.
PolicyLatch never executes or replays the proposed action.
