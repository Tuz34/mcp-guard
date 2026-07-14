# Decision receipts

Every new policy evaluation report carries a versioned `receipt` object. The
receipt proves what PolicyLatch decided under a resolved policy; it does **not**
claim that the proposed tool ran.

Receipt v1 contains:

- a SHA-256 hash of canonical resolved policy semantics;
- a fingerprint of a redacted request projection;
- the decision and matched rule IDs/effects;
- profile/include and matched-rule provenance;
- the PolicyLatch evaluator version;
- `execution.claimed: false` and an empty extension object.

There is no timestamp in the canonical content. The same normalized projection,
policy, and decision therefore produce the same fingerprint. Policy or decision
changes produce a different receipt fingerprint.

## Privacy boundary

The request projection records only fixed contract facts such as action type,
recognized field names, capability categories, and record counts. It never
contains raw arguments, prompts, query strings, paths, hostnames, descriptions,
or schema default values. This intentionally creates privacy-preserving
collisions: two requests with the same redacted shape can share a request
fingerprint. The receipt is decision provenance, not a unique event ID.

Extract and revalidate a receipt as JSON or canonical one-line JSONL:

```bash
policylatch receipt --input report.json --format json
policylatch receipt --input report.json --format jsonl --output receipt.jsonl
policylatch schema --kind receipt --output receipt-v1.schema.json
```

Markdown, HTML, and SARIF reports reference the receipt fingerprint. JSON keeps
the complete receipt. `extensions` is reserved for a future opt-in local
signature provider; the MVP manages no key, credential, or crypto secret.
