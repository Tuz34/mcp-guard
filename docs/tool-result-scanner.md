# Tool result scanner

`result-scan` is a deterministic post-flight check for a saved or synthetic tool
result. It does not execute a tool, intercept runtime traffic, or feed the result
into another agent step.

```bash
policylatch result-scan \
  --input examples/tool-results/malicious.json \
  --format html \
  --output tool-result.html
```

The versioned `tool_result` v1 contract requires request/result correlation IDs,
a tool identifier, and a caller-declared source trust level. Optional content,
string fields, and expected domains are bounded by total input, content, line,
field-count, field-name, field-value, and domain-count limits. Unknown top-level
fields are rejected rather than ignored.

## Outcomes

The primary post-flight result is:

- `clean`: no deterministic signal found;
- `review`: a PII-like field name or unexpected external URL needs review;
- `block-next-step`: prompt-injection, secret-like, or exfiltration-direction
  signal means the result should not enter another tool/agent step.

The report also carries allow/warn/deny solely for existing report renderers and
automation exit codes. Source trust is a caller assertion, not verification, and
all trust levels receive the same scan.

## Data minimization

Raw content, field values/names, IDs, URLs, hostnames, and matched text are never
copied into JSON, Markdown, HTML, SARIF, or the decision receipt. Correlation IDs,
tool ID, and finding locations are represented as deterministic SHA-256
fingerprints. Messages contain only fixed category text.

Expected domain values are used in memory to classify URLs and are omitted from
reports. The scanner is rule-based and offline; it does not claim to detect every
credential, personal-data shape, or instruction-smuggling attempt.
