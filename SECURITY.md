# Security policy

## Scope

`mcp-guard` v0 is a static, local policy evaluator. It reads YAML and JSON files and
writes reports. It does not execute proposed actions, invoke MCP tools, connect to MCP
servers, or provide a sandbox.

The experimental Windows audit library API does not change the default CLI behavior.
Windows reads are off by default. Providers can check only explicitly selected
targets after `enabled=True`. State providers may read fixed Registry DWORDs or
query service status, but they never serialize raw Registry values, service paths,
or arbitrary text. They do not write settings, request elevation, execute commands,
or run in the background.
Optional JSONL history writes only validated summary records after a separate
explicit opt-in; it rejects raw values and value hashes.

The following are security-relevant:

- A malformed input or policy bypassing validation.
- A documented deny rule incorrectly returning allow.
- Unexpected file or network access by the CLI.
- Report output that exposes data not present in the supplied input or policy.
- A Windows provider reading before explicit opt-in, querying raw values, changing a
  setting, or reporting an observation as independently verified.
- Audit history accepting undocumented fields or sensitive before/after values.
- A provider accepting an unallowlisted target or emitting a free-form fact value.

Rule coverage gaps and false negatives are important, but they are not proof of a
sandbox escape because v0 is not a sandbox.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting feature when it is available for
the repository. Do not include real credentials, private workspace data, or active
exploit targets. A minimal synthetic reproduction is preferred.

Include:

- Affected version.
- Command and synthetic input needed to reproduce the behavior.
- Expected and actual decision.
- Potential impact.

Do not open a public issue for a vulnerability that could expose users before a fix
is available.

## Safe test data

Tests and examples must remain synthetic. Never commit API keys, credentials, private
keys, tokens, customer data, or reports created from a real sensitive workspace.
