# Clean-room development policy

PolicyLatch may learn from public product behavior while keeping its
implementation independently designed and reviewable.

## Allowed research

- Public README, user documentation, release notes, papers, specifications, and
  product demos.
- High-level capability comparisons such as pre-flight checks, profiles, audit,
  CI integration, or runtime proxying.
- License and provenance metadata used to decide whether a source can be linked.

## Prohibited reuse

- Copying or lightly rewriting competitor source code, rule packs, regexes,
  schemas, tests, fixtures, README prose, screenshots, or diagrams.
- Installing, vendoring, or executing a competitor package to harvest behavior
  unless a separate issue documents the license, threat model, and explicit user
  approval.
- Treating generated output from another project as a PolicyLatch fixture.
- Presenting a competitor claim as independently verified fact.

## Required provenance note

An issue or pull request influenced by adjacent work records:

- source URL and access date;
- the general problem learned from the source;
- the independent requirement and acceptance criteria;
- adopt, adapt, defer, or reject decision; and
- confirmation that fixtures and implementation were written from the local
  requirement, not translated from the source.

Use this compact template:

```text
Source: <public documentation URL>, accessed YYYY-MM-DD
Problem: <general user or security problem>
Decision: adopt | adapt | defer | reject
Independent requirement: <PolicyLatch behavior>
Clean-room check: no source code, rules, tests, fixtures, or prose reused
```

## Review gate

Before merge, the reviewer checks that new public claims are supportable, all
fixtures are synthetic, no new network or execution boundary appeared silently,
and copied wording or unexplained rule material is absent. If provenance is
unclear, the change stays out until it can be independently specified.

