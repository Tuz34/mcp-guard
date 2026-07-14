# Contributing

Thanks for helping PolicyLatch make agent tool use easier to review.

## Design principles

- Keep decisions deterministic and explainable.
- Reject invalid input instead of guessing intent.
- Do not add tool execution, network calls, or hidden side effects to v0.
- Prefer focused rules over large frameworks.
- Use only synthetic fixtures in tests and documentation.
- Add false-positive coverage with every broad new rule.

## Local setup

```bash
python -m venv .venv
python -m pip install -e ".[dev]"
pytest
ruff check .
```

## Pull requests

Keep changes small enough to review. Explain the user-visible decision behavior and
include tests for allow, warn, deny, and invalid input where applicable. Update the
policy reference when adding or changing a rule key.

If adjacent open-source work influenced a feature, follow the
[clean-room development policy](docs/clean-room-development.md). Record the public
documentation source and the independently written requirement; do not copy rule
text, fixtures, tests, prose, or implementation.

By contributing, you agree that your contribution is licensed under the MIT License.
