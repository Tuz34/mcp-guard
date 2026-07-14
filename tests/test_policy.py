from pathlib import Path

import pytest

from policylatch.policy import PolicyError, load_policy

ROOT = Path(__file__).parents[1]


def test_loads_balanced_policy():
    policy = load_policy(ROOT / "examples/policies/balanced.yaml")
    assert policy["version"] == 1
    assert policy["default_decision"] == "allow"


def test_rejects_unknown_version(tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text("version: 2\nrules: {}\n", encoding="utf-8")
    with pytest.raises(PolicyError, match="version 1"):
        load_policy(path)


def test_rejects_unknown_rule_name(tmp_path):
    path = tmp_path / "typo.yaml"
    path.write_text(
        "version: 1\nrules:\n  shell:\n    deny_pattern: ['rm -rf']\n",
        encoding="utf-8",
    )
    with pytest.raises(PolicyError, match="Unknown rule"):
        load_policy(path)


def test_rejects_empty_pattern(tmp_path):
    path = tmp_path / "empty.yaml"
    path.write_text(
        "version: 1\nrules:\n  shell:\n    deny_patterns: ['']\n",
        encoding="utf-8",
    )
    with pytest.raises(PolicyError, match="empty patterns"):
        load_policy(path)
