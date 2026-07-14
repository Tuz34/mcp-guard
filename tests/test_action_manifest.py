from pathlib import Path

import yaml

ROOT = Path(__file__).parents[1]


def test_composite_action_exposes_a_small_explicit_contract():
    manifest = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))

    assert manifest["runs"]["using"] == "composite"
    assert set(manifest["inputs"]) == {
        "command",
        "input-file",
        "policy-file",
        "format",
        "output-file",
        "fail-on",
        "python-version",
    }
    assert set(manifest["outputs"]) == {"exit-code", "decision", "report-path"}


def test_composite_action_runs_only_the_local_mcp_guard_cli():
    manifest = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))
    steps = manifest["runs"]["steps"]
    scripts = "\n".join(step.get("run", "") for step in steps)

    assert steps[0]["uses"] == "actions/setup-python@v6"
    assert 'pip install "$GITHUB_ACTION_PATH"' in scripts
    assert 'python -m mcp_guard "$MCP_GUARD_COMMAND"' in scripts
    assert "curl" not in scripts
    assert "Invoke-WebRequest" not in scripts
    assert "powershell" not in scripts.lower()
