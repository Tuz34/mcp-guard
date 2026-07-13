from pathlib import Path

ROOT = Path(__file__).parents[1]


def test_windows_modules_contain_no_mutation_or_command_execution_api():
    forbidden = {
        "StartService",
        "ControlService",
        "ChangeServiceConfig",
        "SetValue",
        "CreateKey",
        "DeleteKey",
        "subprocess",
        "powershell",
        "netsh",
    }
    sources = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted((ROOT / "src/mcp_guard").glob("windows_*.py"))
    )

    assert forbidden.isdisjoint(sources.split())
    for token in forbidden:
        assert token not in sources
