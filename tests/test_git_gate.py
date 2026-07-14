import json
from pathlib import Path

import pytest

from policylatch.cli import main
from policylatch.git_gate import git_check_document, git_integration_snippet, parse_unified_diff
from policylatch.reports import json_report, validate_report
from policylatch.validation import InputError

ROOT = Path(__file__).parents[1]
POLICY = ROOT / "examples/policies/gateway-strict.yaml"


def modified_diff(path="src/app.py", old="old", new="new", newline="\n"):
    return newline.join(
        [
            f"diff --git a/{path} b/{path}",
            "index 1111111..2222222 100644",
            f"--- a/{path}",
            f"+++ b/{path}",
            "@@ -1 +1 @@",
            f"-{old}",
            f"+{new}",
            "",
        ]
    ).encode()


def test_parser_handles_add_delete_rename_and_binary():
    raw = b"".join(
        [
            b"diff --git a/mcp.json b/mcp.json\nnew file mode 100644\n"
            b"--- /dev/null\n+++ b/mcp.json\n@@ -0,0 +1 @@\n+{}\n",
            b"diff --git a/old.txt b/old.txt\ndeleted file mode 100644\n"
            b"--- a/old.txt\n+++ /dev/null\n@@ -1 +0,0 @@\n-old\n",
            b"diff --git a/old/mcp.json b/new/mcp.json\nsimilarity index 100%\n"
            b"rename from old/mcp.json\nrename to new/mcp.json\n",
            b"diff --git a/image.bin b/image.bin\nindex 1..2 100644\n"
            b"Binary files a/image.bin and b/image.bin differ\n",
        ]
    )
    changes = parse_unified_diff(raw)

    assert [change.status for change in changes] == ["added", "deleted", "renamed", "binary"]
    assert changes[0].category == "mcp-config"
    assert changes[2].old_path == "old/mcp.json"


def test_parser_accepts_crlf_and_quoted_space_path():
    raw = modified_diff("docs/file name.txt", newline="\r\n")
    quoted = (
        raw.replace(
            b"diff --git a/docs/file name.txt b/docs/file name.txt",
            b'diff --git "a/docs/file name.txt" "b/docs/file name.txt"',
        )
        .replace(b"--- a/docs/file name.txt", b'--- "a/docs/file name.txt"')
        .replace(b"+++ b/docs/file name.txt", b'+++ "b/docs/file name.txt"')
    )

    change = parse_unified_diff(quoted)[0]
    assert change.path == "docs/file name.txt"
    assert change.status == "modified"


@pytest.mark.parametrize(
    "raw,match",
    [
        (modified_diff("../secret.txt"), "traversal"),
        (
            b"diff --git a/file.txt b/file.txt\nindex 1..2 100644\n"
            b"--- a/file.txt\n+++ b/file.txt\n",
            "missing a hunk",
        ),
        (
            b"diff --git a/file.txt b/file.txt\n--- a/file.txt\n+++ b/file.txt\n"
            b"@@ -1 +1 @@\n-old\n",
            "truncated",
        ),
    ],
)
def test_parser_rejects_traversal_and_truncated_diff(raw, match):
    with pytest.raises(InputError, match=match):
        parse_unified_diff(raw)


def test_gate_never_copies_added_or_removed_lines():
    marker = "SYNTHETIC_PRIVATE_DIFF_LINE"
    changes = parse_unified_diff(modified_diff(new=marker))
    report = git_check_document(
        changes,
        manifest_evidence=None,
        policy_evidence=None,
        fail_on="warn",
    )
    rendered = json_report(report)

    assert report["decision"] == "allow"
    assert report["gate"]["failed"] is False
    assert marker not in rendered
    assert validate_report(report)


def test_relevant_config_without_evidence_fails_gate():
    changes = parse_unified_diff(modified_diff("mcp.json"))
    report = git_check_document(
        changes,
        manifest_evidence=None,
        policy_evidence=None,
        fail_on="warn",
    )
    assert report["decision"] == "deny"
    assert report["gate"]["failed"] is True


def test_binary_and_unknown_metadata_never_become_allow():
    binary = parse_unified_diff(
        b"diff --git a/image.bin b/image.bin\nBinary files a/image.bin and b/image.bin differ\n"
    )
    binary_report = git_check_document(
        binary, manifest_evidence=None, policy_evidence=None, fail_on="warn"
    )
    unknown = parse_unified_diff(
        b"diff --git a/src/app.py b/src/app.py\nsynthetic unknown metadata\n"
    )
    unknown_report = git_check_document(
        unknown, manifest_evidence=None, policy_evidence=None, fail_on="warn"
    )

    assert binary_report["decision"] == "deny"
    assert unknown_report["decision"] == "warn"
    assert binary_report["gate"]["failed"] is True
    assert unknown_report["gate"]["failed"] is True


def test_git_check_cli_reuses_clean_manifest_scan(tmp_path):
    diff = tmp_path / "change.diff"
    diff.write_bytes(modified_diff("mcp.json"))
    manifest = tmp_path / "mcp.json"
    manifest.write_text(
        json.dumps(
            {
                "tools": [
                    {
                        "name": "read_file",
                        "description": "synthetic",
                        "inputSchema": {"type": "object"},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    output = tmp_path / "gate.json"
    code = main(
        [
            "git-check",
            "--diff",
            str(diff),
            "--manifest",
            str(manifest),
            "--policy",
            str(POLICY),
            "--output",
            str(output),
        ]
    )

    assert code == 0
    assert json.loads(output.read_text(encoding="utf-8"))["decision"] == "allow"


def test_manifest_evidence_basename_must_match_changed_path(tmp_path):
    diff = tmp_path / "change.diff"
    diff.write_bytes(modified_diff("mcp.json"))
    manifest = tmp_path / "different.json"
    manifest.write_text('{"tools":[{"name":"read_file","inputSchema":{}}]}', encoding="utf-8")
    code = main(
        [
            "git-check",
            "--diff",
            str(diff),
            "--manifest",
            str(manifest),
            "--policy",
            str(POLICY),
        ]
    )
    assert code == 2


def test_git_check_cli_reuses_policy_diff(tmp_path):
    diff = tmp_path / "policy.diff"
    diff.write_bytes(modified_diff("examples/policies/gateway-strict.yaml"))
    output = tmp_path / "gate.sarif"
    code = main(
        [
            "git-check",
            "--diff",
            str(diff),
            "--policy-before",
            str(POLICY),
            "--policy-after",
            str(POLICY),
            "--fixtures",
            str(ROOT / "examples/policy-tests"),
            "--format",
            "sarif",
            "--output",
            str(output),
        ]
    )

    assert code == 0
    assert json.loads(output.read_text(encoding="utf-8"))["version"] == "2.1.0"


def test_snippets_are_review_first_and_never_auto_install():
    for kind in ("pre-commit", "github-actions"):
        snippet = git_integration_snippet(kind)
        assert "policylatch git-check --diff" in snippet
        assert "git diff" in snippet
        assert "pre-commit install" not in snippet
        assert "git config" not in snippet

    implementation = (ROOT / "src/policylatch/git_gate.py").read_text(encoding="utf-8")
    assert "import subprocess" not in implementation
    assert "os.system" not in implementation


@pytest.mark.parametrize(
    "format_name,extension", [("json", "json"), ("markdown", "md"), ("sarif", "sarif")]
)
def test_git_check_cli_supports_all_reports(tmp_path, format_name, extension):
    diff = tmp_path / "source.diff"
    diff.write_bytes(modified_diff("src/app.py"))
    output = tmp_path / f"gate.{extension}"
    code = main(
        [
            "git-check",
            "--diff",
            str(diff),
            "--format",
            format_name,
            "--output",
            str(output),
        ]
    )
    assert code == 0
    assert output.exists()


def test_git_snippet_cli_only_writes_requested_artifact(tmp_path):
    output = tmp_path / "snippet.yaml"
    assert (
        main(
            [
                "git-snippet",
                "--kind",
                "pre-commit",
                "--output",
                str(output),
            ]
        )
        == 0
    )
    assert "policylatch git-check" in output.read_text(encoding="utf-8")
