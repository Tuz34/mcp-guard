import json

from mcp_guard.sarif_report import sarif_document, sarif_report


def _scan_result(source="examples/mcp/risky-server.json"):
    return {
        "schema_version": 1,
        "kind": "manifest_scan",
        "source": source,
        "decision": "deny",
        "risk_level": "high",
        "results": [
            {
                "subject": "synthetic_shell",
                "decision": "warn",
                "risk_level": "medium",
                "reasons": [
                    {
                        "rule": "mcp_tools.warn_if_name_contains",
                        "effect": "warn",
                        "matched": "sensitive synthetic match",
                        "message": "Tool name contains a review keyword.",
                    }
                ],
            },
            {
                "subject": "synthetic_upload",
                "decision": "deny",
                "risk_level": "high",
                "reasons": [
                    {
                        "rule": "mcp_tools.deny_if_description_contains",
                        "effect": "deny",
                        "matched": "send file contents",
                        "message": "Tool description contains a blocked instruction.",
                    }
                ],
            },
        ],
    }


def test_sarif_document_has_github_compatible_core_fields():
    document = sarif_document(_scan_result())
    run = document["runs"][0]

    assert document["$schema"].endswith("sarif-2.1.0.json")
    assert document["version"] == "2.1.0"
    assert run["tool"]["driver"]["name"] == "mcp-guard"
    assert [rule["id"] for rule in run["tool"]["driver"]["rules"]] == [
        "mcp_tools.deny_if_description_contains",
        "mcp_tools.warn_if_name_contains",
    ]
    assert [result["level"] for result in run["results"]] == ["warning", "error"]
    assert run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"] == {
        "uri": "examples/mcp/risky-server.json"
    }


def test_sarif_does_not_publish_matched_content_or_absolute_paths():
    rendered = sarif_report(_scan_result(r"C:\Users\demo\private\manifest.json"))
    document = json.loads(rendered)

    assert "sensitive synthetic match" not in rendered
    assert "send file contents" not in rendered
    assert "C:\\Users" not in rendered
    assert document["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
        "artifactLocation"
    ] == {"uri": "manifest.json"}


def test_sarif_allows_an_empty_result_set_for_allow_decisions():
    document = sarif_document(
        {
            "source": "safe.json",
            "decision": "allow",
            "risk_level": "low",
            "reasons": [],
        }
    )

    assert document["runs"][0]["tool"]["driver"]["rules"] == []
    assert document["runs"][0]["results"] == []
