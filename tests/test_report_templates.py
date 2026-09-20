from __future__ import annotations

from reportsmith.reports.templates import (
    platform_list,
    render_report,
    render_report_from_finding,
)


def test_render_hackerone():
    md = render_report("hackerone", {"title": "IDOR test", "vulnerability_type": "idor", "severity": "high"})
    assert "# IDOR test" in md
    assert "Summary" in md
    assert "IDOR test" in md
    assert "sensitive data" in md  # from impact text


def test_render_bugcrowd():
    md = render_report("bugcrowd", {"title": "SSRF test", "vulnerability_type": "ssrf", "severity": "critical"})
    assert "Vulnerability Report:" in md
    assert "SSRF" in md
    assert "Critical" in md  # bugcrowd header includes severity


def test_render_intigriti():
    md = render_report("intigriti", {"title": "XSS test", "vulnerability_type": "xss", "severity": "medium"})
    assert "Security Vulnerability Report" in md
    assert "XSS" in md
    assert "Medium" in md  # intigriti header includes severity


def test_render_immunefi():
    md = render_report(
        "immunefi",
        {
            "title": "Critical Auth Bypass",
            "vulnerability_type": "auth_bypass",
            "severity": "critical",
            "cvss_score": "9.5",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cwe_id": "CWE-288",
            "endpoint": "/api/admin",
        },
    )
    assert "Immunefi Vulnerability Report" in md
    assert "auth_bypass".upper() in md
    assert "CWE-288" in md
    assert "ORION Security Intelligence" in md


def test_render_immunefi_with_poc():
    md = render_report(
        "immunefi",
        {
            "title": "SQLi test",
            "vulnerability_type": "sqli",
            "severity": "critical",
            "poc": {
                "curl": "curl -X GET 'http://example.com?id=1'",
                "nuclei_template": "id: test\ninfo:\n  severity: critical\n",
            },
        },
    )
    assert "cURL" in md
    assert "nuclei_template" not in md  # not in rendered output without the key

    # nuclei should be rendered in immunefi
    import re

    assert re.search(r"Automated Verification", md)


def test_render_with_js_fetch_and_httpie():
    md = render_report(
        "bugcrowd",
        {
            "title": "Test",
            "vulnerability_type": "idor",
            "severity": "medium",
            "poc": {
                "curl": "curl ...",
                "javascript": "fetch(...)",
                "httpie": "http GET ...",
            },
        },
    )
    assert "JavaScript (Fetch API)" in md
    assert "HTTPie" in md
    assert "cURL" in md


def test_render_report_from_finding_minimal():
    data = render_report_from_finding(
        {
            "id": 1,
            "title": "IDOR in profile",
            "description": "Unauthorized access to user data",
            "vulnerability_type": "idor",
            "severity": "high",
            "notes": "",
        }
    )
    assert data["title"] == "IDOR in profile"
    assert data["cvss_score"] != ""
    assert data["cwe_id"] == "CWE-639"


def test_render_report_from_finding_with_endpoint_target():
    data = render_report_from_finding(
        {
            "id": 2,
            "title": "SSRF check",
            "description": "",
            "vulnerability_type": "ssrf",
            "severity": "medium",
            "notes": "",
        },
        endpoint={"path": "/api/fetch", "method": "POST", "parsed_params": {"url": "test"}},
        target={"name": "example", "domain": "example.com"},
    )
    assert data["endpoint"] == "/api/fetch"
    assert data["method"] == "POST"
    assert data["program"] == "example.com"
    assert data["scope_check"] == "In scope — example"


def test_render_report_from_finding_with_notes():
    import json

    data = render_report_from_finding(
        {
            "id": 3,
            "title": "XSS in search",
            "description": "Reflected XSS",
            "vulnerability_type": "xss",
            "severity": "high",
            "notes": json.dumps(
                {"reproduction_steps": ["Go to /search", "Inject <script>"], "business_impact": "Account takeover"}
            ),
        }
    )
    assert "Go to /search" in str(data.get("reproduction_steps", []))


def test_platform_list_includes_immunefi():
    platforms = platform_list()
    assert "immunefi" in platforms
    assert "hackerone" in platforms
    assert "bugcrowd" in platforms
    assert "intigriti" in platforms


def test_render_unknown_platform_raises():
    import pytest

    with pytest.raises(ValueError, match="Unknown platform"):
        render_report("unknown_platform", {})
