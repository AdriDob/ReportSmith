"""Tests for Report Critic — pre-submission quality gate."""

from __future__ import annotations

from reportsmith.reports.critic import CriticCheck, CriticResult, ReportCritic


def test_critic_check_defaults():
    c = CriticCheck(name="test", description="A test check")
    assert c.passed is False
    assert c.weight == 1.0
    assert c.notes == ""
    assert c.score == 0.0

    c.passed = True
    assert c.score == 1.0


def test_critic_check_weighted():
    c = CriticCheck(name="important", description="Important", weight=2.0)
    assert c.score == 0.0
    c.passed = True
    assert c.score == 2.0


def test_critic_result_defaults():
    r = CriticResult()
    assert r.score == 0.0
    assert r.max_score == 0.0
    assert r.checks == []
    assert r.suggestions == []
    assert r.verdict == "unknown"
    assert r.to_dict()["percentage"] == 0.0


def test_critic_result_to_dict():
    c = CriticCheck(name="check1", description="desc", passed=True, weight=2.0)
    r = CriticResult(score=8.0, max_score=10.0, checks=[c], suggestions=["fix it"], verdict="needs_improvement")
    d = r.to_dict()
    assert d["score"] == 8.0
    assert d["max_score"] == 10.0
    assert d["percentage"] == 80.0
    assert d["verdict"] == "needs_improvement"
    assert d["suggestions"] == ["fix it"]
    assert len(d["checks"]) == 1
    assert d["checks"][0]["name"] == "check1"


def test_poor_finding_verdict():
    critic = ReportCritic()
    result = critic.evaluate(
        {
            "title": "",
            "description": "",
            "vulnerability_type": "",
            "severity": "",
            "evidence": [],
        }
    )
    assert result.verdict == "rework"
    assert result.score < result.max_score / 2


def test_good_finding_verdict():
    critic = ReportCritic()
    result = critic.evaluate(
        {
            "title": "IDOR in user profile allows accessing other users personal data",
            "description": "The endpoint GET /api/users/{id} does not verify that the authenticated user owns the requested profile. An attacker can enumerate user IDs and access any profile including email, phone, and address.",
            "vulnerability_type": "idor",
            "severity": "high",
            "reproduction_steps": [
                "Log in as user A",
                "Navigate to GET /api/users/1",
                "Confirm access to admin profile",
                "Try /api/users/2, /api/users/3",
                "Verify unauthorized access to any profile",
            ],
            "poc": {"curl": "curl -H 'Authorization: Bearer TOKEN' https://target.com/api/users/1"},
            "evidence": ["Screenshot of admin profile", "HTTP response with user data"],
            "impact": "An attacker can access the personal data of any user in the system.",
            "cvss_score": 7.5,
            "cwe_id": "CWE-639",
            "remediation": "Implement server-side authorization checks to ensure users can only access their own profile. Use a centralized authorization middleware that validates resource ownership before returning data.",
        }
    )
    assert result.verdict in ("ready", "needs_improvement")
    assert result.score >= result.max_score * 0.75


def test_empty_finding_has_suggestions():
    critic = ReportCritic()
    result = critic.evaluate({"title": "", "description": "", "vulnerability_type": "", "severity": "", "evidence": []})
    assert len(result.suggestions) > 5


def test_platform_specific_checks():
    critic = ReportCritic()
    # H1 should have asset_type check
    result = critic.evaluate(
        {
            "title": "Test",
            "description": "x" * 100,
            "vulnerability_type": "xss",
            "severity": "high",
            "reproduction_steps": ["Step 1", "Step 2", "Step 3"],
            "poc": {"curl": "curl test"},
            "evidence": ["test"],
            "impact": "business impact",
            "cvss_score": 5.0,
            "cwe_id": "CWE-79",
            "remediation": "remediation advice here",
        },
        platform="hackerone",
    )
    h1_check_names = {c.name for c in result.checks}
    assert "h1_asset_type" in h1_check_names

    # Intigriti should have tags check instead
    result2 = critic.evaluate(
        {
            "title": "Test",
            "description": "x" * 100,
            "vulnerability_type": "xss",
            "severity": "high",
            "reproduction_steps": ["Step 1", "Step 2", "Step 3"],
            "poc": {"curl": "curl test"},
            "evidence": ["test"],
            "impact": "business impact",
            "cvss_score": 5.0,
            "cwe_id": "CWE-79",
            "remediation": "remediation advice here",
        },
        platform="intigriti",
    )
    inti_check_names = {c.name for c in result2.checks}
    assert "inti_tags" in inti_check_names
    assert "h1_asset_type" not in inti_check_names


def test_suggestions_map_to_failed_checks():
    critic = ReportCritic()
    result = critic.evaluate({"title": "", "description": "", "vulnerability_type": "", "severity": "", "evidence": []})
    # Every failed check should have a suggestion
    failed = [c for c in result.checks if not c.passed]
    assert len(result.suggestions) == len(failed)


def test_weak_language_detected():
    critic = ReportCritic()
    result = critic.evaluate(
        {
            "title": "Test",
            "description": "This might be a vulnerability. It could be an XSS issue. I think it works maybe.",
            "vulnerability_type": "xss",
            "severity": "medium",
            "reproduction_steps": ["Step 1", "Step 2", "Step 3"],
            "poc": {"curl": "curl test"},
            "evidence": ["test"],
            "impact": "Yes",
            "cvss_score": 5.0,
            "cwe_id": "CWE-79",
            "remediation": "Fix it",
        }
    )
    desc_conf_check = [c for c in result.checks if c.name == "description_confident"]
    assert len(desc_conf_check) == 1
    assert not desc_conf_check[0].passed
    assert "Weak language" in desc_conf_check[0].notes


def test_full_coverage_ready_report():
    critic = ReportCritic()
    result = critic.evaluate(
        {
            "title": "SQL Injection in search endpoint allows database extraction",
            "description": "The GET /api/search?q= parameter directly concatenates user input into SQL queries without parameterization. An attacker can inject SQL commands via the q parameter, allowing extraction of arbitrary database contents including user credentials and sensitive data.",
            "vulnerability_type": "sqli",
            "severity": "critical",
            "reproduction_steps": [
                "Send request: GET https://target.com/api/search?q=test' OR '1'='1",
                "Observe that the response returns all records instead of filtered results",
                "Use UNION-based injection: GET https://target.com/api/search?q=' UNION SELECT username,password FROM users--",
                "Confirm credential extraction from response",
            ],
            "poc": {
                "curl": "curl 'https://target.com/api/search?q=test%27%20OR%20%271%27%3D%271'",
            },
            "python_script": "import requests\nr = requests.get('https://target.com/api/search', params={'q': \"' OR '1'='1\"})\nprint(r.text)",
            "request": "GET /api/search?q=test' OR '1'='1 HTTP/1.1\nHost: target.com",
            "response": "HTTP/1.1 200 OK\n\n[all user records returned]",
            "evidence": [
                "Response showing all records",
                "Screenshot of UNION injection result",
                "HAR file: https://target.com/api/search",
            ],
            "impact": "Complete database compromise. An attacker can extract all user credentials, PII, and business data. Can lead to account takeover and data breach.",
            "cvss_score": 9.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cwe_id": "CWE-89",
            "remediation": "Replace dynamic SQL query construction with parameterized queries. Use an ORM or prepared statements. Apply least privilege to the database user.",
            "tags": ["sql-injection", "critical"],
            "classification": "sqli",
        }
    )
    assert result.score >= result.max_score * 0.7, f"Score {result.score}/{result.max_score} too low for ready report"
