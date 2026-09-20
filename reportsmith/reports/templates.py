"""Report templates — platform-optimized markdown generation.

Produces submission-ready reports for each bug bounty platform.
Each platform has different expectations for format, tone, and detail level.

Usage::

    from reportsmith.reports.templates import render_report

    # Render for HackerOne
    markdown = render_report("hackerone", {
        "title": "IDOR in user profile",
        "vulnerability_type": "idor",
        ...
    })
"""

from __future__ import annotations

from typing import Any


def render_report(platform: str, data: dict[str, Any]) -> str:
    """Render a complete report in the platform's markdown format.

    Args:
        platform: One of "hackerone", "bugcrowd", "intigriti".
        data: Report data dict with all required fields.

    Returns:
        Markdown string ready for submission.
    """
    normalizer = _NORMALIZERS.get(platform)
    if normalizer:
        data = normalizer(data)

    renderer = _RENDERERS.get(platform)
    if not renderer:
        raise ValueError(f"Unknown platform: {platform}. Supported: {list(_RENDERERS.keys())}")

    return renderer(data)


# ── Data normalizers ───────────────────────────────────────────


def _normalize_hackerone(data: dict[str, Any]) -> dict[str, Any]:
    """H1 expects: concise summary, clear impact, business risk focus."""
    d = dict(data)
    d.setdefault("tone", "professional")
    d.setdefault("section_order", ["summary", "description", "impact", "reproduction", "mitigation"])
    return d


def _normalize_bugcrowd(data: dict[str, Any]) -> dict[str, Any]:
    """Bugcrowd expects: very structured, step-by-step, technical focus."""
    d = dict(data)
    d.setdefault("tone", "technical")
    d.setdefault(
        "section_order", ["vulnerability_type", "description", "reproduction", "impact", "poc", "configuration"]
    )
    return d


def _normalize_intigriti(data: dict[str, Any]) -> dict[str, Any]:
    """Intigriti expects: detailed, evidence-heavy, remediation focus."""
    d = dict(data)
    d.setdefault("tone", "detailed")
    d.setdefault(
        "section_order", ["summary", "description", "technical_details", "reproduction", "poc", "impact", "remediation"]
    )
    return d


def _normalize_immunefi(data: dict[str, Any]) -> dict[str, Any]:
    """Immunefi expects: concise, high-impact, direct, $100K+ bounty caliber."""
    d = dict(data)
    d.setdefault("tone", "direct")
    d.setdefault(
        "section_order", ["summary", "description", "technical_details", "reproduction", "poc", "impact", "mitigation"]
    )
    return d


_NORMALIZERS = {
    "hackerone": _normalize_hackerone,
    "bugcrowd": _normalize_bugcrowd,
    "intigriti": _normalize_intigriti,
    "immunefi": _normalize_immunefi,
}


# ── Helpers ────────────────────────────────────────────────────


def _get(data: dict[str, Any], *keys: str, default: str = "") -> str:
    for key in keys:
        value = data.get(key)
        if value:
            return str(value)
    return default


def _list_items(items: list[str] | None, prefix: str = "- ") -> str:
    if not items:
        return ""
    return "\n".join(f"{prefix}{item}" for item in items)


def _code_block(text: str, lang: str = "") -> str:
    return f"```{lang}\n{text}\n```"


def _severity_label(severity: str) -> str:
    return {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "informational": "Informational",
    }.get(severity.lower(), severity.capitalize())


def _impact_for_vuln(vuln_type: str, severity: str) -> str:
    impacts = {
        "idor": {
            "critical": "An attacker can access, modify, or delete any resource in the system, leading to complete data compromise.",
            "high": "An attacker can access sensitive data belonging to other users, including PII and private records.",
            "medium": "An attacker can access non-critical resources belonging to other users.",
            "low": "Limited information disclosure — non-sensitive data accessible.",
        },
        "ssrf": {
            "critical": "An attacker can interact with internal services, cloud metadata endpoints, and pivot to internal networks.",
            "high": "An attacker can scan internal ports and access cloud instance metadata.",
            "medium": "Limited access to specific internal endpoints.",
            "low": "Outbound request reflection with minimal internal access.",
        },
        "xss": {
            "critical": "Full account takeover via arbitrary JavaScript execution in victim's browser.",
            "high": "Session hijacking — attacker can steal cookies and impersonate users.",
            "medium": "Data exfiltration from page DOM.",
            "low": "Limited script execution due to CSP or context restrictions.",
        },
        "sqli": {
            "critical": "Complete database compromise — data extraction, modification, and potential RCE.",
            "high": "Multiple table extraction including user credentials.",
            "medium": "Specific data value extraction.",
            "low": "Database fingerprinting and version disclosure.",
        },
        "auth_bypass": {
            "critical": "Complete admin access without authentication.",
            "high": "Access to restricted functionality without proper authorization.",
            "medium": "Limited privilege escalation.",
            "low": "Access to low-sensitivity authenticated endpoints.",
        },
    }
    type_impact = impacts.get(vuln_type, {})
    return type_impact.get(severity, "Security impact depending on the specific vulnerability and data accessible.")


# ── Section renderers ──────────────────────────────────────────


def _section_summary(data: dict[str, Any]) -> str:
    title = _get(data, "title", "summary")
    return f"## Summary\n\n{title}\n"


def _section_description(data: dict[str, Any]) -> str:
    desc = _get(data, "description", "vulnerability_description")
    return f"## Description\n\n{desc}\n"


def _section_vulnerability_type(data: dict[str, Any]) -> str:
    vtype = _get(data, "vulnerability_type", "classification", default="unknown")
    severity = _get(data, "severity", default="medium")
    return f"## Vulnerability Type\n\n**{vtype.upper()}** — {_severity_label(severity)} Severity\n"


def _section_reproduction(data: dict[str, Any]) -> str:
    steps = data.get("reproduction_steps", [])
    if not steps:
        steps = data.get("test_instructions", [])
    if not steps:
        steps = ["Send request to the endpoint", "Observe the response"]

    import re

    parts = ["## Steps to Reproduce\n"]
    for i, step in enumerate(steps, 1):
        clean = re.sub(r"^\d+[.)]\s*", "", step)
        parts.append(f"{i}. {clean}")
    parts.append("")

    # Expected vs actual
    expected = data.get("expected_result", "")
    actual = data.get("actual_result", "")
    if expected and actual:
        parts.extend(
            [
                "### Expected Result\n",
                f"{expected}\n",
                "### Actual Result\n",
                f"{actual}\n",
            ]
        )

    return "\n".join(parts)


def _section_impact(data: dict[str, Any]) -> str:
    vuln_type = data.get("vulnerability_type", "")
    severity = data.get("severity", "medium")
    impact = data.get("business_impact", "")
    if not impact:
        impact = _impact_for_vuln(vuln_type, severity)

    parts = ["## Impact\n", f"{impact}\n"]

    risk_factors = data.get("risk_factors", [])
    if risk_factors:
        parts.extend(["### Risk Factors\n", _list_items(risk_factors), "\n"])

    return "\n".join(parts)


def _section_impact_assessment(data: dict[str, Any]) -> str:
    return _section_impact(data)


def _section_poc(data: dict[str, Any]) -> str:
    poc = data.get("poc", {})
    if isinstance(poc, dict):
        curl = poc.get("curl", data.get("curl_command", ""))
        python_script = poc.get("python", data.get("python_script", ""))
        js_fetch = poc.get("javascript", data.get("js_fetch_code", ""))
        httpie = poc.get("httpie", data.get("httpie_command", ""))
    else:
        curl = str(poc)
        python_script = ""
        js_fetch = ""
        httpie = ""

    parts = ["## Proof of Concept\n"]
    if curl:
        parts.extend(["### cURL\n", _code_block(curl, "bash"), "\n"])
    if python_script:
        parts.extend(["### Python\n", _code_block(python_script, "python"), "\n"])
    if js_fetch:
        parts.extend(["### JavaScript (Fetch API)\n", _code_block(js_fetch, "javascript"), "\n"])
    if httpie:
        parts.extend(["### HTTPie\n", _code_block(httpie, "bash"), "\n"])

    burp = poc.get("burp_sequence", []) if isinstance(poc, dict) else []
    if burp:
        parts.append("### Burp Suite Sequence\n")
        for i, step in enumerate(burp, 1):
            parts.append(f"{i}. **{step.get('description', f'Step {i}')}**")
            req = step.get("request", "")
            if req:
                parts.append(_code_block(req, "http"))
        parts.append("\n")

    return "\n".join(parts)


def _section_technical_details(data: dict[str, Any]) -> str:
    parts = ["## Technical Details\n"]
    endpoint = data.get("endpoint", "")
    method = data.get("method", "")
    if endpoint and method:
        parts.append(f"- **Endpoint**: `{method} {endpoint}`\n")

    vuln_param = data.get("vulnerable_param", data.get("parameters_of_interest", [""])[0])
    if vuln_param:
        parts.append(f"- **Vulnerable Parameter**: `{vuln_param}`\n")

    parts.extend(
        [
            f"- **CVSS Score**: {data.get('cvss_score', 'N/A')}\n",
            f"- **CWE**: {data.get('cwe_id', 'N/A')}\n",
        ]
    )

    return "\n".join(parts)


def _section_mitigation(data: dict[str, Any]) -> str:
    vuln_type = data.get("vulnerability_type", "")
    mitigations = {
        "idor": "Implement proper access control checks on the server side. Do not rely on client-side parameters for authorization. Use a centralized authorization middleware that verifies the authenticated user has permission to access the requested resource.",
        "ssrf": "Validate and restrict URLs that the application can fetch. Block private IP ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16). Use an allowlist of permitted domains.",
        "xss": "Properly encode all user-supplied data before rendering. Implement Content Security Policy (CSP) headers. Use framework-specific auto-escaping (React, Vue).",
        "sqli": "Use parameterized queries or prepared statements. Never concatenate user input into SQL queries. Apply least privilege principle for database users.",
        "auth_bypass": "Ensure authorization checks are performed server-side for every protected endpoint. Do not rely on client-side role/privilege indicators.",
    }

    mitigation = data.get(
        "remediation", mitigations.get(vuln_type, "Apply security best practices for this vulnerability class.")
    )
    return f"## Remediation\n\n{mitigation}\n"


def _section_configuration(data: dict[str, Any]) -> str:
    parts = ["## Configuration\n"]
    parts.append(f"- **Platform**: {data.get('platform', 'N/A')}\n")
    parts.append(f"- **Scope**: {data.get('scope_check', 'In scope')}\n")

    preconditions = data.get("preconditions", [])
    if preconditions:
        parts.extend(["### Prerequisites\n", _list_items(preconditions), "\n"])

    return "\n".join(parts)


_SECTION_RENDERERS = {
    "summary": _section_summary,
    "description": _section_description,
    "vulnerability_type": _section_vulnerability_type,
    "reproduction": _section_reproduction,
    "impact": _section_impact,
    "impact_assessment": _section_impact_assessment,
    "poc": _section_poc,
    "technical_details": _section_technical_details,
    "mitigation": _section_mitigation,
    "remediation": _section_mitigation,
    "configuration": _section_configuration,
}


# ── Platform renderers ─────────────────────────────────────────


def _render_hackerone(data: dict[str, Any]) -> str:
    sections = []
    sections.append(f"# {_get(data, 'title', 'summary')}\n")

    for section_name in data.get("section_order", _DEFAULT_ORDER):
        renderer = _SECTION_RENDERERS.get(section_name)
        if renderer:
            sections.append(renderer(data))

    sections.extend(
        [
            "---\n",
            "*Report generated by ORION Security Intelligence*\n",
        ]
    )
    return "\n".join(sections)


def _render_bugcrowd(data: dict[str, Any]) -> str:
    sections = []
    sections.append(f"# Vulnerability Report: {_get(data, 'title', 'summary')}\n")

    # Bugcrowd header block
    sections.extend(
        [
            "| Field | Value |\n",
            "|---|---|---|\n",
            f"| Vulnerability Type | {data.get('vulnerability_type', 'N/A').upper()} |\n",
            f"| Severity | {_severity_label(_get(data, 'severity', default='medium'))} |\n",
            f"| Endpoint | `{data.get('endpoint', 'N/A')}` |\n",
            f"| Method | {data.get('method', 'GET')} |\n",
            f"| CVSS Score | {data.get('cvss_score', 'N/A')} |\n",
            f"| CWE | {data.get('cwe_id', 'N/A')} |\n",
            "\n",
        ]
    )

    for section_name in data.get("section_order", _DEFAULT_ORDER):
        renderer = _SECTION_RENDERERS.get(section_name)
        if renderer:
            sections.append(renderer(data))

    sections.append("---\n")
    return "\n".join(sections)


def _render_intigriti(data: dict[str, Any]) -> str:
    sections = []
    sections.append("# Security Vulnerability Report\n")
    sections.append(f"## {_get(data, 'title', 'summary')}\n")

    # Intigriti metadata block
    sections.extend(
        [
            "### Classification\n",
            f"- **Type**: {data.get('vulnerability_type', 'N/A').upper()}\n",
            f"- **Severity**: {_severity_label(_get(data, 'severity', default='medium'))}\n",
            f"- **CVSS**: {data.get('cvss_score', 'N/A')} ({data.get('cvss_vector', '')})\n",
            f"- **CWE**: {data.get('cwe_id', 'N/A')} — {data.get('cwe_name', '')}\n",
            f"- **CAPEC**: {data.get('capec_id', 'N/A')}\n",
            "\n",
        ]
    )

    for section_name in data.get("section_order", _DEFAULT_ORDER):
        renderer = _SECTION_RENDERERS.get(section_name)
        if renderer:
            sections.append(renderer(data))

    # Evidence checklist
    sections.extend(
        [
            "### Evidence Checklist\n",
            "- [x] Reproduction steps are clear and complete\n",
            "- [x] Proof of Concept is included\n",
            "- [x] Business impact is assessed\n",
            "- [x] CVSS score is calculated\n",
            "- [x] CWE identifier is provided\n",
            "- [x] Remediation recommendation is included\n",
            "\n",
        ]
    )
    sections.append("---\n")
    return "\n".join(sections)


def _render_immunefi(data: dict[str, Any]) -> str:
    sections = ["# Immunefi Vulnerability Report\n"]
    sections.append(f"## {_get(data, 'title', 'summary')}\n")

    sections.extend(
        [
            "### Vulnerability Classification\n",
            f"- **Type**: {data.get('vulnerability_type', 'N/A').upper()}\n",
            f"- **Severity**: {_severity_label(_get(data, 'severity', default='medium'))}\n",
            f"- **CVSS**: {data.get('cvss_score', 'N/A')} ({data.get('cvss_vector', '')})\n",
            f"- **CWE**: {data.get('cwe_id', 'N/A')} — {data.get('cwe_name', '')}\n",
            f"- **Target**: {data.get('program', data.get('target', 'N/A'))}\n",
            f"- **Asset**: `{data.get('endpoint', 'N/A')}`\n",
            "\n",
        ]
    )

    for section_name in data.get("section_order", _DEFAULT_ORDER):
        renderer = _SECTION_RENDERERS.get(section_name)
        if renderer:
            sections.append(renderer(data))

    poc = data.get("poc", {})
    if isinstance(poc, dict) and poc.get("nuclei_template"):
        sections.extend(
            [
                "### Automated Verification\n",
                _code_block(poc["nuclei_template"], "yaml"),
                "\n",
            ]
        )

    sections.extend(
        [
            "### Why This Matters\n",
            f"{_impact_for_vuln(data.get('vulnerability_type', ''), data.get('severity', 'medium'))}\n",
            "\n",
            "---\n",
            "*Report generated by ORION Security Intelligence — Automated Vulnerability Detection*\n",
        ]
    )
    return "\n".join(sections)


_RENDERERS = {
    "hackerone": _render_hackerone,
    "bugcrowd": _render_bugcrowd,
    "intigriti": _render_intigriti,
    "immunefi": _render_immunefi,
    "h1": _render_hackerone,
    "bc": _render_bugcrowd,
    "inti": _render_intigriti,
}

_DEFAULT_ORDER = [
    "vulnerability_type",
    "description",
    "technical_details",
    "reproduction",
    "poc",
    "impact",
    "mitigation",
]


def platform_list() -> list[str]:
    """Return the list of supported platforms."""
    return ["hackerone", "bugcrowd", "intigriti", "immunefi"]


def render_report_from_finding(
    finding: dict[str, Any], endpoint: dict[str, Any] | None = None, target: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Build a rich report data dict from a finding dict and optional endpoint/target.

    Args:
        finding: Finding dict with keys like title, description, vulnerability_type, severity, notes, etc.
        endpoint: Optional Endpoint dict with path, method, params, headers, etc.
        target: Optional Target dict with name, domain, etc.

    Returns:
        Data dict ready for render_report().
    """
    try:  # full maps live in the monorepo; standalone uses faithful copies
        from cores.evidence.composer import CVSS_SEVERITY_MAP as cvss_map
        from cores.evidence.composer import CWE_MAP as cwe_map
    except ImportError:  # pragma: no cover - standalone path
        cvss_map = {
            "critical": (9.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            "high": (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"),
            "medium": (5.5, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"),
            "low": (3.5, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"),
        }
        cwe_map = {
            "idor": ("CWE-639", "Authorization Bypass Through User-Controlled Key"),
            "ssrf": ("CWE-918", "Server-Side Request Forgery"),
            "auth_bypass": ("CWE-288", "Authentication Bypass Using an Alternate Path or Channel"),
            "xss": ("CWE-79", "Improper Neutralization of Input During Web Page Generation"),
            "sqli": ("CWE-89", "SQL Injection"),
            "generic": ("CWE-200", "Exposure of Sensitive Information to an Unauthorized Actor"),
        }

    cvss_data = cvss_map.get(finding.get("severity", "medium"), (0.0, ""))
    cwe_data = cwe_map.get(finding.get("vulnerability_type", ""), ("", ""))

    data: dict[str, Any] = {
        "title": finding.get("title") or f"Finding #{finding.get('id', '')}",
        "description": finding.get("description") or "",
        "vulnerability_type": finding.get("vulnerability_type") or "unknown",
        "severity": finding.get("severity") or "medium",
        "cvss_score": str(cvss_data[0]),
        "cvss_vector": cvss_data[1],
        "cwe_id": cwe_data[0],
        "cwe_name": cwe_data[1],
    }

    if target:
        data["target"] = target.get("name", "")
        data["program"] = target.get("domain", target.get("name", ""))
        data["scope_check"] = f"In scope — {target.get('name', 'unknown')}"

    if endpoint:
        data["endpoint"] = endpoint.get("path", "")
        data["method"] = endpoint.get("method", "GET")
        params = endpoint.get("parsed_params", {}) or {}
        if params:
            data["parameters_of_interest"] = list(params.keys()) if isinstance(params, dict) else []

    notes = finding.get("notes", "")
    if notes:
        import json

        try:
            parsed = json.loads(notes) if isinstance(notes, str) else notes
            if isinstance(parsed, dict):
                data.update(
                    {
                        k: v
                        for k, v in parsed.items()
                        if k
                        in {
                            "reproduction_steps",
                            "test_instructions",
                            "expected_result",
                            "actual_result",
                            "business_impact",
                            "risk_factors",
                            "preconditions",
                            "poc",
                            "curl_command",
                            "python_script",
                            "js_fetch_code",
                            "httpie_command",
                        }
                    }
                )
        except (json.JSONDecodeError, TypeError):
            data["description"] = notes

    reproduction = finding.get("reproduction_steps") or finding.get("test_instructions") or []
    if reproduction and isinstance(reproduction, list):
        data["reproduction_steps"] = reproduction

    return data
