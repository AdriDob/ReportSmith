from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

try:  # event bus lives in the monorepo; standalone skips the emit
    from cores.events.types import Events
except ImportError:  # pragma: no cover - standalone path
    Events = None
from reportsmith.reports.critic import ReportCritic

logger = logging.getLogger("reportsmith.reports.optimizer")


# ── Remediation database ─────────────────────────────────────


@dataclass
class Remediation:
    summary: str
    details: str
    owasp_reference: str
    severity_multiplier: float = 1.0


REMEDIATION_DB: dict[str, Remediation] = {
    "idor": Remediation(
        summary="Implement server-side access control checks",
        details=(
            "Validate authorization on every request using a centralized middleware. "
            "Do not rely on client-side parameters (IDs, tokens) for access decisions. "
            "Use indirect object references (maps) instead of exposing database keys. "
            "Apply the principle of least privilege: users should only access resources "
            "they explicitly own. Implement consistent ownership checks across all endpoints."
        ),
        owasp_reference="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References",
    ),
    "ssrf": Remediation(
        summary="Restrict outbound network requests from the server",
        details=(
            "Implement an allowlist of permitted outbound destinations. "
            "Block private and internal IP ranges (127.0.0.0/8, 10.0.0.0/8, "
            "172.16.0.0/12, 192.168.0.0/16, fc00::/7). "
            "Validate and sanitize all user-supplied URLs before fetching. "
            "Use a dedicated HTTP client with disabled redirect following where possible. "
            "Apply network segmentation so the application server cannot reach internal services."
        ),
        owasp_reference="https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
    ),
    "xss": Remediation(
        summary="Properly encode all user-supplied data and implement CSP",
        details=(
            "Contextually encode all user-controlled data before rendering in HTML, "
            "JavaScript, CSS, or URL contexts. Use framework-provided auto-escaping "
            "(React JSX, Vue templates, Django templates). "
            "Implement a Content Security Policy (CSP) header as a defense-in-depth measure. "
            "Avoid using dangerouslySetInnerHTML, v-html, or similar unsafe constructs. "
            "Validate input on both client and server side using an allowlist approach."
        ),
        owasp_reference="https://owasp.org/www-community/attacks/xss/",
    ),
    "sqli": Remediation(
        summary="Use parameterized queries for all database operations",
        details=(
            "Never concatenate user input directly into SQL statements. "
            "Use parameterized queries (prepared statements) for all database operations. "
            "Apply the least privilege principle for database connection users. "
            "Use an ORM with built-in parameterization (SQLAlchemy, Entity Framework). "
            "Implement input validation for expected data types and lengths. "
            "Consider a WAF as defense-in-depth, not as primary mitigation."
        ),
        owasp_reference="https://owasp.org/www-community/attacks/SQL_Injection",
    ),
    "auth_bypass": Remediation(
        summary="Enforce server-side authorization on every protected endpoint",
        details=(
            "Do not rely on client-side role indicators, hidden UI elements, or "
            "HTTP method overrides for access control. Implement a centralized "
            "authorization layer that verifies permissions on every request. "
            "Use role-based access control (RBAC) with explicit deny-by-default. "
            "Test authorization logic with automated integration tests for each role."
        ),
        owasp_reference="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/03-Testing_for_Privilege_Escalation",
    ),
    "open_redirect": Remediation(
        summary="Validate and restrict redirect destinations",
        details=(
            "Maintain an allowlist of valid redirect destinations. "
            "Do not accept arbitrary URLs as redirect parameters. "
            "If dynamic redirects are required, use indirect mappings (IDs to URLs). "
            "Warn users when they are being redirected to external domains."
        ),
        owasp_reference="https://owasp.org/www-community/attacks/Open_redirect",
    ),
    "file_upload": Remediation(
        summary="Validate file type, size, and content on the server side",
        details=(
            "Do not rely on MIME type or file extension alone. Validate file content "
            "magic bytes server-side. Restrict upload size and enforce storage outside "
            "the webroot. Serve uploaded files from a separate domain or CDN. "
            "Scan files for malware. Ensure uploaded files are not executable."
        ),
        owasp_reference="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Miscellaneous_Testing/01-Testing_for_File_Upload",
    ),
    "lfi_rfi": Remediation(
        summary="Avoid dynamic file inclusion; use whitelist-based approach",
        details=(
            "Do not include files based on user-supplied paths. Use a whitelist of "
            "permitted file names. If dynamic inclusion is required, map user input "
            "to predefined file paths. Disable remote file inclusion (allow_url_include). "
            "Apply chroot jails or container isolation for file operations."
        ),
        owasp_reference="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Miscellaneous_Testing/01-Testing_for_Local_File_Inclusion",
    ),
    "rce": Remediation(
        summary="Never execute user input as code or commands",
        details=(
            "Avoid eval(), exec(), system(), popen(), and similar functions with "
            "user-supplied input. Use sandboxed environments for any dynamic code "
            "execution. Validate and sanitize all input passed to command interpreters. "
            "Apply strict input validation and use allowlists for permitted operations."
        ),
        owasp_reference="https://owasp.org/www-community/attacks/Command_Injection",
    ),
    "csrf": Remediation(
        summary="Implement anti-CSRF tokens for all state-changing operations",
        details=(
            "Use a synchronizer token pattern or double-submit cookie pattern. "
            "Ensure tokens are cryptographically random, tied to the user session, "
            "and validated server-side. Set SameSite=Strict or SameSite=Lax on cookies. "
            "Require re-authentication for sensitive actions (password change, MFA)."
        ),
        owasp_reference="https://owasp.org/www-community/attacks/csrf",
    ),
    "information_disclosure": Remediation(
        summary="Remove sensitive information from client-facing responses",
        details=(
            "Do not expose internal paths, stack traces, or configuration details "
            "in error messages. Use generic error responses in production. "
            "Remove debug endpoints, verbose headers (X-Powered-By, Server), "
            "and internal IP addresses from HTTP responses. "
            "Review API responses for unintended data leakage."
        ),
        owasp_reference="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/10-Testing_for_Information_Disclosure_in_Responses",
    ),
    "graphql_injection": Remediation(
        summary="Apply depth limiting, rate limiting, and input validation to GraphQL",
        details=(
            "Limit query depth and complexity to prevent abuse. Validate and sanitize "
            "all GraphQL inputs. Apply proper authorization at the resolver level, "
            "not at the field level. Disable introspection in production. "
            "Implement rate limiting per operation type. Use persisted queries where possible."
        ),
        owasp_reference="https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
    ),
}

VULN_ALIASES: dict[str, str] = {
    "idor": "idor",
    "insecure_direct_object_reference": "idor",
    "ssrf": "ssrf",
    "server_side_request_forgery": "ssrf",
    "xss": "xss",
    "cross_site_scripting": "xss",
    "sqli": "sqli",
    "sql_injection": "sqli",
    "auth_bypass": "auth_bypass",
    "authentication_bypass": "auth_bypass",
    "open_redirect": "open_redirect",
    "file_upload": "file_upload",
    "lfi": "lfi_rfi",
    "rfi": "lfi_rfi",
    "local_file_inclusion": "lfi_rfi",
    "rce": "rce",
    "remote_code_execution": "rce",
    "csrf": "csrf",
    "cross_site_request_forgery": "csrf",
    "info_disclosure": "information_disclosure",
    "information_disclosure": "information_disclosure",
    "graphql_injection": "graphql_injection",
    "graphql": "graphql_injection",
}

PLATFORM_REMEDIATION_PREFIX: dict[str, str] = {
    "hackerone": "### Recommended Fix\n\n",
    "bugcrowd": "## Suggested Remediation\n\n",
    "intigriti": "### Remediation Advice\n\n",
    "immunefi": "## Mitigation\n\n",
}


def get_remediation(vuln_type: str, platform: str = "hackerone") -> dict[str, str]:
    key = VULN_ALIASES.get(vuln_type.lower().strip(), "generic")
    entry = REMEDIATION_DB.get(key)
    if not entry:
        return {
            "summary": "Apply security best practices for this vulnerability class",
            "details": "Review the OWASP documentation for this vulnerability type and apply the recommended controls.",
            "owasp_reference": "",
            "rendered": "",
        }
    prefix = PLATFORM_REMEDIATION_PREFIX.get(platform, "## Remediation\n\n")
    rendered = f"{prefix}{entry.summary}\n\n{entry.details}\n\n**OWASP Reference**: {entry.owasp_reference}"
    return {
        "summary": entry.summary,
        "details": entry.details,
        "owasp_reference": entry.owasp_reference,
        "rendered": rendered,
    }


# ── Report Context Builder ───────────────────────────────────


def get_db_session():
    from database import db

    db.init_db()
    return db.SessionLocal()


def get_quality_scorer():
    from reportsmith.reports.quality.scorer import QualityScorer

    return QualityScorer()


def get_bus():
    from cores.events.event_bus import get_event_bus

    return get_event_bus()


def get_acceptance_learner():
    from reportsmith.reports.acceptance.learner import AcceptanceLearner

    return AcceptanceLearner()


@dataclass
class ReportContext:
    finding: dict[str, Any] = field(default_factory=dict)
    endpoint: dict[str, Any] = field(default_factory=dict)
    target: dict[str, Any] = field(default_factory=dict)
    evidence_count: int = 0
    quality_score: float = 0.0
    quality_dimensions: dict[str, float] = field(default_factory=dict)
    acceptance_probability: float = 0.0
    acceptance_recommendations: list[str] = field(default_factory=list)
    acceptance_weak_dimensions: list[str] = field(default_factory=list)
    remediation: dict[str, str] = field(default_factory=dict)
    platform: str = "hackerone"
    findings_count: int = 1
    template_vars: dict[str, Any] = field(default_factory=dict)
    critic_score: float = 0.0
    critic_verdict: str = ""
    critic_suggestions: list[str] = field(default_factory=list)


class ReportContextBuilder:
    def build(self, finding_id: int, platform: str = "hackerone") -> ReportContext | None:
        session = get_db_session()
        try:
            from database import models

            finding = session.query(models.Finding).filter(models.Finding.id == finding_id).first()
            if not finding:
                return None

            finding_dict = {
                "id": finding.id,
                "title": finding.title or "",
                "description": finding.description or "",
                "severity": finding.severity or "medium",
                "status": finding.status or "open",
                "vulnerability_type": finding.vulnerability_type or "generic",
                "endpoint_id": finding.endpoint_id,
                "target_id": finding.target_id,
                "notes": finding.notes or "",
            }

            endpoint_dict: dict[str, Any] = {}
            if finding.endpoint_id:
                endpoint = session.query(models.Endpoint).filter(models.Endpoint.id == finding.endpoint_id).first()
                if endpoint:
                    endpoint_dict = {
                        "id": endpoint.id,
                        "path": endpoint.path or "",
                        "method": endpoint.method or "",
                        "host": endpoint.host or "",
                    }

            target_dict: dict[str, Any] = {}
            if finding.target_id:
                target = session.query(models.Target).filter(models.Target.id == finding.target_id).first()
                if target:
                    target_dict = {
                        "id": target.id,
                        "name": target.name or "",
                        "domain": target.domain or "",
                        "program_url": target.program_url or "",
                    }
                    if target.name and "_" in target.name:
                        platform = target.name.split("_", 1)[0]

            evidence_count = 0
            if finding.endpoint_id:
                evidence_count = (
                    session.query(models.Evidence)
                    .join(models.Verdict, models.Evidence.verdict_id == models.Verdict.id)
                    .filter(models.Verdict.endpoint_id == finding.endpoint_id)
                    .count()
                )

            qs = get_quality_scorer()
            try:
                quality = qs.score(finding_id)
                quality_score = quality.score
                quality_dims = {k: v * 100 for k, v in quality.dimensions.items()}
            except Exception as exc:
                logger.warning("Quality scoring failed: %s", exc)
                quality_score = 0.0
                quality_dims = {}

            acceptance_probability = 0.0
            acceptance_recs: list[str] = []
            acceptance_weak: list[str] = []
            try:
                learner = get_acceptance_learner()
                dims_for_pred = {k: v / 100 for k, v in quality_dims.items()}
                pred = learner.predict(platform, quality_score, dims_for_pred, evidence_count)
                acceptance_probability = pred.probability
                acceptance_recs = pred.recommendations
                acceptance_weak = pred.weak_dimensions
            except Exception as exc:
                logger.warning("Acceptance prediction failed: %s", exc)

            vuln_type = finding.vulnerability_type or "generic"
            remediation = get_remediation(vuln_type, platform)

            critic = ReportCritic()
            try:
                critic_result = critic.evaluate(finding_dict, platform=platform)
                critic_score = critic_result.score
                critic_verdict = critic_result.verdict
                critic_suggestions = critic_result.suggestions
            except Exception as exc:
                logger.warning("Critic evaluation failed: %s", exc)
                critic_score = 0.0
                critic_verdict = "unknown"
                critic_suggestions = []

            rendered = ""
            try:
                from reportsmith.reports.templates import render_report

                notes_data = _parse_notes(finding_dict.get("notes", ""))
                render_data = {
                    "title": finding_dict["title"],
                    "vulnerability_type": vuln_type,
                    "severity": finding_dict["severity"],
                    "endpoint": endpoint_dict.get("path", "/"),
                    "method": endpoint_dict.get("method", "GET"),
                    "description": finding_dict["description"],
                    "remediation": remediation.get("rendered", ""),
                    "cvss_score": quality_dims.get("impact_severity", 0),
                    "cwe_id": CWE_MAP.get(vuln_type, ("CWE-200", ""))[0],
                    "impact": _generate_impact_text(vuln_type, finding_dict["severity"]),
                    **notes_data,
                }
                if endpoint_dict.get("host"):
                    render_data["host"] = endpoint_dict["host"]
                rendered = render_report(platform, render_data)
            except Exception as exc:
                logger.warning("Report rendering failed: %s", exc)

            ctx = ReportContext(
                finding=finding_dict,
                endpoint=endpoint_dict,
                target=target_dict,
                evidence_count=evidence_count,
                quality_score=quality_score,
                quality_dimensions=quality_dims,
                acceptance_probability=acceptance_probability,
                acceptance_recommendations=acceptance_recs,
                acceptance_weak_dimensions=acceptance_weak,
                remediation=remediation,
                platform=platform,
                template_vars={
                    "title": finding_dict["title"],
                    "vulnerability_type": vuln_type,
                    "cwe_id": CWE_MAP.get(vuln_type, ("CWE-200", ""))[0],
                    "cwe_name": CWE_MAP.get(vuln_type, ("", "Information Exposure"))[1],
                    "severity": finding_dict["severity"],
                    "method": endpoint_dict.get("method", "GET"),
                    "endpoint": endpoint_dict.get("path", "/"),
                    "host": endpoint_dict.get("host", ""),
                    "target": target_dict.get("name", "") or target_dict.get("domain", ""),
                    "program_url": target_dict.get("program_url", ""),
                    "evidence_count": evidence_count,
                    "quality_score": round(quality_score, 1),
                    "acceptance_probability": round(acceptance_probability, 2),
                },
                critic_score=critic_score,
                critic_verdict=critic_verdict,
                critic_suggestions=critic_suggestions,
            )
            ctx.template_vars["rendered_report"] = rendered
            return ctx
        finally:
            session.close()


CWE_MAP: dict[str, tuple[str, str]] = {
    "idor": ("CWE-639", "Authorization Bypass Through User-Controlled Key"),
    "ssrf": ("CWE-918", "Server-Side Request Forgery"),
    "auth_bypass": ("CWE-288", "Authentication Bypass Using an Alternate Path or Channel"),
    "xss": ("CWE-79", "Improper Neutralization of Input During Web Page Generation"),
    "sqli": ("CWE-89", "SQL Injection"),
    "generic": ("CWE-200", "Exposure of Sensitive Information to an Unauthorized Actor"),
    "open_redirect": ("CWE-601", "URL Redirection to Untrusted Site"),
    "file_upload": ("CWE-434", "Unrestricted Upload of File with Dangerous Type"),
    "lfi_rfi": ("CWE-98", "Improper Control of Filename for Include/Require Statement"),
    "rce": ("CWE-78", "Improper Neutralization of Special Elements used in an OS Command"),
    "csrf": ("CWE-352", "Cross-Site Request Forgery"),
    "information_disclosure": ("CWE-200", "Exposure of Sensitive Information to an Unauthorized Actor"),
    "graphql_injection": ("CWE-943", "Improper Neutralization of Special Elements in Data Query Logic"),
    "nosql_injection": ("CWE-943", "Improper Neutralization of Special Elements in Data Query Logic"),
    "xxe": ("CWE-611", "Improper Restriction of XML External Entity Reference"),
    "ssti": ("CWE-1336", "Improper Neutralization of Special Elements Used in a Template Engine"),
    "session_fixation": ("CWE-384", "Session Fixation"),
    "race_condition": ("CWE-362", "Concurrent Execution using Shared Resource with Improper Synchronization"),
    "weak_crypto": ("CWE-327", "Use of a Broken or Risky Cryptographic Algorithm"),
}


def _parse_notes(notes: str) -> dict[str, Any]:
    if not notes:
        return {}
    if notes.startswith("{") or notes.startswith("["):
        try:
            return json.loads(notes)
        except (json.JSONDecodeError, ValueError):
            pass
    return {}


_IMPACT_TEMPLATES: dict[str, dict[str, str]] = {
    "idor": {
        "critical": "An attacker can access and modify any resource in the system, leading to complete data breach and privilege escalation. All users' sensitive data is exposed.",
        "high": "An attacker can access other users' private data by manipulating object references. Sensitive information including personal and financial data may be exposed.",
        "medium": "An attacker may access resources they should not have access to. The impact depends on the sensitivity of the exposed data.",
        "low": "Limited information disclosure where an attacker can access non-sensitive references or metadata.",
    },
    "ssrf": {
        "critical": "An attacker can access internal cloud metadata endpoints, internal services, and potentially achieve remote code execution through service interaction.",
        "high": "An attacker can scan internal networks and access internal services that were not intended to be publicly accessible.",
        "medium": "Limited internal resource access, potentially exposing configuration files or internal service banners.",
        "low": "Minor information disclosure about internal network layout or service availability.",
    },
    "xss": {
        "critical": "An attacker can execute arbitrary JavaScript in the context of any user's session, leading to account takeover, data theft, and malicious actions on behalf of victims.",
        "high": "Stored XSS affects all users who view the affected page. An attacker can steal sessions, perform actions as victims, and deliver malware.",
        "medium": "Reflected XSS requires user interaction but can lead to session theft and phishing attacks against users.",
        "low": "Self-XSS or DOM-based XSS with limited impact and significant user interaction required.",
    },
}


def _generate_impact_text(vuln_type: str, severity: str) -> str:
    vt_impacts = _IMPACT_TEMPLATES.get(vuln_type)
    if vt_impacts:
        return vt_impacts.get(severity, vt_impacts.get("medium", ""))
    if severity == "critical":
        return "This vulnerability poses a critical risk to the application and its users. Immediate remediation is required."
    if severity == "high":
        return "This vulnerability poses a significant security risk that should be addressed promptly."
    if severity == "medium":
        return "This vulnerability poses a moderate security risk that should be addressed in the normal course of development."
    return "This vulnerability poses a limited security risk but should still be addressed."


class ReportOptimizer:
    def __init__(self, builder: ReportContextBuilder | None = None):
        self.builder = builder or ReportContextBuilder()

    def optimize(self, finding_id: int, platform: str = "hackerone") -> dict[str, Any] | None:
        ctx = self.builder.build(finding_id, platform)
        if not ctx:
            return None

        result = ctx.template_vars.copy()
        result.update(
            {
                "finding_id": finding_id,
                "platform": ctx.platform,
                "quality_score": round(ctx.quality_score, 1),
                "quality_dimensions": ctx.quality_dimensions,
                "evidence_count": ctx.evidence_count,
                "acceptance_probability": round(ctx.acceptance_probability, 2),
                "acceptance_recommendations": ctx.acceptance_recommendations,
                "acceptance_weak_dimensions": ctx.acceptance_weak_dimensions,
                "remediation": ctx.remediation,
                "critic_score": round(ctx.critic_score, 1),
                "critic_verdict": ctx.critic_verdict,
                "critic_suggestions": ctx.critic_suggestions[:5],
            }
        )

        if Events is not None:
            try:
                bus = get_bus()
                bus.publish(
                    Events.REPORT_OPTIMIZED,
                    finding_id=finding_id,
                    platform=ctx.platform,
                    quality_score=ctx.quality_score,
                    acceptance_probability=ctx.acceptance_probability,
                    critic_verdict=ctx.critic_verdict,
                )
            except Exception as exc:
                logger.warning("Event publish failed: %s", exc)

        return result

    def batch_optimize(self, finding_ids: list[int], platform: str = "hackerone") -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for fid in finding_ids:
            try:
                result = self.optimize(fid, platform)
                if result:
                    results.append(result)
            except Exception as exc:
                logger.warning("Optimize failed for finding %s: %s", fid, exc)
        return results
