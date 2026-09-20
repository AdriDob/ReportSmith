"""Report Critic — pre-submission quality gate.

Simulates a senior triager reviewing the report before it leaves the system.
Attempts to identify weaknesses, missing information, and rejection risks.

Usage::

    from reportsmith.reports.critic import ReportCritic

    critic = ReportCritic()
    result = critic.evaluate(finding_data, platform="hackerone")
    logger.info("score=%s verdict=%s suggestions=%s", result.score, result.verdict, result.suggestions)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("orion.core.reports.critic")


@dataclass
class CriticCheck:
    name: str
    description: str
    passed: bool = False
    weight: float = 1.0
    notes: str = ""

    @property
    def score(self) -> float:
        return self.weight if self.passed else 0.0


@dataclass
class CriticResult:
    score: float = 0.0
    max_score: float = 0.0
    checks: list[CriticCheck] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)
    verdict: str = "unknown"

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "max_score": self.max_score,
            "percentage": round(self.score / self.max_score * 100, 1) if self.max_score > 0 else 0.0,
            "verdict": self.verdict,
            "checks": [
                {"name": c.name, "description": c.description, "passed": c.passed, "notes": c.notes}
                for c in self.checks
            ],
            "suggestions": self.suggestions,
        }


class ReportCritic:
    """Pre-submission gate that evaluates report quality and acceptance likelihood."""

    def evaluate(self, finding: dict[str, Any], platform: str = "hackerone") -> CriticResult:
        """Run the full critic pipeline on a finding/report.

        Args:
            finding: Finding data dict with keys like title, description, evidence, etc.
            platform: Target platform (hackerone, bugcrowd, intigriti).

        Returns:
            CriticResult with score, checks, suggestions, verdict.
        """
        result = CriticResult()
        _aliases = {"h1": "hackerone", "bc": "bugcrowd", "inti": "intigriti"}
        platform_lower = _aliases.get(platform.lower(), platform.lower())

        checks = [
            *self._check_title(finding),
            *self._check_description(finding),
            *self._check_vulnerability_type(finding),
            *self._check_severity(finding),
            *self._check_reproduction(finding),
            *self._check_poc(finding),
            *self._check_evidence(finding),
            *self._check_impact(finding),
            *self._check_cvss(finding),
            *self._check_cwe(finding),
            *self._check_remediation(finding),
            *self._check_platform_specific(finding, platform_lower),
        ]

        result.checks = checks
        result.max_score = sum(c.weight for c in checks)
        result.score = sum(c.score for c in checks)

        # Generate suggestions from failed checks
        for c in checks:
            if not c.passed:
                result.suggestions.append(self._suggestion_for(c, platform_lower))

        # Verdict based on score percentage
        pct = result.score / result.max_score * 100 if result.max_score > 0 else 0
        if pct >= 90:
            result.verdict = "ready"
        elif pct >= 75:
            result.verdict = "needs_improvement"
        elif pct >= 50:
            result.verdict = "risky"
        else:
            result.verdict = "rework"

        return result

    def _check_title(self, finding: dict[str, Any]) -> list[CriticCheck]:
        title = finding.get("title", "") or ""
        checks = []
        checks.append(
            CriticCheck(
                name="title_exists",
                description="Report has a title",
                passed=bool(title.strip()),
                weight=2.0,
                notes=f"Title: {title[:80]}" if title else "",
            )
        )
        checks.append(
            CriticCheck(
                name="title_descriptive",
                description="Title describes the vulnerability, not just the endpoint",
                passed=len(title.split()) >= 4,
                weight=1.0,
                notes=f"{len(title.split())} words" if title else "",
            )
        )
        return checks

    def _check_description(self, finding: dict[str, Any]) -> list[CriticCheck]:
        desc = finding.get("description", "") or finding.get("vulnerability_description", "") or ""
        checks = []
        checks.append(
            CriticCheck(
                name="description_exists",
                description="Report has a description",
                passed=bool(desc.strip()),
                weight=2.0,
            )
        )
        checks.append(
            CriticCheck(
                name="description_detailed",
                description="Description is detailed (100+ chars)",
                passed=len(desc.strip()) >= 100,
                weight=1.5,
                notes=f"{len(desc.strip())} chars" if desc else "",
            )
        )
        # Check for weak language
        weak_terms = ["maybe", "might", "possibly", "could be", "seems like", "i think"]
        has_weak = any(term in desc.lower() for term in weak_terms)
        checks.append(
            CriticCheck(
                name="description_confident",
                description="Description uses confident language",
                passed=not has_weak,
                weight=1.0,
                notes="Weak language detected" if has_weak else "",
            )
        )
        return checks

    def _check_vulnerability_type(self, finding: dict[str, Any]) -> list[CriticCheck]:
        vtype = finding.get("vulnerability_type", "") or ""
        valid_types = {
            "idor",
            "ssrf",
            "xss",
            "sqli",
            "auth_bypass",
            "csrf",
            "lfi",
            "cmdi",
            "open_redirect",
            "race_condition",
            "cors",
            "business_logic",
            "graphql",
            "rce",
            "deserialization",
            "path_traversal",
            "information_disclosure",
            "http_request_smuggling",
            "template_injection",
            "xxe",
            "nosqli",
            "ldapi",
            "ssti",
            "hpp",
        }
        checks = []
        checks.append(
            CriticCheck(
                name="vuln_type_set",
                description="Vulnerability type is specified",
                passed=bool(vtype.strip()),
                weight=1.5,
                notes=vtype if vtype else "",
            )
        )
        checks.append(
            CriticCheck(
                name="vuln_type_valid",
                description="Vulnerability type is a recognized CWE category",
                passed=vtype.lower() in valid_types,
                weight=0.5,
            )
        )
        return checks

    def _check_severity(self, finding: dict[str, Any]) -> list[CriticCheck]:
        severity = str(finding.get("severity", "") or "")
        valid = {"critical", "high", "medium", "low", "informational"}
        checks = []
        checks.append(
            CriticCheck(
                name="severity_set",
                description="Severity is specified",
                passed=bool(severity.strip()),
                weight=1.0,
                notes=severity if severity else "",
            )
        )
        checks.append(
            CriticCheck(
                name="severity_valid",
                description="Severity is a valid value",
                passed=severity.lower() in valid,
                weight=0.5,
            )
        )
        return checks

    def _check_reproduction(self, finding: dict[str, Any]) -> list[CriticCheck]:
        steps = finding.get("reproduction_steps", []) or finding.get("test_instructions", []) or []
        has_steps = len(steps) >= 3
        checks = []
        checks.append(
            CriticCheck(
                name="reproduction_steps",
                description="At least 3 reproduction steps",
                passed=has_steps,
                weight=2.0,
                notes=f"{len(steps)} steps" if steps else "No steps",
            )
        )
        # Check steps are detailed
        avg_len = sum(len(s) for s in steps) / max(len(steps), 1)
        checks.append(
            CriticCheck(
                name="reproduction_detail",
                description="Reproduction steps have adequate detail",
                passed=avg_len >= 30,
                weight=1.0,
                notes=f"Avg {avg_len:.0f} chars/step" if steps else "",
            )
        )
        return checks

    def _check_poc(self, finding: dict[str, Any]) -> list[CriticCheck]:
        poc = finding.get("poc", {}) or {}
        has_curl = bool(poc.get("curl", "")) if isinstance(poc, dict) else bool(str(poc).strip())

        checks = []
        checks.append(
            CriticCheck(
                name="poc_curl",
                description="curl command is provided in PoC",
                passed=has_curl,
                weight=2.0,
            )
        )
        checks.append(
            CriticCheck(
                name="poc_python",
                description="Python script is provided in PoC",
                passed=bool(finding.get("python_script", "")),
                weight=1.5,
            )
        )
        checks.append(
            CriticCheck(
                name="poc_request_response",
                description="PoC includes both request and response data",
                passed=bool(finding.get("request", "")) and bool(finding.get("response", "")),
                weight=1.0,
            )
        )
        return checks

    def _check_evidence(self, finding: dict[str, Any]) -> list[CriticCheck]:
        evidence = finding.get("evidence", []) or []
        has_evidence = len(evidence) > 0
        checks = []
        checks.append(
            CriticCheck(
                name="evidence_exists",
                description="At least one evidence item is attached",
                passed=has_evidence,
                weight=2.0,
                notes=f"{len(evidence)} evidence items" if evidence else "",
            )
        )
        # Check for URL/screenshot references
        has_url = any("http" in str(e).lower() for e in evidence) if evidence else False
        checks.append(
            CriticCheck(
                name="evidence_urls",
                description="Evidence contains URL references",
                passed=has_url,
                weight=1.0,
            )
        )
        return checks

    def _check_impact(self, finding: dict[str, Any]) -> list[CriticCheck]:
        impact = finding.get("impact", "") or finding.get("business_impact", "") or ""
        checks = []
        checks.append(
            CriticCheck(
                name="impact_exists",
                description="Business impact is clearly stated",
                passed=bool(impact.strip()),
                weight=2.0,
            )
        )
        checks.append(
            CriticCheck(
                name="impact_detailed",
                description="Impact description is substantive (50+ chars)",
                passed=len(impact.strip()) >= 50,
                weight=1.0,
                notes=f"{len(impact.strip())} chars" if impact else "",
            )
        )
        return checks

    def _check_cvss(self, finding: dict[str, Any]) -> list[CriticCheck]:
        cvss = finding.get("cvss_score", 0) or finding.get("cvss", 0) or 0
        cvss_vector = finding.get("cvss_vector", "") or ""
        checks = []
        checks.append(
            CriticCheck(
                name="cvss_scored",
                description="CVSS score is assigned",
                passed=float(cvss) > 0,
                weight=1.5,
                notes=f"CVSS: {cvss}" if float(cvss) > 0 else "",
            )
        )
        checks.append(
            CriticCheck(
                name="cvss_vectored",
                description="CVSS vector string is provided",
                passed=bool(cvss_vector.strip()),
                weight=0.5,
            )
        )
        return checks

    def _check_cwe(self, finding: dict[str, Any]) -> list[CriticCheck]:
        cwe = finding.get("cwe_id", "") or finding.get("cwe", "") or ""
        checks = []
        checks.append(
            CriticCheck(
                name="cwe_set",
                description="CWE identifier is provided",
                passed=bool(cwe.strip()),
                weight=1.0,
                notes=cwe if cwe else "",
            )
        )
        return checks

    def _check_remediation(self, finding: dict[str, Any]) -> list[CriticCheck]:
        remediation = finding.get("remediation", "") or finding.get("fix", "") or ""
        checks = []
        checks.append(
            CriticCheck(
                name="remediation_exists",
                description="Remediation recommendation is included",
                passed=bool(remediation.strip()),
                weight=1.5,
            )
        )
        checks.append(
            CriticCheck(
                name="remediation_detailed",
                description="Remediation is actionable (50+ chars)",
                passed=len(remediation.strip()) >= 50,
                weight=0.5,
                notes=f"{len(remediation.strip())} chars" if remediation else "",
            )
        )
        return checks

    def _check_platform_specific(self, finding: dict[str, Any], platform: str) -> list[CriticCheck]:
        checks = []
        if platform in ("hackerone", "h1"):
            checks.append(
                CriticCheck(
                    name="h1_asset_type",
                    description="H1 requires asset type specification",
                    passed=bool(finding.get("asset_type", "") or finding.get("asset_type_name", "")),
                    weight=1.0,
                    notes="Missing asset type — specify if URL, mobile, API, etc.",
                )
            )
        elif platform in ("bugcrowd", "bc"):
            checks.append(
                CriticCheck(
                    name="bc_bounty_type",
                    description="Bugcrowd needs bounty type (VRT-based)",
                    passed=bool(finding.get("bounty_type", "")),
                    weight=1.0,
                )
            )
        elif platform in ("intigriti", "inti"):
            checks.append(
                CriticCheck(
                    name="inti_tags",
                    description="Intigriti requires tags/classification",
                    passed=bool(finding.get("tags", [])) or bool(finding.get("classification", "")),
                    weight=1.0,
                )
            )
        return checks

    def _suggestion_for(self, check: CriticCheck, platform: str) -> str:
        suggestions = {
            "title_exists": "Add a descriptive title like 'IDOR in user profile endpoint allows accessing other users' data'",
            "title_descriptive": "Make the title more descriptive — include the vulnerability type and affected endpoint",
            "description_exists": "Write a clear description explaining the vulnerability and how it works",
            "description_detailed": "Expand the description to at least 100 characters with technical details",
            "description_confident": "Replace weak language ('maybe', 'might') with confident assertions backed by evidence",
            "vuln_type_set": "Specify the vulnerability type (IDOR, SSRF, XSS, SQLi, etc.)",
            "vuln_type_valid": "Use a recognized vulnerability category from the CWE taxonomy",
            "severity_set": "Assign a severity level (critical/high/medium/low/informational)",
            "reproduction_steps": "Write at least 3 clear, numbered reproduction steps. Each step should be actionable.",
            "reproduction_detail": "Each reproduction step should be detailed (30+ characters). Include specific URLs, parameters, and values.",
            "poc_curl": "Include a curl command that reproduces the issue — use the Evidence Composer to generate it",
            "poc_python": "Add a Python script that reproduces the issue for non-technical triagers",
            "poc_request_response": "Include both the raw request and the raw response in the PoC section",
            "evidence_exists": "Attach at least one evidence file (screenshot, HAR, log)",
            "evidence_urls": "Include URL references in your evidence to make it verifiable",
            "impact_exists": "Explain the business impact: what data an attacker could access or what damage they could cause",
            "impact_detailed": "Expand the business impact to at least 50 characters with specific scenarios",
            "cvss_scored": "Calculate and include a CVSS v3.1 score for the vulnerability",
            "cvss_vectored": "Include the CVSS vector string (e.g., CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)",
            "cwe_set": "Include the CWE identifier (e.g., CWE-200 for Information Disclosure)",
            "remediation_exists": "Add a remediation recommendation. Even if obvious, it shows professionalism.",
            "remediation_detailed": "Make the remediation recommendation specific and actionable (50+ chars)",
        }

        # Platform-specific suggestions
        if check.name == "h1_asset_type":
            return "Specify the asset type (URL, API, Mobile, Source code) — HackerOne requires this for routing"
        if check.name == "bc_bounty_type":
            return "Bugcrowd requires a VRT-based bounty type. Check the current VRT for the correct classification"
        if check.name == "inti_tags":
            return "Intigriti requires tags/classification for proper routing. Add relevant tags."

        return suggestions.get(check.name, f"Fix: {check.description}")
