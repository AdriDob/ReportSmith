"""Copilot Review — final quality checklist before reports leave the system."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("orion.core.copilot.review")


class ReviewItem:
    """A single item in the pre-report checklist."""

    def __init__(self, name: str, description: str) -> None:
        self.name = name
        self.description = description
        self.status = "pending"
        self.notes: str = ""

    def pass_(self, notes: str = "") -> None:
        self.status = "passed"
        self.notes = notes

    def fail(self, notes: str) -> None:
        self.status = "failed"
        self.notes = notes

    def skip(self, notes: str = "") -> None:
        self.status = "skipped"
        self.notes = notes

    def to_dict(self) -> dict[str, str]:
        return {
            "name": self.name,
            "description": self.description,
            "status": self.status,
            "notes": self.notes,
        }


class ReviewReport:
    """Complete pre-report checklist result."""

    def __init__(self, finding_id: str) -> None:
        self.finding_id = finding_id
        self.items: list[ReviewItem] = []
        self.timestamp = None

    def add_item(self, item: ReviewItem) -> None:
        self.items.append(item)

    @property
    def passed(self) -> bool:
        return all(item.status == "passed" for item in self.items)

    @property
    def failed_items(self) -> list[ReviewItem]:
        return [item for item in self.items if item.status == "failed"]

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "passed": self.passed,
            "total_items": len(self.items),
            "passed_count": sum(1 for i in self.items if i.status == "passed"),
            "failed_count": len(self.failed_items),
            "items": [i.to_dict() for i in self.items],
        }


class CopilotReview:
    """Senior Copilot Review — final quality gate before report generation.

    Simulates what a senior hunter would check before sending a report.
    """

    def review(self, finding: dict[str, Any], verdict: dict[str, Any] | None = None) -> ReviewReport:
        """Run the full review checklist on a finding."""
        report = ReviewReport(finding.get("id", "unknown"))

        # 1. Evidence check
        evidence = finding.get("evidence", []) or []
        item = ReviewItem("evidence_exists", "¿Existe evidencia del hallazgo?")
        if evidence:
            item.pass_(f"{len(evidence)} elemento(s) de evidencia")
        else:
            item.fail("No se encontró evidencia adjunta")
        report.add_item(item)

        # 2. Reproducibility
        reproducibility = finding.get("reproducibility", "")
        item = ReviewItem("reproducible", "¿El hallazgo es reproducible?")
        if reproducibility:
            item.pass_(f"Reproducibilidad: {reproducibility}")
        else:
            item.fail("No se especificó cómo reproducir el hallazgo")
        report.add_item(item)

        # 3. Explanation
        item = ReviewItem("has_explanation", "¿Hay una explicación clara?")
        description = finding.get("description", "") or finding.get("title", "")
        if len(description) > 50:
            item.pass_("Descripción suficiente")
        else:
            item.fail("Descripción demasiado corta o ausente")
        report.add_item(item)

        # 4. CVSS Score
        cvss = finding.get("cvss", 0) or finding.get("severity_score", 0)
        item = ReviewItem("cvss_assigned", "¿Hay puntuación CVSS?")
        if cvss:
            item.pass_(f"CVSS: {cvss}")
        else:
            item.fail("Sin puntuación CVSS")
        report.add_item(item)

        # 5. CWE Classification
        cwe = finding.get("cwe", "") or finding.get("vulnerability_type", "")
        item = ReviewItem("cwe_classified", "¿Está clasificado con CWE?")
        if cwe:
            item.pass_(f"CWE: {cwe}")
        else:
            item.fail("Sin clasificación CWE")
        report.add_item(item)

        # 6. Business impact
        impact = finding.get("impact", "") or finding.get("business_impact", "")
        item = ReviewItem("impact_defined", "¿Hay descripción de impacto?")
        if impact:
            item.pass_("Impacto definido")
        else:
            item.fail("Sin descripción de impacto")
        report.add_item(item)

        # 7. Remediation
        remediation = finding.get("remediation", "") or finding.get("fix", "")
        item = ReviewItem("has_remediation", "¿Hay recomendación de remediación?")
        if remediation:
            item.pass_("Remediación definida")
        else:
            item.fail("Sin recomendación de remediación")
        report.add_item(item)

        # 8. Confidence check
        if verdict:
            confidence = verdict.get("confidence", 0.0)
            item = ReviewItem("confidence_adequate", "¿La confianza es suficiente para reportar?")
            if confidence >= 0.70:
                item.pass_(f"Confianza: {confidence:.1%}")
            else:
                item.fail(f"Confianza insuficiente: {confidence:.1%}")
            report.add_item(item)

        # 9. Alternative explanations
        if verdict:
            alternatives = verdict.get("alternative_explanations", [])
            strong_alts = [a for a in alternatives if a.get("weight", 0) > 0.5]
            item = ReviewItem("alternatives_checked", "¿Se consideraron explicaciones alternativas?")
            if not strong_alts:
                item.pass_("Sin alternativas con peso significativo")
            else:
                item.fail(f"{len(strong_alts)} alternativa(s) con peso > 0.5")
            report.add_item(item)

        return report
