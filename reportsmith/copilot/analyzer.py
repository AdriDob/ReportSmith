"""Finding Analyzer — evaluates findings, hypotheses, and evidence."""

from __future__ import annotations

import logging
from typing import Any

from reportsmith.copilot.context import CopilotContext
from reportsmith.copilot.explain import ExplanationEngine

logger = logging.getLogger("orion.core.copilot.analyzer")


class AnalysisResult:
    """Result of a finding/hypothesis analysis."""

    def __init__(
        self,
        finding_id: str,
        status: str,
        confidence: float,
        reasons: list[str],
        inconsistencies: list[str],
        recommendations: list[str],
        needs_human: bool,
    ) -> None:
        self.finding_id = finding_id
        self.status = status
        self.confidence = confidence
        self.reasons = reasons
        self.inconsistencies = inconsistencies
        self.recommendations = recommendations
        self.needs_human = needs_human

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "status": self.status,
            "confidence": self.confidence,
            "reasons": self.reasons,
            "inconsistencies": self.inconsistencies,
            "recommendations": self.recommendations,
            "needs_human": self.needs_human,
        }


class FindingAnalyzer:
    """Analyzes findings, hypotheses, and evidence quality."""

    def __init__(self, explainer: ExplanationEngine | None = None) -> None:
        self.explainer = explainer or ExplanationEngine()

    def analyze(self, context: CopilotContext) -> AnalysisResult:
        """Full analysis of a finding within its context."""
        finding = context.finding or {}
        verdict = context.verdict or {}
        evidence = context.evidence
        confidence_data = context.confidence_score or {}

        finding_id = finding.get("id", "unknown")
        status = "pending"
        reasons: list[str] = []
        inconsistencies: list[str] = []
        recommendations: list[str] = []
        confidence = confidence_data.get("score", verdict.get("confidence", 0.0))

        # Analyze evidence
        if not evidence:
            inconsistencies.append("Sin evidencia adjunta al hallazgo")
            recommendations.append("Recolectar evidencia antes de continuar")
        else:
            evidence_with_against = [e for e in evidence if e.get("type") == "against"]
            evidence_for = [e for e in evidence if e.get("type") in ("for", "pro")]

            if evidence_with_against:
                inconsistencies.append(f"Hay {len(evidence_with_against)} evidencia(s) en contra")

            for ev in evidence:
                if ev.get("source") == "unverified":
                    inconsistencies.append(f"Fuente no verificada: {ev.get('description', 'unknown')}")

            if not evidence_for:
                inconsistencies.append("No hay evidencia a favor del hallazgo")

        # Analyze verdict
        if verdict:
            v_status = verdict.get("status", "")
            if v_status in ("rejected", "invalid"):
                status = "rejected"
                reasons.append(f"Veredicto previo: {v_status}")
            elif v_status == "confirmed":
                if confidence >= 0.85:
                    status = "report_ready"
                    reasons.append("Hallazgo confirmado con alta confianza")
                else:
                    status = "needs_review"
                    reasons.append("Hallazgo confirmado pero con confianza < 85%")

        # Analyze confidence
        if confidence < 0.40:
            reasons.append("Confianza muy baja — recomendar revisión manual")
            recommendations.append("Revisión manual requerida antes de cualquier acción")
        elif confidence < 0.70:
            reasons.append("Confianza moderada — solicitar aprobación humana")
            recommendations.append("Solicitar aprobación antes de proceder")
        elif confidence >= 0.70 and evidence:
            reasons.append("Confianza suficiente + evidencia presente")

        # Check for uncertainties
        if confidence_data.get("uncertainty_penalty", 0) > 0.05:
            inconsistencies.append(f"Penalización por incertidumbre: {confidence_data['uncertainty_penalty']:.2%}")

        # Alternatives
        alternatives = verdict.get("alternative_explanations", [])
        if alternatives:
            top_alt = max(alternatives, key=lambda a: a.get("weight", 0))
            if top_alt.get("weight", 0) > 0.6:
                inconsistencies.append(
                    f"Explicación alternativa fuerte: {top_alt.get('description', 'unknown')} "
                    f"(peso: {top_alt.get('weight', 0):.2f})"
                )

        # Determine overall status
        if not inconsistencies and confidence >= 0.70:
            status = status or "ready"
        elif status == "pending":
            status = "needs_review"

        needs_human = bool(inconsistencies) or confidence < 0.70

        return AnalysisResult(
            finding_id=finding_id,
            status=status,
            confidence=confidence,
            reasons=reasons,
            inconsistencies=inconsistencies,
            recommendations=recommendations,
            needs_human=needs_human,
        )
