from __future__ import annotations

import logging
from typing import Any, Literal

from reportsmith.reports.quality.scorer import QualityScore

logger = logging.getLogger("orion.core.reports.quality.classifier")

ClassificationLabel = Literal["elite", "review", "no_recommend"]

_THRESHOLDS: dict[str, float] = {
    "elite": 85.0,
    "review": 60.0,
}

_BADGES: dict[ClassificationLabel, str] = {
    "elite": "Elite",
    "review": "Review",
    "no_recommend": "No Recomendar",
}


class QualityClassification:
    """Result of classifying a finding's quality."""

    def __init__(
        self,
        finding_id: int,
        score: float,
        label: ClassificationLabel,
        badge: str,
        passed: bool,
        improvement_suggestions: list[str],
        dimension_breakdown: list[dict[str, Any]],
    ) -> None:
        self.finding_id = finding_id
        self.score = score
        self.label = label
        self.badge = badge
        self.passed = passed
        self.improvement_suggestions = improvement_suggestions
        self.dimension_breakdown = dimension_breakdown

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "score": self.score,
            "label": self.label,
            "badge": self.badge,
            "passed": self.passed,
            "improvement_suggestions": self.improvement_suggestions,
            "dimension_breakdown": self.dimension_breakdown,
        }


class QualityClassifier:
    """Classifies findings by quality score into Elite / Review / No Recomendar."""

    def classify(self, quality_score: QualityScore) -> QualityClassification:
        score = quality_score.score
        dims = quality_score.dimensions
        weights = quality_score.weights

        if score >= _THRESHOLDS["elite"]:
            label: ClassificationLabel = "elite"
        elif score >= _THRESHOLDS["review"]:
            label = "review"
        else:
            label = "no_recommend"

        passed = label in ("elite", "review")
        badge = _BADGES[label]

        suggestions = self._generate_suggestions(dims, weights, quality_score)
        breakdown = self._build_breakdown(dims, weights)

        return QualityClassification(
            finding_id=quality_score.finding_id,
            score=score,
            label=label,
            badge=badge,
            passed=passed,
            improvement_suggestions=suggestions,
            dimension_breakdown=breakdown,
        )

    def _build_breakdown(self, dimensions: dict[str, float], weights: dict[str, float]) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for dim, raw_score in dimensions.items():
            weight = weights.get(dim, 0.0)
            contributions = round(raw_score * weight * 0.01, 1)
            pct = round(raw_score * 100.0, 1)
            result.append(
                {
                    "dimension": dim,
                    "score": pct,
                    "weight": weight,
                    "contribution": contributions,
                }
            )
        return sorted(result, key=lambda x: x["score"])

    def _generate_suggestions(
        self,
        dimensions: dict[str, float],
        weights: dict[str, float],
        quality_score: QualityScore,
    ) -> list[str]:
        suggestions: list[str] = []
        review = quality_score.review
        items = {i["name"]: i for i in review.get("items", [])}

        for dim, raw_score in dimensions.items():
            dim_pct = raw_score * 100.0
            if dim_pct >= 90.0:
                continue

            if dim == "evidence":
                if raw_score == 0.0:
                    suggestions.append("Agregar evidencia capturada (request/response pairs)")
                elif raw_score < 0.6:
                    suggestions.append("Recolectar más evidencia consistente (mínimo 2 intentos)")
                elif raw_score < 0.8:
                    suggestions.append("Verificar consistencia entre intentos de validación")

            elif dim == "reproducibility":
                ev = items.get("reproducible", {})
                if ev.get("status") == "failed":
                    suggestions.append("Documentar pasos de reproducción detallados")
                elif raw_score < 0.6:
                    suggestions.append("Refinar procedimiento de reproducción (incluir payloads exactos)")

            elif dim == "clarity":
                ev = items.get("has_explanation", {})
                if ev.get("status") == "failed":
                    suggestions.append("Ampliar descripción del hallazgo (mínimo 50 caracteres)")
                elif raw_score < 0.7:
                    suggestions.append("Mejorar claridad de la explicación técnica")

            elif dim == "impact_severity":
                if items.get("cvss_assigned", {}).get("status") == "failed":
                    suggestions.append("Asignar puntuación CVSS al hallazgo")
                if items.get("cwe_classified", {}).get("status") == "failed":
                    suggestions.append("Clasificar con CWE el tipo de vulnerabilidad")
                if items.get("impact_defined", {}).get("status") == "failed":
                    suggestions.append("Describir el impacto de negocio del hallazgo")

            elif dim == "completeness":
                if items.get("has_remediation", {}).get("status") == "failed":
                    suggestions.append("Agregar recomendación de remediación")
                if raw_score < 0.5:
                    suggestions.append("Completar metadatos del hallazgo (notas, referencias)")

            elif dim == "confidence":
                if items.get("confidence_adequate", {}).get("status") == "failed":
                    suggestions.append("Aumentar confianza del veredicto (>70% requerido)")
                elif raw_score < 0.6:
                    suggestions.append("Realizar validaciones adicionales para elevar confianza")

        analysis = quality_score.analysis
        if analysis:
            inconsistencies = analysis.get("inconsistencies", [])
            for inc in inconsistencies:
                suggestion = f"Resolver inconsistencia: {inc}"
                if suggestion not in suggestions:
                    suggestions.append(suggestion)

            analysis_suggestions = analysis.get("recommendations", [])
            for rec in analysis_suggestions:
                if rec not in suggestions:
                    suggestions.append(rec)

        if suggestions:
            seen: set[str] = set()
            unique: list[str] = []
            for s in suggestions:
                lower = s.lower().strip()
                if lower not in seen:
                    seen.add(lower)
                    unique.append(s)
            suggestions = unique

        return suggestions[:8]
