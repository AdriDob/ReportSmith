"""Explanation Engine — makes every Copilot decision transparent."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("orion.core.copilot.explain")


class ExplanationEngine:
    """Generates human-readable explanations for Copilot decisions.

    Answers questions like:
    - Why did you decide to report?
    - What evidence weighed most?
    - What alternatives did you discard?
    - What changed since yesterday?
    """

    def explain_verdict(self, verdict: dict[str, Any]) -> str:
        """Explain why a verdict was reached."""
        status = verdict.get("status", "unknown")
        confidence = verdict.get("confidence", 0.0)
        reasons = verdict.get("reasons", [])

        parts: list[str] = []
        parts.append(f"Veredicto: **{status.upper()}** (confianza: {confidence:.0%})")

        if reasons:
            parts.append("Razones:")
            for r in reasons:
                parts.append(f"  • {r.get('description', str(r))}")

        alternatives = verdict.get("alternative_explanations", [])
        if alternatives:
            parts.append(f"Alternativas descartadas: {len(alternatives)}")
            for alt in alternatives[:3]:
                parts.append(f"  • {alt.get('description', str(alt))} (peso: {alt.get('weight', 0.0):.2f})")

        return "\n".join(parts)

    def explain_confidence(
        self,
        score: dict[str, Any],
        evidence_count: int = 0,
    ) -> str:
        """Explain how confidence was calculated."""
        base = score.get("base_score", 0.0)
        penalty = score.get("uncertainty_penalty", 0.0)
        final = score.get("score", base - penalty)
        factors = score.get("factors", [])

        parts: list[str] = []
        parts.append(f"Confianza: {final:.1%} (base: {base:.1%}, penalización: {penalty:.1%})")

        if factors:
            parts.append("Factores considerados:")
            for f in factors:
                parts.append(f"  • {f.get('name', str(f))}: {f.get('value', 0.0):.1%}")

        parts.append(f"Evidencia disponible: {evidence_count} elementos")

        if evidence_count == 0:
            parts.append("⚠ Sin evidencia — confianza reducida")

        return "\n".join(parts)

    def explain_action(
        self,
        action: str,
        reason: str,
        confidence: float,
        authority: str,
    ) -> str:
        """Explain why a specific action was chosen."""
        parts: list[str] = [
            f"Acción: **{action}**",
            f"Razón: {reason}",
            f"Confianza: {confidence:.0%}",
            f"Autoridad: {authority}",
        ]

        conf_parts: list[str] = []
        if confidence < 0.40:
            conf_parts.append("confianza muy baja — no actuar")
        elif confidence < 0.70:
            conf_parts.append("confianza moderada — solicitar aprobación")
        elif confidence < 0.90:
            conf_parts.append("confianza buena — ejecutar tareas seguras")
        elif confidence >= 0.90:
            conf_parts.append("confianza alta — puede cerrar el flujo autónomamente")

        if conf_parts:
            parts.append(f"({', '.join(conf_parts)})")

        return "\n".join(parts)

    def explain_changes(self, current: dict, previous: dict | None) -> str:
        """Explain what changed between two states."""
        if previous is None:
            return "Sin estado previo para comparar."

        changes: list[str] = []

        if current.get("confidence") != previous.get("confidence"):
            old_c = previous.get("confidence", 0.0)
            new_c = current.get("confidence", 0.0)
            diff = new_c - old_c
            direction = "subió" if diff > 0 else "bajó"
            changes.append(f"Confianza {direction}: {old_c:.1%} → {new_c:.1%} ({diff:+.1%})")

        old_ev = previous.get("evidence_count", 0)
        new_ev = current.get("evidence_count", 0)
        if new_ev != old_ev:
            changes.append(f"Evidencia: {old_ev} → {new_ev} elementos")

        old_status = previous.get("status", "unknown")
        new_status = current.get("status", "unknown")
        if new_status != old_status:
            changes.append(f"Estado: {old_status} → {new_status}")

        if not changes:
            return "Sin cambios significativos desde la última revisión."

        return "Cambios detectados:\n" + "\n".join(f"  • {c}" for c in changes)

    def explain_alternative_discarded(
        self,
        alt_description: str,
        alt_weight: float,
        chosen_description: str,
        chosen_weight: float,
    ) -> str:
        """Explain why an alternative explanation was discarded."""
        return (
            f"Alternativa descartada: '{alt_description}' "
            f"(peso: {alt_weight:.2f}) vs. '{chosen_description}' "
            f"(peso: {chosen_weight:.2f})"
        )
