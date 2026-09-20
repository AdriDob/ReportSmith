from __future__ import annotations

import contextlib
import json
import logging
from typing import Any

from database.models import Evidence, Finding, Verdict

from database import db
from reportsmith.copilot.analyzer import CopilotContext, FindingAnalyzer
from reportsmith.copilot.review import CopilotReview

logger = logging.getLogger("orion.core.reports.quality.scorer")


def _finding_to_dict(f: Finding) -> dict[str, Any]:
    return {
        "id": str(f.id),
        "title": f.title,
        "description": f.description or "",
        "severity": f.severity or "medium",
        "status": f.status,
        "vulnerability_type": f.vulnerability_type or "unknown",
        "endpoint_id": f.endpoint_id,
        "target_id": f.target_id,
        "notes": f.notes or "",
    }


def _verdict_to_dict(v: Verdict) -> dict[str, Any]:
    d: dict[str, Any] = {
        "id": str(v.id),
        "status": v.status,
        "confidence": v.confidence,
        "reproducibility_score": v.reproducibility_score,
        "reason": v.reason or "",
        "uncertainty_level": v.uncertainty_level or "unknown",
        "vulnerability_type": v.vulnerability_type or "unknown",
        "alternative_explanations": [],
        "next_best_test": v.next_best_test or "",
    }
    if v.confidence_details:
        with contextlib.suppress(json.JSONDecodeError, TypeError):
            d["confidence_details"] = json.loads(v.confidence_details)
    if v.alternative_explanations:
        with contextlib.suppress(json.JSONDecodeError, TypeError):
            d["alternative_explanations"] = json.loads(v.alternative_explanations)
    if v.validation_report:
        try:
            d["validation_report"] = json.loads(v.validation_report)
        except (json.JSONDecodeError, TypeError):
            d["validation_report"] = v.validation_report
    return d


def _evidence_to_dict(e: Evidence) -> dict[str, Any]:
    return {
        "id": str(e.id),
        "attempt_label": e.attempt_label,
        "request_url": e.request_url,
        "request_method": e.request_method,
        "response_status": e.response_status,
        "auth_label": e.auth_label or "",
        "consistent": getattr(e, "consistent", None),
    }


class QualityScore:
    """Result of quality scoring for a single finding."""

    def __init__(
        self,
        finding_id: int,
        score: float,
        dimensions: dict[str, float],
        weights: dict[str, float],
        review: dict[str, Any],
        analysis: dict[str, Any] | None = None,
        evidence_count: int = 0,
        verdict_count: int = 0,
    ) -> None:
        self.finding_id = finding_id
        self.score = round(score, 1)
        self.dimensions = dimensions
        self.weights = weights
        self.review = review
        self.analysis = analysis
        self.evidence_count = evidence_count
        self.verdict_count = verdict_count

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "score": self.score,
            "dimensions": self.dimensions,
            "weights": self.weights,
            "review": self.review,
            "analysis": self.analysis,
            "evidence_count": self.evidence_count,
            "verdict_count": self.verdict_count,
        }


class QualityScorer:
    """Evaluates finding quality across 6 dimensions → score 0-100."""

    WEIGHTS: dict[str, float] = {
        "evidence": 20.0,
        "reproducibility": 20.0,
        "clarity": 15.0,
        "impact_severity": 15.0,
        "completeness": 15.0,
        "confidence": 15.0,
    }

    def __init__(
        self,
        copilot_review: CopilotReview | None = None,
        finding_analyzer: FindingAnalyzer | None = None,
    ) -> None:
        self.reviewer = copilot_review or CopilotReview()
        self.analyzer = finding_analyzer or FindingAnalyzer()

    def score(self, finding_id: int) -> QualityScore:
        session = db.SessionLocal()
        try:
            f = session.query(Finding).filter(Finding.id == finding_id).first()
            if not f:
                raise ValueError(f"Finding {finding_id} not found")

            finding_dict = _finding_to_dict(f)

            verdicts: list[Verdict] = []
            if f.endpoint_id:
                verdicts = session.query(Verdict).filter(Verdict.endpoint_id == f.endpoint_id).all()

            evidence: list[Evidence] = []
            verdict_ids = [v.id for v in verdicts]
            if verdict_ids:
                evidence = session.query(Evidence).filter(Evidence.verdict_id.in_(verdict_ids)).all()

            latest_verdict = verdicts[-1] if verdicts else None
            verdict_dict = _verdict_to_dict(latest_verdict) if latest_verdict else None
            evidence_dicts = [_evidence_to_dict(e) for e in evidence]
            finding_dict["evidence"] = evidence_dicts

            review_report = self.reviewer.review(finding_dict, verdict_dict)
            review_dict = review_report.to_dict()

            context = CopilotContext(
                finding=finding_dict,
                verdict=verdict_dict,
                evidence=evidence_dicts,
                confidence_score=self._parse_confidence(verdict_dict),
            )
            analysis = self.analyzer.analyze(context)
            analysis_dict = analysis.to_dict()

            dimensions = self._compute_dimensions(
                review_dict,
                analysis_dict,
                verdict_dict,
                finding_dict,
                evidence_dicts,
            )

            score = sum(dimensions[dim] * (self.WEIGHTS[dim] / 100.0) for dim in self.WEIGHTS)

            return QualityScore(
                finding_id=finding_id,
                score=score,
                dimensions=dimensions,
                weights=dict(self.WEIGHTS),
                review=review_dict,
                analysis=analysis_dict,
                evidence_count=len(evidence_dicts),
                verdict_count=len(verdicts),
            )
        finally:
            session.close()

    def _parse_confidence(self, verdict_dict: dict[str, Any] | None) -> dict[str, Any]:
        if not verdict_dict:
            return {"score": 0.0, "uncertainty_penalty": 0.0}
        conf = verdict_dict.get("confidence", "0.0")
        details = verdict_dict.get("confidence_details", {})
        if isinstance(conf, str):
            try:
                conf = json.loads(conf)
                if isinstance(conf, dict):
                    return {**conf, **details}
                return {"score": float(conf), "uncertainty_penalty": 0.0, **details}
            except (json.JSONDecodeError, TypeError, ValueError):
                try:
                    conf = float(conf)
                except (ValueError, TypeError):
                    conf = 0.0
        return {"score": float(conf), "uncertainty_penalty": 0.0, **details}

    def _compute_dimensions(
        self,
        review: dict[str, Any],
        analysis: dict[str, Any],
        verdict: dict[str, Any] | None,
        finding: dict[str, Any],
        evidence: list[dict[str, Any]],
    ) -> dict[str, float]:
        dims: dict[str, float] = {}

        items = {i["name"]: i for i in review.get("items", [])}
        evidence_exists = items.get("evidence_exists", {})
        has_evidence = evidence_exists.get("status") == "passed"
        dims["evidence"] = self._score_evidence(has_evidence, evidence, analysis)

        reproducible = items.get("reproducible", {})
        dims["reproducibility"] = self._score_reproducibility(reproducible, verdict)

        has_explanation = items.get("has_explanation", {})
        dims["clarity"] = self._score_clarity(has_explanation, finding)

        cvss = items.get("cvss_assigned", {})
        cwe = items.get("cwe_classified", {})
        impact = items.get("impact_defined", {})
        dims["impact_severity"] = self._score_impact_severity(cvss, cwe, impact, finding)

        remediation = items.get("has_remediation", {})
        alternatives = items.get("alternatives_checked", {})
        dims["completeness"] = self._score_completeness(remediation, alternatives, cwe, finding)

        confidence = items.get("confidence_adequate", {})
        dims["confidence"] = self._score_confidence(confidence, analysis)

        return dims

    def _score_evidence(
        self,
        has_evidence: bool,
        evidence: list[dict[str, Any]],
        analysis: dict[str, Any],
    ) -> float:
        if not has_evidence or not evidence:
            return 0.0
        score = 0.5
        if len(evidence) >= 2:
            score = 0.7
        if len(evidence) >= 3:
            score = 0.85
        consistent = sum(1 for e in evidence if e.get("consistent") is True)
        if consistent >= 2:
            score = min(1.0, score + 0.15)
        if consistent < len(evidence) and consistent > 0:
            score = max(0.4, score - 0.1)
        inconsistencies = analysis.get("inconsistencies", [])
        if inconsistencies:
            score = max(0.2, score - 0.1 * len(inconsistencies))
        return round(score, 2)

    def _score_reproducibility(
        self,
        reproducible: dict[str, Any],
        verdict: dict[str, Any] | None,
    ) -> float:
        if reproducible.get("status") == "failed":
            return 0.0
        if verdict:
            raw = verdict.get("reproducibility_score", "")
            if raw:
                try:
                    raw_d = json.loads(raw) if isinstance(raw, str) else raw
                    if isinstance(raw_d, dict):
                        r = raw_d.get("score", raw_d.get("overall", 0.0))
                        return min(1.0, float(r))
                except (json.JSONDecodeError, TypeError, ValueError):
                    pass
        if reproducible.get("status") == "passed":
            return 0.85
        if reproducible.get("status") == "skipped":
            return 0.5
        return 0.0

    def _score_clarity(
        self,
        has_explanation: dict[str, Any],
        finding: dict[str, Any],
    ) -> float:
        if has_explanation.get("status") == "failed":
            desc = finding.get("description", "")
            title = finding.get("title", "")
            if len(desc) > 100 or len(title) > 50:
                return 0.4
            return 0.1
        if has_explanation.get("status") == "passed":
            desc = finding.get("description", "")
            desc_len = len(desc)
            if desc_len > 300:
                return 1.0
            if desc_len > 150:
                return 0.9
            if desc_len > 50:
                return 0.7
            return 0.5
        return 0.3

    def _score_impact_severity(
        self,
        cvss: dict[str, Any],
        cwe: dict[str, Any],
        impact: dict[str, Any],
        finding: dict[str, Any],
    ) -> float:
        score = 0.0
        if cvss.get("status") == "passed":
            score += 0.35
        if cwe.get("status") == "passed":
            score += 0.25
        if impact.get("status") == "passed":
            score += 0.25
        severity_map = {"critical": 0.15, "high": 0.1, "medium": 0.05, "low": 0.0}
        score += severity_map.get(finding.get("severity", ""), 0.0)
        return round(min(1.0, score), 2)

    def _score_completeness(
        self,
        remediation: dict[str, Any],
        alternatives: dict[str, Any],
        cwe: dict[str, Any],
        finding: dict[str, Any],
    ) -> float:
        score = 0.0
        if remediation.get("status") == "passed":
            score += 0.35
        if alternatives.get("status") == "passed":
            score += 0.20
        if cwe.get("status") == "passed":
            score += 0.20
        notes = finding.get("notes", "")
        if len(notes) > 20:
            score += 0.15
        if finding.get("vulnerability_type", "unknown") != "unknown":
            score += 0.10
        return round(min(1.0, score), 2)

    def _score_confidence(
        self,
        confidence: dict[str, Any],
        analysis: dict[str, Any],
    ) -> float:
        if confidence.get("status") == "failed":
            return 0.15
        if confidence.get("status") == "passed":
            score = 0.7
            conf = analysis.get("confidence", 0.0)
            if conf >= 0.85:
                score = 1.0
            elif conf >= 0.70:
                score = 0.85
            needs_human = analysis.get("needs_human", True)
            if needs_human:
                score = max(0.5, score - 0.15)
            return score
        return 0.3
