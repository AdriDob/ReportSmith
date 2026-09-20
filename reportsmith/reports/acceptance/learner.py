from __future__ import annotations

import json
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from database.models import Report, SubmissionRecord

from database import db
from reportsmith.reports.quality.scorer import QualityScorer

logger = logging.getLogger("orion.core.reports.acceptance.learner")

LEARNED_WEIGHTS_KEY = "acceptance_optimizer:weights"
LEARNED_THRESHOLDS_KEY = "acceptance_optimizer:thresholds"
OBSERVATIONS_KEY = "acceptance_optimizer:observations"

OUTCOME_ACCEPTED = "accepted"
OUTCOME_REJECTED = "rejected"

ACCEPTANCE_STATUSES = {"bounty_paid", "resolved", "accepted"}
REJECTION_STATUSES = {"rejected", "informative", "duplicate", "closed"}


@dataclass
class OutcomeObservation:
    platform: str
    program: str
    vulnerability_type: str
    outcome: str
    dimensions: dict[str, float]
    score: float
    severity: str
    evidence_count: int
    timestamp: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "platform": self.platform,
            "program": self.program,
            "vulnerability_type": self.vulnerability_type,
            "outcome": self.outcome,
            "dimensions": self.dimensions,
            "score": self.score,
            "severity": self.severity,
            "evidence_count": self.evidence_count,
            "timestamp": self.timestamp or datetime.now(UTC).timestamp(),
        }


@dataclass
class PlatformProfile:
    platform: str
    total_observations: int = 0
    accepted_count: int = 0
    rejected_count: int = 0
    acceptance_rate: float = 0.0
    dimension_profiles: dict[str, dict[str, float]] = field(default_factory=dict)
    avg_score_accepted: float = 0.0
    avg_score_rejected: float = 0.0
    min_score_accepted: float = 0.0
    min_evidence_accepted: int = 0
    top_vuln_types: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "platform": self.platform,
            "total_observations": self.total_observations,
            "accepted_count": self.accepted_count,
            "rejected_count": self.rejected_count,
            "acceptance_rate": self.acceptance_rate,
            "dimension_profiles": self.dimension_profiles,
            "avg_score_accepted": self.avg_score_accepted,
            "avg_score_rejected": self.avg_score_rejected,
            "min_score_accepted": self.min_score_accepted,
            "min_evidence_accepted": self.min_evidence_accepted,
            "top_vuln_types": self.top_vuln_types,
        }


@dataclass
class AcceptancePrediction:
    probability: float
    platform: str
    confidence: str
    weak_dimensions: list[dict[str, Any]]
    recommendations: list[str]
    score: float
    min_accepted_score: float
    distance_to_min: float
    evidence_count: int
    avg_evidence_accepted: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "probability": self.probability,
            "platform": self.platform,
            "confidence": self.confidence,
            "weak_dimensions": self.weak_dimensions,
            "recommendations": self.recommendations,
            "score": self.score,
            "min_accepted_score": self.min_accepted_score,
            "distance_to_min": self.distance_to_min,
            "evidence_count": self.evidence_count,
            "avg_evidence_accepted": self.avg_evidence_accepted,
        }


_DEFAULT_WEIGHTS: dict[str, float] = {
    "evidence": 20.0,
    "reproducibility": 20.0,
    "clarity": 15.0,
    "impact_severity": 15.0,
    "completeness": 15.0,
    "confidence": 15.0,
}

_DIMENSION_NAMES = ["evidence", "reproducibility", "clarity", "impact_severity", "completeness", "confidence"]


class AcceptanceLearner:
    def __init__(self, load_persisted: bool = True) -> None:
        self._observations: list[OutcomeObservation] = []
        self._profiles: dict[str, PlatformProfile] = {}
        self._adapted_weights: dict[str, float] = dict(_DEFAULT_WEIGHTS)
        if load_persisted:
            self._load_state()

    def reset(self) -> None:
        self._observations.clear()
        self._profiles.clear()
        self._adapted_weights = dict(_DEFAULT_WEIGHTS)

    def record_outcome(
        self,
        submission_id: int,
    ) -> OutcomeObservation | None:
        db_session = db.SessionLocal()
        try:
            sub = db_session.query(SubmissionRecord).filter(SubmissionRecord.id == submission_id).first()
            if not sub:
                logger.warning("Submission %s not found", submission_id)
                return None

            outcome = self._classify_outcome(sub.status)
            if outcome is None:
                return None

            report = db_session.query(Report).filter(Report.id == sub.report_id).first()
            if not report:
                logger.warning("Report %s not found for submission %s", sub.report_id, submission_id)
                return None

            finding_ids = []
            if report.finding_ids:
                try:
                    finding_ids = (
                        json.loads(report.finding_ids) if isinstance(report.finding_ids, str) else report.finding_ids
                    )
                except (json.JSONDecodeError, TypeError):
                    finding_ids = []

            extra = {}
            if sub.extra_data:
                try:
                    extra = json.loads(sub.extra_data) if isinstance(sub.extra_data, str) else sub.extra_data
                except (json.JSONDecodeError, TypeError):
                    extra = {}

            dimensions = extra.get("quality_dimensions", {}) or {}
            quality_score = extra.get("quality_score", 0.0) or 0.0
            evidence_count = extra.get("evidence_count", 0) or 0

            if not dimensions and finding_ids:
                try:
                    scorer = QualityScorer()
                    qs = scorer.score(int(finding_ids[0]))
                    dimensions = qs.dimensions
                    quality_score = qs.score
                    evidence_count = qs.evidence_count
                except Exception:
                    logger.debug("Could not score finding %s for learning", finding_ids)

            obs = OutcomeObservation(
                platform=sub.platform,
                program=report.program or report.target or "unknown",
                vulnerability_type=report.vulnerability or "unknown",
                outcome=outcome,
                dimensions=dimensions,
                score=quality_score,
                severity=report.severity or "medium",
                evidence_count=evidence_count,
                timestamp=datetime.now(UTC).timestamp(),
            )

            self._observations.append(obs)
            self._recompute_profiles()
            self._adapt_weights()
            self._save_state()
            return obs

        except Exception as exc:
            logger.exception("Failed to record outcome for submission %s: %s", submission_id, exc)
            return None
        finally:
            db_session.close()

    def record_manual_outcome(
        self,
        platform: str,
        program: str,
        vulnerability_type: str,
        outcome: str,
        dimensions: dict[str, float] | None = None,
        score: float = 0.0,
        severity: str = "medium",
        evidence_count: int = 0,
    ) -> OutcomeObservation:
        obs = OutcomeObservation(
            platform=platform,
            program=program,
            vulnerability_type=vulnerability_type,
            outcome=outcome,
            dimensions=dimensions or {},
            score=score,
            severity=severity,
            evidence_count=evidence_count,
            timestamp=datetime.now(UTC).timestamp(),
        )
        self._observations.append(obs)
        self._recompute_profiles()
        self._adapt_weights()
        self._save_state()
        return obs

    def predict(
        self, platform: str, score: float, dimensions: dict[str, float], evidence_count: int
    ) -> AcceptancePrediction:
        profile = self._profiles.get(platform)

        if not profile or profile.total_observations < 3:
            return self._default_prediction(platform, score, dimensions, evidence_count)

        weak_dims: list[dict[str, Any]] = []
        recommendations: list[str] = []

        for dim in _DIMENSION_NAMES:
            dim_profile = profile.dimension_profiles.get(dim, {})
            accepted_avg = dim_profile.get("accepted_avg", 0.0)
            rejected_avg = dim_profile.get("rejected_avg", 0.0)
            current = dimensions.get(dim, 0.0)

            if accepted_avg > 0 and current < accepted_avg:
                gap = round((accepted_avg - current) * 100, 1)
                weak_dims.append(
                    {
                        "dimension": dim,
                        "current": round(current * 100, 1),
                        "accepted_avg": round(accepted_avg * 100, 1),
                        "rejected_avg": round(rejected_avg * 100, 1),
                        "gap": gap,
                    }
                )
                if gap > 15:
                    recommendations.append(
                        f"Mejorar '{dim}': promedio aceptados {accepted_avg * 100:.0f}%, "
                        f"actual {current * 100:.0f}% (brecha {gap:.0f}%)"
                    )

        if evidence_count < profile.min_evidence_accepted and profile.min_evidence_accepted > 0:
            recommendations.append(
                f"Agregar evidencia: mínimo {profile.min_evidence_accepted} piezas (actual: {evidence_count})"
            )

        weak_dims.sort(key=lambda x: x["gap"], reverse=True)

        if score < profile.min_score_accepted:
            recommendations.append(
                f"Score actual ({score:.1f}) está por debajo del mínimo aceptado "
                f"({profile.min_score_accepted:.1f}). Revisar dimensiones débiles."
            )

        positive_factors = max(1, profile.accepted_count)
        negative_factors = max(1, profile.rejected_count)
        distance_to_min = max(0, score - profile.min_score_accepted) if profile.min_score_accepted > 0 else 0

        if positive_factors + negative_factors > 0 and profile.avg_score_accepted > 0:
            if score >= profile.avg_score_accepted:
                base_prob = 0.85
            elif score >= profile.min_score_accepted:
                ratio = (score - profile.min_score_accepted) / (
                    profile.avg_score_accepted - profile.min_score_accepted + 0.01
                )
                base_prob = 0.50 + ratio * 0.35
            else:
                base_prob = max(0.10, score / (profile.avg_score_accepted + 0.01) * 0.40)

            acceptance_prior = profile.acceptance_rate / 100.0
            blended = base_prob * 0.6 + acceptance_prior * 0.4
        else:
            blended = 0.50

        blended = max(0.05, min(0.98, blended))

        if blended >= 0.75:
            confidence = "high"
        elif blended >= 0.45:
            confidence = "medium"
        else:
            confidence = "low"

        return AcceptancePrediction(
            probability=round(blended * 100, 1),
            platform=platform,
            confidence=confidence,
            weak_dimensions=weak_dims[:4],
            recommendations=recommendations[:6],
            score=score,
            min_accepted_score=profile.min_score_accepted,
            distance_to_min=round(distance_to_min, 1),
            evidence_count=evidence_count,
            avg_evidence_accepted=int(profile.min_evidence_accepted),
        )

    def _default_prediction(
        self, platform: str, score: float, dimensions: dict[str, float], evidence_count: int
    ) -> AcceptancePrediction:
        return AcceptancePrediction(
            probability=50.0,
            platform=platform,
            confidence="low",
            weak_dimensions=[],
            recommendations=["Registrar más outcomes de aceptación/rechazo para mejorar predicciones"],
            score=score,
            min_accepted_score=0.0,
            distance_to_min=0.0,
            evidence_count=evidence_count,
            avg_evidence_accepted=2,
        )

    def get_weights(self) -> dict[str, float]:
        return dict(self._adapted_weights)

    def get_profiles(self) -> dict[str, PlatformProfile]:
        return dict(self._profiles)

    def get_platform_profile(self, platform: str) -> PlatformProfile | None:
        return self._profiles.get(platform)

    def get_observations(self, limit: int = 100) -> list[dict[str, Any]]:
        return [o.to_dict() for o in self._observations[-limit:]]

    def sync_from_db(self) -> int:
        db_session = db.SessionLocal()
        count = 0
        try:
            subs = (
                db_session.query(SubmissionRecord)
                .filter(SubmissionRecord.status.in_(list(ACCEPTANCE_STATUSES | REJECTION_STATUSES)))
                .order_by(SubmissionRecord.submitted_at.desc())
                .limit(500)
                .all()
            )

            for sub in subs:
                result = self.record_outcome(sub.id)
                if result:
                    count += 1
        except Exception as exc:
            logger.exception("Failed to sync from DB: %s", exc)
        finally:
            db_session.close()
        if count:
            self._recompute_profiles()
            self._adapt_weights()
            self._save_state()
        return count

    def get_summary(self) -> dict[str, Any]:
        total_obs = len(self._observations)
        accepted = sum(1 for o in self._observations if o.outcome == OUTCOME_ACCEPTED)
        rejected = total_obs - accepted
        profiles_data = {p: profile.to_dict() for p, profile in self._profiles.items()}
        return {
            "total_observations": total_obs,
            "accepted": accepted,
            "rejected": rejected,
            "acceptance_rate": round(accepted / total_obs * 100, 1) if total_obs else 0.0,
            "platforms": list(self._profiles.keys()),
            "adapted_weights": self._adapted_weights,
            "profiles": profiles_data,
            "default_weights": _DEFAULT_WEIGHTS,
            "weight_deltas": {
                dim: round(self._adapted_weights.get(dim, 0) - _DEFAULT_WEIGHTS.get(dim, 0), 1)
                for dim in _DIMENSION_NAMES
            },
        }

    # ── Internal ────────────────────────────────────────────────

    def _classify_outcome(self, status: str) -> str | None:
        sl = status.lower().strip()
        if sl in ACCEPTANCE_STATUSES:
            return OUTCOME_ACCEPTED
        if sl in REJECTION_STATUSES:
            return OUTCOME_REJECTED
        return None

    def _recompute_profiles(self) -> None:
        grouped: dict[str, list[OutcomeObservation]] = defaultdict(list)
        for obs in self._observations:
            grouped[obs.platform].append(obs)

        profiles: dict[str, PlatformProfile] = {}
        for platform, obs_list in grouped.items():
            accepted = [o for o in obs_list if o.outcome == OUTCOME_ACCEPTED]
            rejected = [o for o in obs_list if o.outcome == OUTCOME_REJECTED]

            profile = PlatformProfile(
                platform=platform,
                total_observations=len(obs_list),
                accepted_count=len(accepted),
                rejected_count=len(rejected),
                acceptance_rate=round(len(accepted) / len(obs_list) * 100, 1) if obs_list else 0.0,
            )

            dim_profiles: dict[str, dict[str, float]] = {}
            for dim in _DIMENSION_NAMES:
                acc_values = [o.dimensions.get(dim, 0) for o in accepted if dim in o.dimensions]
                rej_values = [o.dimensions.get(dim, 0) for o in rejected if dim in o.dimensions]
                dim_profiles[dim] = {
                    "accepted_avg": round(sum(acc_values) / len(acc_values), 4) if acc_values else 0.0,
                    "accepted_min": round(min(acc_values), 4) if acc_values else 0.0,
                    "accepted_max": round(max(acc_values), 4) if acc_values else 0.0,
                    "rejected_avg": round(sum(rej_values) / len(rej_values), 4) if rej_values else 0.0,
                    "rejected_min": round(min(rej_values), 4) if rej_values else 0.0,
                    "rejected_max": round(max(rej_values), 4) if rej_values else 0.0,
                    "delta": round(
                        (sum(acc_values) / len(acc_values) - sum(rej_values) / len(rej_values))
                        if acc_values and rej_values
                        else 0.0,
                        4,
                    ),
                }
            profile.dimension_profiles = dim_profiles

            acc_scores = [o.score for o in accepted if o.score > 0]
            rej_scores = [o.score for o in rejected if o.score > 0]
            profile.avg_score_accepted = round(sum(acc_scores) / len(acc_scores), 1) if acc_scores else 0.0
            profile.avg_score_rejected = round(sum(rej_scores) / len(rej_scores), 1) if rej_scores else 0.0
            profile.min_score_accepted = min(acc_scores) if acc_scores else 0.0

            acc_evidence = [o.evidence_count for o in accepted if o.evidence_count > 0]
            profile.min_evidence_accepted = min(acc_evidence) if acc_evidence else 0

            vuln_counter: dict[str, int] = defaultdict(int)
            for o in obs_list:
                vuln_counter[o.vulnerability_type] += 1
            profile.top_vuln_types = sorted(vuln_counter, key=vuln_counter.get, reverse=True)[:5]

            profiles[platform] = profile

        self._profiles = profiles

    def _adapt_weights(self) -> None:
        if len(self._observations) < 5:
            self._adapted_weights = dict(_DEFAULT_WEIGHTS)
            return

        weight_deltas: dict[str, float] = {}
        for dim in _DIMENSION_NAMES:
            deltas = []
            for profile in self._profiles.values():
                dp = profile.dimension_profiles.get(dim)
                if dp and dp["delta"] != 0.0:
                    deltas.append(dp["delta"])
            if deltas:
                avg_delta = sum(deltas) / len(deltas)
                weight_deltas[dim] = round(avg_delta * 30, 1)
            else:
                weight_deltas[dim] = 0.0

        for dim in _DIMENSION_NAMES:
            base = _DEFAULT_WEIGHTS[dim]
            adjustment = min(max(weight_deltas.get(dim, 0), -5), 5)
            self._adapted_weights[dim] = round(base + adjustment, 1)

        total = sum(self._adapted_weights.values())
        if abs(total - 100.0) > 0.1:
            factor = 100.0 / total
            for dim in self._adapted_weights:
                self._adapted_weights[dim] = round(self._adapted_weights[dim] * factor, 1)

    def _save_state(self) -> None:
        try:
            from cores.recovery.persistence import get_recovery_store

            store = get_recovery_store()
            store.update_learning_state(OBSERVATIONS_KEY, json.dumps([o.to_dict() for o in self._observations]))
            store.update_learning_state(LEARNED_WEIGHTS_KEY, json.dumps(self._adapted_weights))
        except Exception as exc:
            logger.debug("Cannot save acceptance state (non-critical): %s", exc)

    def _load_state(self) -> None:
        try:
            from cores.recovery.persistence import get_recovery_store

            store = get_recovery_store()
            obs_raw = store.get_learning_state(OBSERVATIONS_KEY)
            if obs_raw and isinstance(obs_raw, str):
                parsed = json.loads(obs_raw)
                if isinstance(parsed, list):
                    for item in parsed:
                        self._observations.append(OutcomeObservation(**item))
            weights_raw = store.get_learning_state(LEARNED_WEIGHTS_KEY)
            if weights_raw and isinstance(weights_raw, str):
                parsed_w = json.loads(weights_raw)
                if isinstance(parsed_w, dict):
                    self._adapted_weights = parsed_w
            if self._observations:
                self._recompute_profiles()
        except Exception as exc:
            logger.debug("No saved acceptance state to load: %s", exc)
